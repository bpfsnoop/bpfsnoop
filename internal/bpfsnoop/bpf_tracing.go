// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"
	"sync"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sync/errgroup"

	"github.com/bpfsnoop/bpfsnoop/internal/btfx"
)

type bpfTracing struct {
	llock sync.Mutex
	progs []*ebpf.Program
	bprgs []tracingProg
	kfns  []tracingFunc
	insns []tracingInsn
	grphs []tracingGraph
}

type traceeConfig struct {
	funcIP        uint64
	fnArgsNr      int
	fnArgsBufSz   int
	argEntrySz    int
	argExitSz     int
	argDataSz     int
	outputLbr     bool
	outputStack   bool
	outputPkt     bool
	insnMode      bool
	graphMode     bool
	bothEntryExit bool
	isTp          bool
	isProg        bool
	kmultiMode    bool
	withRet       bool
	session       bool
}

func (t *bpfTracing) Progs() []*ebpf.Program {
	return t.progs
}

func setBpfsnoopConfig(spec *ebpf.CollectionSpec, c traceeConfig) error {
	var cfg BpfsnoopConfig
	cfg.SetOutputLbr(c.outputLbr)
	cfg.SetOutputStack(c.outputStack)
	cfg.SetOutputPktTuple(c.outputPkt)
	cfg.SetOutputArg(c.argDataSz != 0)
	cfg.SetBothEntryExit(c.bothEntryExit)
	cfg.SetIsEntry(!c.withRet)
	cfg.SetIsSession(c.session)
	cfg.SetInsnMode(c.insnMode)
	cfg.SetGraphMode(c.graphMode)
	cfg.SetIsTp(c.isTp)
	cfg.SetIsProg(c.isProg)
	cfg.SetKmultiMode(c.kmultiMode)
	cfg.FilterPid = filterPid
	cfg.FnArgsNr = uint32(c.fnArgsNr)
	cfg.WithRet = c.withRet
	cfg.FnArgsBuf = uint32(c.fnArgsBufSz)
	cfg.ArgDataSz = uint32(c.argDataSz)
	cfg.TraceeArgEntrySz = uint32(c.argEntrySz)
	cfg.TraceeArgExitSz = uint32(c.argExitSz)
	cfg.TraceeArgDataSz = uint32(c.argDataSz)

	if err := spec.Variables["bpfsnoop_config"].Set(cfg); err != nil {
		return fmt.Errorf("failed to set bpfsnoop config: %w", err)
	}
	if err := spec.Variables["FUNC_IP"].Set(c.funcIP); err != nil {
		return fmt.Errorf("failed to set FUNC_IP: %w", err)
	}
	if err := spec.Variables["SKIP_TUNNEL"].Set(uint32(b2i(skipTunnel))); err != nil {
		return fmt.Errorf("failed to set SKIP_TUNNEL: %w", err)
	}

	return nil
}

func NewBPFTracing(spec *ebpf.CollectionSpec, reusedMaps map[string]*ebpf.Map, bprogs *bpfProgs, kfuncs KFuncs, insns FuncInsns, graphs FuncGraphs, kfuncsMulti []kfuncInfoMulti) (*bpfTracing, error) {
	var errg errgroup.Group
	var t bpfTracing

	t.traceProgs(&errg, spec, reusedMaps, bprogs)
	if err := t.traceFuncs(&errg, spec, reusedMaps, kfuncs); err != nil {
		return nil, fmt.Errorf("failed to prepare tracing funcs: %w", err)
	}

	if err := t.traceFuncsMulti(&errg, reusedMaps, kfuncsMulti); err != nil {
		return nil, fmt.Errorf("failed to trace kfunc in multi-mode: %w", err)
	}

	if err := t.traceInsns(&errg, reusedMaps, insns); err != nil {
		return nil, fmt.Errorf("failed to trace kfunc insns: %w", err)
	}

	errg.Go(func() error {
		if err := t.traceGraphs(reusedMaps, graphs); err != nil {
			return fmt.Errorf("failed to trace graph funcs/progs: %w", err)
		}
		return nil
	})

	if err := errg.Wait(); err != nil {
		t.Close()
		return nil, fmt.Errorf("failed to trace targets: %w", err)
	}

	return &t, nil
}

func (t *bpfTracing) HaveTracing() bool {
	t.llock.Lock()
	defer t.llock.Unlock()

	return len(t.progs) > 0
}

func (t *bpfTracing) Close() {
	t.llock.Lock()
	defer t.llock.Unlock()

	var errg errgroup.Group

	for _, b := range t.bprgs {
		b := b
		errg.Go(func() error {
			b.Close()
			return nil
		})
	}

	for _, k := range t.kfns {
		k := k
		errg.Go(func() error {
			k.Close()
			return nil
		})
	}

	for _, i := range t.insns {
		i := i
		errg.Go(func() error {
			i.Close()
			return nil
		})
	}

	for _, g := range t.grphs {
		g := g
		errg.Go(func() error {
			g.Close()
			return nil
		})
	}

	_ = errg.Wait()
}

func TracingProgName() string {
	return "bpfsnoop_fn"
}

func (t *bpfTracing) injectArgFilter(prog *ebpf.ProgramSpec, params []btf.FuncParam, spec *btf.Spec, fnName string) error {
	i, err := argFilter.inject(prog, params, spec)
	if err != nil {
		if err == errSkipped {
			clearFilterArgSubprog(prog)
			return nil
		}
		return fmt.Errorf("failed to inject func arg filter expr: %w", err)
	}

	DebugLog("Injected --filter-arg '%s' to func %s", argFilter.args[i].expr, fnName)

	return nil
}

func (t *bpfTracing) injectArgOutput(prog *ebpf.ProgramSpec, params []btf.FuncParam, spec *btf.Spec, fnName string) ([]funcArgumentOutput, int, error) {
	if len(argOutput.args) == 0 {
		return nil, 0, nil
	}

	args, size, err := argOutput.matchParams(params, spec)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to match params: %w", err)
	}

	argOutput.inject(prog, args)

	debugLogIf(len(args) != 0, "Injected --output-arg expr to func %s", fnName)

	return args, size, nil
}

func (t *bpfTracing) injectSkbFilter(prog *ebpf.ProgramSpec, index int, typ btf.Type) error {
	if err := pktFilter.filterSkb(prog, index, typ); err != nil {
		return fmt.Errorf("failed to inject skb pcap-filter: %w", err)
	}

	return nil
}

func (t *bpfTracing) injectXdpFilter(prog *ebpf.ProgramSpec, index int, typ btf.Type) error {
	if err := pktFilter.filterXdp(prog, index, typ); err != nil {
		return fmt.Errorf("failed to inject xdp_buff pcap-filter: %w", err)
	}

	return nil
}

func (t *bpfTracing) injectXdpFrameFilter(prog *ebpf.ProgramSpec, index int, typ btf.Type) error {
	if err := pktFilter.filterXdpFrame(prog, index, typ); err != nil {
		return fmt.Errorf("failed to inject xdp_frame pcap-filter: %w", err)
	}

	return nil
}

func (t *bpfTracing) injectPktFilter(prog *ebpf.ProgramSpec, params []btf.FuncParam, fnName string) error {
	if pktFilter.expr == "" {
		return nil
	}

	for i, p := range params {
		typ := mybtf.UnderlyingType(p.Type)
		ptr, ok := typ.(*btf.Pointer)
		if !ok {
			continue
		}

		stt, ok := ptr.Target.(*btf.Struct)
		if !ok {
			continue
		}

		var err error
		switch stt.Name {
		case "sk_buff":
			err = t.injectSkbFilter(prog, i, typ)

		case "__sk_buff":
			typ, err := btfx.GetStructBtfPointer("sk_buff", getKernelBTF())
			if err != nil {
				return err
			}

			err = t.injectSkbFilter(prog, i, typ)

		case "xdp_buff":
			err = t.injectXdpFilter(prog, i, typ)

		case "xdp_md":
			typ, err := btfx.GetStructBtfPointer("xdp_buff", getKernelBTF())
			if err != nil {
				return err
			}

			err = t.injectXdpFilter(prog, i, typ)

		case "xdp_frame":
			err = t.injectXdpFrameFilter(prog, i, typ)

		default:
			continue
		}

		if err != nil {
			return err
		}

		DebugLog("Injected --filter-pkt expr to %dth param (%s)%s of %s", i, btfx.Repr(typ), p.Name, fnName)
		return nil
	}

	pktFilter.clear(prog)

	return nil
}

func (t *bpfTracing) injectPktOutput(pkt bool, prog *ebpf.ProgramSpec, params []btf.FuncParam, fnName string) bool {
	if !pkt {
		pktOutput.clear(prog)
		return false
	}

	for i, p := range params {
		typ := mybtf.UnderlyingType(p.Type)
		ptr, ok := typ.(*btf.Pointer)
		if !ok {
			continue
		}

		stt, ok := ptr.Target.(*btf.Struct)
		if !ok {
			continue
		}

		switch stt.Name {
		case "sk_buff", "__sk_buff":
			pktOutput.outputSkb(prog, i)
			DebugLog("Injected --output-pkt to %dth param (%s)%s of %s", i, btfx.Repr(p.Type), p.Name, fnName)
			return true

		case "xdp_buff", "xdp_md":
			pktOutput.outputXdpBuff(prog, i)
			DebugLog("Injected --output-pkt to %dth param (%s)%s of %s", i, btfx.Repr(p.Type), p.Name, fnName)
			return true

		case "xdp_frame":
			pktOutput.outputXdpFrame(prog, i)
			DebugLog("Injected --output-pkt to %dth param (%s)%s of %s", i, btfx.Repr(p.Type), p.Name, fnName)
			return true
		}
	}

	pktOutput.clear(prog)

	return false
}
