// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"
	"slices"
	"sync"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sync/errgroup"

	"github.com/bpfsnoop/bpfsnoop/internal/btfx"
	"github.com/bpfsnoop/bpfsnoop/internal/cc"
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
	exitFilter    bool
	pktRetval     bool
}

type traceeOutputs struct {
	args        []funcArgumentOutput
	argDataSize int
	pkt         bool
	pktRetval   bool
	exitFilter  bool
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
	cfg.SetExitFilter(c.exitFilter)
	cfg.SetPktRetval(c.pktRetval)
	cfg.FilterPid = filterPid
	copy(cfg.FilterComm[:], []uint8(filterComm))
	cfg.FilterCommLen = uint32(len(filterComm))
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
		errg.Go(func() error {
			b.Close()
			return nil
		})
	}

	for _, k := range t.kfns {
		errg.Go(func() error {
			k.Close()
			return nil
		})
	}

	for _, i := range t.insns {
		errg.Go(func() error {
			i.Close()
			return nil
		})
	}

	for _, g := range t.grphs {
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

func (t *bpfTracing) injectArgFilter(prog *ebpf.ProgramSpec, params []btf.FuncParam, ret btf.Type, spec *btf.Spec, fnName string, match *funcArgument, compile bool) error {
	if match == nil || !compile {
		clearFilterArgSubprog(prog)
		return nil
	}

	if err := match.inject(prog, getKernelBTF(), spec, params, ret); err != nil {
		return fmt.Errorf("failed to inject func arg filter expr: %w", err)
	}

	DebugLog("Injected --filter-arg '%s' to func %s", match.expr, fnName)

	return nil
}

func (t *bpfTracing) injectArgOutput(prog *ebpf.ProgramSpec, params []btf.FuncParam, ret btf.Type, spec *btf.Spec, fnName string, canExit bool) ([]funcArgumentOutput, int, error) {
	if len(argOutput.args) == 0 {
		clearOutputArgSubprog(prog)
		return nil, 0, nil
	}

	args, size, err := argOutput.matchParams(params, ret, spec, canExit)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to match params: %w", err)
	}

	argOutput.inject(prog, args)

	debugLogIf(len(args) != 0, "Injected --output-arg expr to func %s", fnName)

	return args, size, nil
}

func (t *bpfTracing) injectTraceeOutputs(prog *ebpf.ProgramSpec, params []btf.FuncParam, ret btf.Type, spec *btf.Spec, fnName string, outputPkt, bothEntryExit, isExit, canExit bool) (traceeOutputs, bool, error) {
	var outputs traceeOutputs

	filterMatch, err := argFilter.selectMatch(params, ret, spec)
	if err != nil {
		return outputs, false, fmt.Errorf("failed to match func arg filter expr: %w", err)
	}
	filterRetval := filterMatch != nil && slices.Contains(filterMatch.vars, cc.RetvalName)
	if filterRetval && !canExit {
		DebugLog("Skip %s because selected --filter-arg requires %s in entry-only mode", fnName, cc.RetvalName)
		return outputs, false, nil
	}

	allPacketParams := packetSourceParams(params, ret, pktFilter.retval)
	outputPacketParams := packetSourceParams(params, ret, outputPktRetval)
	outputs.pkt, outputs.pktRetval = t.injectPktOutput(outputPkt, prog, outputPacketParams, fnName, outputPktRetval)
	pktFilterRetval, err := t.injectPktFilter(prog, allPacketParams, fnName, isExit, pktFilter.retval)
	if err != nil {
		return outputs, false, err
	}
	if pktFilterRetval && !canExit {
		DebugLog("Skip %s because --filter-pkt requires %s in entry-only mode", fnName, cc.RetvalName)
		return outputs, false, nil
	}

	outputs.exitFilter = (filterRetval || pktFilterRetval) && bothEntryExit
	if err := t.injectArgFilter(prog, params, ret, spec, fnName, filterMatch, !filterRetval || isExit); err != nil {
		return outputs, false, err
	}
	outputs.args, outputs.argDataSize, err = t.injectArgOutput(prog, params, ret, spec, fnName, canExit)
	if err != nil {
		return outputs, false, err
	}

	return outputs, true, nil
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

func (t *bpfTracing) injectPktFilter(prog *ebpf.ProgramSpec, params []btf.FuncParam, fnName string, compileRetval, retvalOnly bool) (bool, error) {
	if pktFilter.expr == "" {
		return false, nil
	}

	for i, p := range params {
		retval := p.Name == cc.RetvalName
		if retvalOnly && !retval {
			continue
		}
		typ := mybtf.UnderlyingType(p.Type)
		ptr, ok := typ.(*btf.Pointer)
		if !ok {
			continue
		}

		stt, ok := ptr.Target.(*btf.Struct)
		if !ok {
			continue
		}
		if retval && !compileRetval {
			pktFilter.clear(prog)
			return true, nil
		}

		var err error
		switch stt.Name {
		case "sk_buff":
			err = t.injectSkbFilter(prog, i, typ)

		case "__sk_buff":
			typ, err := btfx.GetStructBtfPointer("sk_buff", getKernelBTF())
			if err != nil {
				return false, err
			}

			err = t.injectSkbFilter(prog, i, typ)

		case "xdp_buff":
			err = t.injectXdpFilter(prog, i, typ)

		case "xdp_md":
			typ, err := btfx.GetStructBtfPointer("xdp_buff", getKernelBTF())
			if err != nil {
				return false, err
			}

			err = t.injectXdpFilter(prog, i, typ)

		case "xdp_frame":
			err = t.injectXdpFrameFilter(prog, i, typ)

		default:
			continue
		}

		if err != nil {
			return false, err
		}

		DebugLog("Injected --filter-pkt expr to %dth param (%s)%s of %s", i, btfx.Repr(typ), p.Name, fnName)
		return retval, nil
	}

	pktFilter.clear(prog)

	return false, nil
}

func (t *bpfTracing) injectPktOutput(pkt bool, prog *ebpf.ProgramSpec, params []btf.FuncParam, fnName string, retvalOnly bool) (bool, bool) {
	if !pkt {
		pktOutput.clear(prog)
		return false, false
	}

	for i, p := range params {
		if retvalOnly && p.Name != cc.RetvalName {
			continue
		}
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
			return true, p.Name == cc.RetvalName

		case "xdp_buff", "xdp_md":
			pktOutput.outputXdpBuff(prog, i)
			DebugLog("Injected --output-pkt to %dth param (%s)%s of %s", i, btfx.Repr(p.Type), p.Name, fnName)
			return true, p.Name == cc.RetvalName

		case "xdp_frame":
			pktOutput.outputXdpFrame(prog, i)
			DebugLog("Injected --output-pkt to %dth param (%s)%s of %s", i, btfx.Repr(p.Type), p.Name, fnName)
			return true, p.Name == cc.RetvalName
		}
	}

	pktOutput.clear(prog)

	return false, false
}

func packetSourceParams(params []btf.FuncParam, ret btf.Type, retval bool) []btf.FuncParam {
	if !retval {
		return params
	}
	params = slices.Clone(params)
	return append(params, btf.FuncParam{Name: cc.RetvalName, Type: ret})
}
