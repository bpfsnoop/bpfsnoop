// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"

	"github.com/bpfsnoop/bpfsnoop/internal/btfx"
)

type bpfTracing struct {
	llock sync.Mutex
	progs []*ebpf.Program
	links []link.Link
	klnks []link.Link
	ilnks []link.Link
}

func (t *bpfTracing) Progs() []*ebpf.Program {
	return t.progs
}

func setBpfsnoopConfig(spec *ebpf.CollectionSpec, funcIP uint64, args []FuncParamFlags, ret FuncParamFlags, bothEntryExit, withRet bool) error {
	var cfg BpfsnoopConfig
	cfg.SetOutputLbr(outputLbr)
	cfg.SetOutputStack(outputFuncStack)
	cfg.SetOutputPktTuple(outputPkt)
	cfg.SetOutputArgData(len(argOutput.args) != 0)
	cfg.SetBothEntryExit(bothEntryExit)
	cfg.SetIsEntry(!withRet)
	cfg.FilterPid = filterPid
	cfg.FnArgsNr = uint32(len(args))
	for i, arg := range args {
		cfg.FnArgs[i] = arg.ParamFlags
	}
	cfg.FnRet = ret.ParamFlags
	cfg.WithRet = withRet

	if err := spec.Variables["bpfsnoop_config"].Set(cfg); err != nil {
		return fmt.Errorf("failed to set bpfsnoop config: %w", err)
	}
	if err := spec.Variables["FUNC_IP"].Set(funcIP); err != nil {
		return fmt.Errorf("failed to set FUNC_IP: %w", err)
	}

	return nil
}

func NewBPFTracing(spec, insnSpec *ebpf.CollectionSpec, reusedMaps map[string]*ebpf.Map, bprogs *bpfProgs, kfuncs KFuncs, insns *FuncInsns) (*bpfTracing, error) {
	var t bpfTracing
	t.links = make([]link.Link, 0, len(bprogs.tracings))

	var errg errgroup.Group

	for _, info := range bprogs.tracings {
		info := info
		errg.Go(func() error {
			return t.traceProg(spec, reusedMaps, info, bprogs)
		})
	}

	for _, fn := range kfuncs {
		bothEntryExit := fn.Insn
		fn := fn

		errg.Go(func() error {
			return t.traceFunc(spec, reusedMaps, fn, bothEntryExit, mode == TracingModeExit)
		})

		if bothEntryExit {
			errg.Go(func() error {
				return t.traceFunc(spec, reusedMaps, fn, bothEntryExit, mode != TracingModeExit)
			})
		}
	}

	for _, insn := range insns.Insns {
		insn := insn
		errg.Go(func() error {
			return t.traceInsn(insnSpec, reusedMaps, insn)
		})
	}

	if err := errg.Wait(); err != nil {
		t.Close()
		return nil, fmt.Errorf("failed to trace bpf progs: %w", err)
	}

	return &t, nil
}

func (t *bpfTracing) HaveTracing() bool {
	t.llock.Lock()
	defer t.llock.Unlock()

	return len(t.links) > 0 || len(t.klnks) > 0
}

func (t *bpfTracing) Close() {
	t.llock.Lock()
	defer t.llock.Unlock()

	var errg errgroup.Group

	for _, l := range t.links {
		l := l
		errg.Go(func() error {
			_ = l.Close()
			return nil
		})
	}

	for _, l := range t.klnks {
		l := l
		errg.Go(func() error {
			_ = l.Close()
			return nil
		})
	}

	for _, l := range t.ilnks {
		l := l
		errg.Go(func() error {
			_ = l.Close()
			return nil
		})
	}

	for _, prog := range t.progs {
		prog := prog
		errg.Go(func() error {
			_ = prog.Close()
			return nil
		})
	}

	_ = errg.Wait()
}

func TracingProgName() string {
	return "bpfsnoop_fn"
}

func (t *bpfTracing) injectArgFilter(prog *ebpf.ProgramSpec, params []btf.FuncParam, fnName string) error {
	if len(argFilter) == 0 {
		return nil
	}

	for i, p := range params {
		arg, ok := matchFuncArgs(p)
		if !ok {
			continue
		}

		err := arg.inject(prog, i, p.Type)
		if err != nil {
			return fmt.Errorf("failed to inject func arg filter expr: %w", err)
		}

		DebugLog("Injected --filter-arg expr to %dth param %s of func %s", i, p.Name, fnName)

		return nil
	}

	clearFilterArgSubprog(prog)

	return nil
}

func (t *bpfTracing) injectArgOutput(prog *ebpf.ProgramSpec, params []btf.FuncParam, checkArgType bool, fnName string) ([]funcArgumentOutput, error) {
	if len(argOutput.args) == 0 {
		return nil, nil
	}

	args, err := argOutput.matchParams(params, checkArgType)
	if err != nil {
		return nil, fmt.Errorf("failed to match params: %w", err)
	}

	argOutput.inject(prog, args)

	debugLogIf(len(args) != 0, "Injected --output-arg expr to func %s", fnName)

	return args, nil
}

func (t *bpfTracing) injectSkbFilter(prog *ebpf.ProgramSpec, index int, typ btf.Type) error {
	if err := pktFilter.filterSkb(prog, index, typ); err != nil {
		return fmt.Errorf("failed to inject skb pcap-filter: %w", err)
	}

	return nil
}

func (t *bpfTracing) injectXdpFilter(prog *ebpf.ProgramSpec, index int, typ btf.Type) error {
	if err := pktFilter.filterXdp(prog, index, typ); err != nil {
		return fmt.Errorf("failed to inject xdp pcap-filter: %w", err)
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
			typ, err := btfx.GetStructBtfPointer("sk_buff")
			if err != nil {
				return err
			}

			err = t.injectSkbFilter(prog, i, typ)

		case "xdp_buff":
			err = t.injectXdpFilter(prog, i, typ)

		case "xdp_md":
			typ, err := btfx.GetStructBtfPointer("xdp_buff")
			if err != nil {
				return err
			}

			err = t.injectXdpFilter(prog, i, typ)

		default:
			continue
		}

		if err != nil {
			return err
		}

		DebugLog("Injected --filter-pkt expr to %dth param %s of %s", i, p.Name, fnName)
		return nil
	}

	pktFilter.clear(prog)

	return nil
}

func (t *bpfTracing) injectPktOutput(prog *ebpf.ProgramSpec, params []btf.FuncParam, fnName string) bool {
	if !outputPkt {
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
			DebugLog("Injected --output-pkt to %dth param %s of %s", i, p.Name, fnName)
			return true

		case "xdp_buff", "xdp_md":
			pktOutput.outputXdp(prog, i)
			DebugLog("Injected --output-pkt to %dth param %s of %s", i, p.Name, fnName)
			return true
		}
	}

	pktOutput.clear(prog)

	return false
}

func (t *bpfTracing) traceProg(spec *ebpf.CollectionSpec, reusedMaps map[string]*ebpf.Map, info bpfTracingInfo, bprogs *bpfProgs) error {
	spec = spec.Copy()

	if err := setBpfsnoopConfig(spec, uint64(info.funcIP), info.params, info.ret, false, mode == TracingModeExit); err != nil {
		return fmt.Errorf("failed to set bpfsnoop config: %w", err)
	}

	traceeName := info.fn.Name
	tracingFuncName := TracingProgName()
	progSpec := spec.Programs[tracingFuncName]
	params := info.fn.Type.(*btf.FuncProto).Params
	bprogs.funcs[info.funcIP].pktOutput = t.injectPktOutput(progSpec, params, traceeName)
	if err := t.injectPktFilter(progSpec, params, traceeName); err != nil {
		return err
	}
	if err := t.injectArgFilter(progSpec, params, traceeName); err != nil {
		return err
	}
	args, err := t.injectArgOutput(progSpec, params, true, traceeName)
	if err != nil {
		return err
	}
	bprogs.funcs[info.funcIP].funcArgs = args

	attachType := ebpf.AttachTraceFExit
	if mode == TracingModeEntry {
		attachType = ebpf.AttachTraceFEntry
	}

	progSpec.AttachTarget = info.prog
	progSpec.AttachTo = info.funcName
	progSpec.AttachType = attachType

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: reusedMaps,
	})
	if err != nil {
		return fmt.Errorf("failed to create bpf collection for tracing prog %s: %w", traceeName, err)
	}
	defer coll.Close()

	prog := coll.Programs[tracingFuncName]
	delete(coll.Programs, tracingFuncName)

	l, err := link.AttachTracing(link.TracingOptions{
		Program:    prog,
		AttachType: attachType,
	})
	if err != nil {
		_ = prog.Close()
		if strings.Contains(err.Error(), "Cannot recursively attach") {
			VerboseLog("Skipped tracing a tracing prog %s", traceeName)
			return nil
		}
		return fmt.Errorf("failed to attach tracing prog %s: %w", traceeName, err)
	}

	VerboseLog("Tracing %s of prog %v", info.funcName, info.prog)

	t.llock.Lock()
	t.progs = append(t.progs, prog)
	t.links = append(t.links, l)
	t.llock.Unlock()

	return nil
}

func (t *bpfTracing) traceFunc(spec *ebpf.CollectionSpec, reusedMaps map[string]*ebpf.Map, fn *KFunc, bothEntryExit, isExit bool) error {
	spec = spec.Copy()

	isTracepoint := fn.IsTp
	tracingFuncName := TracingProgName()

	withRet := !isTracepoint && isExit
	if err := setBpfsnoopConfig(spec, fn.Ksym.addr, fn.Prms, fn.Ret, bothEntryExit, withRet); err != nil {
		return fmt.Errorf("failed to set bpfsnoop config: %w", err)
	}

	traceeName := fn.Func.Name
	progSpec := spec.Programs[tracingFuncName]
	funcProto := fn.Func.Type.(*btf.FuncProto)
	params := funcProto.Params
	fn.Pkt = t.injectPktOutput(progSpec, params, traceeName)
	if err := t.injectPktFilter(progSpec, params, traceeName); err != nil {
		return err
	}
	if err := t.injectArgFilter(progSpec, params, traceeName); err != nil {
		return err
	}
	args, err := t.injectArgOutput(progSpec, params, false, traceeName)
	if err != nil {
		return err
	}
	fn.Args = args

	attachType := ebpf.AttachTraceFEntry
	if isExit {
		attachType = ebpf.AttachTraceFExit
	}
	if isTracepoint {
		attachType = ebpf.AttachTraceRawTp
	}

	fnName := fn.Func.Name
	progSpec.AttachTo = fnName
	progSpec.AttachType = attachType

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: reusedMaps,
	})
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("failed to create bpf collection for tracing %s: %w", traceeName, err)
	}
	defer coll.Close()

	prog := coll.Programs[tracingFuncName]
	delete(coll.Programs, tracingFuncName)
	l, err := link.AttachTracing(link.TracingOptions{
		Program:    prog,
		AttachType: attachType,
	})
	if err != nil {
		_ = prog.Close()
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EINVAL) {
			return nil
		}
		if errors.Is(err, unix.EBUSY) /* Because no nop5 at the function entry, especially non-traceable funcs */ {
			if verbose {
				log.Printf("Cannot trace kernel function %s", fnName)
			}
			return nil
		}
		return fmt.Errorf("failed to attach tracing: %w", err)
	}

	verboseLogIf(!isTracepoint && isExit, "Tracing(fexit) kernel function %s", fnName)
	verboseLogIf(!isTracepoint && !isExit, "Tracing(fentry) kernel function %s", fnName)
	verboseLogIf(isTracepoint, "Tracing kernel tracepoint %s", fnName)

	t.llock.Lock()
	t.progs = append(t.progs, prog)
	t.klnks = append(t.klnks, l)
	t.llock.Unlock()

	return nil
}

func (t *bpfTracing) traceInsn(spec *ebpf.CollectionSpec, reusedMaps map[string]*ebpf.Map, insn FuncInsn) error {
	spec = spec.Copy()

	if err := spec.Variables["INSN_IP"].Set(insn.IP); err != nil {
		return fmt.Errorf("failed to set INSN_IP: %w", err)
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			".data.ready":       reusedMaps[".data.ready"],
			"bpfsnoop_events":   reusedMaps["bpfsnoop_events"],
			"bpfsnoop_sessions": reusedMaps["bpfsnoop_sessions"],
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create bpf collection for tracing insn '%s': %w", insn.Desc, err)
	}
	defer coll.Close()

	prog := coll.Programs["k_insn"]
	delete(coll.Programs, "k_insn")
	l, err := link.Kprobe(insn.Func, prog, &link.KprobeOptions{
		Offset: insn.Off,
	})
	if err != nil {
		_ = prog.Close()
		DebugLog("Failed to attach kprobe %s insn '%s': %v", insn.Func, insn.Desc, err)
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EADDRNOTAVAIL) {
			return nil
		}
		return fmt.Errorf("failed to attach kprobe %s insn '%s': %w", insn.Func, insn.Desc, err)
	}

	VerboseLog("Tracing func %s insn '%s'", insn.Func, insn.Desc)

	t.llock.Lock()
	t.progs = append(t.progs, prog)
	t.ilnks = append(t.ilnks, l)
	t.llock.Unlock()

	return nil
}
