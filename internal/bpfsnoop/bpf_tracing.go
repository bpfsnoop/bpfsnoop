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
}

func (t *bpfTracing) Progs() []*ebpf.Program {
	return t.progs
}

func setBpfsnoopConfig(spec *ebpf.CollectionSpec, funcIP uint64, args []FuncParamFlags, isRetStr bool) error {
	var cfg BpfsnoopConfig
	cfg.SetOutputLbr(outputLbr)
	cfg.SetOutputStack(outputFuncStack)
	cfg.SetOutputPktTuple(outputPkt)
	cfg.SetOutputArgData(len(argOutput.args) != 0)
	cfg.SetIsRetStr(isRetStr)
	cfg.FilterPid = filterPid
	cfg.FnArgsNr = uint32(len(args))
	for i, arg := range args {
		cfg.FnArgs[i] = arg.ParamFlags
	}

	if err := spec.Variables["bpfsnoop_config"].Set(cfg); err != nil {
		return fmt.Errorf("failed to set bpfsnoop config: %w", err)
	}
	if err := spec.Variables["FUNC_IP"].Set(funcIP); err != nil {
		return fmt.Errorf("failed to set FUNC_IP: %w", err)
	}

	return nil
}

func NewBPFTracing(spec *ebpf.CollectionSpec, reusedMaps map[string]*ebpf.Map, bprogs *bpfProgs, kfuncs KFuncs) (*bpfTracing, error) {
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
		fn := fn
		errg.Go(func() error {
			return t.traceFunc(spec, reusedMaps, fn)
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

	_ = errg.Wait()
}

func TracingProgName(mode string) string {
	return fmt.Sprintf("f%s_fn", mode)
}

func TracingTpBtfProgName() string {
	return "tp_btf_fn"
}

func (t *bpfTracing) injectArgFilter(prog *ebpf.ProgramSpec, params []btf.FuncParam, getFuncArg bool, fnName string) error {
	if len(argFilter) == 0 {
		return nil
	}

	for i, p := range params {
		arg, ok := matchFuncArgs(p)
		if !ok {
			continue
		}

		err := arg.inject(prog, i, p.Type, getFuncArg)
		if err != nil {
			return fmt.Errorf("failed to inject func arg filter expr: %w", err)
		}

		DebugLog("Injected --filter-arg expr to %dth param %s of func %s", i, p.Name, fnName)

		return nil
	}

	clearFilterArgSubprog(prog)

	return nil
}

func (t *bpfTracing) injectArgOutput(prog *ebpf.ProgramSpec, params []btf.FuncParam, checkArgType, getFuncArg bool, fnName string) ([]funcArgumentOutput, error) {
	if len(argOutput.args) == 0 {
		return nil, nil
	}

	args, err := argOutput.matchParams(params, checkArgType, getFuncArg)
	if err != nil {
		return nil, fmt.Errorf("failed to match params: %w", err)
	}

	argOutput.inject(prog, args)

	DebugLog("Injected --output-arg expr to func %s", fnName)

	return args, nil
}

func (t *bpfTracing) injectSkbFilter(prog *ebpf.ProgramSpec, index int, typ btf.Type, getFuncArg bool) error {
	if err := pktFilter.filterSkb(prog, index, typ, getFuncArg); err != nil {
		return fmt.Errorf("failed to inject skb pcap-filter: %w", err)
	}

	return nil
}

func (t *bpfTracing) injectXdpFilter(prog *ebpf.ProgramSpec, index int, typ btf.Type, getFuncArg bool) error {
	if err := pktFilter.filterXdp(prog, index, typ, getFuncArg); err != nil {
		return fmt.Errorf("failed to inject xdp pcap-filter: %w", err)
	}

	return nil
}

func (t *bpfTracing) injectPktFilter(prog *ebpf.ProgramSpec, params []btf.FuncParam, getFuncArg bool, fnName string) error {
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
			err = t.injectSkbFilter(prog, i, typ, getFuncArg)

		case "__sk_buff":
			typ, err := btfx.GetStructBtfPointer("sk_buff")
			if err != nil {
				return err
			}

			err = t.injectSkbFilter(prog, i, typ, getFuncArg)

		case "xdp_buff":
			err = t.injectXdpFilter(prog, i, typ, getFuncArg)

		case "xdp_md":
			typ, err := btfx.GetStructBtfPointer("xdp_buff")
			if err != nil {
				return err
			}

			err = t.injectXdpFilter(prog, i, typ, getFuncArg)

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

func (t *bpfTracing) injectPktOutput(prog *ebpf.ProgramSpec, params []btf.FuncParam, getFuncArg bool, fnName string) {
	if !outputPkt {
		return
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
			pktOutput.outputSkb(prog, i, getFuncArg)
			DebugLog("Injected --output-pkt to %dth param %s of %s", i, p.Name, fnName)
			return

		case "xdp_buff", "xdp_md":
			pktOutput.outputXdp(prog, i, getFuncArg)
			DebugLog("Injected --output-pkt to %dth param %s of %s", i, p.Name, fnName)
			return
		}
	}

	pktOutput.clear(prog)
}

func (t *bpfTracing) traceProg(spec *ebpf.CollectionSpec, reusedMaps map[string]*ebpf.Map, info bpfTracingInfo, bprogs *bpfProgs) error {
	spec = spec.Copy()
	delete(spec.Programs, TracingTpBtfProgName())

	if err := setBpfsnoopConfig(spec, uint64(info.funcIP), info.params, false); err != nil {
		return fmt.Errorf("failed to set bpfsnoop config: %w", err)
	}

	traceeName := info.fn.Name
	tracingFuncName := TracingProgName(mode)
	progSpec := spec.Programs[tracingFuncName]
	params := info.fn.Type.(*btf.FuncProto).Params
	t.injectPktOutput(progSpec, params, true, traceeName)
	if err := t.injectPktFilter(progSpec, params, true, traceeName); err != nil {
		return err
	}
	if err := t.injectArgFilter(progSpec, params, true, traceeName); err != nil {
		return err
	}
	args, err := t.injectArgOutput(progSpec, params, true, true, traceeName)
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
		return fmt.Errorf("failed to create bpf collection for tracing: %w", err)
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
			VerboseLog("Skipped tracing a tracing prog %s", info.fn.Name)
			return nil
		}
		return fmt.Errorf("failed to attach tracing: %w", err)
	}

	VerboseLog("Tracing %s of prog %v", info.funcName, info.prog)

	t.llock.Lock()
	t.progs = append(t.progs, prog)
	t.links = append(t.links, l)
	t.llock.Unlock()

	return nil
}

func (t *bpfTracing) traceFunc(spec *ebpf.CollectionSpec, reusedMaps map[string]*ebpf.Map, fn *KFunc) error {
	spec = spec.Copy()

	isTracepoint := fn.IsTp
	tracingFuncName := TracingProgName(mode)
	if isTracepoint {
		delete(spec.Programs, tracingFuncName)
		tracingFuncName = TracingTpBtfProgName()
	} else {
		delete(spec.Programs, TracingTpBtfProgName())
	}

	if err := setBpfsnoopConfig(spec, fn.Ksym.addr, fn.Prms, fn.IsRetStr); err != nil {
		return fmt.Errorf("failed to set bpfsnoop config: %w", err)
	}

	traceeName := fn.Func.Name
	progSpec := spec.Programs[tracingFuncName]
	funcProto := fn.Func.Type.(*btf.FuncProto)
	params := funcProto.Params
	t.injectPktOutput(progSpec, params, !isTracepoint, traceeName)
	if err := t.injectPktFilter(progSpec, params, !isTracepoint, traceeName); err != nil {
		return err
	}
	if err := t.injectArgFilter(progSpec, params, !isTracepoint, traceeName); err != nil {
		return err
	}
	args, err := t.injectArgOutput(progSpec, params, false, !isTracepoint, traceeName)
	if err != nil {
		return err
	}
	fn.Args = args

	if isTracepoint {
		err := t.injectTpBtfFn(progSpec, funcProto, traceeName)
		if err != nil {
			return fmt.Errorf("failed to update tp_btf_fn: %w", err)
		}
	}

	attachType := ebpf.AttachTraceFExit
	if mode == TracingModeEntry {
		attachType = ebpf.AttachTraceFEntry
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
		return fmt.Errorf("failed to create bpf collection for tracing: %w", err)
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

	VerboseLog("Tracing kernel function %s", fnName)

	t.llock.Lock()
	t.progs = append(t.progs, prog)
	t.klnks = append(t.klnks, l)
	t.llock.Unlock()

	return nil
}
