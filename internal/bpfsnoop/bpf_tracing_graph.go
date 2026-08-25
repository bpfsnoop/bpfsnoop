// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"

	"github.com/bpfsnoop/bpfsnoop/internal/bpf"
	"github.com/bpfsnoop/bpfsnoop/internal/slicex"
	"github.com/bpfsnoop/gapstone"
)

const (
	graphHookModeEntry int = iota
	graphHookModeExit
	graphHookModeSession
)

type tracingGraph struct {
	l link.Link
	p *ebpf.Program
}

func (t *tracingGraph) Close() {
	_ = t.l.Close()
	_ = t.p.Close()
}

type bpfFgraphConfig struct {
	FuncIP    uint64
	MaxDepth  uint32
	Mode      uint8
	TinBPF    uint8 // tailcall in bpf2bpf
	Pad2      uint16
	MyPID     uint32
	FnArgsNr  uint32
	WithRet   uint8
	Pad       [3]uint8
	FnArgsBuf uint32
}

func (t *bpfTracing) traceGraph(spec *ebpf.CollectionSpec,
	reusedMaps map[string]*ebpf.Map, bp *ebpf.Program, params []FuncParamFlags,
	ret FuncParamFlags, traceeName string, graph *FuncGraph, entry, fsession bool,
) error {
	tracingProgName := "bpfsnoop_fgraph"
	progSpec := spec.Programs[tracingProgName]
	fnArgsBufSize, err := injectOutputFuncArgs(progSpec, params, ret, !entry || fsession)
	if err != nil {
		return fmt.Errorf("failed to inject output func args: %w", err)
	}
	if entry {
		graph.ArgsEnSz = fnArgsBufSize
	} else {
		graph.ArgsExSz = fnArgsBufSize
	}

	mode := graphHookModeEntry
	if !entry {
		mode = graphHookModeExit
	}
	if fsession {
		mode = graphHookModeSession
	}

	var cfg bpfFgraphConfig
	cfg.FuncIP = graph.IP
	cfg.MaxDepth = uint32(graph.MaxDepth)
	cfg.Mode = uint8(mode)
	cfg.TinBPF = uint8(b2i(tailcallInfo.supportTailcallInBpf2bpf))
	cfg.FnArgsNr = uint32(len(params))
	cfg.WithRet = uint8(b2i(!entry))
	cfg.FnArgsBuf = uint32(fnArgsBufSize)
	cfg.MyPID = uint32(os.Getpid())

	if err := spec.Variables["BSN_FGRAPH_CFG"].Set(cfg); err != nil {
		return fmt.Errorf("failed to set bpfsnoop fgraph config: %w", err)
	}

	attachType := ebpf.AttachTraceFExit
	if entry {
		attachType = ebpf.AttachTraceFEntry
	}
	if fsession {
		attachType = ebpf.AttachTraceFSession
	}

	if bp != nil {
		progSpec.AttachTarget = bp
	}
	progSpec.AttachTo = traceeName
	progSpec.AttachType = attachType

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: reusedMaps,
	})
	if err != nil {
		if ignoreFuncTraceVerifierErr(err, traceeName) {
			return nil
		}
		return fmt.Errorf("failed to create bpf collection for tracing graph target '%s': %w", traceeName, err)
	}
	defer coll.Close()

	prog := coll.Programs[tracingProgName]
	l, err := link.AttachTracing(link.TracingOptions{
		Program:    prog,
		AttachType: attachType,
	})
	if err != nil {
		if ignoreFuncTraceErr(err, traceeName) {
			return nil
		}
		return fmt.Errorf("failed to attach tracing graph target '%s': %w", traceeName, err)
	}

	verboseLogIf(attachType == ebpf.AttachTraceFEntry, "Tracing(fentry) func graph %s at %#x", traceeName, graph.IP)
	verboseLogIf(attachType == ebpf.AttachTraceFExit, "Tracing(fexit) func graph %s at %#x", traceeName, graph.IP)
	verboseLogIf(attachType == ebpf.AttachTraceFSession, "Tracing(fsession) func graph %s at %#x", traceeName, graph.IP)

	delete(coll.Programs, tracingProgName)
	t.llock.Lock()
	t.progs = append(t.progs, prog)
	t.grphs = append(t.grphs, tracingGraph{
		l: l,
		p: prog,
	})
	t.llock.Unlock()

	return nil
}

func (t *bpfTracing) traceGraphFunc(spec *ebpf.CollectionSpec, reusedMaps map[string]*ebpf.Map, graph *FuncGraph, entry, fsession bool) error {
	spec = spec.Copy()

	fn := graph.Kfunc
	traceeName := fn.Ksym.name
	err := t.traceGraph(spec, reusedMaps, nil, fn.Prms, fn.Ret, traceeName, graph, entry, fsession)
	if err != nil {
		return fmt.Errorf("failed to trace graph func '%s': %w", traceeName, err)
	}

	return nil
}

func (t *bpfTracing) traceGraphProg(spec *ebpf.CollectionSpec, reusedMaps map[string]*ebpf.Map, graph *FuncGraph, entry, fsession bool) error {
	spec = spec.Copy()

	gp := graph.Bprog
	traceeName := gp.funcName
	err := t.traceGraph(spec, reusedMaps, gp.prog, gp.funcParams, gp.retParam, traceeName, graph, entry, fsession)
	if err != nil {
		return fmt.Errorf("failed to trace graph prog '%s': %w", traceeName, err)
	}

	return nil
}

func setupFgraphStack(spec *ebpf.CollectionSpec) error {
	maxStack, err := readKernelPerfEventMaxStack()
	if err != nil {
		return fmt.Errorf("failed to read kernel perf event max stack: %w", err)
	}

	m, ok := spec.Maps["bpfsnoop_fgraph_stack"]
	if !ok {
		return fmt.Errorf("map spec %s not found", "bpfsnoop_fgraph_stack")
	}
	m.ValueSize = uint32(maxStack) * 8
	arr, ok := m.Value.(*btf.Array)
	if !ok {
		return fmt.Errorf("unexpected map value type for %s: %T", "bpfsnoop_fgraph_stack", m.Value)
	}
	arr.Nelems = uint32(maxStack)

	if err := spec.Variables["STACK_DEPTH"].Set(uint32(maxStack)); err != nil {
		return fmt.Errorf("failed to set fgraph stack depth: %w", err)
	}

	return nil
}

func (t *bpfTracing) traceGraphs(reusedMaps map[string]*ebpf.Map, graphs FuncGraphs) error {
	if len(graphs) == 0 {
		return nil
	}

	spec, err := bpf.LoadGraph()
	if err != nil {
		return fmt.Errorf("failed to load graph bpf spec: %w", err)
	}

	if err := setupFgraphStack(spec); err != nil {
		return fmt.Errorf("failed to setup fgraph stack: %w", err)
	}

	if err := PatchBPFSessionInsns(spec); err != nil {
		return fmt.Errorf("failed to patch BPF session insns: %w", err)
	}

	traceeIPsMapName := "bpfsnoop_fgraph_tracee_ips"
	traceeIPs, err := ebpf.NewMap(spec.Maps[traceeIPsMapName])
	if err != nil {
		return fmt.Errorf("failed to create tracee IPs map: %w", err)
	}
	defer traceeIPs.Close()

	replacedMaps := map[string]*ebpf.Map{
		traceeIPsMapName:    traceeIPs,
		".data.ready":       reusedMaps[".data.ready"],
		"bpfsnoop_events":   reusedMaps["bpfsnoop_events"],
		"bpfsnoop_sessions": reusedMaps["bpfsnoop_sessions"],
	}

	var errg errgroup.Group

	for _, graph := range graphs {
		if graph.Root {
			// roots are traced by regular fentry/fexit programs.
			continue
		}
		if hasFsession {
			if graph.Kfunc != nil {
				errg.Go(func() error {
					return t.traceGraphFunc(spec, replacedMaps, graph, false, true)
				})
			} else {
				errg.Go(func() error {
					return t.traceGraphProg(spec, replacedMaps, graph, false, true)
				})
			}
			continue
		}

		if graph.Kfunc != nil {
			errg.Go(func() error {
				return t.traceGraphFunc(spec, replacedMaps, graph, true, false)
			})
			errg.Go(func() error {
				return t.traceGraphFunc(spec, replacedMaps, graph, false, false)
			})
		} else {
			errg.Go(func() error {
				return t.traceGraphProg(spec, replacedMaps, graph, true, false)
			})
			errg.Go(func() error {
				return t.traceGraphProg(spec, replacedMaps, graph, false, false)
			})
		}
	}

	if err := errg.Wait(); err != nil {
		WarnLogIf(errors.Is(err, unix.EMFILE), "Too many open files, please increase the limit with 'ulimit -n' or 'sysctl fs.file-max'.")
		return fmt.Errorf("failed to trace graph funcs/progs: %w", err)
	}

	if err := t.populateFgraphTraceeIPs(traceeIPs, graphs); err != nil {
		return fmt.Errorf("failed to populate fgraph tracee IPs map: %w", err)
	}

	if err := t.populateFgraphTrampolineIPs(traceeIPs, graphs); err != nil {
		return fmt.Errorf("failed to populate fgraph trampoline IPs: %w", err)
	}

	return nil
}

func (t *bpfTracing) populateFgraphTraceeIPs(ips *ebpf.Map, graphs FuncGraphs) error {
	traceeIPs := make(map[uint64]uint64, len(graphs))
	for _, graph := range graphs {
		var funcIP uint64
		if graph.Kfunc != nil {
			funcIP = graph.Kfunc.Ksym.addr
		} else if graph.Bprog != nil {
			funcIP = uint64(graph.Bprog.kaddrRange.start)
		} else {
			continue
		}

		// Stack unwinding reports the return address immediately after the
		// trampoline call. Keep roots in the map as well, since they are traced
		// by the regular fentry/fexit path rather than the graph programs.
		traceeIP := funcIP + insnCallqSize
		if hasEndbr {
			traceeIP += insnEndbrSize
		}
		if onArm64 {
			traceeIP += insnSize
		}
		traceeIPs[traceeIP] = funcIP
	}

	// update_batch is supported since kernel 5.6
	// commit aa2e93b ("bpf: Add generic support for update and delete batch ops")

	keys := make([]uint64, 0, len(traceeIPs))
	vals := make([]uint64, 0, len(traceeIPs))
	for traceeIP, funcIP := range traceeIPs {
		keys = append(keys, traceeIP)
		vals = append(vals, funcIP)
	}
	if _, err := ips.BatchUpdate(keys, vals, nil); err != nil {
		return fmt.Errorf("failed to update fgraph tracee IPs map: %w", err)
	}

	return nil
}

func probeTrampAddrs(graphs FuncGraphs, silent bool) ([]uint64, []uint64, error) {
	spec, err := bpf.LoadTraceable()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load traceable bpf spec: %w", err)
	}

	addrs := slices.Sorted(maps.Keys(graphs))

	trampAddrs := make([]uint64, 0, len(addrs))
	kfuncAddrs := make([]uint64, 0, len(addrs))
	for len(addrs) != 0 {
		var detect []uintptr
		if len(addrs) > AddrCap {
			detect = slicex.U64sToUintptrs(addrs[:AddrCap])
			addrs = addrs[AddrCap:]
		} else {
			detect = slicex.U64sToUintptrs(addrs)
			addrs = nil
		}

		traceable, tramps, err := detectTraceable(spec, detect)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to detect traceable: %w", err)
		}

		for i := range detect {
			if traceable[i] {
				// map trampoline call-return addr to the original func
				// addr, so that we can recognize them in stack
				// unwinding.
				trampAddrs = append(trampAddrs, tramps[i])
				kfuncAddrs = append(kfuncAddrs, uint64(detect[i]))
			}
		}
	}

	return trampAddrs, kfuncAddrs, nil
}

func (t *bpfTracing) extractTrampolineIPs(addr uint64, engine *gapstone.Engine, ksyms *Kallsyms) ([]uint64, error) {
	insts, err := disasmKfuncAt(addr, 0, ksyms, engine)
	if err != nil {
		return nil, fmt.Errorf("failed to disassemble trampoline at %#x: %w", addr, err)
	}

	ips, pc := make([]uint64, 0, 4), addr
	for i := range insts {
		pc += uint64(insts[i].Size)
		if insts[i].Bytes[0] == 0xE8 { // callq
			ips = append(ips, pc)
		}
	}
	return ips, nil
}

func (t *bpfTracing) populateFgraphTrampolineIPs(ips *ebpf.Map, graphs FuncGraphs) error {
	if !trampJmpMode {
		return nil
	}

	trampAddrs, kfuncAddrs, err := probeTrampAddrs(graphs, true)
	if err != nil {
		return fmt.Errorf("failed to probe trampoline addresses: %w", err)
	}

	ksyms, err := NewKallsyms()
	if err != nil {
		return fmt.Errorf("failed to read kallsyms: %w", err)
	}

	engine, err := createGapstoneEngine()
	if err != nil {
		return fmt.Errorf("failed to create gapstone engine: %w", err)
	}
	defer engine.Close()

	trampIPs := make(map[uint64]uint64, len(trampAddrs)*4)
	for i, addr := range trampAddrs {
		ips, err := t.extractTrampolineIPs(addr, engine, ksyms)
		if err != nil {
			return fmt.Errorf("failed to extract trampoline IPs: %w", err)
		}

		for _, ip := range ips {
			trampIPs[ip] = kfuncAddrs[i]
		}
	}

	keys := make([]uint64, 0, len(trampIPs))
	vals := make([]uint64, 0, len(trampIPs))
	for traceeIP, funcIP := range trampIPs {
		keys = append(keys, traceeIP)
		vals = append(vals, funcIP)
	}
	if _, err := ips.BatchUpdate(keys, vals, nil); err != nil {
		return fmt.Errorf("failed to update fgraph trampoline IPs to bpf map: %w", err)
	}

	return nil
}
