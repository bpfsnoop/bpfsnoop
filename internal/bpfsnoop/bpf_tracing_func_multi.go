// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sync/errgroup"

	"github.com/bpfsnoop/bpfsnoop/internal/assert"
	"github.com/bpfsnoop/bpfsnoop/internal/bpf"
	"github.com/bpfsnoop/bpfsnoop/internal/mathx"
)

// tools/testing/selftests/bpf/trace_helpers.c::skip_entry()
var kprobe_trace_skip_entry = []string{
	"arch_cpu_idle",
	"default_idle",
	"rcu_",
	"__ftrace_invalid_address__",
}

func skipKprobeMultiSymbol(sym string) bool {
	for _, entry := range kprobe_trace_skip_entry {
		if strings.HasPrefix(sym, entry) {
			return true
		}
	}
	return false
}

type kfuncMultiGroupInfo struct {
	flt string
	fns []string
	fn  *KFunc
}

func loadAvailableFilterFunctions() (map[string]struct{}, error) {
	var f *os.File
	var err error

	// Linux v6.17+ enforce this new path for tracing functionality.
	f, err = os.Open("/sys/kernel/tracing/available_filter_functions")
	if err != nil {
		f, err = os.Open("/sys/kernel/debug/tracing/available_filter_functions")
		if err != nil {
			return nil, fmt.Errorf("failed to open available_filter_functions: %w", err)
		}
	}
	defer f.Close()

	funcs := make(map[string]struct{}, 4096)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Usually "<symbol> [module]".
		name := strings.Fields(line)[0]
		funcs[name] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read available_filter_functions: %w", err)
	}

	return funcs, nil
}

func filterKprobeMultiSymbols(symbols []string, funcs map[string]struct{}) ([]string, []string) {
	keep := make([]string, 0, len(symbols))
	skip := make([]string, 0)
	for _, sym := range symbols {
		if skipKprobeMultiSymbol(sym) {
			skip = append(skip, sym)
			continue
		}

		if _, ok := funcs[sym]; ok {
			keep = append(keep, sym)
		} else {
			skip = append(skip, sym)
		}
	}
	return keep, skip
}

func (t *bpfTracing) traceFuncsMulti(errg *errgroup.Group, reusedMaps map[string]*ebpf.Map, fns []kfuncInfoMulti) error {
	availableFilterFuncs, err := loadAvailableFilterFunctions()
	if err != nil {
		return fmt.Errorf("failed to load kprobe.multi available symbols: %w", err)
	}

	groups := make(map[int]*kfuncMultiGroupInfo)
	for _, fn := range fns {
		for _, kf := range fn.fns {
			idx := findMatchedArgIndex(kf)
			assert.True(idx >= 0, "Failed to find arg index")
			g, ok := groups[idx]
			if !ok {
				g = &kfuncMultiGroupInfo{
					flt: kf.Flag.fltrExpr,
					fn:  kf,
				}
				groups[idx] = g
			}
			g.fns = append(g.fns, kf.Ksym.name)
		}
	}

	for i, g := range groups {
		g := g

		symbols, skipped := filterKprobeMultiSymbols(g.fns, availableFilterFuncs)
		if len(skipped) != 0 {
			DebugLog("Skip unavailable kprobe.multi symbols: %v for filter [%s]", skipped, g.flt)
		}
		if len(symbols) == 0 {
			VerboseLog("Skipped attaching kprobe.multi, no available symbols for filter [%s]", g.flt)
			continue
		}

		g.fns = symbols
		errg.Go(func() error {
			return t.traceKfuncMulti(reusedMaps, g, i)
		})
	}

	return nil
}

func (t *bpfTracing) traceKfuncMulti(reusedMaps map[string]*ebpf.Map, g *kfuncMultiGroupInfo, idx int) error {
	fn := g.fn
	sessionMode := fn.Flag.both && hasKprobeSession
	if sessionMode {
		return t.traceKfuncMultiMode(reusedMaps, g, false, true, idx)
	}

	if fn.Flag.both {
		if err := t.traceKfuncMultiMode(reusedMaps, g, false, false, idx); err != nil {
			return err
		}
		return t.traceKfuncMultiMode(reusedMaps, g, true, false, idx)
	}

	return t.traceKfuncMultiMode(reusedMaps, g, hasModeExit(), false, idx)
}

func (t *bpfTracing) traceKfuncMultiMode(reusedMaps map[string]*ebpf.Map, g *kfuncMultiGroupInfo, isExit, sessionMode bool, idx int) error {
	spec, err := bpf.LoadKmulti()
	if err != nil {
		return fmt.Errorf("failed to load kmulti bpf spec: %w", err)
	}

	if err := updateMapsSpec(spec); err != nil {
		return fmt.Errorf("failed to update .data.lbrs map spec for kmulti: %w", err)
	}

	numCPU, err := ebpf.PossibleCPU()
	if err != nil {
		return fmt.Errorf("failed to get possible cpu count for kmulti spec: %w", err)
	}
	if err := spec.Variables["CPU_MASK"].Set(uint32(mathx.Mask(numCPU))); err != nil {
		return fmt.Errorf("failed to set CPU_MASK for kmulti spec: %w", err)
	}

	if err := spec.Variables["PID"].Set(uint32(os.Getpid())); err != nil {
		return fmt.Errorf("failed to set PID for kmulti spec: %w", err)
	}

	fn := g.fn
	bothEntryExit := fn.Flag.both
	if err := validateKmultiArgOutput(fn); err != nil {
		return err
	}

	tracingFuncName := "bpfsnoop_kmulti"
	progSpec := spec.Programs[tracingFuncName]
	funcProto := fn.Func.Type.(*btf.FuncProto)
	params := funcProto.Params

	fn.Pkt = t.injectPktOutput(fn.Flag.pkt, progSpec, params, fn.Func.Name)
	if err := t.injectPktFilter(progSpec, params, fn.Func.Name); err != nil {
		return err
	}
	if err := t.injectArgFilter(progSpec, params, fn.Btf, fn.Func.Name); err != nil {
		return err
	}
	args, argDataSize, err := t.injectArgOutput(progSpec, params, fn.Btf, fn.Func.Name)
	if err != nil {
		return err
	}
	fn.Args = args
	fn.Data = argDataSize

	withRet := sessionMode || isExit
	fnArgsBufSize, err := injectOutputKmultiFnArgs(progSpec, maxArgsKmulti, withRet)
	if err != nil {
		return fmt.Errorf("failed to inject output func args for kmulti: %w", err)
	}

	argEntrySize, argExitSize := 0, 0
	if sessionMode {
		argEntrySize = fnArgsBufSize
		argExitSize = fnArgsBufSize
	} else if isExit {
		argExitSize = fnArgsBufSize
	} else {
		argEntrySize = fnArgsBufSize
	}

	err = setBpfsnoopConfig(spec, traceeConfig{
		funcIP:        0,
		fnArgsNr:      maxArgsKmulti,
		fnArgsBufSz:   fnArgsBufSize,
		argEntrySz:    argEntrySize,
		argExitSz:     argExitSize,
		argDataSz:     argDataSize,
		outputLbr:     fn.Flag.lbr,
		outputStack:   fn.Flag.stack,
		outputPkt:     fn.Pkt,
		insnMode:      false,
		graphMode:     fn.Flag.graph,
		bothEntryExit: bothEntryExit,
		isTp:          false,
		isProg:        false,
		kmultiMode:    true,
		withRet:       withRet,
		session:       sessionMode,
	})
	if err != nil {
		return fmt.Errorf("failed to set bpfsnoop config: %w", err)
	}

	attachType := ebpf.AttachTraceKprobeMulti
	if sessionMode {
		attachType = ebpf.AttachTraceKprobeSession
	}
	progSpec.AttachType = attachType

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: reusedMaps,
	})
	if err != nil {
		if ignoreFuncTraceVerifierErr(err, fn.Func.Name) {
			return nil
		}
		return fmt.Errorf("failed to create bpf collection for tracing in multi mode: %w", err)
	}
	defer coll.Close()

	prog := coll.Programs[tracingFuncName]
	delete(coll.Programs, tracingFuncName)

	symbols := g.fns
	opts := link.KprobeMultiOptions{
		Symbols: symbols,
		Session: sessionMode,
	}

	var l link.Link
	if isExit && !opts.Session {
		l, err = link.KretprobeMulti(prog, opts)
	} else {
		l, err = link.KprobeMulti(prog, opts)
	}
	if err != nil {
		_ = prog.Close()
		return fmt.Errorf("failed to attach tracing in multi mode %v: %w", symbols, err)
	}

	verboseLogIf(opts.Session, "Tracing(ksession) %d kernel functions[%d:%s]: %v", len(symbols), idx, fn.Flag.argName, symbols)
	verboseLogIf(!opts.Session && isExit, "Tracing(kretprobe.multi) %d kernel functions[%d:%s]: %v", len(symbols), idx, fn.Flag.argName, symbols)
	verboseLogIf(!opts.Session && !isExit, "Tracing(kprobe.multi) %d kernel functions[%d:%s]: %v", len(symbols), idx, fn.Flag.argName, symbols)

	t.llock.Lock()
	t.progs = append(t.progs, prog)
	t.kfns = append(t.kfns, tracingFunc{
		l: l,
		p: prog,
	})
	t.llock.Unlock()

	return nil
}

func validateKmultiArgOutput(fn *KFunc) error {
	if len(argOutput.args) == 0 {
		return nil
	}

	for _, a := range argOutput.args {
		for _, v := range a.vars {
			if v != fn.Flag.argName {
				return fmt.Errorf("kmulti --output-arg '%s' must match trace arg '%s'", a.expr, fn.Flag.argName)
			}
		}
	}

	return nil
}

// findMatchedArgIndex returns the parameter index of the matched argument
// in the function's BTF signature.
func findMatchedArgIndex(fn *KFunc) int {
	funcProto := fn.Func.Type.(*btf.FuncProto)
	for i, p := range funcProto.Params {
		if p.Name == fn.Flag.argName {
			return i
		}
	}
	return -1
}
