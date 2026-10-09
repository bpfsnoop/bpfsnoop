// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"

	"github.com/bpfsnoop/bpfsnoop/internal/btfx"
)

type bpfTracingInfo struct {
	prog     *ebpf.Program
	fn       *btf.Func
	jitedLen uint32 // length of the jited function
	funcIP   uintptr
	funcName string
	disAll   bool
	flag     progFlagImmInfo
	params   []FuncParamFlags
	ret      FuncParamFlags
}

func getFuncParams(fn *btf.Func) ([]FuncParamFlags, FuncParamFlags, error) {
	strUsed := false // Only one string is allowed
	fnParams := fn.Type.(*btf.FuncProto).Params
	params := make([]FuncParamFlags, 0, len(fnParams))
	ret := FuncParamFlags{}
	for _, p := range fnParams {
		v := mybtf.IsConstCharPtr(p.Type)
		isStr := v && !strUsed
		strUsed = strUsed || v

		size, err := btf.Sizeof(p.Type)
		if err != nil {
			return nil, ret, fmt.Errorf("failed to get size of type %v: %w", p.Type, err)
		}

		if size > 16 {
			return nil, ret, fmt.Errorf("size of type %v is too large: %d", p.Type, size)
		}
		if size > 8 {
			// struct arg occupies 2 regs
			params = append(params,
				FuncParamFlags{},
				FuncParamFlags{
					partOfPrevParam: true,
				})
			continue
		}

		params = append(params, FuncParamFlags{
			ParamFlags: ParamFlags{
				IsNumberPtr: btfx.IsNumberPointer(p.Type),
				IsStr:       isStr,
			},
		})
	}

	rettype := fn.Type.(*btf.FuncProto).Return
	ret.IsStr = mybtf.IsConstCharPtr(rettype)
	ret.IsNumberPtr = btfx.IsNumberPointer(rettype)

	return params, ret, nil
}

func getProgFunc(fns btf.FuncOffsets, funcName string) (int, error) {
	for i, fn := range fns {
		if fn.Func.Name == funcName {
			return i, nil
		}
	}

	return -1, fmt.Errorf("failed to find func %s", funcName)
}

func (p *bpfProgs) canTrace(prog *ebpf.Program, id ebpf.ProgramID) bool {
	if prog.Type() != ebpf.Tracing {
		return true
	}

	if result, ok := p.traceable.Load(id); ok {
		return result.(bool)
	}

	canTrace := func() bool {
		if !hasNestedTracing {
			return false
		}
		// The link's target ID cannot distinguish attachment to an ordinary
		// BPF program from attachment to another tracing program. Ask the
		// verifier, which checks aux->attach_tracing_prog, including after
		// the original link has been closed.
		info, err := fetchBPFProgInfo(prog)
		if err != nil {
			DebugLog("Failed to get tracing program %d info: %v", id, err)
			return false
		}
		funcName, err := getProgEntryFuncName(info)
		if err != nil {
			DebugLog("Failed to get entry func name of prog %d: %v", id, err)
			return false
		}
		return probeTracingTarget(prog, funcName)
	}()

	p.traceable.Store(id, canTrace)
	return canTrace
}

func (p *bpfProgs) addTracing(id ebpf.ProgramID, funcName string, prog *ebpf.Program, flag progFlagImmInfo) error {
	if !p.canTrace(prog, id) && !p.disasm {
		return nil
	}

	key := fmt.Sprintf("%d:%s", id, funcName)
	if _, ok := p.tracings[key]; ok {
		return nil
	}

	info, ok := p.infos[id]
	if !ok {
		i, err := fetchBPFProgInfo(prog)
		if err != nil {
			return fmt.Errorf("failed to get info for %d: %w", id, err)
		}

		info = i
	}

	jitedKsymAddrs, ok := info.JitedKsymAddrs()
	if !ok {
		return fmt.Errorf("failed to get jited ksym addrs for %d", id)
	}

	jitedLens, ok := info.JitedFuncLens()
	if !ok {
		return fmt.Errorf("failed to get jited func lens for %d", id)
	}

	fns, err := info.FuncInfos()
	if err != nil {
		return fmt.Errorf("failed to get func infos for %d: %w", id, err)
	}

	idx, err := getProgFunc(fns, funcName)
	if err != nil {
		return fmt.Errorf("failed to get func for %s: %w", funcName, err)
	}

	if idx != 0 && haveTailcallInfiniteLoopIssue() {
		// Skip to trace those tail_call_reachable subprogs. See
		// https://lore.kernel.org/all/20230912150442.2009-3-hffilwlqm@gmail.com/
		// for more details.

		// Only the entry prologue is needed, even for very large programs.
		jitedInsns, err := readKernel(uint64(jitedKsymAddrs[0]), min(jitedLens[0], 16))
		if err != nil {
			return fmt.Errorf("failed to read entry prologue for %d: %w", id, err)
		}

		// It's unable to check whether the subprog is tail_call_reachable, so
		// check the entry prog instead.

		insns := jitedInsns
		if isTailcallReachable(insns) {
			VerboseLog("Skipped tracing tail_call_reachable subprog %s of prog %s", funcName, fns[0].Func.Name)
			return nil
		}
	}

	params, ret, err := getFuncParams(fns[idx].Func)
	if err != nil {
		return fmt.Errorf("failed to get func params for %s: %w", funcName, err)
	}

	if prev, ok := p.progs[id]; !ok {
		prog, err = prog.Clone()
		if err != nil {
			return fmt.Errorf("failed to clone prog %d: %w", id, err)
		}

		p.progs[id] = prog
		p.infos[id] = info
	} else {
		prog = prev
	}

	p.tracings[key] = &bpfTracingInfo{
		prog:     prog,
		fn:       fns[idx].Func,
		jitedLen: jitedLens[idx],
		funcIP:   jitedKsymAddrs[idx],
		funcName: funcName,
		disAll:   flag.funcName == "",
		flag:     flag,
		params:   params,
		ret:      ret,
	}

	return nil
}
