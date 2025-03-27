// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"
	"slices"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"

	"github.com/bpfsnoop/bpfsnoop/internal/btfx"
)

type bpfTracingInfo struct {
	prog     *ebpf.Program
	fn       *btf.Func
	funcIP   uintptr
	funcName string
	params   []FuncParamFlags
}

func getFuncParams(fn *btf.Func) ([]FuncParamFlags, error) {
	strUsed := false // Only one string is allowed
	fnParams := fn.Type.(*btf.FuncProto).Params
	params := make([]FuncParamFlags, 0, len(fnParams))
	for _, p := range fnParams {
		v := mybtf.IsConstCharPtr(p.Type)
		isStr := v && !strUsed
		strUsed = strUsed || v

		size, err := btf.Sizeof(p.Type)
		if err != nil {
			return nil, fmt.Errorf("failed to get size of type %v: %w", p.Type, err)
		}

		if size > 16 {
			return nil, fmt.Errorf("size of type %v is too large: %d", p.Type, size)
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
	return params, nil
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

	link, ok := p.links.links[id]
	if !ok {
		return true
	}

	if slices.Contains([]ebpf.AttachType{ebpf.AttachTraceFEntry, ebpf.AttachTraceFExit}, link.attachType) {
		// fentry/fexit can be traced if not attached to another prog since v6.8
		// kernel.
		return link.attachProg == 0
	}

	return true
}

func (p *bpfProgs) addTracing(id ebpf.ProgramID, funcName string, prog *ebpf.Program) error {
	if !p.canTrace(prog, id) && !p.disasm {
		return nil
	}

	key := fmt.Sprintf("%d:%s", id, funcName)
	if _, ok := p.tracings[key]; ok {
		return nil
	}

	info, ok := p.infos[id]
	if !ok {
		i, err := prog.Info()
		if err != nil {
			return fmt.Errorf("failed to get info for %d: %w", id, err)
		}

		info = i
	}

	jitedKsymAddrs, ok := info.JitedKsymAddrs()
	if !ok {
		return fmt.Errorf("failed to get jited ksym addrs for %d", id)
	}

	fns, err := info.FuncInfos()
	if err != nil {
		return fmt.Errorf("failed to get func infos for %d: %w", id, err)
	}

	idx, err := getProgFunc(fns, funcName)
	if err != nil {
		return fmt.Errorf("failed to get func for %s: %w", funcName, err)
	}

	if idx != 0 && !tailcallInfo.fixedTailcallInfiniteLoopCausedByTrampoline {
		// Skip to trace those tail_call_reachable subprogs. See
		// https://lore.kernel.org/all/20230912150442.2009-3-hffilwlqm@gmail.com/
		// for more details.

		jitedInsns, ok := info.JitedInsns()
		if !ok {
			return fmt.Errorf("failed to get jited insns for %d", id)
		}

		// It's unable to check whether the subprog is tail_call_reachable, so
		// check the entry prog instead.

		insns := jitedInsns
		if isTailcallReachable(insns) {
			VerboseLog("Skipped tracing tail_call_reachable subprog %s of prog %s", funcName, fns[0].Func.Name)
			return nil
		}
	}

	params, err := getFuncParams(fns[idx].Func)
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

	p.tracings[key] = bpfTracingInfo{
		prog:     prog,
		fn:       fns[idx].Func,
		funcIP:   jitedKsymAddrs[idx],
		funcName: funcName,
		params:   params,
	}

	return nil
}
