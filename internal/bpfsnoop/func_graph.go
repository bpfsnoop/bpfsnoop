// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"context"
	"fmt"
)

// They maybe cause kernel deadlock.
// TODO: troubleshoot more details about deadlock.
var fgraphInternalExcludes = []string{
	"*rcu_read_lock_*",
	"*rcu_lockdep_*",
	"*raw_*lock*",
	"*raw_*unlock*",
	"*queued_*lock*",
	"*queued_*unlock*",
}

type FuncGraph struct {
	Func     string
	IP       uint64
	MaxDepth uint
	Kfunc    *KFunc
	Bprog    *bpfProgFuncInfo
	ArgsEnSz int
	ArgsExSz int
}

type FuncGraphs map[uint64]*FuncGraph // key is the func IP

func FindGraphFuncs(ctx context.Context, flags *Flags, kfuncs KFuncs, bprogs *bpfProgs, ksyms *Kallsyms, maxArgs int) (FuncGraphs, error) {
	var kfs []*KFunc
	for _, kf := range kfuncs {
		if kf.Grph {
			kfs = append(kfs, kf)
		}
	}

	var bps []*bpfTracingInfo
	for _, bp := range bprogs.tracings {
		if bp.graph {
			bps = append(bps, bp)
		}
	}

	if len(kfs) == 0 && len(bps) == 0 {
		return nil, nil
	}

	bprogs, err := NewBPFProgs([]ProgFlag{{all: true}}, false, true)
	if err != nil {
		return FuncGraphs{}, fmt.Errorf("failed to prepare bpf progs: %w", err)
	}
	defer bprogs.Close()

	includes, err := kfuncFlags2matches(flags.fgraphInclude)
	if err != nil {
		return FuncGraphs{}, fmt.Errorf("failed to parse include flags: %w", err)
	}

	excludes, err := kfuncFlags2matches(flags.fgraphExclude)
	if err != nil {
		return FuncGraphs{}, fmt.Errorf("failed to parse exclude flags: %w", err)
	}

	internalExcludes, err := kfuncFlags2matches(fgraphInternalExcludes)
	if err != nil {
		return FuncGraphs{}, fmt.Errorf("failed to parse internal excludes: %w", err)
	}
	if !flags.fgragphDebugLock {
		excludes = append(excludes, internalExcludes...)
	}

	extraKfuncs, err := FindKernelFuncs(flags.fgraphKfuncs, ksyms, maxArgs)
	if err != nil {
		return FuncGraphs{}, fmt.Errorf("failed to find extra kfuncs: %w", err)
	}

	engine, err := createGapstoneEngine()
	if err != nil {
		return FuncGraphs{}, fmt.Errorf("failed to create gapstone engine: %w", err)
	}
	defer engine.Close()

	parser := newFuncGraphParser(ctx, ksyms, bprogs, engine, flags.fgraphDepth, maxArgs, includes, excludes)

	for _, kf := range kfs {
		addr := kf.Ksym.addr
		bytes := guessBytes(uintptr(addr), ksyms, 0)
		parser.addParse(addr, bytes, 0, kf.Ksym.name)
	}

	for _, bp := range bps {
		addr := bp.funcIP
		bytes := bp.jitedLen
		parser.addParse(uint64(addr), uint(bytes), 0, bp.funcName+"[bpf]")
	}

	for _, kf := range extraKfuncs {
		addr := kf.Ksym.addr
		bytes := guessBytes(uintptr(addr), ksyms, 0)
		parser.addParse(addr, bytes, 1, kf.Name())
	}

	err = parser.wait()
	if err != nil {
		return nil, fmt.Errorf("failed to parse func graphs: %w", err)
	}

	for ip, graph := range parser.graphs {
		if graph.Kfunc == nil && graph.Bprog == nil {
			delete(parser.graphs, ip) // remove empty graphs
		}
	}
	return parser.graphs, nil
}
