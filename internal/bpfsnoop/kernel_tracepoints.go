// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"
	rand "math/rand/v2"

	"github.com/cilium/ebpf/btf"

	"github.com/bpfsnoop/bpfsnoop/internal/bpf"
)

type Tracepoints map[string]*KFunc

func matchKernelTracepoints(tps []string, tpInfos map[string]tracepointInfo, silent bool) (Tracepoints, error) {
	matches, err := kfuncFlags2matches(tps)
	if err != nil {
		return Tracepoints{}, err
	}

	krnl, err := btf.LoadKernelSpec()
	if err != nil {
		return Tracepoints{}, fmt.Errorf("failed to load kernel btf spec: %w", err)
	}

	kmods := make(map[string]*btf.Spec)

	ktps := make(Tracepoints, len(tps))
	for tpName, tp := range tpInfos {
		fn := *tp.fn
		fp := *tp.fn.Type.(*btf.FuncProto)
		fp.Params = fp.Params[1:] // skip 'void *__data'
		fn.Type = &fp

		if len(fp.Params) < int(tp.nrArgs) {
			verboseLogIf(!silent, "%s has %d params, which is required %d params for tracepoint %s",
				tp.fn.Name, len(fp.Params), tp.nrArgs, tpName)
			continue
		}

		if len(fp.Params) > MAX_BPF_FUNC_ARGS {
			verboseLogIf(!silent, "%s has %d params, which is more than %d params for tp_btf %s",
				tp.fn.Name, len(fp.Params), MAX_BPF_FUNC_ARGS, tpName)
			continue
		}

		_, ok := matchKfunc(tpName, &fp, matches)
		if !ok {
			continue
		}

		params, ret, err := getFuncParams(&fn)
		if err != nil {
			verboseLogIf(!silent, "Failed to prepare params info for tracepoint %s: %w", tpName, err)
			continue
		}

		kbtf := krnl
		if tp.kmod != "" {
			if mod, ok := kmods[tp.kmod]; ok {
				kbtf = mod
			} else {
				mod, err := btf.LoadKernelModuleSpec(tp.kmod)
				if err != nil {
					return nil, fmt.Errorf("failed to load kernel module btf spec for %s: %w", tp.kmod, err)
				}

				kmods[tp.kmod] = mod
				kbtf = mod
			}
		}

		fn.Name = tpName
		ktps[tpName] = &KFunc{
			Ksym: &KsymEntry{name: tpName},
			Func: &fn,
			Btf:  kbtf,
			Prms: params,
			Ret:  ret,
			IsTp: true,
		}
	}

	return ktps, nil
}

func probeKernelTracepoints(tps []string, ksyms *Kallsyms, silent bool) (Tracepoints, error) {
	if len(tps) == 0 {
		return Tracepoints{}, nil
	}

	tpSpec, err := bpf.LoadTracepoint()
	if err != nil {
		return Tracepoints{}, fmt.Errorf("failed to load tracepoint bpf spec: %w", err)
	}

	tpModSpec, err := bpf.LoadTracepoint_module()
	if err != nil {
		return Tracepoints{}, fmt.Errorf("failed to load tracepoint_module bpf spec: %w", err)
	}

	tpInfos, err := ProbeTracepoints(tpSpec, ksyms)
	if err != nil {
		return Tracepoints{}, err
	}

	kmods, err := ProbeTracepointModuleInfos(tpModSpec, tpSpec, ksyms)
	if err != nil {
		return nil, fmt.Errorf("failed to probe tracepoint module infos: %w", err)
	}

	for _, mod := range kmods {
		for _, tp := range mod.tps {
			if _, ok := tpInfos[tp.name]; !ok {
				tp.kmod = mod.module
				tpInfos[tp.name] = tp
			}
		}
	}

	return matchKernelTracepoints(tps, tpInfos, silent)
}

func FindKernelTracepoints(tps []string, ksyms *Kallsyms) (Tracepoints, error) {
	return probeKernelTracepoints(tps, ksyms, false)
}

func MergeTracepointsToKfuncs(tps Tracepoints, kfuncs KFuncs) {
	for _, tp := range tps {
		id := rand.Uint64()
		for {
			if _, ok := kfuncs[uintptr(id)]; !ok {
				break
			}

			id = rand.Uint64()
		}

		tp.Ksym.addr = id
		kfuncs[uintptr(id)] = tp
	}
}
