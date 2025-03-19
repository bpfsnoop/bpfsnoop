// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	rand "math/rand/v2"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"

	"github.com/bpfsnoop/bpfsnoop/internal/btfx"
)

type Tracepoints map[string]*KFunc

func findKernelTracepoints(tps []string, spec *ebpf.CollectionSpec, ksyms *Kallsyms, silent bool) (Tracepoints, error) {
	matches, err := kfuncFlags2matches(tps)
	if err != nil {
		return Tracepoints{}, err
	}

	tpInfos, err := ProbeTracepoints(spec, ksyms)
	if err != nil {
		return Tracepoints{}, err
	}

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

		ok := matchKfunc(tpName, &fp, matches)
		if !ok {
			continue
		}

		params, err := getFuncParams(&fn)
		if err != nil {
			verboseLogIf(!silent, "Failed to prepare params info for tracepoint %s: %w", tpName, err)
			continue
		}

		fn.Name = tpName
		ktps[tpName] = &KFunc{
			Ksym:     &KsymEntry{name: tpName},
			Func:     &fn,
			Prms:     params,
			IsRetStr: btfx.IsStr(fp.Return),
			IsTp:     true,
		}
	}

	return ktps, nil
}

func FindKernelTracepoints(tps []string, spec *ebpf.CollectionSpec, ksyms *Kallsyms) (Tracepoints, error) {
	if len(tps) == 0 {
		return Tracepoints{}, nil
	}

	return findKernelTracepoints(tps, spec, ksyms, false)
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
