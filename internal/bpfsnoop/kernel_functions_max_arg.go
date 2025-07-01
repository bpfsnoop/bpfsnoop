// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"golang.org/x/exp/maps"
)

func DetectSupportedMaxArg(spec *ebpf.CollectionSpec, ksyms *Kallsyms) (int, error) {
	kfuncs, err := findKernelFuncs([]string{"ip_*", "tcp_*"}, nil, ksyms, MAX_BPF_FUNC_ARGS, true, true)
	if err != nil {
		return 0, fmt.Errorf("failed to find kernel functions with many args: %w", err)
	}

	kfuncs, err = detectTraceables(kfuncs, true)
	if err != nil {
		return 0, fmt.Errorf("failed to detect traceable kernel functions: %w", err)
	}
	if len(kfuncs) == 0 {
		return 0, fmt.Errorf("no traceable kernel functions found")
	}

	spec = spec.Copy()
	reusedMaps := PrepareBPFMaps(spec)
	defer CloseBPFMaps(reusedMaps)

	prog := spec.Programs[TracingProgName()]
	pktFilter.clear(prog)
	pktOutput.clear(prog)
	argOutput.clear(prog)
	clearFilterArgSubprog(prog)

	attachType := ebpf.AttachTraceFExit
	kfunc := maps.Values(kfuncs)[0]
	prog.AttachTo = kfunc.Ksym.name
	prog.AttachType = attachType
	DebugLog("Using %s to detect max arg", kfunc.Name())

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: reusedMaps,
	})
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			DebugLog("Verifier log:\n%+v", verr)
		}
		DebugLog("Failed to create max-arg detection bpf collection: %v", err)
		return MAX_BPF_FUNC_ARGS_PREV, nil
	}
	defer coll.Close()

	return MAX_BPF_FUNC_ARGS, nil
}
