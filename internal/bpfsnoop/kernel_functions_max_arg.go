// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
)

const (
	MAX_BPF_FUNC_ARGS      = 12
	MAX_BPF_FUNC_ARGS_PREV = 6
)

var (
	maxArgsMu sync.Mutex
	maxArgs   int
)

func DetectSupportedMaxArg(spec *ebpf.CollectionSpec, ksyms *Kallsyms) (int, error) {
	maxArgsMu.Lock()
	defer maxArgsMu.Unlock()

	if maxArgs != 0 {
		return maxArgs, nil
	}

	var err error
	maxArgs, err = detectSupportedMaxArg(spec, ksyms)
	return maxArgs, err
}

func findDetectKfunc(ksyms *Kallsyms) (*KFunc, error) {
	kfuncs, err := findKernelFuncs([]string{"ip_*", "tcp_*"}, nil, ksyms, MAX_BPF_FUNC_ARGS, true, true)
	if err != nil {
		return nil, fmt.Errorf("failed to find kernel functions with many args: %w", err)
	}

	kfuncs, err = detectTraceables(kfuncs, true)
	if err != nil {
		return nil, fmt.Errorf("failed to detect traceable kernel functions: %w", err)
	}

	for _, kfunc := range kfuncs {
		return kfunc, nil
	}

	return nil, fmt.Errorf("no traceable kernel functions found")
}

func detectSupportedMaxArg(spec *ebpf.CollectionSpec, ksyms *Kallsyms) (int, error) {
	kfunc, err := findDetectKfunc(ksyms)
	if err != nil {
		return 0, err
	}

	spec = spec.Copy()
	reusedMaps := PrepareBPFMaps(spec, nil)
	defer CloseBPFMaps(reusedMaps)

	prog := spec.Programs[TracingProgName()]
	pktFilter.clear(prog)
	pktOutput.clear(prog)
	clearOutputArgSubprog(prog)
	clearFilterArgSubprog(prog)

	attachType := ebpf.AttachTraceFExit
	prog.AttachTo = kfunc.Ksym.name
	prog.AttachType = attachType
	DebugLog("Using %s to detect max arg", kfunc.Name())

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: reusedMaps,
	})
	if err != nil {
		if verr, ok := errors.AsType[*ebpf.VerifierError](err); ok {
			DebugLog("Verifier log:\n%+v", verr)
		}
		DebugLog("Failed to create max-arg detection bpf collection: %v", err)
		return MAX_BPF_FUNC_ARGS_PREV, nil
	}
	defer coll.Close()

	return MAX_BPF_FUNC_ARGS, nil
}
