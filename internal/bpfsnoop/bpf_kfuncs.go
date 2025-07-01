// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"errors"
	"fmt"
	"slices"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/exp/maps"

	"github.com/bpfsnoop/bpfsnoop/internal/bpf"
)

// bpf_kfuncs.go is to detect a bunch of kernel functions are traceable.

const AddrCap = 1024

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func detectTraceable(spec *ebpf.CollectionSpec, addrs []uintptr) ([]uintptr, error) {
	spec = spec.Copy()

	var addresses [AddrCap]uint64
	for i, addr := range addrs {
		addresses[i] = uint64(addr)
	}
	if err := spec.Variables["addrs"].Set(addresses); err != nil {
		return nil, fmt.Errorf("failed to set addrs: %w", err)
	}
	if err := spec.Variables["nr_addrs"].Set(uint32(len(addrs))); err != nil {
		return nil, fmt.Errorf("failed to set nr_addrs: %w", err)
	}
	if err := spec.Variables["has_endbr"].Set(uint32(b2i(hasEndbr))); err != nil {
		return nil, fmt.Errorf("failed to set has_endbr: %w", err)
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogDisabled: true,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create bpf collection: %w", err)
	}
	defer coll.Close()

	prog := coll.Programs["detect"]
	l, err := link.AttachTracing(link.TracingOptions{
		Program:    prog,
		AttachType: ebpf.AttachTraceFEntry,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fentry nanosleep: %w", err)
	}
	defer l.Close()

	nanosleep()

	var run bool
	if err := coll.Variables["run"].Get(&run); err != nil {
		return nil, fmt.Errorf("failed to get run: %w", err)
	}
	if !run {
		return nil, errors.New("traceable detection was not triggered")
	}

	var traceables [AddrCap]bool
	if err := coll.Variables["traceables"].Get(&traceables); err != nil {
		return nil, fmt.Errorf("failed to get traceables: %w", err)
	}

	var nontraceables []uintptr
	for i := 0; i < len(addrs); i++ {
		if !traceables[i] {
			nontraceables = append(nontraceables, addrs[i])
		}
	}

	return nontraceables, nil
}

func detectTraceables(kfuncs KFuncs, silent bool) (KFuncs, error) {
	spec, err := bpf.LoadTraceable()
	if err != nil {
		return nil, fmt.Errorf("failed to load traceable bpf spec: %w", err)
	}

	addrs := maps.Keys(kfuncs)
	slices.Sort(addrs)

	for len(addrs) != 0 {
		var detect []uintptr
		if len(addrs) > AddrCap {
			detect = addrs[:AddrCap]
			addrs = addrs[AddrCap:]
		} else {
			detect = addrs
			addrs = nil
		}

		nontraceables, err := detectTraceable(spec, detect)
		if err != nil {
			return kfuncs, fmt.Errorf("failed to detect traceable: %w", err)
		}

		for _, nt := range nontraceables {
			verboseLogIf(!silent, "Skip non-traceable kernel function %s", kfuncs[nt].Ksym.name)
			delete(kfuncs, nt)
		}
	}

	return kfuncs, nil
}

func DetectTraceable(kfuncs KFuncs) (KFuncs, error) {
	if len(kfuncs) == 0 {
		return kfuncs, nil
	}

	return detectTraceables(kfuncs, false)
}
