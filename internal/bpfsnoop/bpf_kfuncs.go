// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

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

func detectTraceable(spec *ebpf.CollectionSpec, addrs []uintptr) ([]bool, []uint64, error) {
	spec = spec.Copy()

	var addresses [AddrCap]uint64
	for i, addr := range addrs {
		addresses[i] = uint64(addr)
	}
	if err := spec.Variables["addrs"].Set(addresses); err != nil {
		return nil, nil, fmt.Errorf("failed to set addrs: %w", err)
	}
	if err := spec.Variables["nr_addrs"].Set(uint32(len(addrs))); err != nil {
		return nil, nil, fmt.Errorf("failed to set nr_addrs: %w", err)
	}
	if err := spec.Variables["has_endbr"].Set(uint32(b2i(hasEndbr))); err != nil {
		return nil, nil, fmt.Errorf("failed to set has_endbr: %w", err)
	}
	if err := spec.Variables["tramp_jmp"].Set(uint32(b2i(trampJmpMode))); err != nil {
		return nil, nil, fmt.Errorf("failed to set tramp_jmp: %w", err)
	}

	spec.Programs["detect"].AttachTo = bpfFentryTest1
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create bpf collection: %w", err)
	}
	defer coll.Close()

	prog := coll.Programs["detect"]
	l, err := link.AttachTracing(link.TracingOptions{
		Program:    prog,
		AttachType: ebpf.AttachTraceFEntry,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fentry %s: %w", bpfFentryTest1, err)
	}
	defer l.Close()

	_, err = prog.Run(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to run detect program: %w", err)
	}

	var run bool
	if err := coll.Variables["run"].Get(&run); err != nil {
		return nil, nil, fmt.Errorf("failed to get run: %w", err)
	}
	if !run {
		return nil, nil, errors.New("traceable detection was not triggered")
	}

	var tramps [AddrCap]uint64
	if err := coll.Variables["tramps"].Get(&tramps); err != nil {
		return nil, nil, fmt.Errorf("failed to get tramps: %w", err)
	}

	var traceables [AddrCap]bool
	if err := coll.Variables["traceables"].Get(&traceables); err != nil {
		return nil, nil, fmt.Errorf("failed to get traceables: %w", err)
	}

	return traceables[:len(addrs)], tramps[:len(addrs)], nil
}

func detectTraceables(kfuncs KFuncs, silent bool) (KFuncs, error) {
	spec, err := bpf.LoadTraceable()
	if err != nil {
		return nil, fmt.Errorf("failed to load traceable bpf spec: %w", err)
	}

	addrs := slices.Sorted(maps.Keys(kfuncs))

	for len(addrs) != 0 {
		var detect []uintptr
		if len(addrs) > AddrCap {
			detect = addrs[:AddrCap]
			addrs = addrs[AddrCap:]
		} else {
			detect = addrs
			addrs = nil
		}

		traceables, _, err := detectTraceable(spec, detect)
		if err != nil {
			return kfuncs, fmt.Errorf("failed to detect traceable: %w", err)
		}

		for i, t := range traceables {
			if !t {
				verboseLogIf(!silent, "Skip non-traceable kernel function %s", kfuncs[detect[i]].Ksym.name)
				delete(kfuncs, detect[i])
			}
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
