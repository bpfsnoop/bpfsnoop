// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/bpfsnoop/bpfsnoop/internal/assert"
)

func updateMMapableMapSpec(spec *ebpf.CollectionSpec, mapName string, valueSize uint32) error {
	m, ok := spec.Maps[mapName]
	if !ok {
		return fmt.Errorf("map spec %s not found", mapName)
	}

	m.Flags |= unix.BPF_F_MMAPABLE
	if valueSize == 0 {
		return nil
	}

	m.ValueSize = valueSize
	if len(m.Contents) == 0 {
		m.Contents = append(m.Contents, ebpf.MapKV{
			Key:   uint32(0),
			Value: make([]byte, valueSize),
		})
	} else {
		m.Contents[0].Value = make([]byte, valueSize)
	}

	return nil
}

func updateLbrsDataMapSpec(spec *ebpf.CollectionSpec) error {
	numCPU, err := ebpf.PossibleCPU()
	if err != nil {
		return fmt.Errorf("failed to get possible cpu number: %w", err)
	}

	valueSize := uint32(unsafe.Sizeof(LbrData{})) * uint32(numCPU)
	return updateMMapableMapSpec(spec, ".data.lbrs", valueSize)
}

func updateStacksMapSpec(spec *ebpf.CollectionSpec) error {
	maxStack, err := readKernelPerfEventMaxStack()
	if err != nil {
		return fmt.Errorf("failed to read kernel.perf_event_max_stack: %w", err)
	}

	m, ok := spec.Maps["bpfsnoop_stacks"]
	if !ok {
		return fmt.Errorf("map spec %s not found", "bpfsnoop_stacks")
	}

	m.ValueSize = uint32(maxStack) * 8
	return nil
}

func updateMapsSpec(spec *ebpf.CollectionSpec) error {
	if err := updateLbrsDataMapSpec(spec); err != nil {
		return fmt.Errorf("failed to update .data.lbrs map spec: %w", err)
	}
	if err := updateStacksMapSpec(spec); err != nil {
		return fmt.Errorf("failed to update bpfsnoop_stacks map spec: %w", err)
	}
	if err := updateMMapableMapSpec(spec, ".data.ready", 0); err != nil {
		return fmt.Errorf("failed to update .data.ready map spec: %w", err)
	}
	return nil
}

func PrepareBPFMaps(spec *ebpf.CollectionSpec) map[string]*ebpf.Map {
	err := updateMapsSpec(spec)
	assert.NoErr(err, "Failed to update bpf maps spec: %v")

	lbrsData, err := ebpf.NewMap(spec.Maps[".data.lbrs"])
	assert.NoErr(err, "Failed to create lbrs map: %v")

	lbrs, err := ebpf.NewMap(spec.Maps["bpfsnoop_lbrs"])
	assert.NoErr(err, "Failed to create bpfsnoop_lbrs map: %v")

	stacks, err := ebpf.NewMap(spec.Maps["bpfsnoop_stacks"])
	assert.NoErr(err, "Failed to create bpfsnoop_stacks map: %v")

	sessions, err := ebpf.NewMap(spec.Maps["bpfsnoop_sessions"])
	assert.NoErr(err, "Failed to create bpfsnoop_sessions map: %v")

	readyData, err := ebpf.NewMap(spec.Maps[".data.ready"])
	assert.NoErr(err, "Failed to create ready data map: %v")

	events, err := ebpf.NewMap(spec.Maps["bpfsnoop_events"])
	assert.NoErr(err, "Failed to create events map: %v")

	return map[string]*ebpf.Map{
		"bpfsnoop_sessions": sessions,

		"bpfsnoop_events": events,
		"bpfsnoop_lbrs":   lbrs,
		".data.lbrs":      lbrsData,
		".data.ready":     readyData,
		"bpfsnoop_stacks": stacks,
	}
}

func CloseBPFMaps(maps map[string]*ebpf.Map) {
	for _, m := range maps {
		_ = m.Close()
	}
}
