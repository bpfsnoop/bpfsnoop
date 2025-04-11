// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/bpfsnoop/bpfsnoop/internal/assert"
)

func PrepareBPFMaps(spec *ebpf.CollectionSpec) map[string]*ebpf.Map {
	numCPU, err := ebpf.PossibleCPU()
	assert.NoErr(err, "Failed to get possible cpu: %v")

	lbrsMapSpec := spec.Maps[".data.lbrs"]
	lbrsMapSpec.Flags |= unix.BPF_F_MMAPABLE
	lbrsMapSpec.ValueSize = uint32(unsafe.Sizeof(LbrData{})) * uint32(numCPU)
	lbrsMapSpec.Contents[0].Value = make([]byte, lbrsMapSpec.ValueSize)
	lbrsData, err := ebpf.NewMap(lbrsMapSpec)
	assert.NoErr(err, "Failed to create lbrs map: %v")

	lbrs, err := ebpf.NewMap(spec.Maps["bpfsnoop_lbrs"])
	assert.NoErr(err, "Failed to create bpfsnoop_lbrs map: %v")

	argsMapSpec := spec.Maps[".data.args"]
	argsMapSpec.Flags |= unix.BPF_F_MMAPABLE
	argsMapSpec.ValueSize = uint32(unsafe.Sizeof(ArgData{})) * uint32(numCPU)
	argsMapSpec.Contents[0].Value = make([]byte, argsMapSpec.ValueSize)
	argsData, err := ebpf.NewMap(argsMapSpec)
	assert.NoErr(err, "Failed to create args map: %v")

	args, err := ebpf.NewMap(spec.Maps["bpfsnoop_args"])
	assert.NoErr(err, "Failed to create bpfsnoop_args map: %v")

	strsMapSpec := spec.Maps[".data.strs"]
	strsMapSpec.Flags |= unix.BPF_F_MMAPABLE
	strsMapSpec.ValueSize = uint32(unsafe.Sizeof(StrData{})) * uint32(numCPU)
	strsMapSpec.Contents[0].Value = make([]byte, strsMapSpec.ValueSize)
	strsData, err := ebpf.NewMap(strsMapSpec)
	assert.NoErr(err, "Failed to create strs map: %v")

	strs, err := ebpf.NewMap(spec.Maps["bpfsnoop_strs"])
	assert.NoErr(err, "Failed to create bpfsnoop_strs map: %v")

	pktsMapSpec := spec.Maps[".data.pkts"]
	pktsMapSpec.Flags |= unix.BPF_F_MMAPABLE
	pktsMapSpec.ValueSize = uint32(unsafe.Sizeof(StrData{})) * uint32(numCPU)
	pktsMapSpec.Contents[0].Value = make([]byte, pktsMapSpec.ValueSize)
	pktsData, err := ebpf.NewMap(pktsMapSpec)
	assert.NoErr(err, "Failed to create pkts map: %v")

	pkts, err := ebpf.NewMap(spec.Maps["bpfsnoop_pkts"])
	assert.NoErr(err, "Failed to create bpfsnoop_pkts map: %v")

	stacks, err := ebpf.NewMap(spec.Maps["bpfsnoop_stacks"])
	assert.NoErr(err, "Failed to create bpfsnoop_stacks map: %v")

	sessions, err := ebpf.NewMap(spec.Maps["bpfsnoop_sessions"])
	assert.NoErr(err, "Failed to create bpfsnoop_sessions map: %v")

	readyDataMapSpec := spec.Maps[".data.ready"]
	readyDataMapSpec.Flags |= unix.BPF_F_MMAPABLE
	readyData, err := ebpf.NewMap(readyDataMapSpec)
	assert.NoErr(err, "Failed to create ready data map: %v")

	evsMapSpec := spec.Maps[".data.events"]
	evsMapSpec.Flags |= unix.BPF_F_MMAPABLE
	evsMapSpec.ValueSize = uint32(unsafe.Sizeof(Event{})) * uint32(numCPU)
	evsMapSpec.Contents[0].Value = make([]byte, evsMapSpec.ValueSize)
	evsData, err := ebpf.NewMap(evsMapSpec)
	assert.NoErr(err, "Failed to create events data map: %v")

	events, err := ebpf.NewMap(spec.Maps["bpfsnoop_events"])
	assert.NoErr(err, "Failed to create events map: %v")

	return map[string]*ebpf.Map{
		"bpfsnoop_sessions": sessions,

		"bpfsnoop_events": events,
		"bpfsnoop_lbrs":   lbrs,
		"bpfsnoop_strs":   strs,
		"bpfsnoop_pkts":   pkts,
		"bpfsnoop_args":   args,
		".data.events":    evsData,
		".data.lbrs":      lbrsData,
		".data.strs":      strsData,
		".data.pkts":      pktsData,
		".data.args":      argsData,
		".data.ready":     readyData,
		"bpfsnoop_stacks": stacks,
	}
}

func CloseBPFMaps(maps map[string]*ebpf.Map) {
	for _, m := range maps {
		_ = m.Close()
	}
}
