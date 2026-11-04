// Copyright 2026 Liang Tang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"encoding/binary"
	"fmt"
	"slices"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"

	"github.com/bpfsnoop/bpfsnoop/internal/cc"
)

// The sections of the string literals of bpf/bpfsnoop_str.h.
const (
	strLitSection    = ".rodata.strlit"
	strLitLenSection = ".rodata.strlit.length"
)

// strBufSize is the size of the ringbuf that bpfsnoop_str_eq() reserves its
// buffers from in a bpf prog without event readers: room for 248 of them.
const strBufSize = 64 * 1024

// prepareStrBufs gives the event ringbufs of spec, for a bpf prog without event
// readers, e.g. of --read, to bpfsnoop_str_eq() in bpf/bpfsnoop_str.h: one small
// ringbuf for all CPUs, which nothing reads. A run of the prog discards the
// buffers it reserves, so it doesn't fill. If prog compares no str(), the
// event ringbufs are dropped instead. The caller closes the ringbuf.
func prepareStrBufs(spec *ebpf.CollectionSpec, prog *ebpf.ProgramSpec) (*ebpf.Map, error) {
	if !slices.ContainsFunc(prog.Instructions, func(ins asm.Instruction) bool {
		return ins.IsFunctionCall() && ins.Reference() == cc.StrEqFunc
	}) {
		delete(spec.Maps, "bpfsnoop_events")
		return nil, nil
	}

	cpus, err := possibleCPU()
	if err != nil {
		return nil, fmt.Errorf("failed to read possible CPU number: %w", err)
	}

	events := spec.Maps["bpfsnoop_events"].Copy()
	events.InnerMap.MaxEntries = strBufSize
	buf, err := ebpf.NewMap(events.InnerMap)
	if err != nil {
		return nil, fmt.Errorf("failed to create ringbuf for str(): %w", err)
	}

	events.MaxEntries = uint32(cpus)
	events.Contents = make([]ebpf.MapKV, cpus)
	for i := range events.Contents {
		events.Contents[i] = ebpf.MapKV{Key: uint32(i), Value: buf}
	}
	spec.Maps["bpfsnoop_events"] = events
	return buf, nil
}

// dropUnusedStrLits drops the .rodata.strlit sections from spec if no prog
// uses them, so that no map is created for them.
func dropUnusedStrLits(spec *ebpf.CollectionSpec) {
	for _, prog := range spec.Programs {
		for _, ins := range prog.Instructions {
			if ref := ins.Reference(); ref == strLitSection || ref == strLitLenSection {
				return
			}
		}
	}

	delete(spec.Maps, strLitSection)
	delete(spec.Maps, strLitLenSection)
	for name, v := range spec.Variables {
		if v.SectionName == strLitSection || v.SectionName == strLitLenSection {
			delete(spec.Variables, name)
		}
	}
}

// injectStrLits indexes the string literals of the str() comparisons compiled
// into prog, e.g. in its arg filter and outputs, and puts them in the
// .rodata.strlit sections of spec, for bpfsnoop_str_eq() in bpf/bpfsnoop_str.h.
// Without any, the sections are dropped if no other prog uses them.
func injectStrLits(spec *ebpf.CollectionSpec, prog *ebpf.ProgramSpec) error {
	lits := cc.IndexStrLits(prog.Instructions)
	if len(lits) == 0 {
		dropUnusedStrLits(spec)
		return nil
	}

	// A literal takes cc.StrLitSize bytes, with its NUL and zero padding.
	data := make([]byte, len(lits)*cc.StrLitSize)
	lens := make([]byte, 0, len(lits)*4)
	for i, lit := range lits {
		copy(data[i*cc.StrLitSize:], lit)
		lens = binary.NativeEndian.AppendUint32(lens, uint32(len(lit)+1))
	}

	if err := setArraySection(spec, strLitSection, data); err != nil {
		return err
	}
	return setArraySection(spec, strLitLenSection, lens)
}

// setArraySection sets the contents of a data section that holds one array,
// resizing the array to them.
func setArraySection(spec *ebpf.CollectionSpec, name string, data []byte) error {
	ms, ok := spec.Maps[name]
	if !ok {
		return fmt.Errorf("section %s not found", name)
	}

	ds, ok := ms.Value.(*btf.Datasec)
	if !ok || len(ds.Vars) != 1 {
		return fmt.Errorf("section %s doesn't hold one variable", name)
	}
	v, ok := ds.Vars[0].Type.(*btf.Var)
	if !ok {
		return fmt.Errorf("section %s doesn't hold a variable", name)
	}
	arr, ok := btf.UnderlyingType(v.Type).(*btf.Array)
	if !ok {
		return fmt.Errorf("variable %s of section %s isn't an array", v.Name, name)
	}
	elemSize, err := btf.Sizeof(arr.Type)
	if err != nil || elemSize == 0 || len(data)%elemSize != 0 {
		return fmt.Errorf("can't hold %d bytes in variable %s of section %s: %v", len(data), v.Name, name, err)
	}

	size := uint32(len(data))
	resized := &btf.Var{
		Name:    v.Name,
		Type:    &btf.Array{Index: arr.Index, Type: arr.Type, Nelems: size / uint32(elemSize)},
		Linkage: v.Linkage,
	}

	ms = ms.Copy()
	ms.ValueSize = size
	ms.Contents = []ebpf.MapKV{{Key: uint32(0), Value: data}}
	ms.Value = &btf.Datasec{
		Name: ds.Name,
		Size: size,
		Vars: []btf.VarSecinfo{{Type: resized, Size: size}},
	}
	spec.Maps[name] = ms

	// The variable's value goes over the contents when loading.
	if vs, ok := spec.Variables[v.Name]; ok {
		vs = vs.Copy()
		vs.Value = slices.Clone(data)
		vs.Type = resized
		spec.Variables[v.Name] = vs
	}
	return nil
}
