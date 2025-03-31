// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/bpfsnoop/gapstone"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

var tailcallInfo TailcallInfo

type TailcallInfo struct {
	fixedTailcallInfiniteLoopCausedByTrampoline bool
}

func isTailcallReachable(insns []byte) bool {
	if len(insns) == 0 || len(insns) < 4+5+3 {
		return false
	}

	offset := 5
	u32 := binary.NativeEndian.Uint32(insns[:4])
	if isEndbrInsn(u32) {
		offset += 4
	}

	var tailcallReachable bool
	tailcallReachable = tailcallReachable || bytes.Equal(insns[offset:offset+2], []byte{0x31, 0xc0})       /* xor eax, eax */
	tailcallReachable = tailcallReachable || bytes.Equal(insns[offset:offset+3], []byte{0x48, 0x31, 0xc0}) /* xor rax, rax */

	return tailcallReachable
}

func probeTailcallInfo(prog *ebpf.Program, readSpec *ebpf.CollectionSpec) (TailcallInfo, error) {
	var info TailcallInfo

	pinfo, err := prog.Info()
	if err != nil {
		return info, fmt.Errorf("failed to get program info: %w", err)
	}

	jitedKsyms, _ := pinfo.JitedKsymAddrs()
	jitedInsns, _ := pinfo.JitedInsns()
	if len(jitedInsns) == 0 {
		return info, nil
	}

	kaddr := jitedKsyms[0]
	jinsns := jitedInsns
	u32 := binary.NativeEndian.Uint32(jinsns[:4])
	if isEndbrInsn(u32) {
		jinsns = jinsns[4:]
		kaddr += 4
	}

	if !isTailcallReachable(jinsns) {
		return info, nil
	}

	// Check whether there is `pushq %rax` insn in the trampoline. If so, the
	// kernel has fixed the tailcall infinite loop issue caused by trampoline.

	offset := binary.NativeEndian.Uint32(jinsns[1:])
	kaddrTramp := kaddr + 5 /* next insn */ + uintptr(offset) /* callq target */

	data, err := readKernel(readSpec, uint64(kaddrTramp), 512)
	if err != nil {
		return info, fmt.Errorf("failed to read kernel memory from %#x: %w", kaddrTramp, err)
	}
	if len(data) == 0 {
		return info, fmt.Errorf("failed to read kernel memory from %#x: no data", kaddrTramp)
	}

	engine, err := gapstone.New(int(gapstone.CS_ARCH_X86), int(gapstone.CS_MODE_64))
	if err != nil {
		return info, fmt.Errorf("failed to create disassembler: %w", err)
	}
	defer engine.Close()

	insns, b, pc := []gapstone.Instruction{}, data[:], uint64(kaddrTramp)
	for len(b) != 0 {
		insts, err := engine.Disasm(b, pc, 1)
		if err != nil && len(b) <= 10 {
			break
		}
		if err != nil {
			return info, fmt.Errorf("failed to disasm trampoline insns: %w", err)
		}

		insn := insts[0]
		insns = append(insns, insn)

		insnSize := insn.Size
		if insnSize == 1 && insn.Bytes[0] == 0x50 /* pushq %rax */ {
			info.fixedTailcallInfiniteLoopCausedByTrampoline = true
			break
		}

		if insnSize == 1 && insn.Bytes[0] == 0xc3 /* retq */ {
			break
		}

		pc += uint64(insnSize)
		b = b[insnSize:]
	}

	return info, nil
}

func ProbeTailcallIssue(spec, tailcallSpec, readSpec *ebpf.CollectionSpec) error {
	tcColl, err := ebpf.NewCollection(tailcallSpec)
	if err != nil {
		return fmt.Errorf("failed to create tailcall collection: %w", err)
	}
	defer tcColl.Close()

	tcProgName := "entry"
	tcProg := tcColl.Programs[tcProgName]

	spec = spec.Copy()
	reusedMaps := PrepareBPFMaps(spec)
	defer CloseBPFMaps(reusedMaps)

	prog := spec.Programs[TracingProgName()]
	pktFilter.clear(prog)
	pktOutput.clear(prog)
	argOutput.clear(prog)
	clearFilterArgSubprog(prog)

	attachType := ebpf.AttachTraceFExit
	if mode == TracingModeEntry {
		attachType = ebpf.AttachTraceFEntry
	}

	prog.AttachTarget = tcProg
	prog.AttachTo = tcProgName
	prog.AttachType = attachType

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: reusedMaps,
	})
	if err != nil {
		return fmt.Errorf("failed to create tailcall detection bpf collection: %w", err)
	}
	defer coll.Close()

	l, err := link.AttachTracing(link.TracingOptions{
		Program:    coll.Programs[TracingProgName()],
		AttachType: attachType,
	})
	if err != nil {
		return fmt.Errorf("failed to %s bpf prog: %w", TracingProgName(), err)
	}
	defer l.Close()

	info, err := probeTailcallInfo(tcProg, readSpec)
	if err != nil {
		return fmt.Errorf("failed to probe tailcall info: %w", err)
	}

	DebugLog("Current kernel has fixed tailcall infinite loop issue caused by trampoline: %v",
		info.fixedTailcallInfiniteLoopCausedByTrampoline)
	verboseLogIf(!info.fixedTailcallInfiniteLoopCausedByTrampoline,
		"Current kernel does not have fixed tailcall infinite loop issue caused by trampoline")

	tailcallInfo = info

	return nil
}
