// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func findStartIndex(prog *ebpf.ProgramSpec, stub string) (int, bool) {
	for i := 0; i < len(prog.Instructions); i++ {
		if symbol := prog.Instructions[i].Symbol(); symbol == stub {
			return i, true
		}
	}
	return -1, false
}

func findReturnIndex(prog *ebpf.ProgramSpec, start int) (int, bool) {
	retOpCode := asm.Return().OpCode
	for i := start; i < len(prog.Instructions); i++ {
		if prog.Instructions[i].OpCode == retOpCode {
			return i, true
		}
	}
	return -1, false
}

func injectInsns(prog *ebpf.ProgramSpec, stub string, insns asm.Instructions) {
	injIdx, ok := findStartIndex(prog, stub)
	if !ok {
		return
	}

	retIdx, ok := findReturnIndex(prog, injIdx)
	if !ok {
		return
	}

	if len(insns) != 0 {
		insns[0] = insns[0].WithMetadata(prog.Instructions[injIdx].Metadata)
	}
	prog.Instructions = append(prog.Instructions[:injIdx],
		append(insns, prog.Instructions[retIdx+1:]...)...)
}

func __clearSubprog(prog *ebpf.ProgramSpec, stub string, isFilter bool) {
	injectInsns(prog, stub, nil)

	for i := 0; i < len(prog.Instructions); i++ {
		if ref := prog.Instructions[i].Reference(); ref == stub {
			prog.Instructions[i] = asm.Mov.Imm(asm.R0, int32(b2i(isFilter)))
		}
	}
}

func clearOutputSubprog(prog *ebpf.ProgramSpec, stub string) {
	__clearSubprog(prog, stub, false)
}

func clearFilterSubprog(prog *ebpf.ProgramSpec, stub string) {
	__clearSubprog(prog, stub, true)
}
