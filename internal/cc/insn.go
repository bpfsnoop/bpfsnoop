// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import "github.com/cilium/ebpf/asm"

// fitsImm32 reports whether v survives the sign-extended 32-bit immediate of
// an ALU or jump instruction. Encoding a larger constant there truncates it
// silently.
func fitsImm32(v int64) bool {
	return int64(int32(v)) == v
}

// movImm loads v into dst, with ld_imm64 if v doesn't fit in a 32-bit
// immediate. ld_imm64 takes two instruction slots, see rawLen.
func movImm(dst asm.Register, v int64) asm.Instruction {
	if fitsImm32(v) {
		return asm.Instruction{
			OpCode:   asm.Mov.Op(asm.ImmSource),
			Dst:      dst,
			Constant: v,
		}
	}
	return asm.LoadImm(dst, v, asm.DWord)
}

// rawLen returns the length of insns in instruction slots, the unit of jump
// offsets.
func rawLen(insns asm.Instructions) int {
	n := 0
	for _, ins := range insns {
		n += int(ins.Size() / asm.InstructionSize)
	}
	return n
}

func JmpOff(op asm.JumpOp, dst asm.Register, value int64, offset int16) asm.Instruction {
	return asm.Instruction{
		OpCode:   op.Op(asm.ImmSource),
		Dst:      dst,
		Offset:   offset,
		Constant: value,
	}
}

func JmpReg(op asm.JumpOp, dst, src asm.Register, offset int16) asm.Instruction {
	return asm.Instruction{
		OpCode: op.Op(asm.RegSource),
		Dst:    dst,
		Src:    src,
		Offset: offset,
	}
}

func Ja(offset int16) asm.Instruction {
	return asm.Instruction{
		OpCode: asm.Ja.Op(asm.ImmSource),
		Offset: offset,
	}
}
