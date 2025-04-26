// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import "github.com/cilium/ebpf/asm"

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
