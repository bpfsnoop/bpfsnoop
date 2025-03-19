// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import "github.com/cilium/ebpf/asm"

func genGetFuncArg(index int, dst asm.Register) asm.Instructions {
	return asm.Instructions{
		asm.Mov.Reg(asm.R3, asm.R10),
		asm.Add.Imm(asm.R3, -8),
		asm.Mov.Imm(asm.R2, int32(index)),
		asm.FnGetFuncArg.Call(),
		asm.LoadMem(dst, asm.R10, -8, asm.DWord),
	}
}

func genAccessArg(index int, dst asm.Register) asm.Instructions {
	return asm.Instructions{
		asm.LoadMem(dst, asm.R1, int16(index*8), asm.DWord),
	}
}
