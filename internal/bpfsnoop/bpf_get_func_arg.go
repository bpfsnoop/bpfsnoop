// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import "github.com/cilium/ebpf/asm"

func genAccessArg(index int, dst asm.Register) asm.Instructions {
	return asm.Instructions{
		asm.LoadMem(dst, asm.R1, int16(index*8), asm.DWord),
	}
}
