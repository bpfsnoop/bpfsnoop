// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"fmt"

	"github.com/cilium/ebpf/asm"
)

type RegisterAllocator struct {
	registers [10]bool // r0 - r9
}

func (ra *RegisterAllocator) Alloc() (asm.Register, error) {
	for i := int(asm.R8); i >= int(asm.R0); i-- {
		if !ra.registers[i] {
			ra.registers[i] = true
			return asm.Register(i), nil
		}
	}

	return asm.R0, ErrRegisterNotEnough
}

func (ra *RegisterAllocator) Free(reg asm.Register) {
	if reg >= asm.R0 && reg <= asm.R9 {
		ra.registers[reg] = false
	}
}

func (ra *RegisterAllocator) IsUsed(reg asm.Register) bool {
	if reg >= asm.R0 && reg <= asm.R9 {
		return ra.registers[reg]
	}

	panic(fmt.Sprintf("register %d is out of range", reg))
}
