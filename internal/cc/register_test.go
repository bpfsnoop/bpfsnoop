// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"testing"

	"github.com/bpfsnoop/bpfsnoop/internal/test"
	"github.com/cilium/ebpf/asm"
)

func (ra *RegisterAllocator) reset() {
	for i := 0; i < len(ra.registers); i++ {
		ra.registers[i] = false
	}
}

func TestRegister(t *testing.T) {
	var ra RegisterAllocator

	t.Run("Free", func(t *testing.T) {
		defer ra.reset()

		ra.registers[asm.R9] = true
		ra.Free(asm.R9)
		test.AssertFalse(t, ra.registers[asm.R9])
	})

	t.Run("IsUsed", func(t *testing.T) {
		defer ra.reset()

		ra.registers[asm.R9] = true
		test.AssertTrue(t, ra.IsUsed(asm.R9))
		test.AssertFalse(t, ra.IsUsed(asm.R8))
	})

	t.Run("IsUsed panic", func(t *testing.T) {
		defer ra.reset()

		test.AssertPanic(t, func() {
			ra.IsUsed(asm.R10)
		})
	})
}
