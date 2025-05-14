// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"testing"

	"github.com/bpfsnoop/bpfsnoop/internal/test"
	"github.com/cilium/ebpf/asm"
)

func TestProbeReadOffsets(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("one offset with address", func(t *testing.T) {
		defer c.reset()
		c.probeReadOffsets([]accessOffset{{offset: 4, address: true}}, asm.R8)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Add.Imm(asm.R8, 4),
		})
	})

	t.Run("one offset", func(t *testing.T) {
		defer c.reset()
		c.probeReadOffsets([]accessOffset{{offset: 4}}, asm.R8)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Mov.Reg(asm.R3, asm.R8),
			asm.Add.Imm(asm.R3, 4),
			asm.Mov.Imm(asm.R2, 8),
			asm.Mov.Reg(asm.R1, asm.RFP),
			asm.Add.Imm(asm.R1, -8),
			asm.FnProbeReadKernel.Call(),
			asm.LoadMem(asm.R8, asm.RFP, -8, asm.DWord),
		})
	})

	t.Run("multiple offsets", func(t *testing.T) {
		defer c.reset()
		c.probeReadOffsets([]accessOffset{
			{offset: 4},
			{offset: 8},
			{offset: 12, address: true},
		}, asm.R8)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Mov.Reg(asm.R3, asm.R8),
			asm.Add.Imm(asm.R3, 4),
			asm.Mov.Imm(asm.R2, 8),
			asm.Mov.Reg(asm.R1, asm.RFP),
			asm.Add.Imm(asm.R1, -8),
			asm.FnProbeReadKernel.Call(),
			asm.LoadMem(asm.R3, asm.RFP, -8, asm.DWord),
			asm.JEq.Imm(asm.R3, 0, c.labelExit),
			asm.Add.Imm(asm.R3, 8),
			asm.Mov.Imm(asm.R2, 8),
			asm.Mov.Reg(asm.R1, asm.RFP),
			asm.Add.Imm(asm.R1, -8),
			asm.FnProbeReadKernel.Call(),
			asm.LoadMem(asm.R3, asm.RFP, -8, asm.DWord),
			asm.JEq.Imm(asm.R3, 0, c.labelExit),
			asm.Add.Imm(asm.R3, 12),
			asm.Mov.Reg(asm.R8, asm.R3),
		})
	})
}
