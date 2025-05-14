// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"testing"

	"github.com/cilium/ebpf/asm"

	"github.com/bpfsnoop/bpfsnoop/internal/test"
)

func TestDirectReadOffsets(t *testing.T) {
	c := prepareCompiler(t)

	const reg = asm.R8
	c.directReadOffsets([]accessOffset{
		{
			offset:  4,
			address: true,
		},
		{
			offset: 8,
		},
		{
			offset: 12,
		},
	}, reg)

	test.AssertEqualSlice(t, c.insns, asm.Instructions{
		asm.Add.Imm(reg, 4),
		asm.LoadMem(reg, reg, 8, asm.DWord),
		asm.JEq.Imm(reg, 0, c.labelExit),
		asm.LoadMem(reg, reg, 12, asm.DWord),
	})
}
