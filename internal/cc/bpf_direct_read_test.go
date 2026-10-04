// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"

	"github.com/bpfsnoop/bpfsnoop/internal/test"
)

func prepareCompilerDirectRead(t *testing.T) *compiler {
	t.Helper()
	c := prepareCompiler(t)
	c.memMode = MemoryReadModeDirectRead
	return c
}

func resetCompilerDirectRead(c *compiler) {
	c.reset()
	c.memMode = MemoryReadModeDirectRead
}

func TestEmitDirectRead(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("addr only", func(t *testing.T) {
		defer c.reset()

		offsets := []pendingOffset{
			{offset: 16, deref: true}, // skb->dev
			{offset: 1464},            // skb->dev.dev
			{offset: 0},               // skb->dev.dev.kobj
			{offset: 24},              // dev->dev.dev.kobj.parent
		}

		test.AssertNoErr(t, c.emitDirectRead(offsets, r8, directReadOptions{checkImm: true}))
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.LoadMem(r8, r8, 16, dword),
			asm.JEq.Imm(r8, 0, c.labelExit),
			asm.Add.Imm(r8, 1464),
			asm.Add.Imm(r8, 24),
		})
	})

	t.Run("offsets", func(t *testing.T) {
		defer c.reset()

		val := prepareExprVal(t, c, "skb->dev->dev.kobj.parent->name")
		offsets := val.offsets

		test.AssertNoErr(t, c.emitDirectRead(offsets, r8, directReadOptions{checkImm: true}))
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.LoadMem(r8, r8, 16, dword),
			asm.JEq.Imm(r8, 0, c.labelExit),
			asm.LoadMem(r8, r8, 1488, dword),
			asm.JEq.Imm(r8, 0, c.labelExit),
			asm.LoadMem(r8, r8, 0, dword),
		})
	})

	t.Run("typed scalar followed by address arithmetic", func(t *testing.T) {
		defer c.reset()

		offsets := []pendingOffset{
			{deref: true, offset: 4, btf: &btf.Int{Size: 4}},
			{offset: 8},
		}
		test.AssertNoErr(t, c.emitDirectRead(offsets, r8, directReadOptions{useBTFSize: true}))
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.LoadMem(r8, r8, 4, asm.Word),
			asm.Add.Imm(r8, 8),
		})
		test.AssertFalse(t, c.labelExitUsed)
	})
}
