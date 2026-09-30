// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"testing"

	"github.com/bpfsnoop/bpfsnoop/internal/test"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

const (
	bpfRdonlyCastKfuncID = 41126 // bpf_rdonly_cast
)

func TestCanRdonlyCast(t *testing.T) {
	t.Run("int", func(t *testing.T) {
		intTyp, err := testBtf.AnyTypeByName("int")
		test.AssertNoErr(t, err)

		ok, id, err := canRdonlyCast(testBtf, intTyp)
		test.AssertFalse(t, ok)
		test.AssertEqual(t, id, 0)
		test.AssertNoErr(t, err)
	})

	t.Run("int *", func(t *testing.T) {
		intTyp, err := testBtf.AnyTypeByName("int")
		test.AssertNoErr(t, err)
		intPtr := &btf.Pointer{Target: intTyp}

		ok, id, err := canRdonlyCast(testBtf, intPtr)
		test.AssertFalse(t, ok)
		test.AssertEqual(t, id, 0)
		test.AssertNoErr(t, err)
	})

	t.Run("struct sk_buff *", func(t *testing.T) {
		skbTyp, err := testBtf.AnyTypeByName("sk_buff")
		test.AssertNoErr(t, err)
		skbPtr := &btf.Pointer{Target: skbTyp}
		skbID, err := testBtf.TypeID(skbTyp)
		test.AssertNoErr(t, err)

		ok, id, err := canRdonlyCast(testBtf, skbPtr)
		test.AssertTrue(t, ok)
		test.AssertEqual(t, id, skbID)
		test.AssertNoErr(t, err)
	})

	t.Run("struct not in kernel btf *", func(t *testing.T) {
		podPtr := &btf.Pointer{Target: getProgLocalStructBtf(t)}

		ok, id, err := canRdonlyCast(testBtf, podPtr)
		test.AssertFalse(t, ok)
		test.AssertEqual(t, id, 0)
		test.AssertNoErr(t, err)
	})

	t.Run("prog-local type with kernel name", func(t *testing.T) {
		for _, target := range []btf.Type{
			&btf.Struct{Name: "sk_buff"},
			&btf.Union{Name: "bpf_attr"},
		} {
			ok, id, err := canRdonlyCast(testBtf, &btf.Pointer{Target: target})
			test.AssertFalse(t, ok)
			test.AssertEqual(t, id, 0)
			test.AssertNoErr(t, err)
		}
	})

	t.Run("qualified kernel union pointer", func(t *testing.T) {
		attr, err := testBtf.AnyTypeByName("bpf_attr")
		test.AssertNoErr(t, err)
		wantID, err := testBtf.TypeID(attr)
		test.AssertNoErr(t, err)
		typ := &btf.Typedef{Type: &btf.Const{Type: &btf.Pointer{
			Target: &btf.Volatile{Type: attr},
		}}}
		ok, id, err := canRdonlyCast(testBtf, typ)
		test.AssertTrue(t, ok)
		test.AssertEqual(t, id, wantID)
		test.AssertNoErr(t, err)
	})
}

// getProgLocalStructBtf returns a struct that only exists in a bpf prog's
// BTF, not in the kernel BTF.
func getProgLocalStructBtf(t *testing.T) *btf.Struct {
	s64, err := testBtf.AnyTypeByName("s64")
	test.AssertNoErr(t, err)

	return &btf.Struct{
		Name: "bpfsnoop_test_pod",
		Size: 16,
		Members: []btf.Member{
			{Name: "id", Type: s64, Offset: 0},
			{Name: "refs", Type: s64, Offset: 64},
		},
	}
}

func TestCanReadByRdonlyCast(t *testing.T) {
	t.Run("fn", func(t *testing.T) {
		fnTyp, err := testBtf.AnyTypeByName("bpf_rdonly_cast")
		test.AssertNoErr(t, err)

		ok := canReadByRdonlyCast(fnTyp)
		test.AssertFalse(t, ok)
	})

	t.Run("int", func(t *testing.T) {
		intTyp, err := testBtf.AnyTypeByName("int")
		test.AssertNoErr(t, err)

		ok := canReadByRdonlyCast(intTyp)
		test.AssertTrue(t, ok)
	})

	t.Run("int *", func(t *testing.T) {
		intTyp, err := testBtf.AnyTypeByName("int")
		test.AssertNoErr(t, err)
		intPtr := &btf.Pointer{Target: intTyp}

		ok := canReadByRdonlyCast(intPtr)
		test.AssertTrue(t, ok)
	})

	t.Run("struct sk_buff *", func(t *testing.T) {
		skbTyp, err := testBtf.AnyTypeByName("sk_buff")
		test.AssertNoErr(t, err)
		skbPtr := &btf.Pointer{Target: skbTyp}

		ok := canReadByRdonlyCast(skbPtr)
		test.AssertTrue(t, ok)
	})
}

func TestEmitCoreRead(t *testing.T) {
	c := prepareCompilerCoreRead(t)
	c.memMode = MemoryReadModeCoreRead

	t.Run("rdonly cast fastcall", func(t *testing.T) {
		c.rdonlyCastFastcall = true
		defer func() {
			c.rdonlyCastFastcall = false
			resetCompilerCoreRead(c)
		}()

		val := prepareExprVal(t, c, "skb->dev->ifindex")
		offsets := val.offsets

		err := c.emitCoreRead(offsets, r8)
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Mov.Reg(r1, r8),
			asm.Mov.Imm(r2, 1875),
			bpfKfuncCall(bpfRdonlyCastKfuncID),
			asm.LoadMem(r1, r0, 16, dword),
			asm.JEq.Imm(r1, 0, c.labelExit),
			asm.Mov.Imm(r2, 6973),
			bpfKfuncCall(bpfRdonlyCastKfuncID),
			asm.LoadMem(r8, r0, 224, asm.Word),
		})
	})

	t.Run("addr only", func(t *testing.T) {
		defer resetCompilerCoreRead(c)

		offsets := []pendingOffset{
			{offset: 16, deref: true}, // skb->dev
			{offset: 1464},            // skb->dev.dev
			{offset: 0},               // skb->dev.dev.kobj
			{offset: 24},              // dev->dev.dev.kobj.parent
		}

		err := c.emitCoreRead(offsets, r8)
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Mov.Reg(r1, r8),
			asm.Add.Imm(r1, 16),
			asm.Mov.Reg(r3, r1),
			asm.Mov.Imm(r2, 8),
			asm.Mov.Reg(r1, rfp),
			asm.Add.Imm(r1, -8),
			asm.FnProbeReadKernel.Call(),
			asm.LoadMem(r1, rfp, -8, dword),
			asm.Add.Imm(r1, 1464),
			asm.Add.Imm(r1, 24),
			asm.Mov.Reg(r8, r1),
		})
	})

	t.Run("rdonly cast err", func(t *testing.T) {
		defer resetCompilerCoreRead(c)

		// skb->dev->ifindex (inject error)
		val := prepareExprVal(t, c, "skb->dev->ifindex")
		offsets := val.offsets

		spec := newSpec(t, testBtf)
		spec.typeID = spec.getTypeIDErr

		c.btfSpec = spec
		defer func() { c.btfSpec = testBtf }()

		err := c.emitCoreRead(offsets, r8)
		test.AssertErrorPrefix(t, err, "failed to check if ")
	})

	t.Run("cannot rdonly cast", func(t *testing.T) {
		defer resetCompilerCoreRead(c)

		// skb->dev->ifindex
		val := prepareExprVal(t, c, "skb->dev->dev.kobj.parent->name")
		offsets := val.offsets

		err := c.emitCoreRead(offsets, r8)
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Mov.Reg(r1, r8),
			asm.Mov.Imm(r2, 1875),
			bpfKfuncCall(bpfRdonlyCastKfuncID),
			asm.LoadMem(r1, r0, 16, dword),
			asm.JEq.Imm(r1, 0, c.labelExit),
			asm.Mov.Imm(r2, 6973),
			bpfKfuncCall(bpfRdonlyCastKfuncID),
			asm.LoadMem(r1, r0, 1488, dword),
			asm.JEq.Imm(r1, 0, c.labelExit),
			asm.Mov.Imm(r2, 751),
			bpfKfuncCall(bpfRdonlyCastKfuncID),
			asm.LoadMem(r8, r0, 0, dword),
		})
	})

	t.Run("probe read fallback", func(t *testing.T) {
		defer resetCompilerCoreRead(c)

		val := prepareExprVal(t, c, "*(unsigned long *)(skb->head + 144)")
		offsets := val.offsets

		err := c.emitCoreRead(offsets, r8)
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Mov.Reg(asm.R1, r8),
			asm.Mov.Imm(asm.R2, 1875),
			bpfKfuncCall(bpfRdonlyCastKfuncID),
			asm.LoadMem(asm.R1, asm.R0, 200, asm.DWord),
			asm.JEq.Imm(asm.R1, 0, c.labelExit),
			asm.Add.Imm(asm.R1, 144),
			asm.Mov.Reg(asm.R3, asm.R1),
			asm.Mov.Imm(asm.R2, 8),
			asm.Mov.Reg(asm.R1, asm.RFP),
			asm.Add.Imm(asm.R1, -8),
			asm.FnProbeReadKernel.Call(),
			asm.LoadMem(r8, asm.RFP, -8, asm.DWord),
		})
	})

	t.Run("bad size", func(t *testing.T) {
		defer resetCompilerCoreRead(c)

		skb := getSkbBtf(t)
		fn := &btf.Func{
			Name: "bpf_rdonly_cast",
		}

		offsets := []pendingOffset{
			{prevBtf: skb, btf: fn, deref: true, offset: 4},
		}

		err := c.emitCoreRead(offsets, r8)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "failed to get size of")
	})

	t.Run("probe read fallback skb->users", func(t *testing.T) {
		defer resetCompilerCoreRead(c)

		val := prepareExprVal(t, c, "skb->users")
		offsets := val.offsets

		err := c.emitCoreRead(offsets, r8)
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Mov.Reg(r1, r8),
			asm.Add.Imm(r1, 220),
			asm.Mov.Reg(r3, r1),
			asm.Mov.Imm(r2, 8),
			asm.Mov.Reg(r1, rfp),
			asm.Add.Imm(r1, -8),
			asm.FnProbeReadKernel.Call(),
			asm.LoadMem(r8, rfp, -8, dword),
		})
	})

	t.Run("last is address", func(t *testing.T) {
		defer resetCompilerCoreRead(c)

		skb := getSkbBtf(t)
		dev := getNetDeviceBtf(t)
		u64 := getU64Btf(t)

		offsets := []pendingOffset{
			{prevBtf: skb, btf: dev, deref: true, offset: 4},
			{prevBtf: dev, btf: u64, deref: false, offset: 8},
		}

		err := c.emitCoreRead(offsets, r8)
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Mov.Reg(r1, r8),
			asm.Mov.Imm(r2, 1875),
			bpfKfuncCall(41126),
			asm.LoadMem(r1, r0, 4, dword),
			asm.JEq.Imm(r1, 0, c.labelExit),
			asm.Add.Imm(r1, 8),
			asm.Mov.Reg(r8, r1),
		})
	})

	t.Run("probe read fallback prog-local struct", func(t *testing.T) {
		defer resetCompilerCoreRead(c)

		pod := getProgLocalStructBtf(t)
		podPtr := &btf.Pointer{Target: pod}
		u64 := getU64Btf(t)

		// pod->refs
		offsets := []pendingOffset{
			{prevBtf: podPtr, btf: u64, deref: true, offset: 8},
		}

		err := c.emitCoreRead(offsets, r8)
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Mov.Reg(r1, r8),
			asm.Add.Imm(r1, 8),
			asm.Mov.Reg(r3, r1),
			asm.Mov.Imm(r2, 8),
			asm.Mov.Reg(r1, rfp),
			asm.Add.Imm(r1, -8),
			asm.FnProbeReadKernel.Call(),
			asm.LoadMem(r8, rfp, -8, dword),
		})
	})

	t.Run("last is u64", func(t *testing.T) {
		defer resetCompilerCoreRead(c)

		c.rdonlyCastFastcall = true
		defer func() { c.rdonlyCastFastcall = false }()

		c.regalloc.registers[r0] = true
		c.regalloc.registers[r1] = true

		skb := getSkbBtf(t)
		dev := getNetDeviceBtf(t)
		u64 := getU64Btf(t)

		offsets := []pendingOffset{
			{prevBtf: skb, btf: dev, deref: true, offset: 4},
			{prevBtf: dev, btf: u64, deref: true, offset: 8},
		}

		err := c.emitCoreRead(offsets, r8)
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.StoreMem(rfp, -24, r0, dword),
			asm.StoreMem(rfp, -16, r1, dword),
			asm.Mov.Reg(r1, r8),
			asm.Mov.Imm(r2, 1875),
			bpfKfuncCall(41126),
			asm.LoadMem(r1, r0, 4, dword),
			asm.JEq.Imm(r1, 0, c.labelExit),
			asm.Mov.Imm(r2, 6973),
			bpfKfuncCall(41126),
			asm.LoadMem(r8, r0, 8, dword),
			asm.LoadMem(r1, rfp, -16, dword),
			asm.LoadMem(r0, rfp, -24, dword),
		})
	})
}
