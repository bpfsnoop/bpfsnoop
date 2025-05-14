// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"unsafe"

	"github.com/bpfsnoop/bpfsnoop/internal/test"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"rsc.io/c2go/cc"
)

// immutableTypes is a set of types which musn't be changed.
type immutableTypes struct {
	// All types contained by the spec, not including types from the base in
	// case the spec was parsed from split BTF.
	types []btf.Type

	// Type IDs indexed by type.
	typeIDs map[btf.Type]btf.TypeID

	// The ID of the first type in types.
	firstTypeID btf.TypeID

	// Types indexed by essential name.
	// Includes all struct flavors and types with the same name.
	namedTypes map[string][]btf.TypeID

	// Byte order of the types. This affects things like struct member order
	// when using bitfields.
	byteOrder binary.ByteOrder
}

// mutableTypes is a set of types which may be changed.
type mutableTypes struct {
	imm           immutableTypes
	mu            sync.RWMutex            // protects copies below
	copies        map[btf.Type]btf.Type   // map[orig]copy
	copiedTypeIDs map[btf.Type]btf.TypeID // map[copy]origID
}

// Spec allows querying a set of Types and loading the set into the
// kernel.
type Spec struct {
	*mutableTypes

	// String table from ELF.
	strings uintptr
}

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

func TestCoreReadOffsets(t *testing.T) {
	c := prepareCompiler(t)

	const reg = asm.R8

	t.Run("bpf_rdonly_cast not found", func(t *testing.T) {
		defer c.reset()

		_, err := testBtf.AnyTypeByName(kfuncBpfRdonlyCast)
		test.AssertNoErr(t, err)

		spec := (*Spec)(unsafe.Pointer(c.kernelBtf))
		ids := spec.mutableTypes.imm.namedTypes[kfuncBpfRdonlyCast]
		delete(spec.mutableTypes.imm.namedTypes, kfuncBpfRdonlyCast)
		defer func() { spec.mutableTypes.imm.namedTypes[kfuncBpfRdonlyCast] = ids }()

		offsets := []accessOffset{
			{address: false, offset: 4},
			{address: false, offset: 8},
		}

		err = c.coreReadOffsets(offsets, reg)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "failed to find kfunc bpf_rdonly_cast")
		test.AssertTrue(t, errors.Is(err, btf.ErrNotFound))
	})

	t.Run("bpf_rdonly_cast not a function", func(t *testing.T) {
		defer c.reset()

		_, err := testBtf.AnyTypeByName(kfuncBpfRdonlyCast)
		test.AssertNoErr(t, err)

		u64 := getU64Btf(t)
		test.AssertNoErr(t, err)
		u64ID, err := testBtf.TypeID(u64)
		test.AssertNoErr(t, err)
		u64Ptr := &btf.Struct{
			Name: "bpf_rdonly_cast",
		}

		spec := (*Spec)(unsafe.Pointer(c.kernelBtf))
		ids := spec.mutableTypes.imm.namedTypes[kfuncBpfRdonlyCast]
		spec.mutableTypes.imm.namedTypes[kfuncBpfRdonlyCast] = []btf.TypeID{u64ID}
		spec.mutableTypes.imm.types[u64ID] = u64Ptr
		defer func() {
			spec.mutableTypes.imm.namedTypes[kfuncBpfRdonlyCast] = ids
			spec.mutableTypes.imm.types[u64ID] = u64
		}()

		offsets := []accessOffset{
			{address: false, offset: 4},
			{address: false, offset: 8},
		}

		err = c.coreReadOffsets(offsets, reg)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "bpf_rdonly_cast should be a function")
	})

	t.Run("bpf_rdonly_cast type ID not found", func(t *testing.T) {
		defer c.reset()

		rdonlyCast, err := testBtf.AnyTypeByName(kfuncBpfRdonlyCast)
		test.AssertNoErr(t, err)

		spec := (*Spec)(unsafe.Pointer(c.kernelBtf))
		id := spec.mutableTypes.copiedTypeIDs[rdonlyCast]
		delete(spec.mutableTypes.copiedTypeIDs, rdonlyCast)
		defer func() { spec.mutableTypes.copiedTypeIDs[rdonlyCast] = id }()

		offsets := []accessOffset{
			{address: false, offset: 4},
			{address: false, offset: 8},
		}

		err = c.coreReadOffsets(offsets, reg)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "failed to get type ID for kfunc bpf_rdonly_cast")
		test.AssertTrue(t, errors.Is(err, btf.ErrNotFound))
	})

	t.Run("not_found btf", func(t *testing.T) {
		defer c.reset()

		notFound := &btf.Pointer{
			Target: &btf.Struct{
				Name: "not_found",
			},
		}
		uintTyp, err := testBtf.AnyTypeByName("unsigned int")
		test.AssertNoErr(t, err)

		offsets := []accessOffset{
			{prev: notFound, address: false, offset: 4},
			{prev: uintTyp, address: false, offset: 8},
		}

		err = c.coreReadOffsets(offsets, reg)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "failed to check if")
	})

	t.Run("can't cast", func(t *testing.T) {
		defer c.reset()

		u64 := getU64Btf(t)

		offsets := []accessOffset{
			{prev: u64, address: false, offset: 4},
		}

		err := c.coreReadOffsets(offsets, reg)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), `type Typedef:"__u64"[Int:"long long unsigned int"] cannot be bpf_rdonly_cast`)
	})

	t.Run("skb->cb[2]", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("skb->cb[2]")
		test.AssertNoErr(t, err)

		res, err := c.accessMemory(expr)
		test.AssertNoErr(t, err)

		err = c.coreReadOffsets(res.offsets, reg)
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Mov.Reg(asm.R1, reg),
			asm.Add.Imm(asm.R1, 40),
			asm.Mov.Reg(asm.R3, asm.R1),
			asm.Mov.Imm(asm.R2, 8),
			asm.Mov.Reg(asm.R1, asm.RFP),
			asm.Add.Imm(asm.R1, -8),
			asm.FnProbeReadKernel.Call(),
			asm.LoadMem(reg, asm.RFP, -8, asm.DWord),
		})
	})

	t.Run("bad size", func(t *testing.T) {
		defer c.reset()

		skb := getSkbBtf(t)
		fn := &btf.Func{
			Name: "bpf_rdonly_cast",
		}

		offsets := []accessOffset{
			{prev: skb, btf: fn, address: false, offset: 4},
		}

		err := c.coreReadOffsets(offsets, reg)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "failed to get size of btf type")
	})

	t.Run("last is address", func(t *testing.T) {
		defer c.reset()

		skb := getSkbBtf(t)
		dev := getNetDeviceBtf(t)
		u64 := getU64Btf(t)

		offsets := []accessOffset{
			{prev: skb, btf: dev, address: false, offset: 4},
			{prev: dev, btf: u64, address: true, offset: 8},
		}

		err := c.coreReadOffsets(offsets, reg)
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Mov.Reg(asm.R1, reg),
			asm.Mov.Imm(asm.R2, 1875),
			bpfKfuncCall(41126),
			asm.LoadMem(asm.R1, asm.R0, 4, asm.DWord),
			asm.JEq.Imm(asm.R1, 0, c.labelExit),
			asm.Add.Imm(asm.R1, 8),
			asm.Mov.Reg(reg, asm.R1),
		})
	})

	t.Run("last is u64", func(t *testing.T) {
		defer c.reset()

		c.regalloc.registers[asm.R1] = true

		skb := getSkbBtf(t)
		dev := getNetDeviceBtf(t)
		u64 := getU64Btf(t)

		offsets := []accessOffset{
			{prev: skb, btf: dev, address: false, offset: 4},
			{prev: dev, btf: u64, address: false, offset: 8},
		}

		err := c.coreReadOffsets(offsets, reg)
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.StoreMem(asm.RFP, -16, asm.R1, asm.DWord),
			asm.Mov.Reg(asm.R1, reg),
			asm.Mov.Imm(asm.R2, 1875),
			bpfKfuncCall(41126),
			asm.LoadMem(asm.R1, asm.R0, 4, asm.DWord),
			asm.JEq.Imm(asm.R1, 0, c.labelExit),
			asm.Mov.Imm(asm.R2, 6973),
			bpfKfuncCall(41126),
			asm.LoadMem(reg, asm.R0, 8, asm.DWord),
			asm.LoadMem(asm.R1, asm.RFP, -16, asm.DWord),
		})
	})
}
