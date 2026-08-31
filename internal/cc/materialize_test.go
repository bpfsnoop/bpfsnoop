// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"rsc.io/c2go/cc"

	"github.com/bpfsnoop/bpfsnoop/internal/test"
)

const (
	r0    = asm.R0
	r1    = asm.R1
	r2    = asm.R2
	r3    = asm.R3
	r7    = asm.R7
	r8    = asm.R8
	rfp   = asm.RFP
	dword = asm.DWord
)

func prepareCcExpr(t *testing.T, expr string) *cc.Expr {
	t.Helper()
	e, err := cc.ParseExpr(expr)
	test.AssertNoErr(t, err)
	return e
}

func prepareExprVal(t *testing.T, c *compiler, expr string) exprValue {
	t.Helper()
	e, err := cc.ParseExpr(expr)
	test.AssertNoErr(t, err)

	val, err := c.evaluate(e)
	test.AssertNoErr(t, err)
	return val
}

func prepareCompilerCoreRead(t *testing.T) *compiler {
	t.Helper()
	c := prepareCompiler(t)
	c.memMode = MemoryReadModeCoreRead
	return c
}

func resetCompilerCoreRead(c *compiler) {
	c.reset()
	c.memMode = MemoryReadModeCoreRead
}

func TestMaterialize(t *testing.T) {
	c := prepareCompilerDirectRead(t)

	t.Run("constant", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		val := newConstant(42)
		mv, err := c.materialize(val)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, mv.isMaterialized())
		test.AssertEqual(t, mv.reg, r8)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Instruction{
				OpCode:   asm.Mov.Op(asm.ImmSource),
				Dst:      r8,
				Constant: 42,
			},
		})
	})

	t.Run("pending", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		val := prepareExprVal(t, c, "skb->len")
		val, err := c.materialize(val)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqual(t, val.reg, r8)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.LoadMem(r8, argsReg, 0, dword), // skb pointer
			asm.LoadMem(r8, r8, 112, dword),    // skb->len
			asm.LSh.Imm(r8, 32),
			asm.RSh.Imm(r8, 32),
		})
	})

	t.Run("materialized", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		val := newMaterialized(asm.R5, getSkbBtf(t))
		mv, err := c.materialize(val)
		test.AssertNoErr(t, err)
		test.AssertDeepEqual(t, mv, val)
	})

	t.Run("enum maybe", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		val := newEnumMaybe("TEST_ENUM")
		_, err := c.materialize(val)
		test.AssertErrorPrefix(t, err, "cannot materialize unresolved enum 'TEST_ENUM'")
	})

	t.Run("unknown kind", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		val := exprValue{kind: exprValueKind(999)}
		_, err := c.materialize(val)
		test.AssertErrorPrefix(t, err, "cannot materialize unknown value kind")
	})
}

func TestMaterializeConstant(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("reg alloc", func(t *testing.T) {
		c.markRegisterAllUsed()
		defer c.reset()

		var val exprValue
		_, err := c.materializeConstant(val)
		test.AssertErrorPrefix(t, err, "failed to allocate register for constant")
	})

	t.Run("success", func(t *testing.T) {
		defer c.reset()

		val := newConstant(42)
		mv, err := c.materializeConstant(val)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, mv.isMaterialized())
		test.AssertEqual(t, mv.reg, r8)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Instruction{
				OpCode:   asm.Mov.Op(asm.ImmSource),
				Dst:      r8,
				Constant: 42,
			},
		})
	})
}

func TestMaterializePending(t *testing.T) {
	c := prepareCompilerDirectRead(t)

	t.Run("reg alloc", func(t *testing.T) {
		c.markRegisterAllUsed()
		defer resetCompilerDirectRead(c)

		var val exprValue
		_, err := c.materializePending(val)
		test.AssertErrorPrefix(t, err, "failed to allocate register for pending value")
	})

	t.Run("bitfield", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		val := prepareExprVal(t, c, "skb->cloned")
		val, err := c.materializePending(val)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqual(t, val.reg, r8)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.LoadMem(r8, argsReg, 0, dword), // skb pointer
			asm.LoadMem(r8, r8, 126, dword),    // skb->cloned
			asm.And.Imm(r8, 1),                 // bitfield mask
		})
	})

	t.Run("uptr", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		uptrVal := 0x12345678
		val := newPendingUptr(uint64(uptrVal), getSkbBtf(t))
		val, err := c.materializePending(val)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqual(t, val.reg, r8)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Instruction{
				OpCode:   asm.Mov.Op(asm.ImmSource),
				Dst:      r8,
				Constant: int64(uptrVal),
			},
		})
	})

	t.Run("offsets err", func(t *testing.T) {
		defer resetCompilerDirectRead(c)
		c.memMode = MemoryReadModeCoreRead

		// skb->dev->ifindex (inject error)
		val := prepareExprVal(t, c, "skb->dev->ifindex")

		spec := newSpec(t, testBtf)
		spec.typeID = spec.getTypeIDErr

		c.btfSpec = spec
		defer func() { c.btfSpec = testBtf }()

		val, err := c.materializePending(val)
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "failed to emit offset chain")
	})

	t.Run("base reg", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		val := newPendingReg(asm.R1, getSkbBtf(t))
		val, err := c.materializePending(val)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqual(t, val.reg, r8)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Mov.Reg(r8, asm.R1),
		})
	})

	t.Run("offsets", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		val := prepareExprVal(t, c, "skb->dev->ifindex")
		val, err := c.materializePending(val)
		test.AssertNoErr(t, err)
		test.AssertTrue(t, val.isMaterialized())
		test.AssertEqual(t, val.reg, r8)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.LoadMem(r8, argsReg, 0, dword), // skb pointer
			asm.LoadMem(r8, r8, 16, dword),     // skb->dev
			asm.JEq.Imm(r8, 0, c.labelExit),    // null check
			asm.LoadMem(r8, r8, 224, dword),    // dev->ifindex
			asm.LSh.Imm(r8, 32),
			asm.ArSh.Imm(r8, 32),
		})
	})
}

func TestEmitOffsetChain(t *testing.T) {
	c := prepareCompilerDirectRead(t)

	t.Run("all address", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		offsets := []pendingOffset{
			{offset: 8, deref: false},
		}

		err := c.emitOffsetChain(offsets, r8)
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Add.Imm(r8, 8),
		})
	})

	t.Run("core read", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		c.memMode = MemoryReadModeCoreRead

		val := prepareExprVal(t, c, "skb->dev")
		offsets := val.offsets

		err := c.emitOffsetChain(offsets, r8)
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Mov.Reg(r1, r8),
			asm.Mov.Imm(r2, 1875),
			bpfKfuncCall(bpfRdonlyCastKfuncID),
			asm.LoadMem(r8, r0, 16, dword),
		})
	})

	t.Run("direct read", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		val := prepareExprVal(t, c, "skb->dev")
		offsets := val.offsets

		err := c.emitOffsetChain(offsets, r8)
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.LoadMem(r8, r8, 16, dword),
		})
	})

	t.Run("probe read", func(t *testing.T) {
		defer resetCompilerDirectRead(c)

		c.memMode = MemoryReadModeProbeRead

		val := prepareExprVal(t, c, "skb->dev")
		offsets := val.offsets

		err := c.emitOffsetChain(offsets, r8)
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Mov.Reg(r3, r8),
			asm.Add.Imm(r3, 16),
			asm.Mov.Imm(r2, 8),
			asm.Mov.Reg(r1, rfp),
			asm.Add.Imm(r1, -8),
			asm.FnProbeReadKernel.Call(),
			asm.LoadMem(r8, rfp, -8, dword),
		})
	})
}

func TestEmitBitfieldExtract(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("delta non-zero", func(t *testing.T) {
		defer c.reset()

		val := prepareExprVal(t, c, "skb->peeked")

		c.emitBitfieldExtract(val.mem, r8)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.RSh.Imm(r8, 4),
			asm.And.Imm(r8, 1),
		})
	})

	t.Run("delta zero", func(t *testing.T) {
		defer c.reset()

		val := prepareExprVal(t, c, "skb->cloned")

		c.emitBitfieldExtract(val.mem, r8)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.And.Imm(r8, 1),
		})
	})
}

func TestAdjustRegisterSize(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("no adjust", func(t *testing.T) {
		defer c.reset()

		val := newConstant(0)
		c.adjustRegisterSize(val)
		test.AssertEmptySlice(t, c.insns)
	})

	t.Run("invalid sizeof btf", func(t *testing.T) {
		defer c.reset()

		fn := &btf.Func{
			Name: "bpf_rdonly_cast",
		}
		val := newMaterialized(r8, fn)

		c.adjustRegisterSize(val)
		test.AssertEmptySlice(t, c.insns)
	})

	t.Run("adjust to byte", func(t *testing.T) {
		defer c.reset()

		u8 := getU8Btf(t)
		val := newMaterialized(r8, u8)

		c.adjustRegisterSize(val)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.And.Imm(r8, 0xFF),
		})
	})

	t.Run("sign extend byte", func(t *testing.T) {
		defer c.reset()

		i8 := &btf.Int{Name: "signed char", Size: 1, Encoding: btf.Signed}
		val := newMaterialized(r8, i8)

		c.adjustRegisterSize(val)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.LSh.Imm(r8, 56),
			asm.ArSh.Imm(r8, 56),
		})
	})

	t.Run("adjust to word", func(t *testing.T) {
		defer c.reset()

		u16 := getU16Btf(t)
		val := newMaterialized(r8, u16)

		c.adjustRegisterSize(val)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.And.Imm(r8, 0xFFFF),
		})
	})

	t.Run("sign extend word", func(t *testing.T) {
		defer c.reset()

		i16 := &btf.Int{Name: "short", Size: 2, Encoding: btf.Signed}
		val := newMaterialized(r8, i16)

		c.adjustRegisterSize(val)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.LSh.Imm(r8, 48),
			asm.ArSh.Imm(r8, 48),
		})
	})

	t.Run("adjust to dword", func(t *testing.T) {
		defer c.reset()

		u32 := getU32Btf(t)
		val := newMaterialized(r8, u32)

		c.adjustRegisterSize(val)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.LSh.Imm(r8, 32),
			asm.RSh.Imm(r8, 32),
		})
	})

	t.Run("sign extend dword", func(t *testing.T) {
		defer c.reset()

		i32 := &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}
		val := newMaterialized(r8, i32)

		c.adjustRegisterSize(val)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.LSh.Imm(r8, 32),
			asm.ArSh.Imm(r8, 32),
		})
	})
}
