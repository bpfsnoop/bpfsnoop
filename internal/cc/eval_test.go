// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"errors"
	"reflect"
	"testing"

	"github.com/bpfsnoop/bpfsnoop/internal/test"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"rsc.io/c2go/cc"
)

func TestEvalValue(t *testing.T) {
	tests := []struct {
		name string
		eval evalValue
		exp  string
	}{
		{
			name: "num",
			eval: evalValue{
				typ: evalValueTypeNum,
				num: 123,
			},
			exp: "123",
		},
		{
			name: "btf",
			eval: evalValue{
				typ: evalValueTypeRegBtf,
				reg: asm.R9,
				btf: getSkbBtf(t),
			},
			exp: `r9(Pointer[target=Struct:"sk_buff"])`,
		},
		{
			name: "enum",
			eval: evalValue{
				typ:  evalValueTypeEnumMaybe,
				name: "BPF_PROG_TYPE_XDP",
			},
			exp: "BPF_PROG_TYPE_XDP",
		},
		{
			name: "unknown",
			eval: evalValue{
				typ: -1,
			},
			exp: "unspecified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			test.AssertEqual(t, tt.eval.String(), tt.exp)
		})
	}
}

func TestExtractEnum(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("not enum", func(t *testing.T) {
		_, err := c.extractEnum(&btf.Int{}, "")
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "type Int[unsigned size=0] is not an enum")
	})

	t.Run("valid enum", func(t *testing.T) {
		progType := getBpfProgTypeBtf(t)
		enum, err := c.extractEnum(progType, "BPF_PROG_TYPE_XDP")
		test.AssertNoErr(t, err)
		test.AssertEqual(t, enum, 6)
	})

	t.Run("invalid enum", func(t *testing.T) {
		progType := getBpfProgTypeBtf(t)
		_, err := c.extractEnum(progType, "BPF_PROG_TYPE_INVALID")
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "enum 'BPF_PROG_TYPE_INVALID' not found in type")
	})
}

func TestAdjustNum(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("not reg", func(t *testing.T) {
		n := c.adjustNum(-1, evalValue{})
		test.AssertEqual(t, n, -1)
	})

	t.Run("bitfield", func(t *testing.T) {
		n := c.adjustNum(0b1101, evalValue{
			typ: evalValueTypeRegBtf,
			mem: &btf.Member{
				BitfieldSize: 3,
			},
		})
		test.AssertEqual(t, n, 0b101)
	})

	t.Run("u8", func(t *testing.T) {
		u8, err := c.kernelBtf.AnyTypeByName("__u8")
		test.AssertNoErr(t, err)

		n := c.adjustNum(257, evalValue{
			typ: evalValueTypeRegBtf,
			btf: u8,
		})
		test.AssertEqual(t, n, 1)
	})

	t.Run("u16", func(t *testing.T) {
		u16, err := c.kernelBtf.AnyTypeByName("__u16")
		test.AssertNoErr(t, err)

		n := c.adjustNum(0x12345678, evalValue{
			typ: evalValueTypeRegBtf,
			btf: u16,
		})
		test.AssertEqual(t, n, 0x5678)
	})

	t.Run("u32", func(t *testing.T) {
		u32, err := c.kernelBtf.AnyTypeByName("__u32")
		test.AssertNoErr(t, err)

		n := c.adjustNum(0x12345678, evalValue{
			typ: evalValueTypeRegBtf,
			btf: u32,
		})
		test.AssertEqual(t, n, 0x12345678)
	})

	t.Run("u64", func(t *testing.T) {
		u64, err := c.kernelBtf.AnyTypeByName("__u64")
		test.AssertNoErr(t, err)

		n := c.adjustNum(0x12345678, evalValue{
			typ: evalValueTypeRegBtf,
			btf: u64,
		})
		test.AssertEqual(t, n, 0x12345678)
	})
}

func TestPreHandleBinaryOp(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("a.btf cannot be calculated", func(t *testing.T) {
		skb, err := c.kernelBtf.AnyTypeByName("sk_buff")
		test.AssertNoErr(t, err)

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = skb

		a, b, err = c.preHandleBinaryOp(a, b)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "disallow type")
	})

	t.Run("b.btf cannot be calculated", func(t *testing.T) {
		skb, err := c.kernelBtf.AnyTypeByName("sk_buff")
		test.AssertNoErr(t, err)

		var a, b evalValue
		b.typ = evalValueTypeRegBtf
		b.btf = skb

		a, b, err = c.preHandleBinaryOp(a, b)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "disallow type")
	})

	t.Run("a is invalid enum", func(t *testing.T) {
		progType := getBpfProgTypeBtf(t)

		var a, b evalValue
		a.typ = evalValueTypeEnumMaybe
		a.name = "BPF_PROG_TYPE_NONE"
		b.typ = evalValueTypeRegBtf
		b.btf = progType

		a, b, err := c.preHandleBinaryOp(a, b)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "failed to extract enum")
	})

	t.Run("a is valid enum", func(t *testing.T) {
		progType := getBpfProgTypeBtf(t)

		var a, b evalValue
		a.typ = evalValueTypeEnumMaybe
		a.name = "BPF_PROG_TYPE_XDP"
		b.typ = evalValueTypeRegBtf
		b.btf = progType

		a, b, err := c.preHandleBinaryOp(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, a.typ, evalValueTypeNum)
		test.AssertEqual(t, a.num, 6)
	})

	t.Run("b is invalid enum", func(t *testing.T) {
		progType := getBpfProgTypeBtf(t)

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = progType
		b.typ = evalValueTypeEnumMaybe
		b.name = "BPF_PROG_TYPE_NONE"

		a, b, err := c.preHandleBinaryOp(a, b)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "failed to extract enum")
	})

	t.Run("b is valid enum", func(t *testing.T) {
		progType := getBpfProgTypeBtf(t)

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = progType
		b.typ = evalValueTypeEnumMaybe
		b.name = "BPF_PROG_TYPE_XDP"

		a, b, err := c.preHandleBinaryOp(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, b.typ, evalValueTypeNum)
		test.AssertEqual(t, b.num, 6)
	})

	t.Run("not enum", func(t *testing.T) {
		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = getSkbBtf(t)
		b.typ = evalValueTypeRegBtf
		b.btf = getBpfProgBtf(t)

		a, b, err := c.preHandleBinaryOp(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, a.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, b.typ, evalValueTypeRegBtf)
	})
}

func TestAdd(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("failed to pre-handle", func(t *testing.T) {
		skb, err := c.kernelBtf.AnyTypeByName("sk_buff")
		test.AssertNoErr(t, err)

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = skb

		a, err = c.add(a, b)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "disallow type")
	})

	t.Run("num + num", func(t *testing.T) {
		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 123
		b.typ = evalValueTypeNum
		b.num = 456

		res, err := c.add(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeNum)
		test.AssertEqual(t, res.num, 123+456)
	})

	t.Run("reg(ptr) + reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.reg, _ = c.regalloc.Alloc()
		a.btf = getSkbBtf(t)
		b.typ = evalValueTypeRegBtf
		b.reg, _ = c.regalloc.Alloc()
		b.btf = getU64Btf(t)

		size, _ := btf.Sizeof(a.btf.(*btf.Pointer).Target)

		res, err := c.add(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertFalse(t, c.regalloc.IsUsed(b.reg))
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Mul.Imm(b.reg, int32(size)),
			asm.Add.Reg(a.reg, b.reg),
		})
	})

	t.Run("reg(array) + reg", func(t *testing.T) {
		expr, err := cc.ParseExpr("skb->cb")
		test.AssertNoErr(t, err)

		defer c.reset()

		a, err := c.access(expr)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, a.typ, evalValueTypeRegBtf)

		var b evalValue
		b.typ = evalValueTypeRegBtf
		b.reg, _ = c.regalloc.Alloc()
		b.btf = getU64Btf(t)

		size, _ := btf.Sizeof(getU8Btf(t))

		res, err := c.add(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertFalse(t, c.regalloc.IsUsed(b.reg))
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.LoadMem(asm.R8, asm.R9, 0, asm.DWord),
			asm.Add.Imm(asm.R8, 40),
			asm.Mul.Imm(b.reg, int32(size)),
			asm.Add.Reg(a.reg, b.reg),
		})
	})

	t.Run("num(0) + reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeNum
		b.typ = evalValueTypeRegBtf
		b.btf = getSkbBtf(t)
		b.reg, _ = c.regalloc.Alloc()

		res, err := c.add(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, b.reg)
	})

	t.Run("num(1) + reg(void *)", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 1
		b.typ = evalValueTypeRegBtf
		b.btf = &btf.Pointer{Target: &btf.Void{}}
		b.reg, _ = c.regalloc.Alloc()

		res, err := c.add(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, b.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Add.Imm(b.reg, 1),
		})
	})

	t.Run("num(1) + reg(func *)", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 1
		b.typ = evalValueTypeRegBtf
		b.btf = &btf.Pointer{Target: &btf.FuncProto{}}
		b.reg, _ = c.regalloc.Alloc()

		_, err := c.add(a, b)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "disallow type")
	})

	t.Run("num(1) + reg(struct bpf_map *)", func(t *testing.T) {
		defer c.reset()

		bpfMap, err := c.kernelBtf.AnyTypeByName("bpf_map")
		test.AssertNoErr(t, err)

		size, _ := btf.Sizeof(bpfMap)

		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 1
		b.typ = evalValueTypeRegBtf
		b.btf = &btf.Pointer{Target: bpfMap}
		b.reg, _ = c.regalloc.Alloc()

		res, err := c.add(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, b.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Add.Imm(b.reg, int32(size)),
		})
	})

	t.Run("num(1) + reg(array[void])", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 1
		b.typ = evalValueTypeRegBtf
		b.btf = &btf.Array{
			Index:  getU8Btf(t),
			Type:   &btf.Void{},
			Nelems: 10,
		}
		b.reg, _ = c.regalloc.Alloc()

		_, err := c.add(a, b)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "disallow type")
	})

	t.Run("num(1) + reg(array[struct bpf_map *])", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 1
		b.typ = evalValueTypeRegBtf
		b.btf = &btf.Array{
			Index:  getU8Btf(t),
			Type:   getBpfMapBtf(t),
			Nelems: 10,
		}
		b.reg, _ = c.regalloc.Alloc()

		res, err := c.add(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, b.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Add.Imm(b.reg, 8),
		})
	})

	t.Run("num(1) + reg(u64)", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 1
		b.typ = evalValueTypeRegBtf
		b.btf = getU64Btf(t)
		b.reg, _ = c.regalloc.Alloc()

		res, err := c.add(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, b.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Add.Imm(b.reg, 1),
		})
	})

	t.Run("reg + num(0)", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeNum
		b.num = 0

		res, err := c.add(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertEmptySlice(t, c.insns)
	})

	t.Run("reg(void *) + num(1)", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = &btf.Pointer{Target: &btf.Void{}}
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeNum
		b.num = 1

		res, err := c.add(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Add.Imm(a.reg, 1),
		})
	})

	t.Run("reg(func *) + num(1)", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = &btf.Pointer{Target: &btf.FuncProto{}}
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeNum
		b.num = 1

		_, err := c.add(a, b)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "disallow type")
	})

	t.Run("reg(struct bpf_map *) + num(1)", func(t *testing.T) {
		defer c.reset()

		bpfMap, err := c.kernelBtf.AnyTypeByName("bpf_map")
		test.AssertNoErr(t, err)

		size, _ := btf.Sizeof(bpfMap)

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = &btf.Pointer{Target: bpfMap}
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeNum
		b.num = 1

		res, err := c.add(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Add.Imm(a.reg, int32(size)),
		})
	})

	t.Run("reg(array[void]) + num(1)", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = &btf.Array{
			Index:  getU8Btf(t),
			Type:   &btf.Void{},
			Nelems: 10,
		}
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeNum
		b.num = 1

		_, err := c.add(a, b)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "disallow type")
	})

	t.Run("reg(array[struct bpf_map *]) + num(1)", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = &btf.Array{
			Index:  getU8Btf(t),
			Type:   getBpfMapBtf(t),
			Nelems: 10,
		}
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeNum
		b.num = 1

		res, err := c.add(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Add.Imm(a.reg, 8),
		})
	})

	t.Run("reg(u64) + num(1)", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = getU64Btf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeNum
		b.num = 1

		res, err := c.add(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Add.Imm(a.reg, 1),
		})
	})

	t.Run("not implemented", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeUnspec
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeRegBtf
		b.btf = getU8Btf(t)
		b.reg, _ = c.regalloc.Alloc()

		_, err := c.add(a, b)
		test.AssertHaveErr(t, err)
		test.AssertTrue(t, errors.Is(err, ErrNotImplemented))
	})
}

func TestAnd(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("failed to pre-handle", func(t *testing.T) {
		skb, err := c.kernelBtf.AnyTypeByName("sk_buff")
		test.AssertNoErr(t, err)

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = skb

		_, err = c.and(a, b)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "disallow type")
	})

	t.Run("num & num", func(t *testing.T) {
		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 123
		b.typ = evalValueTypeNum
		b.num = 456

		res, err := c.and(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeNum)
		test.AssertEqual(t, res.num, 123&456)
	})

	t.Run("reg & reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.reg, _ = c.regalloc.Alloc()
		a.btf = getSkbBtf(t)
		b.typ = evalValueTypeRegBtf
		b.reg, _ = c.regalloc.Alloc()
		b.btf = getU64Btf(t)

		res, err := c.and(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertFalse(t, c.regalloc.IsUsed(b.reg))
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.And.Reg(a.reg, b.reg),
		})
	})

	t.Run("num & reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 123
		b.typ = evalValueTypeRegBtf
		b.btf = getSkbBtf(t)
		b.reg, _ = c.regalloc.Alloc()

		res, err := c.and(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, b.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.And.Imm(b.reg, 123),
		})
	})

	t.Run("reg & num", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeNum
		b.num = 123

		res, err := c.and(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.And.Imm(a.reg, 123),
		})
	})

	t.Run("not implemented", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeUnspec
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeRegBtf
		b.btf = getU8Btf(t)
		b.reg, _ = c.regalloc.Alloc()

		_, err := c.and(a, b)
		test.AssertHaveErr(t, err)
		test.AssertTrue(t, errors.Is(err, ErrNotImplemented))
	})
}

func TestAndand(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("failed to pre-handle", func(t *testing.T) {
		skb, err := c.kernelBtf.AnyTypeByName("sk_buff")
		test.AssertNoErr(t, err)

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = skb

		_, err = c.andand(a, b)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "disallow type")
	})

	t.Run("num(123) && num(456)", func(t *testing.T) {
		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 123
		b.typ = evalValueTypeNum
		b.num = 456

		res, err := c.andand(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeNum)
		test.AssertEqual(t, res.num, 1)
	})

	t.Run("num(0) && num(0)", func(t *testing.T) {
		var a, b evalValue
		a.typ = evalValueTypeNum
		b.typ = evalValueTypeNum

		res, err := c.andand(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeNum)
		test.AssertEqual(t, res.num, 0)
	})

	t.Run("reg && reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.reg, _ = c.regalloc.Alloc()
		a.btf = getSkbBtf(t)
		b.typ = evalValueTypeRegBtf
		b.reg, _ = c.regalloc.Alloc()
		b.btf = getU64Btf(t)

		res, err := c.andand(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertFalse(t, c.regalloc.IsUsed(b.reg))
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			JmpOff(asm.JEq, a.reg, 0, 3),
			JmpOff(asm.JEq, b.reg, 0, 2),
			asm.Mov.Imm(a.reg, 1),
			Ja(1),
			asm.Xor.Reg(a.reg, a.reg),
		})
	})

	t.Run("num(0) && reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 0
		b.typ = evalValueTypeRegBtf
		b.btf = getSkbBtf(t)
		b.reg, _ = c.regalloc.Alloc()

		res, err := c.andand(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeNum)
		test.AssertEqual(t, res.num, 0)
		test.AssertFalse(t, c.regalloc.IsUsed(b.reg))
		test.AssertEmptySlice(t, c.insns)
	})

	t.Run("num(1) && reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 1
		b.typ = evalValueTypeRegBtf
		b.btf = getSkbBtf(t)
		b.reg, _ = c.regalloc.Alloc()

		res, err := c.andand(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, b.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			JmpOff(asm.JEq, b.reg, 0, 2),
			asm.Mov.Imm(b.reg, 1),
			Ja(1),
			asm.Xor.Reg(b.reg, b.reg),
		})
	})

	t.Run("reg && num(0)", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeNum
		b.num = 0

		res, err := c.andand(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeNum)
		test.AssertEqual(t, res.num, 0)
		test.AssertFalse(t, c.regalloc.IsUsed(a.reg))
		test.AssertEmptySlice(t, c.insns)
	})

	t.Run("reg && num(1)", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeNum
		b.num = 1

		res, err := c.andand(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			JmpOff(asm.JEq, a.reg, 0, 2),
			asm.Mov.Imm(a.reg, 1),
			Ja(1),
			asm.Xor.Reg(a.reg, a.reg),
		})
	})

	t.Run("not implemented", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeUnspec
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeRegBtf
		b.btf = getU8Btf(t)
		b.reg, _ = c.regalloc.Alloc()

		_, err := c.andand(a, b)
		test.AssertHaveErr(t, err)
		test.AssertTrue(t, errors.Is(err, ErrNotImplemented))
	})
}

func TestCond(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("invalid cond", func(t *testing.T) {
		skb, err := c.kernelBtf.AnyTypeByName("sk_buff")
		test.AssertNoErr(t, err)

		var cond, a, b evalValue
		cond.typ = evalValueTypeRegBtf
		cond.btf = skb

		_, err = c.cond(cond, a, b)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "disallow type")
	})

	t.Run("invalid first value", func(t *testing.T) {
		skb, err := c.kernelBtf.AnyTypeByName("sk_buff")
		test.AssertNoErr(t, err)

		var cond, a, b evalValue
		cond.typ = evalValueTypeNum
		a.typ = evalValueTypeRegBtf
		a.btf = skb

		_, err = c.cond(cond, a, b)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "disallow type")
	})

	t.Run("invalid second value", func(t *testing.T) {
		skb, err := c.kernelBtf.AnyTypeByName("sk_buff")
		test.AssertNoErr(t, err)

		var cond, a, b evalValue
		cond.typ = evalValueTypeNum
		a.typ = evalValueTypeNum
		b.typ = evalValueTypeRegBtf
		b.btf = skb

		_, err = c.cond(cond, a, b)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "disallow type")
	})

	t.Run("num(1) ? a : b", func(t *testing.T) {
		var cond, a, b evalValue
		cond.typ = evalValueTypeNum
		cond.num = 1
		a.typ = evalValueTypeNum
		a.num = 123
		b.typ = evalValueTypeNum
		b.num = 456

		res, err := c.cond(cond, a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeNum)
		test.AssertEqual(t, res.num, 123)
	})

	t.Run("num(0) ? a : b", func(t *testing.T) {
		var cond, a, b evalValue
		cond.typ = evalValueTypeNum
		cond.num = 0
		a.typ = evalValueTypeNum
		a.num = 123
		b.typ = evalValueTypeNum
		b.num = 456

		res, err := c.cond(cond, a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeNum)
		test.AssertEqual(t, res.num, 456)
	})

	t.Run("reg ? num(123) : num(456)", func(t *testing.T) {
		defer c.reset()

		var cond, a, b evalValue
		cond.typ = evalValueTypeRegBtf
		cond.reg, _ = c.regalloc.Alloc()
		cond.btf = getSkbBtf(t)
		a.typ = evalValueTypeNum
		a.num = 123
		b.typ = evalValueTypeNum
		b.num = 456

		res, err := c.cond(cond, a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, cond.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			JmpOff(asm.JEq, cond.reg, 0, 2),
			asm.Mov.Imm(cond.reg, 123),
			Ja(1),
			asm.Mov.Imm(cond.reg, 456),
		})
	})

	t.Run("reg ? reg : reg", func(t *testing.T) {
		defer c.reset()

		var cond, a, b evalValue
		cond.typ = evalValueTypeRegBtf
		cond.reg, _ = c.regalloc.Alloc()
		cond.btf = getSkbBtf(t)
		a.typ = evalValueTypeRegBtf
		a.reg, _ = c.regalloc.Alloc()
		a.btf = getU64Btf(t)
		b.typ = evalValueTypeRegBtf
		b.reg, _ = c.regalloc.Alloc()
		b.btf = getU8Btf(t)

		res, err := c.cond(cond, a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, cond.reg)
		test.AssertFalse(t, c.regalloc.IsUsed(a.reg))
		test.AssertFalse(t, c.regalloc.IsUsed(b.reg))
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			JmpOff(asm.JEq, cond.reg, 0, 2),
			asm.Mov.Reg(cond.reg, a.reg),
			Ja(1),
			asm.Mov.Reg(cond.reg, b.reg),
		})
	})
}

func TestDiv(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("failed to pre-handle", func(t *testing.T) {
		skb, err := c.kernelBtf.AnyTypeByName("sk_buff")
		test.AssertNoErr(t, err)

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = skb

		_, err = c.div(a, b)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "disallow type")
	})

	t.Run("x / num(0)", func(t *testing.T) {
		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 123
		b.typ = evalValueTypeNum
		b.num = 0

		_, err := c.div(a, b)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "division by zero")
	})

	t.Run("num(456) / num(123)", func(t *testing.T) {
		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 456
		b.typ = evalValueTypeNum
		b.num = 123

		res, err := c.div(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeNum)
		test.AssertEqual(t, res.num, 456/123)
	})

	t.Run("num(456) / reg, no available reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 456
		b.typ = evalValueTypeRegBtf
		b.btf = getSkbBtf(t)
		b.reg, _ = c.regalloc.Alloc()

		for i := range c.regalloc.registers[:] {
			c.regalloc.registers[i] = true
		}

		_, err := c.div(a, b)
		test.AssertHaveErr(t, err)
		test.AssertTrue(t, errors.Is(err, ErrRegisterNotEnough))
	})

	t.Run("num(456) / reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 456
		b.typ = evalValueTypeRegBtf
		b.btf = getSkbBtf(t)
		b.reg, _ = c.regalloc.Alloc()

		res, err := c.div(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertFalse(t, c.regalloc.IsUsed(b.reg))
		test.AssertEqual(t, res.reg, asm.R7)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			JmpOff(asm.JEq, b.reg, 0, 2),
			asm.Mov.Imm(asm.R7, 0),
			Ja(2),
			asm.Mov.Imm(asm.R7, 456),
			asm.Div.Reg(asm.R7, b.reg),
		})
	})

	t.Run("reg / num(123)", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeNum
		b.num = 123

		res, err := c.div(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Div.Imm(a.reg, 123),
		})
	})

	t.Run("reg / reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.reg, _ = c.regalloc.Alloc()
		a.btf = getSkbBtf(t)
		b.typ = evalValueTypeRegBtf
		b.reg, _ = c.regalloc.Alloc()
		b.btf = getU64Btf(t)

		res, err := c.div(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertFalse(t, c.regalloc.IsUsed(b.reg))
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			JmpOff(asm.JEq, b.reg, 0, 2),
			asm.Mov.Imm(a.reg, 0),
			Ja(1),
			asm.Div.Reg(a.reg, b.reg),
		})
	})

	t.Run("not implemented", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeUnspec
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeRegBtf
		b.btf = getU8Btf(t)
		b.reg, _ = c.regalloc.Alloc()

		_, err := c.div(a, b)
		test.AssertHaveErr(t, err)
		test.AssertTrue(t, errors.Is(err, ErrNotImplemented))
	})
}

func TestEqeq(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("failed to pre-handle", func(t *testing.T) {
		skb, err := c.kernelBtf.AnyTypeByName("sk_buff")
		test.AssertNoErr(t, err)

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = skb

		_, err = c.eqeq(a, b)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "disallow type")
	})

	t.Run("num == num", func(t *testing.T) {
		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 123
		b.typ = evalValueTypeNum
		b.num = 456

		res, err := c.eqeq(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeNum)
		test.AssertEqual(t, res.num, 0)
	})

	t.Run("num == reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 123
		b.typ = evalValueTypeRegBtf
		b.btf = getSkbBtf(t)
		b.reg, _ = c.regalloc.Alloc()

		res, err := c.eqeq(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, b.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			JmpOff(asm.JNE, b.reg, int64(a.num), 2),
			asm.Mov.Imm(b.reg, 1),
			Ja(1),
			asm.Xor.Reg(b.reg, b.reg),
		})
	})

	t.Run("reg == num", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeNum
		b.num = 123

		res, err := c.eqeq(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			JmpOff(asm.JNE, a.reg, int64(b.num), 2),
			asm.Mov.Imm(a.reg, 1),
			Ja(1),
			asm.Xor.Reg(a.reg, a.reg),
		})
	})

	t.Run("reg == reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.reg, _ = c.regalloc.Alloc()
		a.btf = getSkbBtf(t)
		b.typ = evalValueTypeRegBtf
		b.reg, _ = c.regalloc.Alloc()
		b.btf = getU64Btf(t)

		res, err := c.eqeq(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertFalse(t, c.regalloc.IsUsed(b.reg))
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			JmpReg(asm.JNE, a.reg, b.reg, 2),
			asm.Mov.Imm(a.reg, 1),
			Ja(1),
			asm.Xor.Reg(a.reg, a.reg),
		})
	})

	t.Run("not implemented", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeUnspec
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeRegBtf
		b.btf = getU8Btf(t)
		b.reg, _ = c.regalloc.Alloc()

		_, err := c.eqeq(a, b)
		test.AssertHaveErr(t, err)
		test.AssertTrue(t, errors.Is(err, ErrNotImplemented))
	})
}

func TestGt(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("failed to pre-handle", func(t *testing.T) {
		skb, err := c.kernelBtf.AnyTypeByName("sk_buff")
		test.AssertNoErr(t, err)

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = skb

		_, err = c.gt(a, b)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "disallow type")
	})

	t.Run("num > num", func(t *testing.T) {
		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 123
		b.typ = evalValueTypeNum
		b.num = 456

		res, err := c.gt(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeNum)
		test.AssertEqual(t, res.num, 0)
	})

	t.Run("num > reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 123
		b.typ = evalValueTypeRegBtf
		b.btf = getSkbBtf(t)
		b.reg, _ = c.regalloc.Alloc()

		res, err := c.gt(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, b.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			JmpOff(asm.JLE, b.reg, int64(a.num), 2),
			asm.Mov.Imm(b.reg, 1),
			Ja(1),
			asm.Xor.Reg(b.reg, b.reg),
		})
	})

	t.Run("reg > num", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeNum
		b.num = 123

		res, err := c.gt(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			JmpOff(asm.JLE, a.reg, int64(b.num), 2),
			asm.Mov.Imm(a.reg, 1),
			Ja(1),
			asm.Xor.Reg(a.reg, a.reg),
		})
	})

	t.Run("reg > reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.reg, _ = c.regalloc.Alloc()
		a.btf = getSkbBtf(t)
		b.typ = evalValueTypeRegBtf
		b.reg, _ = c.regalloc.Alloc()
		b.btf = getU64Btf(t)

		res, err := c.gt(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertFalse(t, c.regalloc.IsUsed(b.reg))
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			JmpReg(asm.JLE, a.reg, b.reg, 2),
			asm.Mov.Imm(a.reg, 1),
			Ja(1),
			asm.Xor.Reg(a.reg, a.reg),
		})
	})

	t.Run("not implemented", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeUnspec
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeRegBtf
		b.btf = getU8Btf(t)
		b.reg, _ = c.regalloc.Alloc()

		_, err := c.gt(a, b)
		test.AssertHaveErr(t, err)
		test.AssertTrue(t, errors.Is(err, ErrNotImplemented))
	})
}

func TestGteq(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("failed to pre-handle", func(t *testing.T) {
		skb, err := c.kernelBtf.AnyTypeByName("sk_buff")
		test.AssertNoErr(t, err)

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = skb

		_, err = c.gteq(a, b)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "disallow type")
	})

	t.Run("num >= num", func(t *testing.T) {
		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 123
		b.typ = evalValueTypeNum
		b.num = 456

		res, err := c.gteq(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeNum)
		test.AssertEqual(t, res.num, 0)
	})

	t.Run("num >= reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 123
		b.typ = evalValueTypeRegBtf
		b.btf = getSkbBtf(t)
		b.reg, _ = c.regalloc.Alloc()

		res, err := c.gteq(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, b.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			JmpOff(asm.JLT, b.reg, int64(a.num), 2),
			asm.Mov.Imm(b.reg, 1),
			Ja(1),
			asm.Xor.Reg(b.reg, b.reg),
		})
	})

	t.Run("reg >= num", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeNum
		b.num = 123

		res, err := c.gteq(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			JmpOff(asm.JLT, a.reg, int64(b.num), 2),
			asm.Mov.Imm(a.reg, 1),
			Ja(1),
			asm.Xor.Reg(a.reg, a.reg),
		})
	})

	t.Run("reg >= reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.reg, _ = c.regalloc.Alloc()
		a.btf = getSkbBtf(t)
		b.typ = evalValueTypeRegBtf
		b.reg, _ = c.regalloc.Alloc()
		b.btf = getU64Btf(t)

		res, err := c.gteq(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertFalse(t, c.regalloc.IsUsed(b.reg))
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			JmpReg(asm.JLT, a.reg, b.reg, 2),
			asm.Mov.Imm(a.reg, 1),
			Ja(1),
			asm.Xor.Reg(a.reg, a.reg),
		})
	})

	t.Run("not implemented", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeUnspec
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeRegBtf
		b.btf = getU8Btf(t)
		b.reg, _ = c.regalloc.Alloc()

		_, err := c.gteq(a, b)
		test.AssertHaveErr(t, err)
		test.AssertTrue(t, errors.Is(err, ErrNotImplemented))
	})
}

func TestLsh(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("failed to pre-handle", func(t *testing.T) {
		skb, err := c.kernelBtf.AnyTypeByName("sk_buff")
		test.AssertNoErr(t, err)

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = skb

		_, err = c.lsh(a, b)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "disallow type")
	})

	t.Run("num << num", func(t *testing.T) {
		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 123
		b.typ = evalValueTypeNum
		b.num = 4

		res, err := c.lsh(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeNum)
		test.AssertEqual(t, res.num, 123<<4)
	})

	t.Run("num(0) << reg", func(t *testing.T) {
		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 0
		b.typ = evalValueTypeRegBtf
		b.btf = getSkbBtf(t)
		b.reg, _ = c.regalloc.Alloc()

		res, err := c.lsh(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeNum)
		test.AssertEqual(t, res.num, 0)
		test.AssertFalse(t, c.regalloc.IsUsed(b.reg))
		test.AssertEmptySlice(t, c.insns)
	})

	t.Run("num(123) << reg, no available reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 123
		b.typ = evalValueTypeRegBtf
		b.btf = getSkbBtf(t)
		b.reg, _ = c.regalloc.Alloc()

		for i := range c.regalloc.registers[:] {
			c.regalloc.registers[i] = true
		}

		_, err := c.lsh(a, b)
		test.AssertHaveErr(t, err)
		test.AssertTrue(t, errors.Is(err, ErrRegisterNotEnough))
	})

	t.Run("num(123) << reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 123
		b.typ = evalValueTypeRegBtf
		b.btf = getSkbBtf(t)
		b.reg, _ = c.regalloc.Alloc()

		res, err := c.lsh(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, asm.R7)
		test.AssertFalse(t, c.regalloc.IsUsed(b.reg))
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Mov.Imm(asm.R7, 123),
			asm.LSh.Reg(asm.R7, b.reg),
		})
	})

	t.Run("reg << num(-1)", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeNum
		b.num = -1

		_, err := c.lsh(a, b)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "shift count is negative")
	})

	t.Run("reg << num(0)", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeNum
		b.num = 0

		res, err := c.lsh(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertEmptySlice(t, c.insns)
	})

	t.Run("reg << num(4)", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeNum
		b.num = 4
		b.reg, _ = c.regalloc.Alloc()

		res, err := c.lsh(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.LSh.Imm(a.reg, 4),
		})
	})

	t.Run("reg << reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.reg, _ = c.regalloc.Alloc()
		a.btf = getSkbBtf(t)
		b.typ = evalValueTypeRegBtf
		b.reg, _ = c.regalloc.Alloc()
		b.btf = getU64Btf(t)

		res, err := c.lsh(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertFalse(t, c.regalloc.IsUsed(b.reg))
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			JmpOff(asm.JLE, b.reg, 0, 1),
			asm.LSh.Reg(a.reg, b.reg),
		})
	})

	t.Run("not implemented", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeUnspec
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeRegBtf
		b.btf = getU8Btf(t)
		b.reg, _ = c.regalloc.Alloc()

		_, err := c.lsh(a, b)
		test.AssertHaveErr(t, err)
		test.AssertTrue(t, errors.Is(err, ErrNotImplemented))
	})
}

func TestLt(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("failed to pre-handle", func(t *testing.T) {
		skb, err := c.kernelBtf.AnyTypeByName("sk_buff")
		test.AssertNoErr(t, err)

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = skb

		_, err = c.lt(a, b)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "disallow type")
	})

	t.Run("num < num", func(t *testing.T) {
		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 123
		b.typ = evalValueTypeNum
		b.num = 456

		res, err := c.lt(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeNum)
		test.AssertEqual(t, res.num, 1)
	})

	t.Run("num < reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 123
		b.typ = evalValueTypeRegBtf
		b.btf = getSkbBtf(t)
		b.reg, _ = c.regalloc.Alloc()

		res, err := c.lt(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, b.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			JmpOff(asm.JGE, b.reg, int64(a.num), 2),
			asm.Mov.Imm(b.reg, 1),
			Ja(1),
			asm.Xor.Reg(b.reg, b.reg),
		})
	})

	t.Run("reg < num", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeNum
		b.num = 123

		res, err := c.lt(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			JmpOff(asm.JGE, a.reg, int64(b.num), 2),
			asm.Mov.Imm(a.reg, 1),
			Ja(1),
			asm.Xor.Reg(a.reg, a.reg),
		})
	})

	t.Run("reg < reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.reg, _ = c.regalloc.Alloc()
		a.btf = getSkbBtf(t)
		b.typ = evalValueTypeRegBtf
		b.reg, _ = c.regalloc.Alloc()
		b.btf = getU64Btf(t)

		res, err := c.lt(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertFalse(t, c.regalloc.IsUsed(b.reg))
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			JmpReg(asm.JGE, a.reg, b.reg, 2),
			asm.Mov.Imm(a.reg, 1),
			Ja(1),
			asm.Xor.Reg(a.reg, a.reg),
		})
	})

	t.Run("not implemented", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeUnspec
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeRegBtf
		b.btf = getU8Btf(t)
		b.reg, _ = c.regalloc.Alloc()

		_, err := c.lt(a, b)
		test.AssertHaveErr(t, err)
		test.AssertTrue(t, errors.Is(err, ErrNotImplemented))
	})
}

func TestLteq(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("failed to pre-handle", func(t *testing.T) {
		skb, err := c.kernelBtf.AnyTypeByName("sk_buff")
		test.AssertNoErr(t, err)

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = skb

		_, err = c.lteq(a, b)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "disallow type")
	})

	t.Run("num <= num", func(t *testing.T) {
		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 123
		b.typ = evalValueTypeNum
		b.num = 456

		res, err := c.lteq(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeNum)
		test.AssertEqual(t, res.num, 1)
	})

	t.Run("num <= reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 123
		b.typ = evalValueTypeRegBtf
		b.btf = getSkbBtf(t)
		b.reg, _ = c.regalloc.Alloc()

		res, err := c.lteq(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, b.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			JmpOff(asm.JGT, b.reg, int64(a.num), 2),
			asm.Mov.Imm(b.reg, 1),
			Ja(1),
			asm.Xor.Reg(b.reg, b.reg),
		})
	})

	t.Run("reg <= num", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeNum
		b.num = 123

		res, err := c.lteq(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			JmpOff(asm.JGT, a.reg, int64(b.num), 2),
			asm.Mov.Imm(a.reg, 1),
			Ja(1),
			asm.Xor.Reg(a.reg, a.reg),
		})
	})

	t.Run("reg <= reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.reg, _ = c.regalloc.Alloc()
		a.btf = getSkbBtf(t)
		b.typ = evalValueTypeRegBtf
		b.reg, _ = c.regalloc.Alloc()
		b.btf = getU64Btf(t)

		res, err := c.lteq(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertFalse(t, c.regalloc.IsUsed(b.reg))
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			JmpReg(asm.JGT, a.reg, b.reg, 2),
			asm.Mov.Imm(a.reg, 1),
			Ja(1),
			asm.Xor.Reg(a.reg, a.reg),
		})
	})

	t.Run("not implemented", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeUnspec
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeRegBtf
		b.btf = getU8Btf(t)
		b.reg, _ = c.regalloc.Alloc()

		_, err := c.lteq(a, b)
		test.AssertHaveErr(t, err)
		test.AssertTrue(t, errors.Is(err, ErrNotImplemented))
	})
}

func TestMinus(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("-num", func(t *testing.T) {
		var a evalValue
		a.typ = evalValueTypeNum
		a.num = 123

		res, err := c.minus(a)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeNum)
		test.AssertEqual(t, res.num, -123)
	})

	t.Run("-reg", func(t *testing.T) {
		defer c.reset()

		var a evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()

		res, err := c.minus(a)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Neg.Reg(a.reg, a.reg),
		})
	})

	t.Run("not implemented", func(t *testing.T) {
		defer c.reset()

		var a evalValue
		a.typ = evalValueTypeUnspec
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()

		_, err := c.minus(a)
		test.AssertHaveErr(t, err)
		test.AssertTrue(t, errors.Is(err, ErrNotImplemented))
	})
}

func TestMod(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("failed to pre-handle", func(t *testing.T) {
		skb, err := c.kernelBtf.AnyTypeByName("sk_buff")
		test.AssertNoErr(t, err)

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = skb

		_, err = c.mod(a, b)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "disallow type")
	})

	t.Run("x % num(0)", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeNum
		b.num = 0

		_, err := c.mod(a, b)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "mod by zero")
	})

	t.Run("num(456) % num(123)", func(t *testing.T) {
		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 456
		b.typ = evalValueTypeNum
		b.num = 123

		res, err := c.mod(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeNum)
		test.AssertEqual(t, res.num, 456%123)
	})

	t.Run("num(0) % reg", func(t *testing.T) {
		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 0
		b.typ = evalValueTypeRegBtf
		b.btf = getSkbBtf(t)
		b.reg, _ = c.regalloc.Alloc()

		res, err := c.mod(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeNum)
		test.AssertEqual(t, res.num, 0)
		test.AssertFalse(t, c.regalloc.IsUsed(b.reg))
		test.AssertEmptySlice(t, c.insns)
	})

	t.Run("num(456) % reg, no available reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 456
		b.typ = evalValueTypeRegBtf
		b.btf = getSkbBtf(t)
		b.reg, _ = c.regalloc.Alloc()

		for i := range c.regalloc.registers[:] {
			c.regalloc.registers[i] = true
		}

		_, err := c.mod(a, b)
		test.AssertHaveErr(t, err)
		test.AssertTrue(t, errors.Is(err, ErrRegisterNotEnough))
	})

	t.Run("num(456) % reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 456
		b.typ = evalValueTypeRegBtf
		b.btf = getSkbBtf(t)
		b.reg, _ = c.regalloc.Alloc()

		res, err := c.mod(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, asm.R7)
		test.AssertFalse(t, c.regalloc.IsUsed(b.reg))
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Mov.Imm(asm.R7, 456),
			asm.Mod.Reg(asm.R7, b.reg),
		})
	})

	t.Run("reg % num(1)", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeNum
		b.num = 1

		res, err := c.mod(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Mov.Imm(a.reg, 0),
		})
	})

	t.Run("reg % num(123)", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeNum
		b.num = 123

		res, err := c.mod(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Mod.Imm(a.reg, 123),
		})
	})

	t.Run("reg % reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.reg, _ = c.regalloc.Alloc()
		a.btf = getSkbBtf(t)
		b.typ = evalValueTypeRegBtf
		b.reg, _ = c.regalloc.Alloc()
		b.btf = getU64Btf(t)

		res, err := c.mod(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertFalse(t, c.regalloc.IsUsed(b.reg))
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			JmpOff(asm.JEq, b.reg, 0, 1),
			asm.Mod.Reg(a.reg, b.reg),
		})
	})

	t.Run("not implemented", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeUnspec
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeRegBtf
		b.btf = getU8Btf(t)
		b.reg, _ = c.regalloc.Alloc()

		_, err := c.mod(a, b)
		test.AssertHaveErr(t, err)
		test.AssertTrue(t, errors.Is(err, ErrNotImplemented))
	})
}

func TestMul(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("failed to pre-handle", func(t *testing.T) {
		skb, err := c.kernelBtf.AnyTypeByName("sk_buff")
		test.AssertNoErr(t, err)

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = skb

		_, err = c.mul(a, b)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "disallow type")
	})

	t.Run("num * num", func(t *testing.T) {
		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 123
		b.typ = evalValueTypeNum
		b.num = 456

		res, err := c.mul(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeNum)
		test.AssertEqual(t, res.num, 123*456)
	})

	t.Run("reg * reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.reg, _ = c.regalloc.Alloc()
		a.btf = getSkbBtf(t)
		b.typ = evalValueTypeRegBtf
		b.reg, _ = c.regalloc.Alloc()
		b.btf = getU64Btf(t)

		res, err := c.mul(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertFalse(t, c.regalloc.IsUsed(b.reg))
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Mul.Reg(a.reg, b.reg),
		})
	})

	t.Run("num(0) * reg", func(t *testing.T) {
		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 0
		b.typ = evalValueTypeRegBtf
		b.btf = getSkbBtf(t)
		b.reg, _ = c.regalloc.Alloc()

		res, err := c.mul(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeNum)
		test.AssertEqual(t, res.num, 0)
		test.AssertFalse(t, c.regalloc.IsUsed(b.reg))
		test.AssertEmptySlice(t, c.insns)
	})

	t.Run("num(1) * reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 1
		b.typ = evalValueTypeRegBtf
		b.btf = getSkbBtf(t)
		b.reg, _ = c.regalloc.Alloc()

		res, err := c.mul(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, b.reg)
		test.AssertFalse(t, c.regalloc.IsUsed(a.reg))
		test.AssertEmptySlice(t, c.insns)
	})

	t.Run("num(123) * reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 123
		b.typ = evalValueTypeRegBtf
		b.btf = getSkbBtf(t)
		b.reg, _ = c.regalloc.Alloc()

		res, err := c.mul(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, asm.R8)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Mul.Imm(asm.R8, 123),
		})
	})

	t.Run("not implemented", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeUnspec
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeRegBtf
		b.btf = getU8Btf(t)
		b.reg, _ = c.regalloc.Alloc()

		_, err := c.mul(a, b)
		test.AssertHaveErr(t, err)
		test.AssertTrue(t, errors.Is(err, ErrNotImplemented))
	})
}

func TestNot(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("!num", func(t *testing.T) {
		var a evalValue
		a.typ = evalValueTypeNum
		a.num = 123

		res, err := c.not(a)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeNum)
		test.AssertEqual(t, res.num, 0)
	})

	t.Run("!reg, invalid type", func(t *testing.T) {
		defer c.reset()

		skb, err := c.kernelBtf.AnyTypeByName("sk_buff")
		test.AssertNoErr(t, err)

		var a evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = skb
		a.reg, _ = c.regalloc.Alloc()

		_, err = c.not(a)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "disallow type")
	})

	t.Run("!reg", func(t *testing.T) {
		defer c.reset()

		var a evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()

		res, err := c.not(a)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			JmpOff(asm.JNE, a.reg, 0, 2),
			asm.Mov.Imm(a.reg, 1),
			Ja(1),
			asm.Xor.Reg(a.reg, a.reg),
		})
	})

	t.Run("not implemented", func(t *testing.T) {
		defer c.reset()

		var a evalValue
		a.typ = evalValueTypeUnspec
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()

		_, err := c.not(a)
		test.AssertHaveErr(t, err)
		test.AssertTrue(t, errors.Is(err, ErrNotImplemented))
	})
}

func TestNoteq(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("failed to pre-handle", func(t *testing.T) {
		skb, err := c.kernelBtf.AnyTypeByName("sk_buff")
		test.AssertNoErr(t, err)

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = skb

		_, err = c.noteq(a, b)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "disallow type")
	})

	t.Run("num != num", func(t *testing.T) {
		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 123
		b.typ = evalValueTypeNum
		b.num = 456

		res, err := c.noteq(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeNum)
		test.AssertEqual(t, res.num, 1)
	})

	t.Run("num != reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 123
		b.typ = evalValueTypeRegBtf
		b.btf = getSkbBtf(t)
		b.reg, _ = c.regalloc.Alloc()

		res, err := c.noteq(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, b.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			JmpOff(asm.JEq, b.reg, int64(a.num), 2),
			asm.Mov.Imm(b.reg, 1),
			Ja(1),
			asm.Xor.Reg(b.reg, b.reg),
		})
	})

	t.Run("reg != num", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeNum
		b.num = 123

		res, err := c.noteq(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			JmpOff(asm.JEq, a.reg, int64(b.num), 2),
			asm.Mov.Imm(a.reg, 1),
			Ja(1),
			asm.Xor.Reg(a.reg, a.reg),
		})
	})

	t.Run("reg != reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.reg, _ = c.regalloc.Alloc()
		a.btf = getSkbBtf(t)
		b.typ = evalValueTypeRegBtf
		b.reg, _ = c.regalloc.Alloc()
		b.btf = getU64Btf(t)

		res, err := c.noteq(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertFalse(t, c.regalloc.IsUsed(b.reg))
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			JmpReg(asm.JEq, a.reg, b.reg, 2),
			asm.Mov.Imm(a.reg, 1),
			Ja(1),
			asm.Xor.Reg(a.reg, a.reg),
		})
	})

	t.Run("not implemented", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeUnspec
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeRegBtf
		b.btf = getU8Btf(t)
		b.reg, _ = c.regalloc.Alloc()

		_, err := c.noteq(a, b)
		test.AssertHaveErr(t, err)
		test.AssertTrue(t, errors.Is(err, ErrNotImplemented))
	})
}

func TestOr(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("failed to pre-handle", func(t *testing.T) {
		skb, err := c.kernelBtf.AnyTypeByName("sk_buff")
		test.AssertNoErr(t, err)

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = skb

		_, err = c.or(a, b)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "disallow type")
	})

	t.Run("num | num", func(t *testing.T) {
		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 123
		b.typ = evalValueTypeNum
		b.num = 456

		res, err := c.or(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeNum)
		test.AssertEqual(t, res.num, 123|456)
	})

	t.Run("reg | reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.reg, _ = c.regalloc.Alloc()
		a.btf = getSkbBtf(t)
		b.typ = evalValueTypeRegBtf
		b.reg, _ = c.regalloc.Alloc()
		b.btf = getU64Btf(t)

		res, err := c.or(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertFalse(t, c.regalloc.IsUsed(b.reg))
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Or.Reg(a.reg, b.reg),
		})
	})

	t.Run("num(0) | reg", func(t *testing.T) {
		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 0
		b.typ = evalValueTypeRegBtf
		b.btf = getSkbBtf(t)
		b.reg, _ = c.regalloc.Alloc()

		res, err := c.or(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeNum)
		test.AssertEqual(t, res.num, 0)
		test.AssertFalse(t, c.regalloc.IsUsed(b.reg))
		test.AssertEmptySlice(t, c.insns)
	})

	t.Run("num(1) | reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 1
		b.typ = evalValueTypeRegBtf
		b.btf = getSkbBtf(t)
		b.reg, _ = c.regalloc.Alloc()

		res, err := c.or(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, b.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Or.Imm(b.reg, 1),
		})
	})

	t.Run("reg | num(0)", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeNum
		b.num = 0

		res, err := c.or(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeNum)
		test.AssertEqual(t, res.num, 0)
		test.AssertFalse(t, c.regalloc.IsUsed(a.reg))
		test.AssertEmptySlice(t, c.insns)
	})

	t.Run("reg | num(123)", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeNum
		b.num = 123

		res, err := c.or(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Or.Imm(a.reg, 123),
		})
	})

	t.Run("not implemented", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeUnspec
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeRegBtf
		b.btf = getU8Btf(t)
		b.reg, _ = c.regalloc.Alloc()

		_, err := c.or(a, b)
		test.AssertHaveErr(t, err)
		test.AssertTrue(t, errors.Is(err, ErrNotImplemented))
	})
}

func TestOror(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("failed to pre-handle", func(t *testing.T) {
		skb, err := c.kernelBtf.AnyTypeByName("sk_buff")
		test.AssertNoErr(t, err)

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = skb

		_, err = c.oror(a, b)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "disallow type")
	})

	t.Run("num || num", func(t *testing.T) {
		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 123
		b.typ = evalValueTypeNum
		b.num = 456

		res, err := c.oror(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeNum)
		test.AssertEqual(t, res.num, 1)
	})

	t.Run("reg || reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.reg, _ = c.regalloc.Alloc()
		a.btf = getSkbBtf(t)
		b.typ = evalValueTypeRegBtf
		b.reg, _ = c.regalloc.Alloc()
		b.btf = getU64Btf(t)

		res, err := c.oror(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertFalse(t, c.regalloc.IsUsed(b.reg))
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			JmpOff(asm.JNE, a.reg, 0, 3),
			JmpOff(asm.JNE, b.reg, 0, 2),
			asm.Xor.Reg(a.reg, a.reg),
			Ja(1),
			asm.Mov.Imm(a.reg, 1),
		})
	})

	t.Run("num(1) || reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 1
		b.typ = evalValueTypeRegBtf
		b.btf = getSkbBtf(t)
		b.reg, _ = c.regalloc.Alloc()

		res, err := c.oror(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeNum)
		test.AssertEqual(t, res.num, 1)
		test.AssertFalse(t, c.regalloc.IsUsed(b.reg))
		test.AssertEmptySlice(t, c.insns)
	})

	t.Run("num(0) || reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 0
		b.typ = evalValueTypeRegBtf
		b.btf = getSkbBtf(t)
		b.reg, _ = c.regalloc.Alloc()

		res, err := c.oror(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, b.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			JmpOff(asm.JEq, b.reg, 0, 2),
			asm.Mov.Imm(b.reg, 1),
			Ja(1),
			asm.Xor.Reg(b.reg, b.reg),
		})
	})

	t.Run("reg || num(1)", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeNum
		b.num = 1

		res, err := c.oror(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeNum)
		test.AssertEqual(t, res.num, 1)
		test.AssertFalse(t, c.regalloc.IsUsed(a.reg))
		test.AssertEmptySlice(t, c.insns)
	})

	t.Run("reg || num(0)", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeNum
		b.num = 0

		res, err := c.oror(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			JmpOff(asm.JEq, a.reg, 0, 2),
			asm.Mov.Imm(a.reg, 1),
			Ja(1),
			asm.Xor.Reg(a.reg, a.reg),
		})
	})

	t.Run("not implemented", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeUnspec
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeRegBtf
		b.btf = getU8Btf(t)
		b.reg, _ = c.regalloc.Alloc()

		_, err := c.oror(a, b)
		test.AssertHaveErr(t, err)
		test.AssertTrue(t, errors.Is(err, ErrNotImplemented))
	})
}

func TestPreDec(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("num", func(t *testing.T) {
		var a evalValue
		a.typ = evalValueTypeNum
		a.num = 123

		res, err := c.preDec(a)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeNum)
		test.AssertEqual(t, res.num, 122)
	})

	t.Run("reg, invalid type", func(t *testing.T) {
		defer c.reset()

		skb, err := c.kernelBtf.AnyTypeByName("sk_buff")
		test.AssertNoErr(t, err)

		var a evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = skb

		_, err = c.preDec(a)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "disallow type")
	})

	t.Run("reg", func(t *testing.T) {
		defer c.reset()

		var a evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()

		res, err := c.preDec(a)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Sub.Imm(a.reg, 1),
		})
	})

	t.Run("not implemented", func(t *testing.T) {
		defer c.reset()

		var a evalValue
		a.typ = evalValueTypeUnspec
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()

		_, err := c.preDec(a)
		test.AssertHaveErr(t, err)
		test.AssertTrue(t, errors.Is(err, ErrNotImplemented))
	})
}

func TestPreInc(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("num", func(t *testing.T) {
		var a evalValue
		a.typ = evalValueTypeNum
		a.num = 123

		res, err := c.preInc(a)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeNum)
		test.AssertEqual(t, res.num, 124)
	})

	t.Run("reg, invalid type", func(t *testing.T) {
		defer c.reset()

		skb, err := c.kernelBtf.AnyTypeByName("sk_buff")
		test.AssertNoErr(t, err)

		var a evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = skb

		_, err = c.preInc(a)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "disallow type")
	})

	t.Run("reg", func(t *testing.T) {
		defer c.reset()

		var a evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()

		res, err := c.preInc(a)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Add.Imm(a.reg, 1),
		})
	})

	t.Run("not implemented", func(t *testing.T) {
		defer c.reset()

		var a evalValue
		a.typ = evalValueTypeUnspec
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()

		_, err := c.preInc(a)
		test.AssertHaveErr(t, err)
		test.AssertTrue(t, errors.Is(err, ErrNotImplemented))
	})
}

func TestRsh(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("failed to pre-handle", func(t *testing.T) {
		skb, err := c.kernelBtf.AnyTypeByName("sk_buff")
		test.AssertNoErr(t, err)

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = skb

		_, err = c.rsh(a, b)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "disallow type")
	})

	t.Run("num >> num", func(t *testing.T) {
		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 123
		b.typ = evalValueTypeNum
		b.num = 456

		res, err := c.rsh(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeNum)
		test.AssertEqual(t, res.num, 123>>456)
	})

	t.Run("num(0) >> reg", func(t *testing.T) {
		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 0
		b.typ = evalValueTypeRegBtf
		b.btf = getSkbBtf(t)
		b.reg, _ = c.regalloc.Alloc()

		res, err := c.rsh(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeNum)
		test.AssertEqual(t, res.num, 0)
		test.AssertFalse(t, c.regalloc.IsUsed(b.reg))
		test.AssertEmptySlice(t, c.insns)
	})

	t.Run("num(1) >> reg, no available reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 1
		b.typ = evalValueTypeRegBtf
		b.btf = getSkbBtf(t)
		b.reg, _ = c.regalloc.Alloc()

		for i := range c.regalloc.registers[:] {
			c.regalloc.registers[i] = true
		}

		_, err := c.rsh(a, b)
		test.AssertHaveErr(t, err)
		test.AssertTrue(t, errors.Is(err, ErrRegisterNotEnough))
	})

	t.Run("num(1) >> reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 1
		b.typ = evalValueTypeRegBtf
		b.btf = getSkbBtf(t)
		b.reg, _ = c.regalloc.Alloc()

		res, err := c.rsh(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, asm.R7)
		test.AssertFalse(t, c.regalloc.IsUsed(b.reg))
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Mov.Imm(asm.R7, 1),
			asm.RSh.Reg(asm.R7, b.reg),
		})
	})

	t.Run("reg >> num(-1)", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeNum
		b.num = -1

		_, err := c.rsh(a, b)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "shift count is negative")
	})

	t.Run("reg >> num(0)", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeNum
		b.num = 0

		res, err := c.rsh(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertEmptySlice(t, c.insns)
	})

	t.Run("reg >> num(1)", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeNum
		b.num = 1

		res, err := c.rsh(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.RSh.Imm(a.reg, 1),
		})
	})

	t.Run("reg >> reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.reg, _ = c.regalloc.Alloc()
		a.btf = getSkbBtf(t)
		b.typ = evalValueTypeRegBtf
		b.reg, _ = c.regalloc.Alloc()
		b.btf = getU64Btf(t)

		res, err := c.rsh(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertFalse(t, c.regalloc.IsUsed(b.reg))
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.RSh.Reg(a.reg, b.reg),
		})
	})

	t.Run("not implemented", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeUnspec
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeRegBtf
		b.btf = getU8Btf(t)
		b.reg, _ = c.regalloc.Alloc()

		_, err := c.rsh(a, b)
		test.AssertHaveErr(t, err)
		test.AssertTrue(t, errors.Is(err, ErrNotImplemented))
	})
}

func TestSub(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("failed to pre-handle", func(t *testing.T) {
		skb, err := c.kernelBtf.AnyTypeByName("sk_buff")
		test.AssertNoErr(t, err)

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = skb

		_, err = c.sub(a, b)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "disallow type")
	})

	t.Run("num - num", func(t *testing.T) {
		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 123
		b.typ = evalValueTypeNum
		b.num = 456

		res, err := c.sub(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeNum)
		test.AssertEqual(t, res.num, 123-456)
	})

	t.Run("num - reg(pointer)", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 123
		b.typ = evalValueTypeRegBtf
		b.btf = getSkbBtf(t)
		b.reg, _ = c.regalloc.Alloc()

		_, err := c.sub(a, b)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "disallow type")
	})

	t.Run("num(0) - reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 0
		b.typ = evalValueTypeRegBtf
		b.btf = getU64Btf(t)
		b.reg, _ = c.regalloc.Alloc()

		res, err := c.sub(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, b.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Neg.Reg(b.reg, b.reg),
		})
	})

	t.Run("num(1) - reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 1
		b.typ = evalValueTypeRegBtf
		b.btf = getU64Btf(t)
		b.reg, _ = c.regalloc.Alloc()

		res, err := c.sub(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, b.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Sub.Imm(b.reg, 1),
		})
	})

	t.Run("reg - num(0)", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeNum
		b.num = 0

		res, err := c.sub(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertEmptySlice(t, c.insns)
	})

	t.Run("reg(void *) - num(123)", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = &btf.Pointer{Target: &btf.Void{}}
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeNum
		b.num = 123

		res, err := c.sub(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Sub.Imm(a.reg, 123),
		})
	})

	t.Run("reg(struct bpf_map **) - num(1)", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = &btf.Pointer{Target: getBpfMapBtf(t)}
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeNum
		b.num = 1

		res, err := c.sub(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Sub.Imm(a.reg, 8),
		})
	})

	t.Run("reg(array(void)) - num(1)", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = &btf.Array{Type: &btf.Void{}, Nelems: 1}
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeNum
		b.num = 1

		_, err := c.sub(a, b)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "disallow type")
	})

	t.Run("reg(array(struct bpf_map *)) - num(1)", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = &btf.Array{Type: getBpfMapBtf(t), Nelems: 1}
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeNum
		b.num = 1

		res, err := c.sub(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Sub.Imm(a.reg, 8),
		})
	})

	t.Run("reg - num(123)", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = getU64Btf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeNum
		b.num = 123

		res, err := c.sub(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Sub.Imm(a.reg, 123),
		})
	})

	t.Run("reg(struct bpf_map **) - reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = &btf.Pointer{Target: getBpfMapBtf(t)}
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeRegBtf
		b.btf = getU64Btf(t)
		b.reg, _ = c.regalloc.Alloc()

		res, err := c.sub(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertFalse(t, c.regalloc.IsUsed(b.reg))
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Mul.Imm(b.reg, 8),
			asm.Sub.Reg(a.reg, b.reg),
		})
	})

	t.Run("reg(array(struct bpf_map *)) - reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = &btf.Array{Type: getBpfMapBtf(t), Nelems: 1}
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeRegBtf
		b.btf = getU64Btf(t)
		b.reg, _ = c.regalloc.Alloc()

		res, err := c.sub(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertFalse(t, c.regalloc.IsUsed(b.reg))
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Mul.Imm(b.reg, 8),
			asm.Sub.Reg(a.reg, b.reg),
		})
	})

	t.Run("reg - reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.reg, _ = c.regalloc.Alloc()
		a.btf = getU64Btf(t)
		b.typ = evalValueTypeRegBtf
		b.reg, _ = c.regalloc.Alloc()
		b.btf = getU8Btf(t)

		res, err := c.sub(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertFalse(t, c.regalloc.IsUsed(b.reg))
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Sub.Reg(a.reg, b.reg),
		})
	})

	t.Run("not implemented", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeUnspec
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeRegBtf
		b.btf = getU8Btf(t)
		b.reg, _ = c.regalloc.Alloc()

		_, err := c.sub(a, b)
		test.AssertHaveErr(t, err)
		test.AssertTrue(t, errors.Is(err, ErrNotImplemented))
	})
}

func TestTwid(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("num", func(t *testing.T) {
		var a evalValue
		a.typ = evalValueTypeNum
		a.num = 123

		res, err := c.twid(a)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeNum)
		test.AssertEqual(t, res.num, ^123)
	})

	t.Run("reg, invalid type", func(t *testing.T) {
		defer c.reset()

		skb, err := c.kernelBtf.AnyTypeByName("sk_buff")
		test.AssertNoErr(t, err)

		var a evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = skb

		_, err = c.twid(a)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "disallow type")
	})

	t.Run("reg", func(t *testing.T) {
		defer c.reset()

		var a evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()

		res, err := c.twid(a)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Xor.Imm(a.reg, -1),
		})
	})

	t.Run("not implemented", func(t *testing.T) {
		defer c.reset()

		var a evalValue
		a.typ = evalValueTypeUnspec
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()

		_, err := c.twid(a)
		test.AssertHaveErr(t, err)
		test.AssertTrue(t, errors.Is(err, ErrNotImplemented))
	})
}

func TestXor(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("failed to pre-handle", func(t *testing.T) {
		skb, err := c.kernelBtf.AnyTypeByName("sk_buff")
		test.AssertNoErr(t, err)

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = skb

		_, err = c.xor(a, b)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "disallow type")
	})

	t.Run("num ^ num", func(t *testing.T) {
		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 123
		b.typ = evalValueTypeNum
		b.num = 456

		res, err := c.xor(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeNum)
		test.AssertEqual(t, res.num, 123^456)
	})

	t.Run("reg ^ reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.reg, _ = c.regalloc.Alloc()
		a.btf = getSkbBtf(t)
		b.typ = evalValueTypeRegBtf
		b.reg, _ = c.regalloc.Alloc()
		b.btf = getU64Btf(t)

		res, err := c.xor(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertFalse(t, c.regalloc.IsUsed(b.reg))
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Xor.Reg(a.reg, b.reg),
		})
	})

	t.Run("num(0) ^ reg", func(t *testing.T) {
		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 0
		b.typ = evalValueTypeRegBtf
		b.btf = getSkbBtf(t)
		b.reg, _ = c.regalloc.Alloc()

		res, err := c.xor(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeNum)
		test.AssertEqual(t, res.num, 0)
		test.AssertFalse(t, c.regalloc.IsUsed(b.reg))
		test.AssertEmptySlice(t, c.insns)
	})

	t.Run("num(1) ^ reg", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeNum
		a.num = 1
		b.typ = evalValueTypeRegBtf
		b.btf = getSkbBtf(t)
		b.reg, _ = c.regalloc.Alloc()

		res, err := c.xor(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, b.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Xor.Imm(b.reg, 1),
		})
	})

	t.Run("reg ^ num(0)", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeNum
		b.num = 0

		res, err := c.xor(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeNum)
		test.AssertEqual(t, res.num, 0)
		test.AssertFalse(t, c.regalloc.IsUsed(a.reg))
		test.AssertEmptySlice(t, c.insns)
	})

	t.Run("reg ^ num(1)", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeRegBtf
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeNum
		b.num = 1

		res, err := c.xor(a, b)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, a.reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Xor.Imm(a.reg, 1),
		})
	})

	t.Run("not implemented", func(t *testing.T) {
		defer c.reset()

		var a, b evalValue
		a.typ = evalValueTypeUnspec
		a.btf = getSkbBtf(t)
		a.reg, _ = c.regalloc.Alloc()
		b.typ = evalValueTypeRegBtf
		b.btf = getU8Btf(t)
		b.reg, _ = c.regalloc.Alloc()

		_, err := c.xor(a, b)
		test.AssertHaveErr(t, err)
		test.AssertTrue(t, errors.Is(err, ErrNotImplemented))
	})
}

func TestEval(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("access", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("skb->len")
		test.AssertNoErr(t, err)

		res, err := c.eval(expr)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.LoadMem(asm.R8, asm.R9, 0, asm.DWord),
			asm.Mov.Reg(asm.R3, asm.R8),
			asm.Add.Imm(asm.R3, 112),
			asm.Mov.Imm(asm.R2, 8),
			asm.Mov.Reg(asm.R1, asm.RFP),
			asm.Add.Imm(asm.R1, -8),
			asm.FnProbeReadKernel.Call(),
			asm.LoadMem(asm.R8, asm.RFP, -8, asm.DWord),
			asm.LSh.Imm(asm.R8, 32),
			asm.RSh.Imm(asm.R8, 32),
		})
	})

	t.Run("add", func(t *testing.T) {
		t.Run("invalid left", func(t *testing.T) {
			expr, err := cc.ParseExpr("not_found->xxx + 1")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate left operand")
		})

		t.Run("invalid right", func(t *testing.T) {
			expr, err := cc.ParseExpr("1 + not_found->xxx")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate right operand")
		})

		t.Run("add", func(t *testing.T) {
			defer c.reset()

			expr, err := cc.ParseExpr("skb->len + 1")
			test.AssertNoErr(t, err)

			unsignedInt, err := c.kernelBtf.AnyTypeByName("unsigned int")
			test.AssertNoErr(t, err)

			res, err := c.eval(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
			test.AssertEqual(t, res.reg, asm.R8)
			test.AssertTrue(t, reflect.DeepEqual(res.btf, unsignedInt))
			test.AssertEqualSlice(t, c.insns, asm.Instructions{
				asm.LoadMem(asm.R8, asm.R9, 0, asm.DWord),
				asm.Mov.Reg(asm.R3, asm.R8),
				asm.Add.Imm(asm.R3, 112),
				asm.Mov.Imm(asm.R2, 8),
				asm.Mov.Reg(asm.R1, asm.RFP),
				asm.Add.Imm(asm.R1, -8),
				asm.FnProbeReadKernel.Call(),
				asm.LoadMem(asm.R8, asm.RFP, -8, asm.DWord),
				asm.LSh.Imm(asm.R8, 32),
				asm.RSh.Imm(asm.R8, 32),
				asm.Add.Imm(asm.R8, 1),
			})
		})
	})

	t.Run("and", func(t *testing.T) {
		t.Run("invalid left", func(t *testing.T) {
			expr, err := cc.ParseExpr("not_found->xxx & 1")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate left operand")
		})

		t.Run("invalid right", func(t *testing.T) {
			expr, err := cc.ParseExpr("1 & not_found->xxx")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate right operand")
		})

		t.Run("and", func(t *testing.T) {
			defer c.reset()

			expr, err := cc.ParseExpr("skb->len & 1")
			test.AssertNoErr(t, err)

			unsignedInt, err := c.kernelBtf.AnyTypeByName("unsigned int")
			test.AssertNoErr(t, err)

			res, err := c.eval(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
			test.AssertEqual(t, res.reg, asm.R8)
			test.AssertTrue(t, reflect.DeepEqual(res.btf, unsignedInt))
			test.AssertEqualSlice(t, c.insns, asm.Instructions{
				asm.LoadMem(asm.R8, asm.R9, 0, asm.DWord),
				asm.Mov.Reg(asm.R3, asm.R8),
				asm.Add.Imm(asm.R3, 112),
				asm.Mov.Imm(asm.R2, 8),
				asm.Mov.Reg(asm.R1, asm.RFP),
				asm.Add.Imm(asm.R1, -8),
				asm.FnProbeReadKernel.Call(),
				asm.LoadMem(asm.R8, asm.RFP, -8, asm.DWord),
				asm.LSh.Imm(asm.R8, 32),
				asm.RSh.Imm(asm.R8, 32),
				asm.And.Imm(asm.R8, 1),
			})
		})
	})

	t.Run("andand", func(t *testing.T) {
		t.Run("invalid left", func(t *testing.T) {
			expr, err := cc.ParseExpr("not_found->xxx && 1")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate left operand")
		})

		t.Run("invalid right", func(t *testing.T) {
			expr, err := cc.ParseExpr("1 && not_found->xxx")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate right operand")
		})

		t.Run("andand", func(t *testing.T) {
			defer c.reset()

			expr, err := cc.ParseExpr("skb->len && 1")
			test.AssertNoErr(t, err)

			unsignedInt, err := c.kernelBtf.AnyTypeByName("unsigned int")
			test.AssertNoErr(t, err)

			res, err := c.eval(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
			test.AssertEqual(t, res.reg, asm.R8)
			test.AssertTrue(t, reflect.DeepEqual(res.btf, unsignedInt))
			test.AssertEqualSlice(t, c.insns, asm.Instructions{
				asm.LoadMem(asm.R8, asm.R9, 0, asm.DWord),
				asm.Mov.Reg(asm.R3, asm.R8),
				asm.Add.Imm(asm.R3, 112),
				asm.Mov.Imm(asm.R2, 8),
				asm.Mov.Reg(asm.R1, asm.RFP),
				asm.Add.Imm(asm.R1, -8),
				asm.FnProbeReadKernel.Call(),
				asm.LoadMem(asm.R8, asm.RFP, -8, asm.DWord),
				asm.LSh.Imm(asm.R8, 32),
				asm.RSh.Imm(asm.R8, 32),
				JmpOff(asm.JEq, asm.R8, 0, 2),
				asm.Mov.Imm(asm.R8, 1),
				Ja(1),
				asm.Xor.Reg(asm.R8, asm.R8),
			})
		})
	})

	t.Run("cond", func(t *testing.T) {
		t.Run("invalid cond", func(t *testing.T) {
			expr, err := cc.ParseExpr("not_found->xxx ? 1 : 2")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate cond operand")
		})

		t.Run("invalid true", func(t *testing.T) {
			expr, err := cc.ParseExpr("1 ? not_found->xxx : 2")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate true operand")
		})

		t.Run("invalid false", func(t *testing.T) {
			expr, err := cc.ParseExpr("1 ? 2 : not_found->xxx")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate false operand")
		})

		t.Run("cond", func(t *testing.T) {
			defer c.reset()

			expr, err := cc.ParseExpr("skb->len ? 1 : 2")
			test.AssertNoErr(t, err)

			unsignedInt, err := c.kernelBtf.AnyTypeByName("unsigned int")
			test.AssertNoErr(t, err)

			res, err := c.eval(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
			test.AssertEqual(t, res.reg, asm.R8)
			test.AssertTrue(t, reflect.DeepEqual(res.btf, unsignedInt))
			test.AssertEqualSlice(t, c.insns, asm.Instructions{
				asm.LoadMem(asm.R8, asm.R9, 0, asm.DWord),
				asm.Mov.Reg(asm.R3, asm.R8),
				asm.Add.Imm(asm.R3, 112),
				asm.Mov.Imm(asm.R2, 8),
				asm.Mov.Reg(asm.R1, asm.RFP),
				asm.Add.Imm(asm.R1, -8),
				asm.FnProbeReadKernel.Call(),
				asm.LoadMem(asm.R8, asm.RFP, -8, asm.DWord),
				asm.LSh.Imm(asm.R8, 32),
				asm.RSh.Imm(asm.R8, 32),
				JmpOff(asm.JEq, asm.R8, 0, 2),
				asm.Mov.Imm(asm.R8, 1),
				Ja(1),
				asm.Mov.Imm(asm.R8, 2),
			})
		})
	})

	t.Run("div", func(t *testing.T) {
		t.Run("invalid left", func(t *testing.T) {
			expr, err := cc.ParseExpr("not_found->xxx / 1")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate left operand")
		})

		t.Run("invalid right", func(t *testing.T) {
			expr, err := cc.ParseExpr("1 / not_found->xxx")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate right operand")
		})

		t.Run("div", func(t *testing.T) {
			defer c.reset()

			expr, err := cc.ParseExpr("skb->len / 1")
			test.AssertNoErr(t, err)

			unsignedInt, err := c.kernelBtf.AnyTypeByName("unsigned int")
			test.AssertNoErr(t, err)

			res, err := c.eval(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
			test.AssertEqual(t, res.reg, asm.R8)
			test.AssertTrue(t, reflect.DeepEqual(res.btf, unsignedInt))
			test.AssertEqualSlice(t, c.insns, asm.Instructions{
				asm.LoadMem(asm.R8, asm.R9, 0, asm.DWord),
				asm.Mov.Reg(asm.R3, asm.R8),
				asm.Add.Imm(asm.R3, 112),
				asm.Mov.Imm(asm.R2, 8),
				asm.Mov.Reg(asm.R1, asm.RFP),
				asm.Add.Imm(asm.R1, -8),
				asm.FnProbeReadKernel.Call(),
				asm.LoadMem(asm.R8, asm.RFP, -8, asm.DWord),
				asm.LSh.Imm(asm.R8, 32),
				asm.RSh.Imm(asm.R8, 32),
				asm.Div.Imm(asm.R8, 1),
			})
		})
	})

	t.Run("eqeq", func(t *testing.T) {
		t.Run("invalid left", func(t *testing.T) {
			expr, err := cc.ParseExpr("not_found->xxx == 1")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate left operand")
		})

		t.Run("invalid right", func(t *testing.T) {
			expr, err := cc.ParseExpr("1 == not_found->xxx")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate right operand")
		})

		t.Run("eqeq", func(t *testing.T) {
			defer c.reset()

			expr, err := cc.ParseExpr("skb->len == 1")
			test.AssertNoErr(t, err)

			unsignedInt, err := c.kernelBtf.AnyTypeByName("unsigned int")
			test.AssertNoErr(t, err)

			res, err := c.eval(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
			test.AssertEqual(t, res.reg, asm.R8)
			test.AssertTrue(t, reflect.DeepEqual(res.btf, unsignedInt))
			test.AssertEqualSlice(t, c.insns, asm.Instructions{
				asm.LoadMem(asm.R8, asm.R9, 0, asm.DWord),
				asm.Mov.Reg(asm.R3, asm.R8),
				asm.Add.Imm(asm.R3, 112),
				asm.Mov.Imm(asm.R2, 8),
				asm.Mov.Reg(asm.R1, asm.RFP),
				asm.Add.Imm(asm.R1, -8),
				asm.FnProbeReadKernel.Call(),
				asm.LoadMem(asm.R8, asm.RFP, -8, asm.DWord),
				asm.LSh.Imm(asm.R8, 32),
				asm.RSh.Imm(asm.R8, 32),
				JmpOff(asm.JNE, asm.R8, 1, 2),
				asm.Mov.Imm(asm.R8, 1),
				Ja(1),
				asm.Xor.Reg(asm.R8, asm.R8),
			})
		})
	})

	t.Run("gt", func(t *testing.T) {
		t.Run("invalid left", func(t *testing.T) {
			expr, err := cc.ParseExpr("not_found->xxx > 1")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate left operand")
		})

		t.Run("invalid right", func(t *testing.T) {
			expr, err := cc.ParseExpr("1 > not_found->xxx")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate right operand")
		})

		t.Run("gt", func(t *testing.T) {
			defer c.reset()

			expr, err := cc.ParseExpr("skb->len > 1")
			test.AssertNoErr(t, err)

			unsignedInt, err := c.kernelBtf.AnyTypeByName("unsigned int")
			test.AssertNoErr(t, err)

			res, err := c.eval(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
			test.AssertEqual(t, res.reg, asm.R8)
			test.AssertTrue(t, reflect.DeepEqual(res.btf, unsignedInt))
			test.AssertEqualSlice(t, c.insns, asm.Instructions{
				asm.LoadMem(asm.R8, asm.R9, 0, asm.DWord),
				asm.Mov.Reg(asm.R3, asm.R8),
				asm.Add.Imm(asm.R3, 112),
				asm.Mov.Imm(asm.R2, 8),
				asm.Mov.Reg(asm.R1, asm.RFP),
				asm.Add.Imm(asm.R1, -8),
				asm.FnProbeReadKernel.Call(),
				asm.LoadMem(asm.R8, asm.RFP, -8, asm.DWord),
				asm.LSh.Imm(asm.R8, 32),
				asm.RSh.Imm(asm.R8, 32),
				JmpOff(asm.JLE, asm.R8, 1, 2),
				asm.Mov.Imm(asm.R8, 1),
				Ja(1),
				asm.Xor.Reg(asm.R8, asm.R8),
			})
		})
	})

	t.Run("gteq", func(t *testing.T) {
		t.Run("invalid left", func(t *testing.T) {
			expr, err := cc.ParseExpr("not_found->xxx >= 1")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate left operand")
		})

		t.Run("invalid right", func(t *testing.T) {
			expr, err := cc.ParseExpr("1 >= not_found->xxx")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate right operand")
		})

		t.Run("gteq", func(t *testing.T) {
			defer c.reset()

			expr, err := cc.ParseExpr("skb->len >= 1")
			test.AssertNoErr(t, err)

			unsignedInt, err := c.kernelBtf.AnyTypeByName("unsigned int")
			test.AssertNoErr(t, err)

			res, err := c.eval(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
			test.AssertEqual(t, res.reg, asm.R8)
			test.AssertTrue(t, reflect.DeepEqual(res.btf, unsignedInt))
			test.AssertEqualSlice(t, c.insns, asm.Instructions{
				asm.LoadMem(asm.R8, asm.R9, 0, asm.DWord),
				asm.Mov.Reg(asm.R3, asm.R8),
				asm.Add.Imm(asm.R3, 112),
				asm.Mov.Imm(asm.R2, 8),
				asm.Mov.Reg(asm.R1, asm.RFP),
				asm.Add.Imm(asm.R1, -8),
				asm.FnProbeReadKernel.Call(),
				asm.LoadMem(asm.R8, asm.RFP, -8, asm.DWord),
				asm.LSh.Imm(asm.R8, 32),
				asm.RSh.Imm(asm.R8, 32),
				JmpOff(asm.JLT, asm.R8, 1, 2),
				asm.Mov.Imm(asm.R8, 1),
				Ja(1),
				asm.Xor.Reg(asm.R8, asm.R8),
			})
		})
	})

	t.Run("lsh", func(t *testing.T) {
		t.Run("invalid left", func(t *testing.T) {
			expr, err := cc.ParseExpr("not_found->xxx << 1")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate left operand")
		})

		t.Run("invalid right", func(t *testing.T) {
			expr, err := cc.ParseExpr("1 << not_found->xxx")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate right operand")
		})

		t.Run("lsh", func(t *testing.T) {
			defer c.reset()

			expr, err := cc.ParseExpr("skb->len << 1")
			test.AssertNoErr(t, err)

			unsignedInt, err := c.kernelBtf.AnyTypeByName("unsigned int")
			test.AssertNoErr(t, err)

			res, err := c.eval(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
			test.AssertEqual(t, res.reg, asm.R8)
			test.AssertTrue(t, reflect.DeepEqual(res.btf, unsignedInt))
			test.AssertEqualSlice(t, c.insns, asm.Instructions{
				asm.LoadMem(asm.R8, asm.R9, 0, asm.DWord),
				asm.Mov.Reg(asm.R3, asm.R8),
				asm.Add.Imm(asm.R3, 112),
				asm.Mov.Imm(asm.R2, 8),
				asm.Mov.Reg(asm.R1, asm.RFP),
				asm.Add.Imm(asm.R1, -8),
				asm.FnProbeReadKernel.Call(),
				asm.LoadMem(asm.R8, asm.RFP, -8, asm.DWord),
				asm.LSh.Imm(asm.R8, 32),
				asm.RSh.Imm(asm.R8, 32),
				asm.LSh.Imm(asm.R8, 1),
			})
		})
	})

	t.Run("lt", func(t *testing.T) {
		t.Run("invalid left", func(t *testing.T) {
			expr, err := cc.ParseExpr("not_found->xxx < 1")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate left operand")
		})

		t.Run("invalid right", func(t *testing.T) {
			expr, err := cc.ParseExpr("1 < not_found->xxx")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate right operand")
		})

		t.Run("lt", func(t *testing.T) {
			defer c.reset()

			expr, err := cc.ParseExpr("skb->len < 1")
			test.AssertNoErr(t, err)

			unsignedInt, err := c.kernelBtf.AnyTypeByName("unsigned int")
			test.AssertNoErr(t, err)

			res, err := c.eval(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
			test.AssertEqual(t, res.reg, asm.R8)
			test.AssertTrue(t, reflect.DeepEqual(res.btf, unsignedInt))
			test.AssertEqualSlice(t, c.insns, asm.Instructions{
				asm.LoadMem(asm.R8, asm.R9, 0, asm.DWord),
				asm.Mov.Reg(asm.R3, asm.R8),
				asm.Add.Imm(asm.R3, 112),
				asm.Mov.Imm(asm.R2, 8),
				asm.Mov.Reg(asm.R1, asm.RFP),
				asm.Add.Imm(asm.R1, -8),
				asm.FnProbeReadKernel.Call(),
				asm.LoadMem(asm.R8, asm.RFP, -8, asm.DWord),
				asm.LSh.Imm(asm.R8, 32),
				asm.RSh.Imm(asm.R8, 32),
				JmpOff(asm.JGE, asm.R8, 1, 2),
				asm.Mov.Imm(asm.R8, 1),
				Ja(1),
				asm.Xor.Reg(asm.R8, asm.R8),
			})
		})
	})

	t.Run("lteq", func(t *testing.T) {
		t.Run("invalid left", func(t *testing.T) {
			expr, err := cc.ParseExpr("not_found->xxx <= 1")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate left operand")
		})

		t.Run("invalid right", func(t *testing.T) {
			expr, err := cc.ParseExpr("1 <= not_found->xxx")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate right operand")
		})

		t.Run("lteq", func(t *testing.T) {
			defer c.reset()

			expr, err := cc.ParseExpr("skb->len <= 1")
			test.AssertNoErr(t, err)

			unsignedInt, err := c.kernelBtf.AnyTypeByName("unsigned int")
			test.AssertNoErr(t, err)

			res, err := c.eval(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
			test.AssertEqual(t, res.reg, asm.R8)
			test.AssertTrue(t, reflect.DeepEqual(res.btf, unsignedInt))
			test.AssertEqualSlice(t, c.insns, asm.Instructions{
				asm.LoadMem(asm.R8, asm.R9, 0, asm.DWord),
				asm.Mov.Reg(asm.R3, asm.R8),
				asm.Add.Imm(asm.R3, 112),
				asm.Mov.Imm(asm.R2, 8),
				asm.Mov.Reg(asm.R1, asm.RFP),
				asm.Add.Imm(asm.R1, -8),
				asm.FnProbeReadKernel.Call(),
				asm.LoadMem(asm.R8, asm.RFP, -8, asm.DWord),
				asm.LSh.Imm(asm.R8, 32),
				asm.RSh.Imm(asm.R8, 32),
				JmpOff(asm.JGT, asm.R8, 1, 2),
				asm.Mov.Imm(asm.R8, 1),
				Ja(1),
				asm.Xor.Reg(asm.R8, asm.R8),
			})
		})
	})

	t.Run("minus", func(t *testing.T) {
		t.Run("invalid operand", func(t *testing.T) {
			expr, err := cc.ParseExpr("-not_found->xxx")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate operand")
		})

		t.Run("minus", func(t *testing.T) {
			defer c.reset()

			expr, err := cc.ParseExpr("-skb->len")
			test.AssertNoErr(t, err)

			unsignedInt, err := c.kernelBtf.AnyTypeByName("unsigned int")
			test.AssertNoErr(t, err)

			res, err := c.eval(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
			test.AssertEqual(t, res.reg, asm.R8)
			test.AssertTrue(t, reflect.DeepEqual(res.btf, unsignedInt))
			test.AssertEqualSlice(t, c.insns, asm.Instructions{
				asm.LoadMem(asm.R8, asm.R9, 0, asm.DWord),
				asm.Mov.Reg(asm.R3, asm.R8),
				asm.Add.Imm(asm.R3, 112),
				asm.Mov.Imm(asm.R2, 8),
				asm.Mov.Reg(asm.R1, asm.RFP),
				asm.Add.Imm(asm.R1, -8),
				asm.FnProbeReadKernel.Call(),
				asm.LoadMem(asm.R8, asm.RFP, -8, asm.DWord),
				asm.LSh.Imm(asm.R8, 32),
				asm.RSh.Imm(asm.R8, 32),
				asm.Neg.Reg(asm.R8, asm.R8),
			})
		})
	})

	t.Run("mod", func(t *testing.T) {
		t.Run("invalid left", func(t *testing.T) {
			expr, err := cc.ParseExpr("not_found->xxx % 1")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate left operand")
		})

		t.Run("invalid right", func(t *testing.T) {
			expr, err := cc.ParseExpr("1 % not_found->xxx")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate right operand")
		})

		t.Run("mod", func(t *testing.T) {
			defer c.reset()

			expr, err := cc.ParseExpr("skb->len % 2")
			test.AssertNoErr(t, err)

			unsignedInt, err := c.kernelBtf.AnyTypeByName("unsigned int")
			test.AssertNoErr(t, err)

			res, err := c.eval(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
			test.AssertEqual(t, res.reg, asm.R8)
			test.AssertTrue(t, reflect.DeepEqual(res.btf, unsignedInt))
			test.AssertEqualSlice(t, c.insns, asm.Instructions{
				asm.LoadMem(asm.R8, asm.R9, 0, asm.DWord),
				asm.Mov.Reg(asm.R3, asm.R8),
				asm.Add.Imm(asm.R3, 112),
				asm.Mov.Imm(asm.R2, 8),
				asm.Mov.Reg(asm.R1, asm.RFP),
				asm.Add.Imm(asm.R1, -8),
				asm.FnProbeReadKernel.Call(),
				asm.LoadMem(asm.R8, asm.RFP, -8, asm.DWord),
				asm.LSh.Imm(asm.R8, 32),
				asm.RSh.Imm(asm.R8, 32),
				asm.Mod.Imm(asm.R8, 2),
			})
		})
	})

	t.Run("mul", func(t *testing.T) {
		t.Run("invalid left", func(t *testing.T) {
			expr, err := cc.ParseExpr("not_found->xxx * 1")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate left operand")
		})

		t.Run("invalid right", func(t *testing.T) {
			expr, err := cc.ParseExpr("1 * not_found->xxx")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate right operand")
		})

		t.Run("mul", func(t *testing.T) {
			defer c.reset()

			expr, err := cc.ParseExpr("skb->len * 2")
			test.AssertNoErr(t, err)

			unsignedInt, err := c.kernelBtf.AnyTypeByName("unsigned int")
			test.AssertNoErr(t, err)

			res, err := c.eval(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
			test.AssertEqual(t, res.reg, asm.R8)
			test.AssertTrue(t, reflect.DeepEqual(res.btf, unsignedInt))
			test.AssertEqualSlice(t, c.insns, asm.Instructions{
				asm.LoadMem(asm.R8, asm.R9, 0, asm.DWord),
				asm.Mov.Reg(asm.R3, asm.R8),
				asm.Add.Imm(asm.R3, 112),
				asm.Mov.Imm(asm.R2, 8),
				asm.Mov.Reg(asm.R1, asm.RFP),
				asm.Add.Imm(asm.R1, -8),
				asm.FnProbeReadKernel.Call(),
				asm.LoadMem(asm.R8, asm.RFP, -8, asm.DWord),
				asm.LSh.Imm(asm.R8, 32),
				asm.RSh.Imm(asm.R8, 32),
				asm.Mul.Imm(asm.R8, 2),
			})
		})
	})

	t.Run("name", func(t *testing.T) {
		t.Run("NULL,false", func(t *testing.T) {
			defer c.reset()

			expr, err := cc.ParseExpr("NULL")
			test.AssertNoErr(t, err)

			res, err := c.eval(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.typ, evalValueTypeNum)
			test.AssertEqual(t, res.num, 0)
		})

		t.Run("true", func(t *testing.T) {
			defer c.reset()

			expr, err := cc.ParseExpr("true")
			test.AssertNoErr(t, err)

			res, err := c.eval(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.typ, evalValueTypeNum)
			test.AssertEqual(t, res.num, 1)
		})

		t.Run("enum maybe", func(t *testing.T) {
			defer c.reset()

			expr, err := cc.ParseExpr("maybe")
			test.AssertNoErr(t, err)

			res, err := c.eval(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.typ, evalValueTypeEnumMaybe)
			test.AssertEqual(t, res.name, "maybe")
		})

		t.Run("no available register", func(t *testing.T) {
			defer c.reset()

			expr, err := cc.ParseExpr("skb")
			test.AssertNoErr(t, err)

			for i := range len(c.regalloc.registers) {
				c.regalloc.registers[i] = true
			}

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrRegisterNotEnough))
		})

		t.Run("skb", func(t *testing.T) {
			defer c.reset()

			expr, err := cc.ParseExpr("skb")
			test.AssertNoErr(t, err)

			res, err := c.eval(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
			test.AssertEqual(t, res.reg, asm.R8)
			test.AssertEqualSlice(t, c.insns, asm.Instructions{
				asm.LoadMem(asm.R8, asm.R9, 0, asm.DWord),
			})
		})
	})

	t.Run("not", func(t *testing.T) {
		t.Run("invalid operand", func(t *testing.T) {
			expr, err := cc.ParseExpr("!not_found->xxx")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate operand")
		})

		t.Run("not", func(t *testing.T) {
			defer c.reset()

			expr, err := cc.ParseExpr("!skb->len")
			test.AssertNoErr(t, err)

			unsignedInt, err := c.kernelBtf.AnyTypeByName("unsigned int")
			test.AssertNoErr(t, err)

			res, err := c.eval(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
			test.AssertEqual(t, res.reg, asm.R8)
			test.AssertTrue(t, reflect.DeepEqual(res.btf, unsignedInt))
			test.AssertEqualSlice(t, c.insns, asm.Instructions{
				asm.LoadMem(asm.R8, asm.R9, 0, asm.DWord),
				asm.Mov.Reg(asm.R3, asm.R8),
				asm.Add.Imm(asm.R3, 112),
				asm.Mov.Imm(asm.R2, 8),
				asm.Mov.Reg(asm.R1, asm.RFP),
				asm.Add.Imm(asm.R1, -8),
				asm.FnProbeReadKernel.Call(),
				asm.LoadMem(asm.R8, asm.RFP, -8, asm.DWord),
				asm.LSh.Imm(asm.R8, 32),
				asm.RSh.Imm(asm.R8, 32),
				JmpOff(asm.JNE, asm.R8, 0, 2),
				asm.Mov.Imm(asm.R8, 1),
				Ja(1),
				asm.Xor.Reg(asm.R8, asm.R8),
			})
		})
	})

	t.Run("noteq", func(t *testing.T) {
		t.Run("invalid left", func(t *testing.T) {
			expr, err := cc.ParseExpr("not_found->xxx != 1")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate left operand")
		})

		t.Run("invalid right", func(t *testing.T) {
			expr, err := cc.ParseExpr("1 != not_found->xxx")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate right operand")
		})

		t.Run("noteq", func(t *testing.T) {
			defer c.reset()

			expr, err := cc.ParseExpr("skb->len != 1")
			test.AssertNoErr(t, err)

			unsignedInt, err := c.kernelBtf.AnyTypeByName("unsigned int")
			test.AssertNoErr(t, err)

			res, err := c.eval(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
			test.AssertEqual(t, res.reg, asm.R8)
			test.AssertTrue(t, reflect.DeepEqual(res.btf, unsignedInt))
			test.AssertEqualSlice(t, c.insns, asm.Instructions{
				asm.LoadMem(asm.R8, asm.R9, 0, asm.DWord),
				asm.Mov.Reg(asm.R3, asm.R8),
				asm.Add.Imm(asm.R3, 112),
				asm.Mov.Imm(asm.R2, 8),
				asm.Mov.Reg(asm.R1, asm.RFP),
				asm.Add.Imm(asm.R1, -8),
				asm.FnProbeReadKernel.Call(),
				asm.LoadMem(asm.R8, asm.RFP, -8, asm.DWord),
				asm.LSh.Imm(asm.R8, 32),
				asm.RSh.Imm(asm.R8, 32),
				JmpOff(asm.JEq, asm.R8, 1, 2),
				asm.Mov.Imm(asm.R8, 1),
				Ja(1),
				asm.Xor.Reg(asm.R8, asm.R8),
			})
		})
	})

	t.Run("number", func(t *testing.T) {
		t.Run("invalid number", func(t *testing.T) {
			expr := &cc.Expr{
				Op:   cc.Number,
				Text: "invalid",
			}

			_, err := c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertStrPrefix(t, err.Error(), "failed to parse number")
		})

		t.Run("number", func(t *testing.T) {
			defer c.reset()

			expr := &cc.Expr{
				Op:   cc.Number,
				Text: "1",
			}

			res, err := c.eval(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.typ, evalValueTypeNum)
			test.AssertEqual(t, res.num, 1)
		})
	})

	t.Run("or", func(t *testing.T) {
		t.Run("invalid left", func(t *testing.T) {
			expr, err := cc.ParseExpr("not_found->xxx | 1")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate left operand")
		})

		t.Run("invalid right", func(t *testing.T) {
			expr, err := cc.ParseExpr("1 | not_found->xxx")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate right operand")
		})

		t.Run("or", func(t *testing.T) {
			defer c.reset()

			expr, err := cc.ParseExpr("skb->len | 1")
			test.AssertNoErr(t, err)

			unsignedInt, err := c.kernelBtf.AnyTypeByName("unsigned int")
			test.AssertNoErr(t, err)

			res, err := c.eval(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
			test.AssertEqual(t, res.reg, asm.R8)
			test.AssertTrue(t, reflect.DeepEqual(res.btf, unsignedInt))
			test.AssertEqualSlice(t, c.insns, asm.Instructions{
				asm.LoadMem(asm.R8, asm.R9, 0, asm.DWord),
				asm.Mov.Reg(asm.R3, asm.R8),
				asm.Add.Imm(asm.R3, 112),
				asm.Mov.Imm(asm.R2, 8),
				asm.Mov.Reg(asm.R1, asm.RFP),
				asm.Add.Imm(asm.R1, -8),
				asm.FnProbeReadKernel.Call(),
				asm.LoadMem(asm.R8, asm.RFP, -8, asm.DWord),
				asm.LSh.Imm(asm.R8, 32),
				asm.RSh.Imm(asm.R8, 32),
				asm.Or.Imm(asm.R8, 1),
			})
		})
	})

	t.Run("oror", func(t *testing.T) {
		t.Run("invalid left", func(t *testing.T) {
			expr, err := cc.ParseExpr("not_found->xxx || 1")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate left operand")
		})

		t.Run("invalid right", func(t *testing.T) {
			expr, err := cc.ParseExpr("1 || not_found->xxx")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate right operand")
		})

		t.Run("oror", func(t *testing.T) {
			defer c.reset()

			expr, err := cc.ParseExpr("skb->len || 0")
			test.AssertNoErr(t, err)

			unsignedInt, err := c.kernelBtf.AnyTypeByName("unsigned int")
			test.AssertNoErr(t, err)

			res, err := c.eval(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
			test.AssertEqual(t, res.reg, asm.R8)
			test.AssertTrue(t, reflect.DeepEqual(res.btf, unsignedInt))
			test.AssertEqualSlice(t, c.insns, asm.Instructions{
				asm.LoadMem(asm.R8, asm.R9, 0, asm.DWord),
				asm.Mov.Reg(asm.R3, asm.R8),
				asm.Add.Imm(asm.R3, 112),
				asm.Mov.Imm(asm.R2, 8),
				asm.Mov.Reg(asm.R1, asm.RFP),
				asm.Add.Imm(asm.R1, -8),
				asm.FnProbeReadKernel.Call(),
				asm.LoadMem(asm.R8, asm.RFP, -8, asm.DWord),
				asm.LSh.Imm(asm.R8, 32),
				asm.RSh.Imm(asm.R8, 32),
				JmpOff(asm.JEq, asm.R8, 0, 2),
				asm.Mov.Imm(asm.R8, 1),
				Ja(1),
				asm.Xor.Reg(asm.R8, asm.R8),
			})
		})
	})

	t.Run("paren", func(t *testing.T) {
		defer c.reset()

		expr, err := cc.ParseExpr("(skb->len)")
		test.AssertNoErr(t, err)

		unsignedInt, err := c.kernelBtf.AnyTypeByName("unsigned int")
		test.AssertNoErr(t, err)

		res, err := c.eval(expr)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, res.reg, asm.R8)
		test.AssertTrue(t, reflect.DeepEqual(res.btf, unsignedInt))
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.LoadMem(asm.R8, asm.R9, 0, asm.DWord),
			asm.Mov.Reg(asm.R3, asm.R8),
			asm.Add.Imm(asm.R3, 112),
			asm.Mov.Imm(asm.R2, 8),
			asm.Mov.Reg(asm.R1, asm.RFP),
			asm.Add.Imm(asm.R1, -8),
			asm.FnProbeReadKernel.Call(),
			asm.LoadMem(asm.R8, asm.RFP, -8, asm.DWord),
			asm.LSh.Imm(asm.R8, 32),
			asm.RSh.Imm(asm.R8, 32),
		})
	})

	t.Run("plus", func(t *testing.T) {
		t.Run("invalid operand", func(t *testing.T) {
			defer c.reset()

			expr, err := cc.ParseExpr("+not_found->xxx")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
		})

		t.Run("plus", func(t *testing.T) {
			defer c.reset()

			expr, err := cc.ParseExpr("+skb->len")
			test.AssertNoErr(t, err)

			unsignedInt, err := c.kernelBtf.AnyTypeByName("unsigned int")
			test.AssertNoErr(t, err)

			res, err := c.eval(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
			test.AssertEqual(t, res.reg, asm.R8)
			test.AssertTrue(t, reflect.DeepEqual(res.btf, unsignedInt))
			test.AssertEqualSlice(t, c.insns, asm.Instructions{
				asm.LoadMem(asm.R8, asm.R9, 0, asm.DWord),
				asm.Mov.Reg(asm.R3, asm.R8),
				asm.Add.Imm(asm.R3, 112),
				asm.Mov.Imm(asm.R2, 8),
				asm.Mov.Reg(asm.R1, asm.RFP),
				asm.Add.Imm(asm.R1, -8),
				asm.FnProbeReadKernel.Call(),
				asm.LoadMem(asm.R8, asm.RFP, -8, asm.DWord),
				asm.LSh.Imm(asm.R8, 32),
				asm.RSh.Imm(asm.R8, 32),
			})
		})
	})

	t.Run("pre-dec", func(t *testing.T) {
		t.Run("invalid operand", func(t *testing.T) {
			expr, err := cc.ParseExpr("--not_found->xxx")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
		})

		t.Run("pre-dec", func(t *testing.T) {
			defer c.reset()

			expr, err := cc.ParseExpr("--skb->len")
			test.AssertNoErr(t, err)

			unsignedInt, err := c.kernelBtf.AnyTypeByName("unsigned int")
			test.AssertNoErr(t, err)

			res, err := c.eval(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
			test.AssertEqual(t, res.reg, asm.R8)
			test.AssertTrue(t, reflect.DeepEqual(res.btf, unsignedInt))
			test.AssertEqualSlice(t, c.insns, asm.Instructions{
				asm.LoadMem(asm.R8, asm.R9, 0, asm.DWord),
				asm.Mov.Reg(asm.R3, asm.R8),
				asm.Add.Imm(asm.R3, 112),
				asm.Mov.Imm(asm.R2, 8),
				asm.Mov.Reg(asm.R1, asm.RFP),
				asm.Add.Imm(asm.R1, -8),
				asm.FnProbeReadKernel.Call(),
				asm.LoadMem(asm.R8, asm.RFP, -8, asm.DWord),
				asm.LSh.Imm(asm.R8, 32),
				asm.RSh.Imm(asm.R8, 32),
				asm.Sub.Imm(asm.R8, 1),
			})
		})
	})

	t.Run("pre-inc", func(t *testing.T) {
		t.Run("invalid operand", func(t *testing.T) {
			expr, err := cc.ParseExpr("++not_found->xxx")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
		})

		t.Run("pre-inc", func(t *testing.T) {
			defer c.reset()

			expr, err := cc.ParseExpr("++skb->len")
			test.AssertNoErr(t, err)

			unsignedInt, err := c.kernelBtf.AnyTypeByName("unsigned int")
			test.AssertNoErr(t, err)

			res, err := c.eval(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
			test.AssertEqual(t, res.reg, asm.R8)
			test.AssertTrue(t, reflect.DeepEqual(res.btf, unsignedInt))
			test.AssertEqualSlice(t, c.insns, asm.Instructions{
				asm.LoadMem(asm.R8, asm.R9, 0, asm.DWord),
				asm.Mov.Reg(asm.R3, asm.R8),
				asm.Add.Imm(asm.R3, 112),
				asm.Mov.Imm(asm.R2, 8),
				asm.Mov.Reg(asm.R1, asm.RFP),
				asm.Add.Imm(asm.R1, -8),
				asm.FnProbeReadKernel.Call(),
				asm.LoadMem(asm.R8, asm.RFP, -8, asm.DWord),
				asm.LSh.Imm(asm.R8, 32),
				asm.RSh.Imm(asm.R8, 32),
				asm.Add.Imm(asm.R8, 1),
			})
		})
	})

	t.Run("rsh", func(t *testing.T) {
		t.Run("invalid left", func(t *testing.T) {
			expr, err := cc.ParseExpr("not_found->xxx >> 1")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate left operand")
		})

		t.Run("invalid right", func(t *testing.T) {
			expr, err := cc.ParseExpr("1 >> not_found->xxx")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate right operand")
		})

		t.Run("rsh", func(t *testing.T) {
			defer c.reset()

			expr, err := cc.ParseExpr("skb->len >> 1")
			test.AssertNoErr(t, err)

			unsignedInt, err := c.kernelBtf.AnyTypeByName("unsigned int")
			test.AssertNoErr(t, err)

			res, err := c.eval(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
			test.AssertEqual(t, res.reg, asm.R8)
			test.AssertTrue(t, reflect.DeepEqual(res.btf, unsignedInt))
			test.AssertEqualSlice(t, c.insns, asm.Instructions{
				asm.LoadMem(asm.R8, asm.R9, 0, asm.DWord),
				asm.Mov.Reg(asm.R3, asm.R8),
				asm.Add.Imm(asm.R3, 112),
				asm.Mov.Imm(asm.R2, 8),
				asm.Mov.Reg(asm.R1, asm.RFP),
				asm.Add.Imm(asm.R1, -8),
				asm.FnProbeReadKernel.Call(),
				asm.LoadMem(asm.R8, asm.RFP, -8, asm.DWord),
				asm.LSh.Imm(asm.R8, 32),
				asm.RSh.Imm(asm.R8, 32),
				asm.RSh.Imm(asm.R8, 1),
			})
		})
	})

	t.Run("sub", func(t *testing.T) {
		t.Run("invalid left", func(t *testing.T) {
			expr, err := cc.ParseExpr("not_found->xxx - 1")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate left operand")
		})

		t.Run("invalid right", func(t *testing.T) {
			expr, err := cc.ParseExpr("1 - not_found->xxx")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate right operand")
		})

		t.Run("sub", func(t *testing.T) {
			defer c.reset()

			expr, err := cc.ParseExpr("skb->len - 2")
			test.AssertNoErr(t, err)

			unsignedInt, err := c.kernelBtf.AnyTypeByName("unsigned int")
			test.AssertNoErr(t, err)

			res, err := c.eval(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
			test.AssertEqual(t, res.reg, asm.R8)
			test.AssertTrue(t, reflect.DeepEqual(res.btf, unsignedInt))
			test.AssertEqualSlice(t, c.insns, asm.Instructions{
				asm.LoadMem(asm.R8, asm.R9, 0, asm.DWord),
				asm.Mov.Reg(asm.R3, asm.R8),
				asm.Add.Imm(asm.R3, 112),
				asm.Mov.Imm(asm.R2, 8),
				asm.Mov.Reg(asm.R1, asm.RFP),
				asm.Add.Imm(asm.R1, -8),
				asm.FnProbeReadKernel.Call(),
				asm.LoadMem(asm.R8, asm.RFP, -8, asm.DWord),
				asm.LSh.Imm(asm.R8, 32),
				asm.RSh.Imm(asm.R8, 32),
				asm.Sub.Imm(asm.R8, 2),
			})
		})
	})

	t.Run("twid", func(t *testing.T) {
		t.Run("invalid operand", func(t *testing.T) {
			expr, err := cc.ParseExpr("~not_found->xxx")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate operand")
		})

		t.Run("twid", func(t *testing.T) {
			defer c.reset()

			expr, err := cc.ParseExpr("~skb->len")
			test.AssertNoErr(t, err)

			unsignedInt, err := c.kernelBtf.AnyTypeByName("unsigned int")
			test.AssertNoErr(t, err)

			res, err := c.eval(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
			test.AssertEqual(t, res.reg, asm.R8)
			test.AssertTrue(t, reflect.DeepEqual(res.btf, unsignedInt))
			test.AssertEqualSlice(t, c.insns, asm.Instructions{
				asm.LoadMem(asm.R8, asm.R9, 0, asm.DWord),
				asm.Mov.Reg(asm.R3, asm.R8),
				asm.Add.Imm(asm.R3, 112),
				asm.Mov.Imm(asm.R2, 8),
				asm.Mov.Reg(asm.R1, asm.RFP),
				asm.Add.Imm(asm.R1, -8),
				asm.FnProbeReadKernel.Call(),
				asm.LoadMem(asm.R8, asm.RFP, -8, asm.DWord),
				asm.LSh.Imm(asm.R8, 32),
				asm.RSh.Imm(asm.R8, 32),
				asm.Xor.Imm(asm.R8, -1),
			})
		})
	})

	t.Run("xor", func(t *testing.T) {
		t.Run("invalid left", func(t *testing.T) {
			expr, err := cc.ParseExpr("not_found->xxx ^ 1")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate left operand")
		})

		t.Run("invalid right", func(t *testing.T) {
			expr, err := cc.ParseExpr("1 ^ not_found->xxx")
			test.AssertNoErr(t, err)

			_, err = c.eval(expr)
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to evaluate right operand")
		})

		t.Run("xor", func(t *testing.T) {
			defer c.reset()

			expr, err := cc.ParseExpr("skb->len ^ 1")
			test.AssertNoErr(t, err)

			unsignedInt, err := c.kernelBtf.AnyTypeByName("unsigned int")
			test.AssertNoErr(t, err)

			res, err := c.eval(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.typ, evalValueTypeRegBtf)
			test.AssertEqual(t, res.reg, asm.R8)
			test.AssertTrue(t, reflect.DeepEqual(res.btf, unsignedInt))
			test.AssertEqualSlice(t, c.insns, asm.Instructions{
				asm.LoadMem(asm.R8, asm.R9, 0, asm.DWord),
				asm.Mov.Reg(asm.R3, asm.R8),
				asm.Add.Imm(asm.R3, 112),
				asm.Mov.Imm(asm.R2, 8),
				asm.Mov.Reg(asm.R1, asm.RFP),
				asm.Add.Imm(asm.R1, -8),
				asm.FnProbeReadKernel.Call(),
				asm.LoadMem(asm.R8, asm.RFP, -8, asm.DWord),
				asm.LSh.Imm(asm.R8, 32),
				asm.RSh.Imm(asm.R8, 32),
				asm.Xor.Imm(asm.R8, 1),
			})
		})
	})

	t.Run("unsupported op", func(t *testing.T) {
		expr, err := cc.ParseExpr("skb->len++")
		test.AssertNoErr(t, err)

		_, err = c.eval(expr)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "unsupported operator")
	})
}
