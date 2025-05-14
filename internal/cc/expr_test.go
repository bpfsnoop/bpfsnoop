// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"bytes"
	_ "embed"
	"errors"
	"log"
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"

	"github.com/bpfsnoop/bpfsnoop/internal/test"
)

//go:embed testdata/vmlinux_v680_btf.o
var btfFile []byte

var (
	testBtf *btf.Spec
	skb     *btf.Pointer
)

func init() {
	spec, err := btf.LoadSpecFromReader(bytes.NewReader(btfFile))
	if err != nil {
		log.Fatalf("Failed to load btf spec: %v", err)
	}

	testBtf = spec

	iter := spec.Iterate()
	for iter.Next() {
		if ptr, ok := iter.Type.(*btf.Pointer); ok {
			if s, ok := ptr.Target.(*btf.Struct); ok && s.Name == "sk_buff" {
				skb = ptr
				break
			}
		}
	}
	if skb == nil {
		log.Fatalf("Failed to find skb pointer in btf spec")
	}
}

func getSkbBtf(t *testing.T) *btf.Pointer {
	_ = t
	return skb
}

func getNetDeviceBtf(t *testing.T) *btf.Pointer {
	netDev, err := testBtf.AnyTypeByName("net_device")
	t.Helper()
	test.AssertNoErr(t, err)
	return &btf.Pointer{Target: netDev}
}

func getBpfProgBtf(t *testing.T) *btf.Pointer {
	bpfProg, err := testBtf.AnyTypeByName("bpf_prog")
	t.Helper()
	test.AssertNoErr(t, err)
	return &btf.Pointer{Target: bpfProg}
}

func getBpfMapBtf(t *testing.T) *btf.Pointer {
	bpfMap, err := testBtf.AnyTypeByName("bpf_map")
	t.Helper()
	test.AssertNoErr(t, err)
	return &btf.Pointer{Target: bpfMap}
}

func getBpfProgAuxBtf(t *testing.T) *btf.Pointer {
	bpfProgAux, err := testBtf.AnyTypeByName("bpf_prog_aux")
	t.Helper()
	test.AssertNoErr(t, err)
	return &btf.Pointer{Target: bpfProgAux}
}

func getBpfProgTypeBtf(t *testing.T) *btf.Enum {
	bpfProgType, err := testBtf.AnyTypeByName("bpf_prog_type")
	t.Helper()
	test.AssertNoErr(t, err)
	return bpfProgType.(*btf.Enum)
}

func getU8Btf(t *testing.T) btf.Type {
	u8, err := testBtf.AnyTypeByName("__u8")
	t.Helper()
	test.AssertNoErr(t, err)
	return u8
}

func getU16Btf(t *testing.T) btf.Type {
	u16, err := testBtf.AnyTypeByName("__u16")
	t.Helper()
	test.AssertNoErr(t, err)
	return u16
}

func getU32Btf(t *testing.T) btf.Type {
	u32, err := testBtf.AnyTypeByName("__u32")
	t.Helper()
	test.AssertNoErr(t, err)
	return u32
}

func getU64Btf(t *testing.T) btf.Type {
	u64, err := testBtf.AnyTypeByName("__u64")
	t.Helper()
	test.AssertNoErr(t, err)
	return u64
}

func getFakeOpsBtf() *btf.Pointer {
	return &btf.Pointer{
		Target: &btf.Struct{
			Name: "fake_ops",
			Members: []btf.Member{
				{
					Name: "lookup_elem",
					Type: &btf.Pointer{Target: &btf.FuncProto{}},
				},
				{
					Name: "batch_lookup_elem",
					Type: &btf.Array{
						Type:   &btf.FuncProto{},
						Nelems: 1,
					},
				},
				{
					Name: "data",
					Type: &btf.Pointer{
						Target: &btf.Void{},
					},
				},
				{
					Name: "arr",
					Type: &btf.Array{
						Type:   &btf.FuncProto{},
						Nelems: 1,
					},
				},
				{
					Name: "fn",
					Type: &btf.Pointer{
						Target: &btf.FuncProto{},
					},
				},
			},
		},
	}
}

func getBpfAttrBtf(t *testing.T) *btf.Pointer {
	bpfAttr, err := testBtf.AnyTypeByName("bpf_attr")
	t.Helper()
	test.AssertNoErr(t, err)
	bpfAttrPtr, ok := bpfAttr.(*btf.Union)
	test.AssertTrue(t, ok)
	return &btf.Pointer{
		Target: bpfAttrPtr,
	}
}

func prepareCompiler(t *testing.T) *compiler {
	c := &compiler{
		labelExit:     "__label_exit",
		reservedStack: 8,
		vars:          []string{"skb", "prog", "ops", "attr"},
		btfs:          []btf.Type{getSkbBtf(t), getBpfProgBtf(t), getFakeOpsBtf(), getBpfAttrBtf(t)},
		kernelBtf:     testBtf,
	}
	c.regalloc.registers[asm.R9] = true
	return c
}

func (c *compiler) reset() {
	c.memMode = MemoryReadModeProbeRead
	c.insns = nil
	c.labelExitUsed = false
	c.regalloc.registers = [10]bool{}
	c.regalloc.registers[asm.R9] = true
	c.reservedStack = 8
}

func TestCompileFilterExpr(t *testing.T) {
	t.Run("empty expr", func(t *testing.T) {
		_, err := CompileFilterExpr(CompileExprOptions{
			Expr:      "",
			LabelExit: "__label_exit",
			Spec:      testBtf,
		})
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "expression and label exit cannot be empty")
	})

	t.Run("empty btf spec", func(t *testing.T) {
		_, err := CompileFilterExpr(CompileExprOptions{
			Expr:      "skb->len == 0",
			LabelExit: "__label_exit",
			Spec:      nil,
		})
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "btf spec cannot be empty")
	})

	t.Run("compile expr failed", func(t *testing.T) {
		_, err := CompileFilterExpr(CompileExprOptions{
			Expr:      "not_found->xxx == 0",
			LabelExit: "__label_exit",
			Spec:      testBtf,
			Params: []btf.FuncParam{
				{
					Name: "skb",
					Type: getSkbBtf(t),
				},
				{
					Name: "prog",
					Type: getBpfProgBtf(t),
				},
			},
		})
		test.AssertHaveErr(t, err)
		test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
	})

	t.Run("compile expr success", func(t *testing.T) {
		insns, err := CompileFilterExpr(CompileExprOptions{
			Expr:      "skb->len == 0",
			LabelExit: "__label_exit",
			Spec:      testBtf,
			Params: []btf.FuncParam{
				{
					Name: "skb",
					Type: getSkbBtf(t),
				},
				{
					Name: "prog",
					Type: getBpfProgBtf(t),
				},
			},
			ReservedStack: 7,
		})
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, insns, []asm.Instruction{
			asm.Mov.Reg(asm.R9, asm.R1),
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
			asm.Mov.Reg(asm.R0, asm.R8),
			asm.Return(),
		})
	})
}

func TestCompile(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("invalid expr", func(t *testing.T) {
		err := c.compile("1 * skb^^>len")
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "failed to parse expression")
	})

	t.Run("unsupported op", func(t *testing.T) {
		err := c.compile("skb->len + skb->len")
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "top op 'Add' of expression")
	})

	t.Run("evaluate failed", func(t *testing.T) {
		err := c.compile("not_found->xxx == 0")
		test.AssertHaveErr(t, err)
		test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
		test.AssertStrPrefix(t, err.Error(), "failed to evaluate expression")
	})

	t.Run("constant value", func(t *testing.T) {
		err := c.compile("1 > 2")
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "disallow constant value")
	})

	t.Run("skb->dev->ifindex == 11", func(t *testing.T) {
		c.reset()
		err := c.compile("skb->dev->ifindex == 11")
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, c.insns, []asm.Instruction{
			asm.LoadMem(asm.R8, asm.R9, 0, asm.DWord),
			asm.Mov.Reg(asm.R3, asm.R8),
			asm.Add.Imm(asm.R3, 16),
			asm.Mov.Imm(asm.R2, 8),
			asm.Mov.Reg(asm.R1, asm.RFP),
			asm.Add.Imm(asm.R1, -8),
			asm.FnProbeReadKernel.Call(),
			asm.LoadMem(asm.R3, asm.RFP, -8, asm.DWord),
			asm.JEq.Imm(asm.R3, 0, c.labelExit),
			asm.Add.Imm(asm.R3, 224),
			asm.Mov.Imm(asm.R2, 8),
			asm.Mov.Reg(asm.R1, asm.RFP),
			asm.Add.Imm(asm.R1, -8),
			asm.FnProbeReadKernel.Call(),
			asm.LoadMem(asm.R8, asm.RFP, -8, asm.DWord),
			asm.LSh.Imm(asm.R8, 32),
			asm.RSh.Imm(asm.R8, 32),
			JmpOff(asm.JNE, asm.R8, 11, 2),
			asm.Mov.Imm(asm.R8, 1),
			Ja(1),
			asm.Xor.Reg(asm.R8, asm.R8).WithSymbol(c.labelExit),
			asm.Mov.Reg(asm.R0, asm.R8),
		})
	})
}

func TestEvalExpr(t *testing.T) {
	t.Run("empty expr", func(t *testing.T) {
		_, err := CompileEvalExpr(CompileExprOptions{})
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "expression and label exit cannot be empty")
	})

	t.Run("empty btf spec", func(t *testing.T) {
		_, err := CompileEvalExpr(CompileExprOptions{
			Expr:      "skb->len == 0",
			LabelExit: "__label_exit",
			Spec:      nil,
		})
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "btf spec cannot be empty")
	})

	t.Run("compile expr failed", func(t *testing.T) {
		_, err := CompileEvalExpr(CompileExprOptions{
			Expr:      "a ^^ b",
			LabelExit: "__label_exit",
			Spec:      testBtf,
			Params: []btf.FuncParam{
				{
					Name: "skb",
					Type: getSkbBtf(t),
				},
				{
					Name: "prog",
					Type: getBpfProgBtf(t),
				},
			},
		})
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "failed to parse expr")
	})

	t.Run("eval failed", func(t *testing.T) {
		_, err := CompileEvalExpr(CompileExprOptions{
			Expr:      "not_found->xxx == 0",
			LabelExit: "__label_exit",
			Spec:      testBtf,
			Params: []btf.FuncParam{
				{
					Name: "skb",
					Type: getSkbBtf(t),
				},
				{
					Name: "prog",
					Type: getBpfProgBtf(t),
				},
			},
		})
		test.AssertHaveErr(t, err)
		test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
		test.AssertStrPrefix(t, err.Error(), "failed to evaluate expression")
	})

	t.Run("constant value", func(t *testing.T) {
		_, err := CompileEvalExpr(CompileExprOptions{
			Expr:          "1 > 2",
			LabelExit:     "__label_exit",
			Spec:          testBtf,
			ReservedStack: 9,
		})
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "disallow constant value")
	})

	t.Run("skb->len", func(t *testing.T) {
		res, err := CompileEvalExpr(CompileExprOptions{
			Expr:          "skb->len",
			LabelExit:     "__label_exit",
			Spec:          testBtf,
			Params:        []btf.FuncParam{{Name: "skb", Type: getSkbBtf(t)}},
			UsedRegisters: []asm.Register{asm.R8, asm.R9},
		})
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, res.Insns, []asm.Instruction{
			asm.LoadMem(asm.R7, asm.R9, 0, asm.DWord),
			asm.Mov.Reg(asm.R3, asm.R7),
			asm.Add.Imm(asm.R3, 112),
			asm.Mov.Imm(asm.R2, 8),
			asm.Mov.Reg(asm.R1, asm.RFP),
			asm.Add.Imm(asm.R1, -8),
			asm.FnProbeReadKernel.Call(),
			asm.LoadMem(asm.R7, asm.RFP, -8, asm.DWord),
			asm.LSh.Imm(asm.R7, 32),
			asm.RSh.Imm(asm.R7, 32),
		})
	})
}
