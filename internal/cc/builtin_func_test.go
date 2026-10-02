// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/bpfsnoop/bpfsnoop/internal/test"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

func TestEvaluateCallErrors(t *testing.T) {
	for _, tt := range []struct {
		expr string
		want string
	}{
		{"(h2ns)(n)", "function call must have a constant name"},
		{"unknown(n)", "unsupported function call in expression: unknown"},
	} {
		t.Run(tt.expr, func(t *testing.T) {
			c := prepareCompiler(t)
			_, err := c.evaluate(prepareCcExpr(t, tt.expr))
			test.AssertHaveErr(t, err)
			test.AssertErrorPrefix(t, err, tt.want)
			test.AssertEmptySlice(t, c.insns)
		})
	}
}

func TestByteOrderArgumentErrors(t *testing.T) {
	for _, fn := range []string{"h2ns", "n2hs", "h2nl", "n2hl"} {
		t.Run(fn+"/evaluation", func(t *testing.T) {
			c := prepareCompiler(t)
			_, err := c.evaluate(prepareCcExpr(t, fn+"(n->len)"))
			test.AssertHaveErr(t, err)
			test.AssertErrorPrefix(t, err, "failed to evaluate "+fn+"() argument:")
			test.AssertEmptySlice(t, c.insns)
		})

		t.Run(fn+"/materialization", func(t *testing.T) {
			c := prepareCompiler(t)
			c.markRegisterAllUsed()
			_, err := c.evaluate(prepareCcExpr(t, fn+"(n)"))
			test.AssertHaveErr(t, err)
			test.AssertErrorPrefix(t, err, "failed to materialize "+fn+"() argument:")
			if !errors.Is(err, ErrRegisterNotEnough) {
				t.Fatalf("expected register exhaustion, got %v", err)
			}
			test.AssertEmptySlice(t, c.insns)
		})
	}
}

func TestByteOrderConstants(t *testing.T) {
	for _, fn := range []string{"h2ns", "n2hs", "h2nl", "n2hl"} {
		for _, n := range []int64{0, 0x12, 0x1234, 0x12345678, 0x123456789a, -1, -128} {
			t.Run(fmt.Sprintf("%s(%d)", fn, n), func(t *testing.T) {
				c := prepareCompiler(t)
				v, err := c.evaluate(prepareCcExpr(t, fmt.Sprintf("%s(%d)", fn, n)))
				test.AssertNoErr(t, err)
				test.AssertTrue(t, v.isConstant())
				var buf [4]byte
				var want int64
				size := uint32(2)
				if strings.HasSuffix(fn, "s") {
					binary.BigEndian.PutUint16(buf[:2], uint16(n))
					want = int64(binary.NativeEndian.Uint16(buf[:2]))
				} else {
					size = 4
					binary.BigEndian.PutUint32(buf[:], uint32(n))
					want = int64(binary.NativeEndian.Uint32(buf[:]))
				}
				test.AssertEqual(t, v.num, want)
				test.AssertEqual(t, v.btf.(*btf.Int).Size, size)
				test.AssertEqual(t, v.btf.(*btf.Int).Encoding, btf.Unsigned)
				test.AssertEmptySlice(t, c.insns)
			})
		}
	}

	c := prepareCompiler(t)
	for _, expr := range []string{"n2hs(h2ns(0x123456))", "n2hl(h2nl(0x123456789a))"} {
		v, err := c.evaluate(prepareCcExpr(t, expr))
		test.AssertNoErr(t, err)
		want := int64(0x3456)
		if strings.Contains(expr, "n2hl") {
			want = 0x3456789a
		}
		test.AssertEqual(t, v.num, want)
	}

	for _, expr := range []string{
		"n2hs(h2ns((short)(65535 + 0)))",
		"n2hl(h2nl((short)(65535 + 0)))",
	} {
		v, err := c.evaluate(prepareCcExpr(t, expr))
		test.AssertNoErr(t, err)
		want := int64(0xffff)
		if strings.Contains(expr, "n2hl") {
			want = 0xffffffff
		}
		test.AssertEqual(t, v.num, want)
	}
}

func TestByteOrderIntegerWidths(t *testing.T) {
	for _, fn := range []string{"h2ns", "n2hs", "h2nl", "n2hl"} {
		for _, width := range []uint32{1, 2, 4, 8} {
			for _, encoding := range []btf.IntEncoding{btf.Signed, btf.Unsigned} {
				t.Run(fmt.Sprintf("%s/%d/%s", fn, width, encoding), func(t *testing.T) {
					c := prepareCompiler(t)
					c.vars = []string{"x"}
					c.btfs = []btf.Type{&btf.Typedef{Name: "integer", Type: &btf.Int{Size: width, Encoding: encoding}}}
					v, err := c.evaluate(prepareCcExpr(t, fn+"(x)"))
					test.AssertNoErr(t, err)
					test.AssertTrue(t, v.isMaterialized())
					size := asm.Half
					if strings.HasSuffix(fn, "l") {
						size = asm.Word
					}
					// The original type must be normalized before conversion, so
					// widening negative signed values preserves their sign.
					want := &compiler{}
					want.emit(asm.LoadMem(v.reg, argsReg, 0, asm.DWord))
					want.adjustRegisterSize(newMaterialized(v.reg, c.btfs[0]))
					want.emit(asm.HostTo(asm.BE, v.reg, size))
					test.AssertEqualSlice(t, c.insns, want.insns)
					test.AssertEqual(t, v.btf.(*btf.Int).Encoding, btf.Unsigned)
				})
			}
		}
	}
}

func TestByteOrderInvalidCalls(t *testing.T) {
	for _, fn := range []string{"h2ns", "n2hs", "h2nl", "n2hl"} {
		for _, args := range []string{"", "n, n", "skb", "skb->cb", "*skb", "unknown", "(void *)(1 + 1)"} {
			t.Run(fn+"("+args+")", func(t *testing.T) {
				c := prepareCompiler(t)
				_, err := c.evaluate(prepareCcExpr(t, fn+"("+args+")"))
				test.AssertHaveErr(t, err)
			})
		}
	}
}

func TestCompileByteOrderExpressions(t *testing.T) {
	opts := CompileExprOptions{
		Params: []btf.FuncParam{{Name: "n", Type: getU32Btf(t)}},
		Spec:   testBtf, Kernel: testBtf, LabelExit: "exit",
	}
	for _, expr := range []string{
		"h2ns(n)", "n2hs(n)", "h2nl(n)", "n2hl(n)",
		"(h2ns(n))", "n2hs(h2ns(n))", "h2nl(n + 1) + n2hl(n)",
		"h2ns(n) == 0x1234", "n2hs(n) > 0 && n2hl(n) != 0",
		"hist(n2hl(n))", "n ? h2ns(n) : n2hs(n)",
	} {
		t.Run(expr, func(t *testing.T) {
			opts.Expr = expr
			_, err := CompileEvalExpr(opts)
			test.AssertNoErr(t, err)
			if strings.Contains(expr, "==") || strings.Contains(expr, "&&") {
				_, err = CompileFilterExpr(opts)
				test.AssertNoErr(t, err)
			}
			names, err := ExtractVarNames(expr)
			test.AssertNoErr(t, err)
			test.AssertEqualSlice(t, names, []string{"n"})
		})
	}
	// A parameter named like a builtin still counts as a variable.
	names, err := ExtractVarNames("h2ns(h2ns) + n2hl(n)")
	test.AssertNoErr(t, err)
	test.AssertEqualSlice(t, names, []string{"h2ns", "n"})

	c := prepareCompiler(t)
	_, err = c.evaluate(prepareCcExpr(t, "n2hs(h2ns(n))"))
	test.AssertNoErr(t, err)
	var swaps int
	for _, ins := range c.insns {
		if ins.OpCode.ALUOp() == asm.Swap {
			swaps++
		}
	}
	test.AssertEqual(t, swaps, 2)
}
