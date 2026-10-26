// Copyright 2026 Liang Tang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"

	"github.com/bpfsnoop/bpfsnoop/internal/test"
)

func strChunk(s string) int64 {
	var b [8]byte
	copy(b[:], s)
	return int64(binary.NativeEndian.Uint64(b[:]))
}

func TestStrCmpOperands(t *testing.T) {
	for _, tt := range []struct {
		expr string
		str  string
		lit  string
		ok   bool
		err  string
	}{
		{expr: `str(skb->dev->name) == "lo"`, str: "str(skb->dev->name)", lit: "lo", ok: true},
		{expr: `"lo" == str(skb->dev->name)`, str: "str(skb->dev->name)", lit: "lo", ok: true},
		{expr: `(str(skb->dev->name)) != ("lo")`, str: "str(skb->dev->name)", lit: "lo", ok: true},
		{expr: `str(skb->dev->name) == "a\tb"`, str: "str(skb->dev->name)", lit: "a\tb", ok: true},
		{expr: `str(skb->dev->name) == ""`, str: "str(skb->dev->name)", lit: "", ok: true},
		{expr: `str(skb->dev->name, 4) == "lo"`, str: "str(skb->dev->name, 4)", lit: "lo", ok: true},
		{expr: `skb->len == 1`},
		{expr: `skb->dev->name == "lo"`, err: "a string literal can only be compared with str()"},
		{expr: `str(skb->dev->name) == 1`, err: "str() can only be compared with a string literal"},
		{expr: `str(skb->dev->name) == str(skb->dev->name)`, err: "str() can only be compared with a string literal"},
		{expr: `str(skb->dev->name) == "a\x00b"`, err: "must not contain NUL"},
		{expr: `str(skb->dev->name) == "\q"`, err: "invalid string literal"},
		{expr: `str(skb->dev->name) == "` + strings.Repeat("a", maxStrCmpLen+1) + `"`, err: "is longer than 254 bytes"},
	} {
		t.Run(tt.expr, func(t *testing.T) {
			str, lit, ok, err := strCmpOperands(prepareCcExpr(t, tt.expr))
			if tt.err != "" {
				test.AssertErrContains(t, err, tt.err)
				return
			}

			test.AssertNoErr(t, err)
			test.AssertEqual(t, ok, tt.ok)
			if ok {
				test.AssertEqual(t, lit, tt.lit)
				test.AssertEqual(t, str.String(), tt.str)
			}
		})
	}
}

// strEqCall returns the index of the only call of StrEqFunc in insns.
func strEqCall(t *testing.T, insns asm.Instructions) int {
	t.Helper()
	idx := -1
	for i, ins := range insns {
		if ins.IsFunctionCall() && ins.Reference() == StrEqFunc {
			test.AssertEqual(t, idx, -1)
			idx = i
		}
	}
	test.AssertTrue(t, idx >= 3)
	return idx
}

func TestEvaluateStrCmp(t *testing.T) {
	for _, tt := range []struct {
		name string
		expr string
		size int32 // most bytes to read, including the NUL
		eq   bool
	}{
		{name: "char array", expr: `str(skb->dev->name) == "lo"`, size: 17, eq: true},
		{name: "not equal", expr: `str(skb->dev->name) != "lo"`, size: 17},
		{name: "literal first", expr: `"lo" == str(skb->dev->name)`, size: 17, eq: true},
		{name: "empty string", expr: `str(skb->dev->name) == ""`, size: 17, eq: true},
		{name: "char pointer", expr: `str(prog->aux->attach_func_name) == "facebook"`, size: StrLitSize, eq: true},
		{name: "sized char array", expr: `str(skb->dev->name, 4) == "lo"`, size: 5, eq: true},
		{name: "sized char pointer", expr: `str(prog->aux->attach_func_name, 4) == "face"`, size: 5, eq: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := prepareCompiler(t)
			val, err := c.evaluate(prepareCcExpr(t, tt.expr))
			test.AssertNoErr(t, err)
			test.AssertTrue(t, val.isMaterialized())

			// bpfsnoop_str_eq(addr, size, 0), whose result goes to the
			// register of the address.
			call := strEqCall(t, c.insns)
			test.AssertEqual(t, c.insns[call-3], asm.Mov.Reg(asm.R1, val.reg))
			test.AssertEqual(t, c.insns[call-2], asm.Mov.Imm(asm.R2, tt.size))
			idx := c.insns[call-1]
			test.AssertEqual(t, idx.Metadata.Get(strLitMeta{}) != nil, true)
			idx.Metadata = asm.Metadata{}
			test.AssertEqual(t, idx, asm.Mov.Imm(asm.R3, 0))
			test.AssertEqual(t, c.insns[call+1], asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord))

			tail := asm.Instructions{asm.LoadMem(val.reg, asm.RFP, -8, asm.DWord)}
			if !tt.eq {
				tail = append(tail, asm.Xor.Imm(val.reg, 1))
			}
			test.AssertEqualSlice(t, c.insns[len(c.insns)-len(tail):], tail)
		})
	}

	// Comparisons compiled apart, e.g. in the arg filter and outputs, are
	// indexed together in the prog.
	t.Run("literals", func(t *testing.T) {
		c := prepareCompiler(t)
		var prog asm.Instructions
		var calls []int
		for _, expr := range []string{
			`str(skb->dev->name) == "lo"`,
			`str(prog->aux->attach_func_name) == "facebook"`,
			`str(skb->dev->name) != "lo"`,
		} {
			c.reset()
			_, err := c.evaluate(prepareCcExpr(t, expr))
			test.AssertNoErr(t, err)
			calls = append(calls, len(prog)+strEqCall(t, c.insns))
			prog = append(prog, c.insns...)
		}

		test.AssertEqualSlice(t, IndexStrLits(prog), []string{"lo", "facebook"})
		var idxs []int64
		for _, call := range calls {
			idxs = append(idxs, prog[call-1].Constant)
		}
		test.AssertEqualSlice(t, idxs, []int64{0, 1, 0})
	})

	// The caller-saved registers in use are saved around the call.
	t.Run("caller-saved registers", func(t *testing.T) {
		c := prepareCompiler(t)
		c.regalloc.MarkUsed(asm.R8)
		c.regalloc.MarkUsed(asm.R2)
		val, err := c.evaluate(prepareCcExpr(t, `str(skb->dev->name) == "lo"`))
		test.AssertNoErr(t, err)
		test.AssertEqual(t, val.reg, asm.R7)

		call := strEqCall(t, c.insns)
		test.AssertEqual(t, c.insns[call-4], asm.StoreMem(asm.RFP, -16, asm.R2, asm.DWord))
		test.AssertEqual(t, c.insns[call+2], asm.LoadMem(asm.R2, asm.RFP, -16, asm.DWord))
	})

	for _, tt := range []struct {
		expr string
		err  string
	}{
		{expr: `str(skb->dev->name) == "0123456789abcdefg"`, err: "string literal of 17 bytes is longer than"},
		{expr: `str(skb->len) == "lo"`, err: "disallow non-{pointer,array} type"},
		{expr: `skb->dev->name == "lo"`, err: "a string literal can only be compared with str()"},
		{expr: `str(skb->nope) == "lo"`, err: "failed to evaluate str() argument"},
		{expr: `str(skb->dev->name, 2) == "lo0"`, err: "string literal of 3 bytes is longer than"},
		{expr: `str(skb->dev) == "lo"`, err: "str() needs a char pointer or array"},
		{expr: `str(prog->aux->used_maps) == "lo"`, err: "str() needs a char pointer or array"},
	} {
		t.Run(tt.expr, func(t *testing.T) {
			c := prepareCompiler(t)
			_, err := c.evaluate(prepareCcExpr(t, tt.expr))
			test.AssertErrContains(t, err, tt.err)
		})
	}
}

func TestCompileFilterExprStrCmp(t *testing.T) {
	params := []btf.FuncParam{
		{Name: "skb", Type: getSkbBtf(t)},
		{Name: "prog", Type: getBpfProgBtf(t)},
	}

	for _, expr := range []string{
		`str(skb->dev->name) == "lo"`,
		`str(prog->aux->attach_func_name) != "facebook" && str(skb->dev->name) == "lo"`,
	} {
		t.Run(expr, func(t *testing.T) {
			analysis, err := AnalyzeExpr(expr)
			test.AssertNoErr(t, err)
			for _, name := range analysis.Vars {
				test.AssertTrue(t, name != strFn)
			}

			insns, err := CompileFilterExpr(CompileExprOptions{
				Expr:      expr,
				Params:    params,
				Spec:      testBtf,
				Kernel:    testBtf,
				LabelExit: "__label_exit",
			})
			test.AssertNoErr(t, err)

			// The call resolves to the helper, which is linked after.
			insns = append(insns,
				asm.Mov.Imm(asm.R0, 0).WithSymbol(StrEqFunc),
				asm.Return(),
			)
			var encoded bytes.Buffer
			test.AssertNoErr(t, insns.Marshal(&encoded, binary.LittleEndian))
		})
	}
}

func TestAnalyzeExprStrCmp(t *testing.T) {
	analysis, err := AnalyzeExpr(`str(skb->dev->name) == "lo"`)
	test.AssertNoErr(t, err)
	test.AssertEqualSlice(t, analysis.Vars, []string{"skb"})
}

// assertRegsWritten fails if an instruction reads a register that isn't
// written yet, or was clobbered by a call, in program order. The verifier
// rejects such a read with "R%d !read_ok".
func assertRegsWritten(t *testing.T, insns asm.Instructions, written ...asm.Register) {
	t.Helper()

	ok := map[asm.Register]bool{asm.RFP: true}
	for _, reg := range written {
		ok[reg] = true
	}
	read := func(i int, reg asm.Register) {
		if !ok[reg] {
			t.Errorf("insn %d '%v' reads %v, which holds nothing", i, insns[i], reg)
		}
	}

	for i, ins := range insns {
		op := ins.OpCode
		switch class := op.Class(); {
		case class.IsALU():
			if op.ALUOp() != asm.Mov {
				read(i, ins.Dst)
			}
			if op.Source() == asm.RegSource {
				read(i, ins.Src)
			}
			ok[ins.Dst] = true

		case class.IsJump():
			switch op.JumpOp() {
			case asm.Call:
				for reg := asm.R1; reg <= asm.R5; reg++ {
					delete(ok, reg)
				}
				ok[asm.R0] = true
			case asm.Exit:
				read(i, asm.R0)
			case asm.Ja:
			default:
				read(i, ins.Dst)
				if op.Source() == asm.RegSource {
					read(i, ins.Src)
				}
			}

		case class == asm.LdXClass:
			read(i, ins.Src)
			ok[ins.Dst] = true

		case class == asm.LdClass:
			ok[ins.Dst] = true

		case class == asm.StXClass:
			read(i, ins.Dst)
			read(i, ins.Src)

		case class == asm.StClass:
			read(i, ins.Dst)
		}
	}
}

func TestStrCmpRegisters(t *testing.T) {
	params := []btf.FuncParam{
		{Name: "skb", Type: getSkbBtf(t)},
		{Name: "prog", Type: getBpfProgBtf(t)},
	}
	cmps := `str(skb->dev->name) == "lo" && str(prog->aux->attach_func_name) == "facebook"`

	for _, mode := range []MemoryReadMode{MemoryReadModeProbeRead, MemoryReadModeCoreRead} {
		t.Run(fmt.Sprintf("filter mode %d", mode), func(t *testing.T) {
			insns, err := CompileFilterExpr(CompileExprOptions{
				Expr: cmps, Params: params, Spec: testBtf, Kernel: testBtf,
				LabelExit: "__label_exit", MemoryReadMode: mode,
			})
			test.AssertNoErr(t, err)
			assertRegsWritten(t, insns, asm.R1)
		})
	}

	// --output-arg reserves registers, so the address of the string is held
	// in a caller-saved register across the call.
	t.Run("output arg", func(t *testing.T) {
		res, err := CompileEvalExpr(CompileExprOptions{
			Expr:          `str(prog->aux->attach_func_name) == "facebook"`,
			Params:        params,
			Spec:          testBtf,
			Kernel:        testBtf,
			LabelExit:     "__label_exit",
			UsedRegisters: []asm.Register{asm.R6, asm.R7, asm.R8, asm.R9},
		})
		test.AssertNoErr(t, err)
		test.AssertTrue(t, res.Reg <= asm.R5)
		assertRegsWritten(t, res.Insns, asm.R6, asm.R7, asm.R8, asm.R9)
	})
}
