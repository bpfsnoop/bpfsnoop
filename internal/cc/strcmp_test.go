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
		lit  string
		ok   bool
		err  string
	}{
		{expr: `str(skb->dev->name) == "lo"`, lit: "lo", ok: true},
		{expr: `"lo" == str(skb->dev->name)`, lit: "lo", ok: true},
		{expr: `(str(skb->dev->name)) != ("lo")`, lit: "lo", ok: true},
		{expr: `str(skb->dev->name) == "a\tb"`, lit: "a\tb", ok: true},
		{expr: `str(skb->dev->name) == ""`, lit: "", ok: true},
		{expr: `skb->len == 1`},
		{expr: `skb->dev->name == "lo"`, err: "a string literal can only be compared with str()"},
		{expr: `str(skb->dev->name) == 1`, err: "str() can only be compared with a string literal"},
		{expr: `str(skb->dev->name) == str(skb->dev->name)`, err: "str() can only be compared with a string literal"},
		{expr: `str(skb->dev->name, 4) == "lo"`, err: "str() must have 1 argument"},
		{expr: `str(skb->dev->name) == "a\x00b"`, err: "must not contain NUL"},
		{expr: `str(skb->dev->name) == "` + strings.Repeat("a", maxStrCmpLen+1) + `"`, err: "is longer than 256 bytes"},
	} {
		t.Run(tt.expr, func(t *testing.T) {
			x, lit, ok, err := strCmpOperands(prepareCcExpr(t, tt.expr))
			if tt.err != "" {
				test.AssertErrContains(t, err, tt.err)
				return
			}

			test.AssertNoErr(t, err)
			test.AssertEqual(t, ok, tt.ok)
			if ok {
				test.AssertEqual(t, lit, tt.lit)
				test.AssertEqual(t, x.String(), "skb->dev->name")
			}
		})
	}
}

func TestEvaluateStrCmp(t *testing.T) {
	probeReads := func(insns asm.Instructions) int {
		n := 0
		for _, ins := range insns {
			if ins.IsBuiltinCall() && asm.BuiltinFunc(ins.Constant) == asm.FnProbeReadKernel {
				n++
			}
		}
		return n
	}

	chunks := func(insns asm.Instructions) []int64 {
		var consts []int64
		for _, ins := range insns {
			if ins.OpCode.IsDWordLoad() {
				consts = append(consts, ins.Constant)
			}
		}
		return consts
	}

	zeroedSlots := func(insns asm.Instructions) int {
		n := 0
		for _, ins := range insns {
			if ins.OpCode == asm.StoreImmOp(asm.Word) && ins.Dst == asm.RFP && ins.Offset == -8 {
				n++
			}
		}
		return n
	}

	for _, tt := range []struct {
		name   string
		expr   string
		chunks []int64
		zeroed int
		eq     bool
	}{
		{
			name:   "char array",
			expr:   `str(skb->dev->name) == "lo"`,
			chunks: []int64{strChunk("lo")},
			zeroed: 1,
			eq:     true,
		},
		{
			name:   "full char array has no NUL",
			expr:   `str(skb->dev->name) == "0123456789abcdef"`,
			chunks: []int64{strChunk("01234567"), strChunk("89abcdef")},
			eq:     true,
		},
		{
			name:   "char pointer",
			expr:   `str(prog->aux->attach_func_name) == "facebook"`,
			chunks: []int64{strChunk("facebook"), 0},
			zeroed: 1,
			eq:     true,
		},
		{
			name:   "not equal",
			expr:   `str(skb->dev->name) != "lo"`,
			chunks: []int64{strChunk("lo")},
			zeroed: 1,
		},
		{
			name:   "empty string",
			expr:   `"" == str(skb->dev->name)`,
			chunks: []int64{0},
			zeroed: 1,
			eq:     true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := prepareCompiler(t)
			val, err := c.evaluate(prepareCcExpr(t, tt.expr))
			test.AssertNoErr(t, err)
			test.AssertTrue(t, val.isMaterialized())

			// Reads to get the address of the string, then one per chunk.
			x, _, _, err := strCmpOperands(prepareCcExpr(t, tt.expr))
			test.AssertNoErr(t, err)
			addr := prepareCompiler(t)
			xval, err := addr.evaluate(x)
			test.AssertNoErr(t, err)
			_, err = addr.materialize(xval)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, probeReads(c.insns), probeReads(addr.insns)+len(tt.chunks))
			test.AssertEqualSlice(t, chunks(c.insns), tt.chunks)
			test.AssertEqual(t, zeroedSlots(c.insns), tt.zeroed)

			// Every chunk jumps to the mismatch result at the end.
			n := len(c.insns)
			label := c.insns[n-1].Symbol()
			test.AssertStrPrefix(t, label, "__label_strcmp_")
			jumps := 0
			for _, ins := range c.insns {
				if ins.OpCode == asm.JNE.Op(asm.RegSource) && ins.Reference() == label {
					jumps++
				}
			}
			test.AssertEqual(t, jumps, len(tt.chunks))

			test.AssertEqual(t, c.insns[n-3], asm.Mov.Imm(val.reg, int32(bool2int(tt.eq))))
			test.AssertEqual(t, c.insns[n-2], Ja(1))
			test.AssertEqual(t, c.insns[n-1].Constant, int64(bool2int(!tt.eq)))
		})
	}

	for _, tt := range []struct {
		expr string
		err  string
	}{
		{expr: `str(skb->dev->name) == "0123456789abcdefg"`, err: "string literal of 17 bytes is longer than"},
		{expr: `str(skb->len) == "lo"`, err: "str() needs a char pointer or array"},
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
	// in a caller-saved register across the reads.
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
