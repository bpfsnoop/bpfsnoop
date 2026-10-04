// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/bpfsnoop/bpfsnoop/internal/test"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"rsc.io/c2go/cc"
)

func prepareMapLookupCompiler(t *testing.T) *compiler {
	c := prepareCompiler(t)
	u32 := &btf.Int{Name: "unsigned int", Size: 4}
	value := &btf.Struct{Name: "lookup_value", Size: 16, Members: []btf.Member{
		{Name: "count", Type: u32, Offset: 64},
	}}
	c.maps = map[BPFMapID]BPFMap{
		{Name: "counts"}: {FD: 7, KeySize: 4, Key: u32, Value: value},
		{ID: 42}:         {FD: 8, KeySize: 4, Key: u32, Value: value},
		{Name: "keys"}:   {FD: 9, KeySize: 4, Key: u32, Value: u32},
	}
	c.vars = []string{"key", "small", "large", "n", "voidptr", "incomplete"}
	c.btfs = []btf.Type{
		&btf.Typedef{Name: "key_ptr", Type: &btf.Pointer{Target: u32}},
		&btf.Pointer{Target: &btf.Int{Size: 1}},
		&btf.Pointer{Target: &btf.Array{Type: u32, Nelems: 2}},
		u32,
		&btf.Pointer{Target: &btf.Void{}},
		&btf.Pointer{Target: &btf.Fwd{Name: "incomplete"}},
	}
	return c
}

func TestAnalyzeMapLookups(t *testing.T) {
	for _, tt := range []struct {
		expr string
		maps []BPFMapID
		vars []string
	}{
		{`map_lookup("counts", key)`, []BPFMapID{{Name: "counts"}}, []string{"key"}},
		{`map_lookup(42, key)`, []BPFMapID{{ID: 42}}, []string{"key"}},
		{`bpf_map_lookup_elem("counts", key)`, []BPFMapID{{Name: "counts"}}, []string{"key"}},
		{`bpf_map_lookup_elem(42, key, 4)`, []BPFMapID{{ID: 42}}, []string{"key"}},
		{`map_lookup(0x2a, key)`, []BPFMapID{{ID: 42}}, []string{"key"}},
		{`map_lookup("42", key) != map_lookup(42, key)`, []BPFMapID{{Name: "42"}, {ID: 42}}, []string{"key"}},
		{`map_lookup("id:42", key)`, []BPFMapID{{Name: "id:42"}}, []string{"key"}},
		{`map_lookup("counts", key)->count + map_lookup("counts", other)->count`, []BPFMapID{{Name: "counts"}}, []string{"key", "other"}},
		{`map_lookup("counts", map_lookup(42, key))`, []BPFMapID{{Name: "counts"}, {ID: 42}}, []string{"key"}},
		{`buf(map_lookup("counts", key), 16)`, []BPFMapID{{Name: "counts"}}, []string{"key"}},
		{`map_lookup("counts", (int *)$retval)`, []BPFMapID{{Name: "counts"}}, []string{RetvalName}},
		{`map_lookup("map_lookup", map_lookup)`, []BPFMapID{{Name: "map_lookup"}}, []string{"map_lookup"}},
		{`map_lookup("counts", (int *)0x1234)`, []BPFMapID{{Name: "counts"}}, nil},
	} {
		t.Run(tt.expr, func(t *testing.T) {
			analysis, err := AnalyzeExpr(tt.expr)
			test.AssertNoErr(t, err)
			test.AssertEqualSlice(t, analysis.Maps, tt.maps)
			test.AssertEqualSlice(t, analysis.Vars, tt.vars)
		})
	}
}

func TestMapLookupSelectors(t *testing.T) {
	for _, tt := range []struct{ expr, want string }{
		{`map_lookup(4294967295, key)`, "4294967295"},
		{`map_lookup("counts", key)`, `"counts"`},
	} {
		selector, err := expr2mapID(prepareCcExpr(t, tt.expr))
		test.AssertNoErr(t, err)
		test.AssertEqual(t, selector.String(), tt.want)
	}
	for _, expr := range []string{
		`bpf_map_lookup_elem()`, `bpf_map_lookup_elem(42, key, 4, 0)`,
		`map_lookup()`, `map_lookup("counts")`, `map_lookup("counts", key, 4, 0)`,
		`map_lookup(0, key)`, `map_lookup(4294967296, key)`, `map_lookup(-1, key)`,
		`map_lookup(1.5, key)`, `map_lookup(0x42ULL, key)`, `map_lookup(n, key)`,
		`map_lookup("", key)`, `map_lookup("co" "unts", key)`,
		`map_lookup("counts") + map_lookup("counts", key)`,
		`map_lookup(id:42, key)`,
	} {
		t.Run(expr, func(t *testing.T) {
			_, err := AnalyzeExpr(expr)
			test.AssertHaveErr(t, err)
		})
	}
	_, err := expr2mapID(&cc.Expr{Op: cc.Call, Left: &cc.Expr{Op: cc.Name, Text: mapLookupFn}, List: []*cc.Expr{{Op: cc.String, Texts: []string{`"\q"`}}, {Op: cc.Name, Text: "key"}}})
	test.AssertHaveErr(t, err)
}

func TestMapLookupValidation(t *testing.T) {
	for _, tt := range []struct{ expr, want string }{
		{`map_lookup("counts")`, "bpf_map_lookup_elem() must have 2 or 3 arguments"},
		{`map_lookup("absent", key)`, "map has not been opened"},
		{`map_lookup("counts", n->field)`, "failed to evaluate map_lookup() key"},
		{`map_lookup("counts", n)`, "key must be a pointer"},
		{`map_lookup("counts", 1)`, "key must be a pointer"},
	} {
		t.Run(tt.expr, func(t *testing.T) {
			c := prepareMapLookupCompiler(t)
			_, err := c.evaluate(prepareCcExpr(t, tt.expr))
			test.AssertHaveErr(t, err)
			test.AssertStrContains(t, err.Error(), tt.want)
		})
	}
	for _, m := range []BPFMap{
		{FD: -1, KeySize: 4, Value: &btf.Int{Size: 4}},
		{FD: 7, KeySize: 4},
		{FD: 7, Value: &btf.Int{Size: 4}},
	} {
		c := prepareMapLookupCompiler(t)
		c.maps[BPFMapID{Name: "counts"}] = m
		_, err := c.evaluate(prepareCcExpr(t, `map_lookup("counts", key)`))
		test.AssertHaveErr(t, err)
		test.AssertStrContains(t, err.Error(), "invalid map metadata or missing value BTF")
	}
	t.Run("register exhaustion", func(t *testing.T) {
		c := prepareMapLookupCompiler(t)
		c.markRegisterAllUsed()
		_, err := c.evaluate(prepareCcExpr(t, `map_lookup("counts", key)`))
		if !errors.Is(err, ErrRegisterNotEnough) {
			t.Fatalf("expected register exhaustion, got %v", err)
		}
		test.AssertErrorPrefix(t, err, "failed to materialize map_lookup() key")
	})
	t.Run("key memory read compilation error", func(t *testing.T) {
		c := prepareMapLookupCompiler(t)
		c.vars = append(c.vars, "skb")
		c.btfs = append(c.btfs, getSkbBtf(t))
		c.setBtfIDErr(t)
		_, err := c.evaluate(prepareCcExpr(t, `map_lookup("counts", &skb->dev->ifindex)`))
		test.AssertHaveErr(t, err)
		test.AssertErrorPrefix(t, err, "failed to materialize map_lookup() key")
	})
	t.Run("stack limit", func(t *testing.T) {
		c := prepareMapLookupCompiler(t)
		c.maps[BPFMapID{Name: "counts"}] = BPFMap{FD: 7, KeySize: 513, Key: &btf.Array{Type: &btf.Int{Size: 1}, Nelems: 513}, Value: &btf.Int{Size: 4}}
		c.btfs[0] = &btf.Pointer{Target: &btf.Array{Type: &btf.Int{Size: 1}, Nelems: 513}}
		_, err := c.evaluate(prepareCcExpr(t, `map_lookup("counts", key)`))
		test.AssertHaveErr(t, err)
		test.AssertStrContains(t, err.Error(), "maximum is 512")
	})
	for _, key := range []string{"key", "large", "small", "voidptr", "incomplete"} {
		c := prepareMapLookupCompiler(t)
		v, err := c.evaluate(prepareCcExpr(t, `map_lookup("counts", `+key+`)`))
		test.AssertNoErr(t, err)
		test.AssertEqual(t, v.btf.(*btf.Pointer).Target, c.maps[BPFMapID{Name: "counts"}].Value)
		test.AssertTrue(t, v.mapLookup)
	}
}

func TestCompileMapLookupExpressions(t *testing.T) {
	c := prepareMapLookupCompiler(t)
	params := make([]btf.FuncParam, len(c.vars))
	for i := range params {
		params[i] = btf.FuncParam{Name: c.vars[i], Type: c.btfs[i]}
	}
	for _, expr := range []string{
		`map_lookup("counts", key)`, `map_lookup(42, key)`,
		`map_lookup("counts", (int *)0)`, `map_lookup("counts", (int *)0x1234)`,
		`*map_lookup("counts", key)`, `map_lookup("counts", key)->count`,
		`h2nl(map_lookup("counts", key)->count)`,
		`h2nl(*map_lookup("keys", key))`,
		`map_lookup("counts", key) + 1`, `map_lookup("counts", key) - 1`,
		`map_lookup("counts", key)[0]`,
		`map_lookup("counts", key)->count + map_lookup(42, key)->count`,
		`map_lookup("counts", map_lookup("keys", key))`,
		`map_lookup(42, key) == NULL`, `map_lookup("counts", key) != NULL`,
		`map_lookup("counts", key)->count > 0`,
		`map_lookup("counts", (int *)$retval)`,
	} {
		t.Run(expr, func(t *testing.T) {
			opts := CompileExprOptions{
				Expr: expr, Params: params, Maps: c.maps,
				Spec: testBtf, Kernel: testBtf, LabelExit: "exit",
				RetvalType:     &btf.Pointer{Target: &btf.Int{Size: 4, Encoding: btf.Signed}},
				MemoryReadMode: MemoryReadModeCoreRead,
			}
			res, err := CompileEvalExpr(opts)
			test.AssertNoErr(t, err)
			if strings.Contains(expr, "NULL") || strings.Contains(expr, " > ") {
				_, err = CompileFilterExpr(opts)
				test.AssertNoErr(t, err)
			}
			if strings.Contains(expr, "->") || strings.Contains(expr, " + ") || strings.Contains(expr, " - ") || strings.Contains(expr, "[0]") {
				test.AssertTrue(t, res.LabelUsed)
			}
			insns := slices.Concat(res.Insns, asm.Instructions{asm.Return().WithSymbol("exit")})
			_, err = insns.SymbolOffsets()
			test.AssertNoErr(t, err)
			if runtime.GOOS == "linux" {
				var encoded bytes.Buffer
				test.AssertNoErr(t, insns.Marshal(&encoded, binary.LittleEndian))
			}
		})
	}
}

func TestMapLookupFieldRegistersReleased(t *testing.T) {
	for _, term := range []string{
		`map_lookup("counts", key)->count`,
		`map_lookup("counts", key)[0].count`,
		`*map_lookup("keys", key)`,
	} {
		t.Run(term, func(t *testing.T) {
			c := prepareMapLookupCompiler(t)
			// A left-associated sum needs only a few live values, regardless of
			// how many lookups it performs.
			expr := strings.TrimSuffix(strings.Repeat(term+" + ", 16), " + ")
			v, err := c.evaluate(prepareCcExpr(t, expr))
			test.AssertNoErr(t, err)
			v, err = c.materialize(v)
			test.AssertNoErr(t, err)
			for reg := asm.R0; reg <= asm.R9; reg++ {
				test.AssertEqual(t, c.regalloc.IsUsed(reg), reg == v.reg || reg == asm.R9)
			}
		})
	}
}

// Check the helper ABI and failure branch directly, without a test-only BPF VM.
func TestMapLookupHelperInstructions(t *testing.T) {
	c := prepareMapLookupCompiler(t)
	c.reservedStack = 16
	v, err := c.evaluate(prepareCcExpr(t, `map_lookup("counts", key)`))
	test.AssertNoErr(t, err)

	insns := c.insns
	var calls []int
	for i, ins := range insns {
		if ins.OpCode.JumpOp() == asm.Call {
			calls = append(calls, i)
		}
	}
	test.AssertEqual(t, len(calls), 2)
	copyAt, lookupAt := calls[0], calls[1]
	assertInsn := func(got, want asm.Instruction) {
		t.Helper()
		test.AssertEqual(t, fmt.Sprint(got), fmt.Sprint(want))
	}
	assertInsn(insns[copyAt], asm.FnProbeReadKernel.Call())
	assertInsn(insns[copyAt-4], asm.Mov.Reg(asm.R3, v.reg))
	assertInsn(insns[copyAt-3], asm.Mov.Imm(asm.R2, 4))
	assertInsn(insns[copyAt-2], asm.Mov.Reg(asm.R1, asm.RFP))
	assertInsn(insns[copyAt-1], asm.Add.Imm(asm.R1, -24))

	// Failed key copies return NULL and skip the map helper.
	lookupLabel := insns[lookupAt-3].Symbol()
	doneLabel := insns[lookupAt+1].Symbol()
	test.AssertTrue(t, lookupLabel != "" && doneLabel != "" && lookupLabel != doneLabel)
	assertInsn(insns[copyAt+1], asm.JEq.Imm(asm.R0, 0, lookupLabel))
	assertInsn(insns[copyAt+2], asm.Mov.Imm(asm.R0, 0))
	assertInsn(insns[copyAt+3], asm.Ja.Label(doneLabel))
	assertInsn(insns[lookupAt-3], asm.LoadMapPtr(asm.R1, 7).WithSymbol(lookupLabel))
	assertInsn(insns[lookupAt-2], asm.Mov.Reg(asm.R2, asm.RFP))
	assertInsn(insns[lookupAt-1], asm.Add.Imm(asm.R2, -24))
	assertInsn(insns[lookupAt], asm.FnMapLookupElem.Call())
	assertInsn(insns[lookupAt+1], asm.Mov.Reg(v.reg, asm.R0).WithSymbol(doneLabel))
}

func TestMapLookupRegisterSpills(t *testing.T) {
	for _, used := range [][]asm.Register{
		nil,
		{asm.R0, asm.R2, asm.R5},
		{asm.R1, asm.R2, asm.R3, asm.R4, asm.R5, asm.R6, asm.R7, asm.R8},
		{asm.R0, asm.R2, asm.R3, asm.R4, asm.R5, asm.R6, asm.R7, asm.R8},
	} {
		t.Run(fmt.Sprint(used), func(t *testing.T) {
			c := prepareMapLookupCompiler(t)
			c.reservedStack = 16
			for _, r := range used {
				c.regalloc.MarkUsed(r)
			}
			v, err := c.evaluate(prepareCcExpr(t, `map_lookup("counts", key)`))
			test.AssertNoErr(t, err)
			spills := make(map[asm.Register]int16)
			for _, ins := range c.insns {
				if ins.OpCode.Class() == asm.StXClass {
					test.AssertEqual(t, ins.Dst, asm.RFP)
					test.AssertTrue(t, ins.Offset < -24) // Below reserved stack and key.
					test.AssertTrue(t, slices.Contains(used, ins.Src) && ins.Src != v.reg)
					spills[ins.Src] = ins.Offset
				}
				if ins.OpCode.Class() == asm.LdXClass && ins.Src == asm.RFP {
					test.AssertEqual(t, ins.Offset, spills[ins.Dst])
					delete(spills, ins.Dst)
				}
			}
			test.AssertEqual(t, len(spills), 0)
			for _, r := range used {
				if r <= asm.R5 {
					test.AssertTrue(t, slices.ContainsFunc(c.insns, func(ins asm.Instruction) bool {
						return ins.OpCode.Class() == asm.StXClass && ins.Src == r
					}))
				}
			}
		})
	}
}

func TestMapLookupNullKey(t *testing.T) {
	c := prepareMapLookupCompiler(t)
	v, err := c.evaluate(prepareCcExpr(t, `map_lookup("counts", (int *)0)`))
	test.AssertNoErr(t, err)
	test.AssertEqual(t, fmt.Sprint(c.insns[0]), fmt.Sprint(asm.Mov.Imm(v.reg, 0)))
}

func TestMapLookupExplicitKeySize(t *testing.T) {
	for _, key := range []string{"key", "small", "voidptr", "incomplete"} {
		for _, size := range []string{"4", "16"} {
			expr := fmt.Sprintf(`bpf_map_lookup_elem("counts", %s, %s)`, key, size)
			t.Run(expr, func(t *testing.T) {
				c := prepareMapLookupCompiler(t)
				v, err := c.evaluate(prepareCcExpr(t, expr))
				test.AssertNoErr(t, err)
				test.AssertEqual(t, v.btf.(*btf.Pointer).Target, c.maps[BPFMapID{Name: "counts"}].Value)
				// The declared buffer size never changes the map's key-copy size.
				test.AssertTrue(t, slices.ContainsFunc(c.insns, func(ins asm.Instruction) bool {
					return ins.OpCode == asm.Mov.Op(asm.ImmSource) && ins.Dst == asm.R2 && ins.Constant == 4
				}))
			})
		}
	}
	for _, tt := range []struct{ args, want string }{
		{`"counts", voidptr, 0`, "must be at least map key size 4"},
		{`"counts", small, 3`, "must be at least map key size 4"},
		{`"counts", key, -1`, "invalid bpf_map_lookup_elem() key size"},
		{`"counts", key, n`, "invalid bpf_map_lookup_elem() key size"},
		{`"counts", key, 1.5`, "invalid bpf_map_lookup_elem() key size"},
		{`"counts", n, 4`, "key must be a pointer"},
	} {
		t.Run(tt.args, func(t *testing.T) {
			c := prepareMapLookupCompiler(t)
			_, err := c.evaluate(prepareCcExpr(t, "bpf_map_lookup_elem("+tt.args+")"))
			test.AssertHaveErr(t, err)
			test.AssertStrContains(t, err.Error(), tt.want)
		})
	}
}

func TestMapLookupInferredKeySize(t *testing.T) {
	for _, size := range []uint32{4, 12} {
		for _, key := range []string{"key", "small", "large", "voidptr", "incomplete"} {
			t.Run(fmt.Sprintf("%d/%s", size, key), func(t *testing.T) {
				c := prepareMapLookupCompiler(t)
				m := c.maps[BPFMapID{Name: "counts"}]
				m.KeySize = size
				m.Key = &btf.Struct{Size: size}
				c.maps[BPFMapID{Name: "counts"}] = m
				_, err := c.evaluate(prepareCcExpr(t, `map_lookup("counts", `+key+`)`))
				test.AssertNoErr(t, err)
				copyIdx := slices.IndexFunc(c.insns, func(ins asm.Instruction) bool {
					return ins == asm.FnProbeReadKernel.Call()
				})
				if copyIdx < 3 {
					t.Fatal("missing key copy")
				}
				test.AssertEqual(t, c.insns[copyIdx-3], asm.Mov.Imm(asm.R2, int32(size)))
			})
		}
	}
	for _, tt := range []struct {
		key  btf.Type
		want string
	}{
		{nil, "cannot infer key size without map key BTF"},
		{&btf.Fwd{Name: "incomplete"}, "failed to infer map_lookup() key size from map key BTF"},
		{&btf.Int{Size: 1}, "key size 1 must be at least map key size 4"},
	} {
		c := prepareMapLookupCompiler(t)
		m := c.maps[BPFMapID{Name: "counts"}]
		m.Key = tt.key
		c.maps[BPFMapID{Name: "counts"}] = m
		_, err := c.evaluate(prepareCcExpr(t, `map_lookup("counts", key)`))
		test.AssertHaveErr(t, err)
		test.AssertStrContains(t, err.Error(), tt.want)
	}

	t.Run("explicit size without key BTF", func(t *testing.T) {
		c := prepareMapLookupCompiler(t)
		m := c.maps[BPFMapID{Name: "counts"}]
		m.Key = nil
		c.maps[BPFMapID{Name: "counts"}] = m
		_, err := c.evaluate(prepareCcExpr(t, `map_lookup("counts", voidptr, 4)`))
		test.AssertNoErr(t, err)
	})
}

func TestMapLookupAlias(t *testing.T) {
	for _, args := range []string{
		`"counts", key`, `42, key`, `"counts", voidptr, 4`,
		`"counts", small, 16`, `"counts", key, 0`, `"counts", key, n`,
	} {
		t.Run(args, func(t *testing.T) {
			alias, helper := prepareMapLookupCompiler(t), prepareMapLookupCompiler(t)
			aliasExpr, helperExpr := "map_lookup("+args+")", "bpf_map_lookup_elem("+args+")"
			_, aliasErr := alias.evaluate(prepareCcExpr(t, aliasExpr))
			_, helperErr := helper.evaluate(prepareCcExpr(t, helperExpr))
			test.AssertEqual(t, aliasErr == nil, helperErr == nil)
			if aliasErr != nil {
				test.AssertStrContains(t, aliasErr.Error(), "map_lookup()")
				test.AssertStrContains(t, helperErr.Error(), "bpf_map_lookup_elem()")
				test.AssertEqual(t, strings.ReplaceAll(aliasErr.Error(), "map_lookup()", "bpf_map_lookup_elem()"), helperErr.Error())
			}
			test.AssertEqual(t, fmt.Sprint(alias.insns), fmt.Sprint(helper.insns))
			a, err := AnalyzeExpr(aliasExpr)
			test.AssertNoErr(t, err)
			b, err := AnalyzeExpr(helperExpr)
			test.AssertNoErr(t, err)
			test.AssertEqualSlice(t, a.Maps, b.Maps)
			test.AssertEqualSlice(t, a.Vars, b.Vars)
		})
	}
}

func TestValidateMapExpr(t *testing.T) {
	for _, expr := range []string{
		`map_lookup("counts", key)`,
		`bpf_map_lookup_elem("counts", key, 4)`,
		`h2nl(n)`,
	} {
		t.Run(expr, func(t *testing.T) {
			test.AssertNoErr(t, validateMapExpr(prepareCcExpr(t, expr)))
		})
	}
}

// A lookup failure can precede allocation of the final comparison register.
// The filter failure target must initialize it without reading its old value.
func TestMapLookupFilterFailureExit(t *testing.T) {
	for _, expr := range []string{
		`map_lookup("counts", &skb->dev->ifindex)->count == 42`,
		`map_lookup("counts", &skb->dev->ifindex)->count != 0`,
		`map_lookup("counts", &skb->dev->ifindex)->count == 42 || skb->len > 0`,
		`map_lookup("counts", &skb->dev->ifindex) == NULL`,
	} {
		t.Run(expr, func(t *testing.T) {
			c := prepareMapLookupCompiler(t)
			insns, err := CompileFilterExpr(CompileExprOptions{
				Expr: expr, Params: []btf.FuncParam{{Name: "skb", Type: getSkbBtf(t)}},
				Maps: c.maps, Spec: testBtf, Kernel: testBtf,
				LabelExit: "exit", MemoryReadMode: MemoryReadModeCoreRead,
			})
			test.AssertNoErr(t, err)
			exit := slices.IndexFunc(insns, func(ins asm.Instruction) bool { return ins.Symbol() == "exit" })
			test.AssertTrue(t, exit > 0)
			test.AssertEqual(t, insns[exit].OpCode, asm.Mov.Op(asm.ImmSource))
			test.AssertEqual(t, insns[exit].Constant, int64(0))
			// Successful evaluation skips the failure assignment.
			test.AssertEqual(t, insns[exit-1].OpCode, Ja(1).OpCode)
			test.AssertEqual(t, insns[exit-1].Offset, int16(1))
			// The initialized register is the one returned to the caller.
			test.AssertEqual(t, insns[exit+1].OpCode, asm.Mov.Op(asm.RegSource))
			test.AssertEqual(t, insns[exit+1].Src, insns[exit].Dst)
			test.AssertEqual(t, insns[exit+1].Dst, asm.R0)
		})
	}
}

func TestMapLookupPointerBoolean(t *testing.T) {
	for _, expr := range []string{
		`map_lookup("counts", key) == NULL`,
		`map_lookup("counts", key) != NULL`,
		`!map_lookup("counts", key)`,
		`map_lookup("counts", key) || map_lookup(42, key)`,
		`map_lookup("counts", key) && map_lookup(42, key)`,
		`bpf_map_lookup_elem("counts", (void *)0, 4) == NULL`,
	} {
		t.Run(expr, func(t *testing.T) {
			c := prepareMapLookupCompiler(t)
			_, err := c.evaluate(prepareCcExpr(t, expr))
			test.AssertNoErr(t, err)
			zeroes := 0
			for _, ins := range c.insns {
				// Clearing a map pointer with XOR is rejected by the verifier.
				test.AssertTrue(t, ins.OpCode != asm.Xor.Op(asm.RegSource))
				if ins.OpCode == asm.Mov.Op(asm.ImmSource) && ins.Constant == 0 {
					zeroes++
				}
			}
			// Both the key-copy failure path and boolean false write zero.
			test.AssertTrue(t, zeroes >= 2)
		})
	}
}
