// Copyright 2026 Liang Tang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"os"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"

	"github.com/bpfsnoop/bpfsnoop/internal/test"
)

// arenaKernelSpec adds the types of arena() to the test kernel BTF, which is
// older than struct bpf_arena.
type arenaKernelSpec struct {
	btfSpecer
	types map[string]btf.Type
}

func (s arenaKernelSpec) AnyTypeByName(name string) (btf.Type, error) {
	if typ, ok := s.types[name]; ok {
		return typ, nil
	}
	return s.btfSpecer.AnyTypeByName(name)
}

func testArenaStruct(members ...btf.Member) *btf.Struct {
	return &btf.Struct{Name: "bpf_arena", Size: 352, Members: members}
}

var (
	testArenaUserVMStart = btf.Member{Name: "user_vm_start", Type: &btf.Int{Name: "u64", Size: 8}, Offset: 248 * 8}
	testArenaKernVM      = btf.Member{Name: "kern_vm", Type: &btf.Pointer{Target: &btf.Struct{Name: "vm_struct"}}, Offset: 264 * 8}
)

func testArenaKernel(types map[string]btf.Type) btfSpecer {
	if types == nil {
		types = map[string]btf.Type{"bpf_arena": testArenaStruct(testArenaUserVMStart, testArenaKernVM)}
	}
	return arenaKernelSpec{testBtf, types}
}

// testArenaMaps has a 1 MiB arena, by name and by ID, a 1-page arena, and a
// hash map.
func testArenaMaps() map[BPFMapID]BPFMap {
	big := BPFMap{FD: 3, Type: ebpf.Arena, MaxEntries: 1 << 20 / uint32(os.Getpagesize())}
	return map[BPFMapID]BPFMap{
		{Name: "arena"}: big,
		{ID: 42}:        big,
		{Name: "small"}: {FD: 4, Type: ebpf.Arena, MaxEntries: 1},
		{Name: "hash"}:  {FD: 5, Type: ebpf.Hash, MaxEntries: 1, KeySize: 4},
	}
}

func compileArenaExpr(expr string, kernel btfSpecer, usedRegs ...asm.Register) (EvalResult, error) {
	return CompileEvalExpr(CompileExprOptions{
		Expr:          expr,
		LabelExit:     "__label_exit",
		Spec:          testBtf,
		Kernel:        kernel,
		Maps:          testArenaMaps(),
		UsedRegisters: usedRegs,

		MemoryReadFlag: MemoryReadFlagForce,
	})
}

func TestArenaGuardSize(t *testing.T) {
	test.AssertEqual(t, arenaGuardSize(4096), 1<<16)
	test.AssertEqual(t, arenaGuardSize(16384), 1<<16)
	test.AssertEqual(t, arenaGuardSize(65536), 1<<17)
}

func TestAnalyzeArena(t *testing.T) {
	for _, tt := range []struct {
		expr string
		maps []BPFMapID
		vars []string
	}{
		{`arena("arena")`, []BPFMapID{{Name: "arena"}}, nil},
		{`arena(42, 64)`, []BPFMapID{{ID: 42}}, nil},
		{`arena("arena", 64, 8)`, []BPFMapID{{Name: "arena"}}, nil},
		{`arena(42) == arena("arena")`, []BPFMapID{{Name: "arena"}, {ID: 42}}, nil},
		{`arena->user_vm_start`, nil, []string{"arena"}},
	} {
		t.Run(tt.expr, func(t *testing.T) {
			analysis, err := AnalyzeExpr(tt.expr)
			test.AssertNoErr(t, err)
			test.AssertEqualSlice(t, analysis.Maps, tt.maps)
			test.AssertEqualSlice(t, analysis.Vars, tt.vars)
		})
	}

	for _, tt := range []struct{ expr, err string }{
		{`arena()`, "arena() must have 1, 2 or 3 arguments"},
		{`arena("arena", 64, 8, 1)`, "arena() must have 1, 2 or 3 arguments"},
		{`arena(0)`, "invalid map ID"},
		{`arena(n)`, "first argument must be an integer ID or a string name"},
	} {
		t.Run(tt.expr, func(t *testing.T) {
			_, err := AnalyzeExpr(tt.expr)
			test.AssertHaveErr(t, err)
			test.AssertStrContains(t, err.Error(), tt.err)
		})
	}
}

func TestCompileArena(t *testing.T) {
	guard := int32(arenaGuardSize(os.Getpagesize()) / 2)

	for _, tt := range []struct {
		expr   string
		fd     int
		offset int32 // (u32)offset
		size   int
	}{
		{`arena("arena")`, 3, 0, 4096},
		{`arena(42)`, 3, 0, 4096},
		{`arena("small", 64)`, 4, 0, 64},
		{`arena("small", 16, 32)`, 4, 32, 16},
		{`arena("arena", 4096, 0xff000)`, 3, 0xff000, 4096},
	} {
		t.Run(tt.expr, func(t *testing.T) {
			res, err := compileArenaExpr(tt.expr, testArenaKernel(nil))
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.Type, EvalResultTypeArena)
			test.AssertEqual(t, res.Size, tt.size)
			test.AssertEqual(t, res.Off, 0)
			test.AssertTrue(t, res.LabelUsed)
			test.AssertEqual(t, res.Reg, asm.R8)
			test.AssertEqualSlice(t, res.Insns, asm.Instructions{
				asm.LoadMapPtr(asm.R8, tt.fd),
				asm.LoadMem(asm.R7, asm.R8, 248, asm.DWord),
				asm.LoadMem(asm.R8, asm.R8, 264, asm.DWord),
				asm.JEq.Imm(asm.R8, 0, "__label_exit"),
				asm.LoadMem(asm.R8, asm.R8, 8, asm.DWord),
				asm.Add.Imm32(asm.R7, tt.offset),
				asm.Add.Reg(asm.R8, asm.R7),
				asm.Add.Imm(asm.R8, guard),
			})
			test.AssertEqualBtf(t, res.Btf, &btf.Array{
				Index:  &btf.Int{Name: "unsigned int", Size: 4},
				Type:   &btf.Int{Name: "u8", Size: 1},
				Nelems: uint32(tt.size),
			})
		})
	}

	// arena() is a u8 array anywhere else in an expression.
	for _, tt := range []struct {
		expr string
		typ  EvalResultType
		btf  btf.Type
	}{
		{`arena("small", 16)[4]`, EvalResultTypeDefault, &btf.Int{Name: "u8", Size: 1}},
		{`*(int *)arena("small", 4, 24)`, EvalResultTypeDeref, &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}},
		{`str(arena("small", 12, 4))`, EvalResultTypeString, nil},
		{`hex(arena("small", 16), 16)`, EvalResultTypeHex, nil},
	} {
		t.Run(tt.expr, func(t *testing.T) {
			res, err := compileArenaExpr(tt.expr, testArenaKernel(nil))
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.Type, tt.typ)
			test.AssertEqual(t, res.Insns[0].IsLoadFromMap(), true)
			test.AssertEqual(t, res.Insns[0].Constant, int64(4))
			if tt.btf != nil {
				test.AssertEqualBtf(t, res.Btf, tt.btf)
			}
		})
	}

	pageSize := os.Getpagesize()
	for _, tt := range []struct{ expr, err string }{
		{`arena()`, "arena() must have 1, 2 or 3 arguments"},
		{`arena(0)`, "invalid map ID"},
		{`arena("arena", 1, 2, 3)`, "arena() must have 1, 2 or 3 arguments"},
		{`arena("absent")`, `arena("absent"): map has not been opened`},
		{`arena("hash")`, `arena("hash"): map is not an arena but Hash`},
		{`arena("small", n)`, "arena() size must be a number"},
		{`arena("small", 0)`, "arena() size must be in (0, 4096]"},
		{`arena("small", 4097)`, "arena() size must be in (0, 4096]"},
		{`arena("small", 64, n)`, "arena() offset must be a number"},
		{`arena("small", 64, 0x2000000)`, "64 bytes at offset 33554432 are out of the arena"},
		{`arena("small", 64, 0xffffffffffffffff)`, "64 bytes at offset -1 are out of the arena"},
		{`map_lookup("small", 0)`, `map_lookup("small"): use arena() for an arena map`},
	} {
		t.Run(tt.expr, func(t *testing.T) {
			_, err := compileArenaExpr(tt.expr, testArenaKernel(nil))
			test.AssertHaveErr(t, err)
			test.AssertStrContains(t, err.Error(), tt.err)
		})
	}

	t.Run("out of a 1-page arena", func(t *testing.T) {
		_, err := compileArenaExpr(`arena("small", 64, 4064)`, testArenaKernel(nil))
		if pageSize == 4096 {
			test.AssertErrContains(t, err, "64 bytes at offset 4064 are out of the arena of 4096 bytes")
		} else {
			test.AssertNoErr(t, err)
		}
	})

	t.Run("kernel BTF", func(t *testing.T) {
		vmStruct, err := testBtf.AnyTypeByName("vm_struct")
		test.AssertNoErr(t, err)

		for _, tt := range []struct {
			name  string
			types map[string]btf.Type
			err   string
		}{
			{"no bpf_arena", map[string]btf.Type{}, "failed to find struct bpf_arena"},
			{"bpf_arena not a struct", map[string]btf.Type{"bpf_arena": &btf.Int{Name: "bpf_arena", Size: 8}}, "bpf_arena is not a struct"},
			{"no user_vm_start", map[string]btf.Type{"bpf_arena": testArenaStruct(testArenaKernVM)}, "failed to find user_vm_start of struct bpf_arena"},
			{"no kern_vm", map[string]btf.Type{"bpf_arena": testArenaStruct(testArenaUserVMStart)}, "failed to find kern_vm of struct bpf_arena"},
			{"no vm_struct addr", map[string]btf.Type{
				"bpf_arena": testArenaStruct(testArenaUserVMStart, testArenaKernVM),
				"vm_struct": &btf.Struct{Name: "vm_struct", Size: vmStruct.(*btf.Struct).Size},
			}, "failed to find addr of struct vm_struct"},
		} {
			t.Run(tt.name, func(t *testing.T) {
				_, err := compileArenaExpr(`arena("small")`, testArenaKernel(tt.types))
				test.AssertErrContains(t, err, tt.err)
			})
		}
	})

	t.Run("register exhaustion", func(t *testing.T) {
		_, err := compileArenaExpr(`arena("small")`, testArenaKernel(nil),
			asm.R0, asm.R1, asm.R2, asm.R3, asm.R4, asm.R5, asm.R6, asm.R7, asm.R8, asm.R9)
		test.AssertIsErr(t, err, ErrRegisterNotEnough)

		_, err = compileArenaExpr(`arena("small")`, testArenaKernel(nil),
			asm.R0, asm.R1, asm.R2, asm.R3, asm.R4, asm.R5, asm.R6, asm.R7, asm.R9)
		test.AssertIsErr(t, err, ErrRegisterNotEnough)
	})

	t.Run("filter", func(t *testing.T) {
		insns, err := CompileFilterExpr(CompileExprOptions{
			Expr:      `arena("small", 4)[0] == 1`,
			LabelExit: "__label_exit",
			Spec:      testBtf,
			Kernel:    testArenaKernel(nil),
			Maps:      testArenaMaps(),
		})
		test.AssertNoErr(t, err)
		test.AssertEqual(t, insns[1].IsLoadFromMap(), true)
		test.AssertEqual(t, insns[1].Constant, int64(4))
	})
}

func testTracedArena() *ArenaInfo {
	return &ArenaInfo{
		FD:        7,
		Params:    []string{"node"},
		guardHalf: 32768,
	}
}

func arenaTranslateInsns(arena *ArenaInfo) asm.Instructions {
	return asm.Instructions{
		asm.Mov.Reg(asm.R2, asm.R3),
		asm.LoadMapPtr(asm.R1, arena.FD),
		asm.Mov.Imm(asm.R3, arena.guardHalf),
		asm.Call.Label(ArenaAddrFunc),
		asm.Mov.Reg(asm.R3, asm.R0),
	}
}

// addArenaNode adds var node, an __arg_arena param pointing to
//
//	struct arena_node { int val; struct arena_node *next; struct task_struct *task; };
func addArenaNode(t *testing.T, c *compiler) {
	t.Helper()

	intTyp, err := testBtf.AnyTypeByName("int")
	test.AssertNoErr(t, err)
	taskTyp, err := testBtf.AnyTypeByName("task_struct")
	test.AssertNoErr(t, err)

	node := &btf.Struct{Name: "arena_node", Size: 24}
	node.Members = []btf.Member{
		{Name: "val", Type: intTyp},
		{Name: "next", Type: &btf.Pointer{Target: node}, Offset: 64},
		{Name: "task", Type: &btf.Pointer{Target: taskTyp}, Offset: 128},
	}
	c.vars = append(c.vars, "node")
	c.btfs = append(c.btfs, &btf.Pointer{Target: node})
}

// translations returns the indexes of the arena translations in insns, by
// their load of the arena map pointer.
func translations(insns asm.Instructions, arena *ArenaInfo) []int {
	var idx []int
	for i, ins := range insns {
		if ins.IsLoadFromMap() && ins.Constant == int64(arena.FD) {
			idx = append(idx, i)
		}
	}
	return idx
}

func TestNewArenaInfo(t *testing.T) {
	arena := NewArenaInfo(7)
	test.AssertEqual(t, arena.FD, 7)
	test.AssertEqual(t, arena.guardHalf, int32(arenaGuardSize(os.Getpagesize())/2))
}

func TestArenaTranslate(t *testing.T) {
	t.Run("no arena", func(t *testing.T) {
		test.AssertEmptySlice(t, ArenaTranslate(nil))
	})

	t.Run("arena", func(t *testing.T) {
		arena := testTracedArena()
		test.AssertEqualSlice(t, ArenaTranslate(arena), arenaTranslateInsns(arena))
	})
}

func TestArenaReads(t *testing.T) {
	arena := testTracedArena()

	for _, tt := range []struct {
		name  string
		expr  string
		core  bool
		reads int // translations
	}{
		{name: "arena param", expr: "node->val", reads: 1},
		{name: "address in the arena", expr: "&node->next"},
		{name: "pointer loaded from the arena", expr: "node->next->val", reads: 2},
		{name: "pointer loaded from the arena, core read", expr: "node->next->val", core: true, reads: 2},
		// Translated if it points into the arena, which it doesn't.
		{name: "kernel pointer stored in the arena", expr: "node->task->pid", reads: 2},
		{name: "kernel pointer stored in the arena, core read", expr: "node->task->pid", core: true, reads: 2},
		{name: "not an arena param", expr: "skb->dev->ifindex"},
		{name: "not an arena param, core read", expr: "skb->dev->ifindex", core: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := prepareCompiler(t)
			if tt.core {
				c = prepareCompilerCoreRead(t)
			}
			c.arena = arena
			addArenaNode(t, c)

			_, err := c.materialize(prepareExprVal(t, c, tt.expr))
			test.AssertNoErr(t, err)

			idx := translations(c.insns, arena)
			test.AssertEqual(t, len(idx), tt.reads)
			if tt.reads != 0 {
				// The translation comes before the first read.
				first := slices.IndexFunc(c.insns, func(ins asm.Instruction) bool { return ins.IsBuiltinCall() })
				test.AssertTrue(t, idx[0] < first)
			}
		})
	}

	t.Run("core read of a program-local struct", func(t *testing.T) {
		c := prepareCompilerCoreRead(t)
		c.arena = arena
		addArenaNode(t, c)

		_, err := c.materialize(prepareExprVal(t, c, "node->val"))
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, c.insns, append(append(asm.Instructions{
			asm.LoadMem(r8, argsReg, 48, dword), // node
			asm.Mov.Reg(r1, r8),
			asm.Mov.Reg(r3, r1),
		}, arenaTranslateInsns(arena)...),
			asm.Mov.Imm(r2, 8),
			asm.Mov.Reg(r1, rfp),
			asm.Add.Imm(r1, -8),
			asm.FnProbeReadKernel.Call(),
			asm.LoadMem(r8, rfp, -8, dword), // node->val
			asm.LSh.Imm(r8, 32),
			asm.ArSh.Imm(r8, 32),
		))
	})

	t.Run("eval result", func(t *testing.T) {
		c := prepareCompiler(t)
		addArenaNode(t, c)
		params := []btf.FuncParam{
			{Name: "skb", Type: getSkbBtf(t)},
			{Name: "node", Type: c.btfs[len(c.btfs)-1]},
		}

		for _, tt := range []struct {
			expr  string
			arena bool // the result may be an address in the arena
		}{
			{expr: "node", arena: true},
			{expr: "*node", arena: true},
			{expr: "node->next", arena: true},
			{expr: "*node->next", arena: true},
			{expr: "skb->dev"},
		} {
			res, err := CompileEvalExpr(CompileExprOptions{
				Expr: tt.expr, Params: params, Spec: testBtf, Kernel: testBtf,
				LabelExit: "__label_exit", Arena: arena,
			})
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.Arena, tt.arena)
		}
	})

	t.Run("filter expr", func(t *testing.T) {
		c := prepareCompiler(t)
		addArenaNode(t, c)

		insns, err := CompileFilterExpr(CompileExprOptions{
			Expr:      "node->next->val == 2 && skb->len == 0",
			LabelExit: "__label_exit",
			Spec:      testBtf,
			Kernel:    testBtf,
			Params: []btf.FuncParam{
				{Name: "skb", Type: getSkbBtf(t)},
				{Name: "node", Type: c.btfs[len(c.btfs)-1]},
			},
			Arena: arena,
		})
		test.AssertNoErr(t, err)
		test.AssertEqual(t, len(translations(insns, arena)), 2) // node->next, ->val
	})
}
