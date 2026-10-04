// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"testing"

	"github.com/bpfsnoop/bpfsnoop/internal/test"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

func TestMapValueDirectReads(t *testing.T) {
	u64 := &btf.Int{Size: 8}
	nest := &btf.Struct{Size: 8, Members: []btf.Member{{Name: "ptr", Type: u64}}}
	skb, err := testBtf.AnyTypeByName("sk_buff")
	test.AssertNoErr(t, err)
	value := &btf.Struct{Size: 104, Members: []btf.Member{
		{Name: "ptr", Type: u64},
		{Name: "nest", Type: nest, Offset: 64},
		{Name: "kernel", Type: &btf.Pointer{Target: skb}, Offset: 128},
		{Name: "arr", Type: &btf.Array{Type: u64, Nelems: 1}, Offset: 192},
		{Name: "small", Type: &btf.Int{Size: 1}, Offset: 256},
		{Name: "half", Type: &btf.Int{Size: 2}, Offset: 272},
		{Name: "word", Type: &btf.Int{Size: 4}, Offset: 288},
		{Name: "nums", Type: &btf.Array{Type: u64, Nelems: 2}, Offset: 320},
		{Name: "nests", Type: &btf.Array{Type: nest, Nelems: 2}, Offset: 448},
		{Name: "matrix", Type: &btf.Array{Type: &btf.Array{Type: u64, Nelems: 2}, Nelems: 2}, Offset: 576},
	}}
	for name, mode := range map[string]MemoryReadMode{
		"probe": MemoryReadModeProbeRead,
		"core":  MemoryReadModeCoreRead,
	} {
		t.Run(name, func(t *testing.T) {
			for _, tt := range []struct {
				expr   string
				offset int16
				size   asm.Size
				kernel bool
			}{
				{`map_lookup("v", key)->ptr`, 0, asm.DWord, false},
				{`map_lookup("v", key)->nest.ptr`, 8, asm.DWord, false},
				{`map_lookup("v", key)->arr[0]`, 0, asm.DWord, false},
				{`map_lookup("v", key)->nums[1]`, 0, asm.DWord, false},
				{`map_lookup("v", key)->nests[1].ptr`, 0, asm.DWord, false},
				{`map_lookup("v", key)->matrix[1][1]`, 0, asm.DWord, false},
				{`map_lookup("v", key)->small`, 32, asm.Byte, false},
				{`map_lookup("v", key)->half`, 34, asm.Half, false},
				{`(unsigned long)map_lookup("v", key)->word`, 36, asm.Word, false},
				{`((struct sk_buff *)map_lookup("v", key)->ptr)->dev->ifindex`, 0, asm.DWord, true},
				{`((struct sk_buff *)map_lookup("v", key)->nest.ptr)->dev->ifindex`, 8, asm.DWord, true},
				{`map_lookup("v", key)->kernel->dev->ifindex`, 16, asm.DWord, true},
				{`h2nl(*(&map_lookup("v", key)->word))`, 0, asm.Word, false},
			} {
				t.Run(tt.expr, func(t *testing.T) {
					c := prepareMapLookupCompiler(t)
					c.memMode = mode
					c.maps[BPFMapID{Name: "v"}] = BPFMap{FD: 7, KeySize: 4, Key: &btf.Int{Size: 4}, Value: value}
					v, err := c.evaluate(prepareCcExpr(t, tt.expr))
					test.AssertNoErr(t, err)
					_, err = c.materialize(v)
					test.AssertNoErr(t, err)
					calls, loads := 0, 0
					for _, ins := range c.insns {
						if ins.OpCode.JumpOp() == asm.Call {
							calls++
						}
						if ins.OpCode.Class() == asm.LdXClass && ins.Src == ins.Dst && ins.Offset == tt.offset && ins.OpCode.Size() == tt.size {
							loads++
						}
					}
					if loads != 1 {
						t.Fatalf("expected one direct field load, got %d:\n%v", loads, c.insns)
					}
					if (!tt.kernel && calls != 2) || (tt.kernel && calls <= 2) {
						t.Fatalf("unexpected helper count %d:\n%v", calls, c.insns)
					}
					test.AssertTrue(t, c.labelExitUsed)
				})
			}
		})
	}
}

func TestMapValueReadInvalidBTF(t *testing.T) {
	c := prepareMapLookupCompiler(t)
	c.maps[BPFMapID{Name: "bad"}] = BPFMap{
		FD: 7, KeySize: 4, Key: &btf.Int{Size: 4},
		Value: &btf.Struct{Size: 8, Members: []btf.Member{
			{Name: "field", Type: &btf.Fwd{Name: "incomplete"}},
		}},
	}
	_, err := c.evaluate(prepareCcExpr(t, `(unsigned long)map_lookup("bad", key)->field`))
	test.AssertHaveErr(t, err)
	test.AssertStrContains(t, err.Error(), "failed to get size")
}
