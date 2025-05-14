// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
	"unsafe"

	"github.com/bpfsnoop/bpfsnoop/internal/test"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"rsc.io/c2go/cc"
)

func equalsOffset(t *testing.T, a, b accessOffset) {
	t.Helper()
	test.AssertEqual(t, a.offset, b.offset)
	test.AssertEqual(t, a.address, b.address)
	test.AssertEqual(t, fmt.Sprintf("%v", a.btf), fmt.Sprintf("%v", b.btf))
	test.AssertEqual(t, fmt.Sprintf("%v", a.prev), fmt.Sprintf("%v", b.prev))
}

func TestAccessMemory(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("name", func(t *testing.T) {
		t.Run("not_found", func(t *testing.T) {
			_, err := c.accessMemory(&cc.Expr{
				Op:   cc.Name,
				Text: "not_found",
			})
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
		})

		t.Run("prog", func(t *testing.T) {
			res, err := c.accessMemory(&cc.Expr{
				Op:   cc.Name,
				Text: "prog",
			})
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.idx, 1)
		})
	})

	t.Run("dot,arrow", func(t *testing.T) {
		t.Run(".not_found", func(t *testing.T) {
			_, err := c.accessMemory(&cc.Expr{
				Op: cc.Dot,
				Left: &cc.Expr{
					Op:   cc.Name,
					Text: "not_found",
				},
			})
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
		})

		t.Run("skb->pkt_type.a", func(t *testing.T) {
			expr, err := cc.ParseExpr("skb->pkt_type.a")
			test.AssertNoErr(t, err)

			_, err = c.accessMemory(expr)
			test.AssertHaveErr(t, err)
			test.AssertEqual(t, err.Error(), "cannot access member of a bitfield type")
		})

		t.Run("skb->len.a", func(t *testing.T) {
			expr, err := cc.ParseExpr("skb->len.a")
			test.AssertNoErr(t, err)

			_, err = c.accessMemory(expr)
			test.AssertHaveErr(t, err)
			test.AssertStrPrefix(t, err.Error(), "unsupported type")
		})

		t.Run("skb->not_found", func(t *testing.T) {
			expr, err := cc.ParseExpr("skb->not_found")
			test.AssertNoErr(t, err)

			_, err = c.accessMemory(expr)
			test.AssertHaveErr(t, err)
			test.AssertStrPrefix(t, err.Error(), "failed to find member")
		})

		t.Run("skb.len", func(t *testing.T) {
			skb, err := testBtf.AnyTypeByName("sk_buff")
			test.AssertNoErr(t, err)

			expr, err := cc.ParseExpr("skb.len")
			test.AssertNoErr(t, err)

			c.btfs[0] = skb
			defer func() { c.btfs[0] = getSkbBtf(t) }()

			_, err = c.accessMemory(expr)
			test.AssertHaveErr(t, err)
			test.AssertStrPrefix(t, err.Error(), "disallow accessing member len of skb via dot")
		})

		t.Run("skb->len", func(t *testing.T) {
			expr, err := cc.ParseExpr("skb->len")
			test.AssertNoErr(t, err)

			skb := getSkbBtf(t)
			unsignedInt, err := testBtf.AnyTypeByName("unsigned int")
			test.AssertNoErr(t, err)

			res, err := c.accessMemory(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.idx, 0)
			test.AssertEqualSliceFn(t, res.offsets,
				[]accessOffset{{prev: skb, offset: 112, btf: unsignedInt}},
				equalsOffset)
		})

		t.Run("skb->users.refs.counter", func(t *testing.T) {
			expr, err := cc.ParseExpr("skb->users.refs.counter")
			test.AssertNoErr(t, err)

			skb := getSkbBtf(t)
			intTyp, err := testBtf.AnyTypeByName("int")
			test.AssertNoErr(t, err)

			res, err := c.accessMemory(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.idx, 0)
			test.AssertEqualSliceFn(t, res.offsets,
				[]accessOffset{{prev: skb, btf: intTyp, offset: 220}},
				equalsOffset)
		})

		t.Run("skb->cb", func(t *testing.T) {
			expr, err := cc.ParseExpr("skb->cb")
			test.AssertNoErr(t, err)

			skb := getSkbBtf(t)
			intTyp, err := testBtf.AnyTypeByName("int")
			test.AssertNoErr(t, err)
			char, err := testBtf.AnyTypeByName("char")
			test.AssertNoErr(t, err)
			cb := &btf.Array{
				Type:   char,
				Index:  intTyp,
				Nelems: 48,
			}

			res, err := c.accessMemory(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.idx, 0)
			test.AssertEqualSliceFn(t, res.offsets,
				[]accessOffset{{prev: skb, btf: cb, offset: 40, address: true}},
				equalsOffset)
		})

		t.Run("attr->map_type", func(t *testing.T) {
			expr, err := cc.ParseExpr("attr->map_type")
			test.AssertNoErr(t, err)

			attr := getBpfAttrBtf(t)
			u32, err := testBtf.AnyTypeByName("__u32")
			test.AssertNoErr(t, err)

			res, err := c.accessMemory(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.idx, 3)
			test.AssertEqualSliceFn(t, res.offsets,
				[]accessOffset{{prev: attr, btf: u32, offset: 0}},
				equalsOffset)
		})
	})

	t.Run("add", func(t *testing.T) {
		t.Run("number(not_found) + 1", func(t *testing.T) {
			expr := &cc.Expr{
				Op: cc.Add,
				Left: &cc.Expr{
					Op:   cc.Number,
					Text: "not_found",
				},
			}

			_, err := c.accessMemory(expr)
			test.AssertHaveErr(t, err)
			test.AssertStrPrefix(t, err.Error(), "failed to parse number of add.left")
		})

		t.Run("1 + skb->pkt_type.a", func(t *testing.T) {
			rexpr, err := cc.ParseExpr("skb->pkt_type.a")
			test.AssertNoErr(t, err)

			expr := &cc.Expr{
				Op: cc.Add,
				Left: &cc.Expr{
					Op:   cc.Number,
					Text: "1",
				},
				Right: rexpr,
			}

			_, err = c.accessMemory(expr)
			test.AssertHaveErr(t, err)
			test.AssertStrPrefix(t, err.Error(), "failed to parse right of add")
		})

		t.Run("skb->pkt_type.a + number(not_found)", func(t *testing.T) {
			lexpr, err := cc.ParseExpr("skb->pkt_type.a")
			test.AssertNoErr(t, err)

			expr := &cc.Expr{
				Op:   cc.Add,
				Left: lexpr,
				Right: &cc.Expr{
					Op:   cc.Number,
					Text: "not_found",
				},
			}

			_, err = c.accessMemory(expr)
			test.AssertHaveErr(t, err)
			test.AssertStrPrefix(t, err.Error(), "failed to parse number of add.right")
		})

		t.Run("skb->pkt_type.a + 1", func(t *testing.T) {
			lexpr, err := cc.ParseExpr("skb->pkt_type.a")
			test.AssertNoErr(t, err)

			expr := &cc.Expr{
				Op:   cc.Add,
				Left: lexpr,
				Right: &cc.Expr{
					Op:   cc.Number,
					Text: "1",
				},
			}

			_, err = c.accessMemory(expr)
			test.AssertHaveErr(t, err)
			test.AssertStrPrefix(t, err.Error(), "failed to parse left of add")
		})

		t.Run("skb->len + skb->head", func(t *testing.T) {
			lexpr, err := cc.ParseExpr("skb->len")
			test.AssertNoErr(t, err)

			rexpr, err := cc.ParseExpr("skb->head")
			test.AssertNoErr(t, err)

			expr := &cc.Expr{
				Op:    cc.Add,
				Left:  lexpr,
				Right: rexpr,
			}

			_, err = c.accessMemory(expr)
			test.AssertHaveErr(t, err)
			test.AssertStrPrefix(t, err.Error(), "number is required for add")
		})

		t.Run("skb->pkt_type + 1", func(t *testing.T) {
			expr, err := cc.ParseExpr("skb->pkt_type + 1")
			test.AssertNoErr(t, err)

			_, err = c.accessMemory(expr)
			test.AssertHaveErr(t, err)
			test.AssertStrPrefix(t, err.Error(), "disallow using bitfield for add")
		})

		t.Run("ops->lookup_elem + 1", func(t *testing.T) {
			expr, err := cc.ParseExpr("ops->lookup_elem + 1")
			test.AssertNoErr(t, err)

			_, err = c.accessMemory(expr)
			test.AssertHaveErr(t, err)
			test.AssertStrPrefix(t, err.Error(), "disallow type")
		})

		t.Run("ops->batch_lookup_elem + 1", func(t *testing.T) {
			expr, err := cc.ParseExpr("ops->batch_lookup_elem + 1")
			test.AssertNoErr(t, err)

			_, err = c.accessMemory(expr)
			test.AssertHaveErr(t, err)
			test.AssertStrPrefix(t, err.Error(), "disallow type")
		})

		t.Run("skb->users + 1", func(t *testing.T) {
			expr, err := cc.ParseExpr("skb->users + 1")
			test.AssertNoErr(t, err)

			_, err = c.accessMemory(expr)
			test.AssertHaveErr(t, err)
			test.AssertStrPrefix(t, err.Error(), "disallow using non-{pointer,array} for add")
		})

		t.Run("skb + 0", func(t *testing.T) {
			expr, err := cc.ParseExpr("skb + 0")
			test.AssertNoErr(t, err)

			skb := getSkbBtf(t)

			res, err := c.accessMemory(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.idx, 0)
			test.AssertEqual(t, fmt.Sprintf("%v", res.btf), fmt.Sprintf("%v", skb))
		})

		t.Run("skb + 1", func(t *testing.T) {
			expr, err := cc.ParseExpr("skb + 1")
			test.AssertNoErr(t, err)

			skb := getSkbBtf(t)

			res, err := c.accessMemory(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.idx, 0)
			test.AssertEqualSliceFn(t, res.offsets,
				[]accessOffset{{btf: skb, offset: 232, address: true}},
				equalsOffset)
		})

		t.Run("prog->aux->jit_data + 1", func(t *testing.T) {
			expr, err := cc.ParseExpr("prog->aux->jit_data + 1")
			test.AssertNoErr(t, err)

			prog := getBpfProgBtf(t)
			aux := getBpfProgAuxBtf(t)
			vptr := &btf.Pointer{Target: &btf.Void{}}

			res, err := c.accessMemory(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.idx, 1)
			test.AssertEqualSliceFn(t, res.offsets,
				[]accessOffset{
					{prev: prog, btf: aux, offset: 56},
					{prev: aux, btf: vptr, offset: 176},
					{prev: aux, btf: vptr, offset: 1, address: true},
				},
				equalsOffset)
		})

		t.Run("skb->cb + 1", func(t *testing.T) {
			expr, err := cc.ParseExpr("skb->cb + 1")
			test.AssertNoErr(t, err)

			skb := getSkbBtf(t)
			char, err := testBtf.AnyTypeByName("char")
			test.AssertNoErr(t, err)
			intTyp, err := testBtf.AnyTypeByName("int")
			test.AssertNoErr(t, err)
			cb := &btf.Array{
				Type:   char,
				Index:  intTyp,
				Nelems: 48,
			}
			charPtr := &btf.Pointer{Target: char}

			res, err := c.accessMemory(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.idx, 0)
			test.AssertEqualSliceFn(t, res.offsets,
				[]accessOffset{
					{prev: skb, btf: cb, offset: 40, address: true},
					{prev: skb, btf: charPtr, offset: 1, address: true},
				}, equalsOffset)
		})
	})

	t.Run("addr", func(t *testing.T) {
		t.Run("&not_found", func(t *testing.T) {
			_, err := c.accessMemory(&cc.Expr{
				Op: cc.Addr,
				Left: &cc.Expr{
					Op:   cc.Name,
					Text: "not_found",
				},
			})
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to access memory for addr")
		})

		t.Run("&skb", func(t *testing.T) {
			expr, err := cc.ParseExpr("&skb")
			test.AssertNoErr(t, err)

			_, err = c.accessMemory(expr)
			test.AssertHaveErr(t, err)
			test.AssertStrPrefix(t, err.Error(), "disallow address")
		})

		t.Run("&skb->len", func(t *testing.T) {
			expr, err := cc.ParseExpr("&skb->len")
			test.AssertNoErr(t, err)

			skb := getSkbBtf(t)
			intTyp, err := testBtf.AnyTypeByName("unsigned int")
			test.AssertNoErr(t, err)
			intPtr := &btf.Pointer{Target: intTyp}

			res, err := c.accessMemory(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.idx, 0)
			test.AssertEqualSliceFn(t, res.offsets,
				[]accessOffset{{prev: skb, btf: intPtr, offset: 112, address: true}},
				equalsOffset,
			)
		})
	})

	t.Run("cast", func(t *testing.T) {
		t.Run("not_found", func(t *testing.T) {
			_, err := c.accessMemory(&cc.Expr{
				Op: cc.Cast,
				Left: &cc.Expr{
					Op:   cc.Name,
					Text: "not_found",
				},
			})
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to access memory for cast")
		})

		t.Run("(struct not_found *)(skb->head)", func(t *testing.T) {
			expr, err := cc.ParseExpr("(struct not_found *)(skb->head)")
			test.AssertNoErr(t, err)

			_, err = c.accessMemory(expr)
			test.AssertHaveErr(t, err)
			test.AssertStrPrefix(t, err.Error(), "failed to find type")
		})

		t.Run("(struct u64 *)(skb->head)", func(t *testing.T) {
			expr, err := cc.ParseExpr("(struct u64 *)(skb->head)")
			test.AssertNoErr(t, err)

			_, err = c.accessMemory(expr)
			test.AssertHaveErr(t, err)
			test.AssertStrPrefix(t, err.Error(), "expected struct/union type for cast")
		})

		t.Run("(union not_found *)(skb->head)", func(t *testing.T) {
			expr, err := cc.ParseExpr("(union not_found *)(skb->head)")
			test.AssertNoErr(t, err)

			_, err = c.accessMemory(expr)
			test.AssertHaveErr(t, err)
			test.AssertStrPrefix(t, err.Error(), "failed to find type")
		})

		t.Run("(union u64 *)(skb->head)", func(t *testing.T) {
			expr, err := cc.ParseExpr("(union u64 *)(skb->head)")
			test.AssertNoErr(t, err)

			_, err = c.accessMemory(expr)
			test.AssertHaveErr(t, err)
			test.AssertStrPrefix(t, err.Error(), "expected struct/union type for cast")
		})

		t.Run("(long long)skb->head", func(t *testing.T) {
			expr, err := cc.ParseExpr("(long long)skb->head")
			test.AssertNoErr(t, err)

			_, err = c.accessMemory(expr)
			test.AssertHaveErr(t, err)
			test.AssertStrPrefix(t, err.Error(), "failed to find type")
		})

		t.Run("(struct ethhdr *)(skb->head)", func(t *testing.T) {
			expr, err := cc.ParseExpr("(struct ethhdr *)(skb->head)")
			test.AssertNoErr(t, err)

			skb := getSkbBtf(t)
			eth, err := testBtf.AnyTypeByName("ethhdr")
			test.AssertNoErr(t, err)
			ethPtr := &btf.Pointer{Target: eth}

			res, err := c.accessMemory(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.idx, 0)
			test.AssertEqualSliceFn(t, res.offsets,
				[]accessOffset{{prev: skb, btf: ethPtr, offset: 200}},
				equalsOffset)
			test.AssertTrue(t, reflect.DeepEqual(res.btf, ethPtr))
		})

		t.Run("(int)(skb->head)", func(t *testing.T) {
			expr, err := cc.ParseExpr("(int)(skb->head)")
			test.AssertNoErr(t, err)

			skb := getSkbBtf(t)
			u64, err := testBtf.AnyTypeByName("int")
			test.AssertNoErr(t, err)

			res, err := c.accessMemory(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.idx, 0)
			test.AssertEqualSliceFn(t, res.offsets,
				[]accessOffset{{prev: skb, btf: u64, offset: 200}},
				equalsOffset)
			test.AssertTrue(t, reflect.DeepEqual(res.btf, u64))
		})
	})

	t.Run("index", func(t *testing.T) {
		t.Run("skb->cbx[3]", func(t *testing.T) {
			expr, err := cc.ParseExpr("skb->cbx[3]")
			test.AssertNoErr(t, err)

			_, err = c.accessMemory(expr)
			test.AssertHaveErr(t, err)
			test.AssertStrPrefix(t, err.Error(), "failed to access memory for index")
		})

		t.Run("skb->pkt_type[3]", func(t *testing.T) {
			expr, err := cc.ParseExpr("skb->pkt_type[3]")
			test.AssertNoErr(t, err)

			_, err = c.accessMemory(expr)
			test.AssertHaveErr(t, err)
			test.AssertStrPrefix(t, err.Error(), "disallow using bitfield for index")
		})

		t.Run("skb->cb[x]", func(t *testing.T) {
			expr, err := cc.ParseExpr("skb->cb[x]")
			test.AssertNoErr(t, err)

			_, err = c.accessMemory(expr)
			test.AssertHaveErr(t, err)
			test.AssertStrPrefix(t, err.Error(), "op of index expected number type")
		})

		t.Run("skb->cb[nan]", func(t *testing.T) {
			expr, err := cc.ParseExpr("skb->cb[nan]")
			test.AssertNoErr(t, err)

			expr.Right.Op = cc.Number

			_, err = c.accessMemory(expr)
			test.AssertHaveErr(t, err)
			test.AssertStrPrefix(t, err.Error(), "failed to parse number")
		})

		t.Run("ops->data[0]", func(t *testing.T) {
			expr, err := cc.ParseExpr("ops->data[0]")
			test.AssertNoErr(t, err)

			_, err = c.accessMemory(expr)
			test.AssertHaveErr(t, err)
			test.AssertStrPrefix(t, err.Error(), "disallow indexing pointer of type")
		})

		t.Run("ops->arr[0]", func(t *testing.T) {
			expr, err := cc.ParseExpr("ops->arr[0]")
			test.AssertNoErr(t, err)

			_, err = c.accessMemory(expr)
			test.AssertHaveErr(t, err)
			test.AssertStrPrefix(t, err.Error(), "disallow indexing array of type")
		})

		t.Run("skb->len[3]", func(t *testing.T) {
			expr, err := cc.ParseExpr("skb->len[3]")
			test.AssertNoErr(t, err)

			_, err = c.accessMemory(expr)
			test.AssertHaveErr(t, err)
			test.AssertStrPrefix(t, err.Error(), "disallow indexing type")
		})

		t.Run("prog->aux->jit_data[0]", func(t *testing.T) {
			expr, err := cc.ParseExpr("prog->aux->jit_data[0]")
			test.AssertNoErr(t, err)

			_, err = c.accessMemory(expr)
			test.AssertHaveErr(t, err)
			test.AssertStrPrefix(t, err.Error(), "disallow indexing pointer of type")
		})

		t.Run("prog->aux->used_maps[1]->map_type", func(t *testing.T) {
			expr, err := cc.ParseExpr("prog->aux->used_maps[1]->map_type")
			test.AssertNoErr(t, err)

			prog := getBpfProgBtf(t)
			bpfMap := getBpfMapBtf(t)
			aux := getBpfProgAuxBtf(t)

			bpfMapType, err := testBtf.AnyTypeByName("bpf_map_type")
			test.AssertNoErr(t, err)

			res, err := c.accessMemory(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.idx, 1)
			test.AssertEqualSliceFn(t, res.offsets,
				[]accessOffset{
					{prev: prog, btf: aux, offset: 56},
					{prev: aux, btf: &btf.Pointer{Target: bpfMap}, offset: 824},
					{prev: aux, btf: bpfMap, offset: 8},
					{prev: bpfMap, btf: bpfMapType, offset: 24},
				}, equalsOffset)
		})

		t.Run("skb->cb[3]", func(t *testing.T) {
			expr, err := cc.ParseExpr("skb->cb[3]")
			test.AssertNoErr(t, err)

			skb := getSkbBtf(t)
			intTyp, err := testBtf.AnyTypeByName("int")
			test.AssertNoErr(t, err)
			char, err := testBtf.AnyTypeByName("char")
			test.AssertNoErr(t, err)
			arr := &btf.Array{
				Type:   char,
				Index:  intTyp,
				Nelems: 48,
			}

			res, err := c.accessMemory(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.idx, 0)
			test.AssertEqualSliceFn(t, res.offsets, []accessOffset{
				{prev: skb, btf: arr, offset: 40, address: true},
				{prev: skb, btf: char, offset: 3},
			}, equalsOffset)
			test.AssertTrue(t, reflect.DeepEqual(res.btf, char))
		})
	})

	t.Run("indir", func(t *testing.T) {
		t.Run("not_found", func(t *testing.T) {
			_, err := c.accessMemory(&cc.Expr{
				Op: cc.Indir,
				Left: &cc.Expr{
					Op:   cc.Name,
					Text: "not_found",
				},
			})
			test.AssertHaveErr(t, err)
			test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
			test.AssertStrPrefix(t, err.Error(), "failed to access memory for indir")
		})

		t.Run("*(skb->pkt_type)", func(t *testing.T) {
			expr, err := cc.ParseExpr("*(skb->pkt_type)")
			test.AssertNoErr(t, err)

			_, err = c.accessMemory(expr)
			test.AssertHaveErr(t, err)
			test.AssertStrPrefix(t, err.Error(), "disallow indirecting bitfield")
		})

		t.Run("*(skb->len)", func(t *testing.T) {
			expr, err := cc.ParseExpr("*(skb->len)")
			test.AssertNoErr(t, err)

			_, err = c.accessMemory(expr)
			test.AssertHaveErr(t, err)
			test.AssertStrPrefix(t, err.Error(), "disallow indirecting type")
		})

		t.Run("*(skb->sk)", func(t *testing.T) {
			expr, err := cc.ParseExpr("*(skb->sk)")
			test.AssertNoErr(t, err)

			skb := getSkbBtf(t)
			sk, err := testBtf.AnyTypeByName("sock")
			test.AssertNoErr(t, err)
			skPtr := &btf.Pointer{Target: sk}

			res, err := c.accessMemory(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.idx, 0)
			test.AssertEqualSliceFn(t, res.offsets, []accessOffset{
				{prev: skb, btf: skPtr, offset: 24},
				{prev: skPtr, btf: sk, offset: 0},
			}, equalsOffset)
			test.AssertTrue(t, reflect.DeepEqual(res.btf, sk))
		})
	})

	t.Run("sub", func(t *testing.T) {
		t.Run("1 - skb->len", func(t *testing.T) {
			expr, err := cc.ParseExpr("1 - skb->len")
			test.AssertNoErr(t, err)

			_, err = c.accessMemory(expr)
			test.AssertHaveErr(t, err)
			test.AssertStrPrefix(t, err.Error(), "sub.right must be number")
		})

		t.Run("1 - nan", func(t *testing.T) {
			expr, err := cc.ParseExpr("1 - nan")
			test.AssertNoErr(t, err)

			expr.Right.Op = cc.Number

			_, err = c.accessMemory(expr)
			test.AssertHaveErr(t, err)
			test.AssertStrPrefix(t, err.Error(), "failed to parse number of sub.right")
		})

		t.Run("1 - 1", func(t *testing.T) {
			expr, err := cc.ParseExpr("1 - 1")
			test.AssertNoErr(t, err)

			_, err = c.accessMemory(expr)
			test.AssertHaveErr(t, err)
			test.AssertStrPrefix(t, err.Error(), "failed to parse sub.left")
		})

		t.Run("skb->pkt_type - 1", func(t *testing.T) {
			expr, err := cc.ParseExpr("skb->pkt_type - 1")
			test.AssertNoErr(t, err)

			_, err = c.accessMemory(expr)
			test.AssertHaveErr(t, err)
			test.AssertStrPrefix(t, err.Error(), "disallow using bitfield for sub")
		})

		t.Run("ops->fn - 1", func(t *testing.T) {
			expr, err := cc.ParseExpr("ops->fn - 1")
			test.AssertNoErr(t, err)

			_, err = c.accessMemory(expr)
			test.AssertHaveErr(t, err)
			test.AssertStrPrefix(t, err.Error(), "disallow type")
		})

		t.Run("ops->arr - 1", func(t *testing.T) {
			expr, err := cc.ParseExpr("ops->arr - 1")
			test.AssertNoErr(t, err)

			_, err = c.accessMemory(expr)
			test.AssertHaveErr(t, err)
			test.AssertStrPrefix(t, err.Error(), "disallow type")
		})

		t.Run("skb->len - 1", func(t *testing.T) {
			expr, err := cc.ParseExpr("skb->len - 1")
			test.AssertNoErr(t, err)

			_, err = c.accessMemory(expr)
			test.AssertHaveErr(t, err)
			test.AssertStrPrefix(t, err.Error(), "disallow using non-{pointer,array} for sub")
		})

		t.Run("prog->aux->jit_data - 1", func(t *testing.T) {
			expr, err := cc.ParseExpr("prog->aux->jit_data - 1")
			test.AssertNoErr(t, err)

			prog := getBpfProgBtf(t)
			aux, err := testBtf.AnyTypeByName("bpf_prog_aux")
			test.AssertNoErr(t, err)
			auxPtr := &btf.Pointer{Target: aux}
			vptr := &btf.Pointer{Target: &btf.Void{}}

			res, err := c.accessMemory(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.idx, 1)
			test.AssertEqualSliceFn(t, res.offsets,
				[]accessOffset{
					{prev: prog, btf: auxPtr, offset: 56},
					{prev: auxPtr, btf: vptr, offset: 176},
					{prev: auxPtr, btf: vptr, offset: -1, address: true},
				}, equalsOffset)
		})

		t.Run("skb->cb - 1", func(t *testing.T) {
			expr, err := cc.ParseExpr("skb->cb - 1")
			test.AssertNoErr(t, err)

			skb := getSkbBtf(t)
			char, err := testBtf.AnyTypeByName("char")
			test.AssertNoErr(t, err)
			intTyp, err := testBtf.AnyTypeByName("int")
			test.AssertNoErr(t, err)
			cb := &btf.Array{
				Type:   char,
				Index:  intTyp,
				Nelems: 48,
			}
			charPtr := &btf.Pointer{Target: char}

			res, err := c.accessMemory(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.idx, 0)
			test.AssertEqualSliceFn(t, res.offsets,
				[]accessOffset{
					{prev: skb, btf: cb, offset: 40, address: true},
					{prev: skb, btf: charPtr, offset: -1, address: true},
				}, equalsOffset)
		})

		t.Run("skb->sk - 1", func(t *testing.T) {
			expr, err := cc.ParseExpr("skb->sk - 1")
			test.AssertNoErr(t, err)

			skb := getSkbBtf(t)
			sk, err := testBtf.AnyTypeByName("sock")
			test.AssertNoErr(t, err)
			sizeofSk, _ := btf.Sizeof(sk)
			skPtr := &btf.Pointer{Target: sk}

			res, err := c.accessMemory(expr)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, res.idx, 0)
			test.AssertEqualSliceFn(t, res.offsets,
				[]accessOffset{
					{prev: skb, btf: skPtr, offset: 24},
					{prev: skb, btf: skPtr, offset: -int64(sizeofSk), address: true},
				}, equalsOffset)
			test.AssertTrue(t, reflect.DeepEqual(res.btf, &btf.Pointer{Target: sk}))
		})
	})

	t.Run("skb->sk * 3", func(t *testing.T) {
		expr, err := cc.ParseExpr("skb->sk * 3")
		test.AssertNoErr(t, err)

		_, err = c.accessMemory(expr)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "unsupported expression op")
	})
}

func TestAccess(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("not_found->xxx", func(t *testing.T) {
		expr, err := cc.ParseExpr("not_found->xxx")
		test.AssertNoErr(t, err)

		_, err = c.access(expr)
		test.AssertTrue(t, errors.Is(err, ErrVarNotFound))
	})

	t.Run("skb->head no available register", func(t *testing.T) {
		expr, err := cc.ParseExpr("skb->head")
		test.AssertNoErr(t, err)

		for i := range len(c.regalloc.registers) {
			c.regalloc.registers[i] = true
		}
		defer c.reset()

		_, err = c.access(expr)
		test.AssertHaveErr(t, err)
		test.AssertTrue(t, errors.Is(err, ErrRegisterNotEnough))
		test.AssertStrPrefix(t, err.Error(), "failed to alloc register")
	})

	t.Run("offset2insns failed", func(t *testing.T) {
		defer c.reset()
		defer func() { c.memMode = MemoryReadModeProbeRead }()
		c.memMode = MemoryReadModeCoreRead

		rdonlyCast, err := testBtf.AnyTypeByName(kfuncBpfRdonlyCast)
		test.AssertNoErr(t, err)

		spec := (*Spec)(unsafe.Pointer(c.kernelBtf))
		id := spec.mutableTypes.copiedTypeIDs[rdonlyCast]
		delete(spec.mutableTypes.copiedTypeIDs, rdonlyCast)
		defer func() {
			spec.mutableTypes.copiedTypeIDs[rdonlyCast] = id
		}()

		expr, err := cc.ParseExpr("skb->dev->ifindex")
		test.AssertNoErr(t, err)

		_, err = c.access(expr)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "failed to convert offsets to instructions")
		test.AssertTrue(t, errors.Is(err, btf.ErrNotFound))
	})

	t.Run("skb->head", func(t *testing.T) {
		expr, err := cc.ParseExpr("skb->head")
		test.AssertNoErr(t, err)

		char, err := testBtf.AnyTypeByName("unsigned char")
		test.AssertNoErr(t, err)

		defer c.reset()

		eval, err := c.access(expr)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, eval.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, eval.reg, asm.R8)
		test.AssertTrue(t, reflect.DeepEqual(eval.btf, &btf.Pointer{Target: char}))
		test.AssertFalse(t, isMemberBitfield(eval.mem))
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.LoadMem(asm.R8, asm.R9, 0, asm.DWord),
			asm.Mov.Reg(asm.R3, asm.R8),
			asm.Add.Imm(asm.R3, 200),
			asm.Mov.Imm(asm.R2, 8),
			asm.Mov.Reg(asm.R1, asm.RFP),
			asm.Add.Imm(asm.R1, -8),
			asm.FnProbeReadKernel.Call(),
			asm.LoadMem(asm.R8, asm.RFP, -8, asm.DWord),
		})
	})

	t.Run("skb->cb", func(t *testing.T) {
		expr, err := cc.ParseExpr("skb->cb")
		test.AssertNoErr(t, err)

		char, err := testBtf.AnyTypeByName("char")
		test.AssertNoErr(t, err)

		intTyp, err := testBtf.AnyTypeByName("int")
		test.AssertNoErr(t, err)

		defer c.reset()

		eval, err := c.access(expr)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, eval.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, eval.reg, asm.R8)
		test.AssertTrue(t, reflect.DeepEqual(eval.btf, &btf.Array{
			Index:  intTyp,
			Type:   char,
			Nelems: 48,
		}))
		test.AssertFalse(t, isMemberBitfield(eval.mem))
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.LoadMem(asm.R8, asm.R9, 0, asm.DWord),
			asm.Add.Imm(asm.R8, 40),
		})
	})

	t.Run("skb->pkt_type", func(t *testing.T) {
		expr, err := cc.ParseExpr("skb->pkt_type")
		test.AssertNoErr(t, err)

		defer c.reset()

		eval, err := c.access(expr)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, eval.typ, evalValueTypeRegBtf)
		test.AssertEqual(t, eval.reg, asm.R8)
		test.AssertTrue(t, isMemberBitfield(eval.mem))
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.LoadMem(asm.R8, asm.R9, 0, asm.DWord),
			asm.Mov.Reg(asm.R3, asm.R8),
			asm.Add.Imm(asm.R3, 128),
			asm.Mov.Imm(asm.R2, 8),
			asm.Mov.Reg(asm.R1, asm.RFP),
			asm.Add.Imm(asm.R1, -8),
			asm.FnProbeReadKernel.Call(),
			asm.LoadMem(asm.R8, asm.RFP, -8, asm.DWord),
			asm.And.Imm(asm.R8, 0x7),
		})
	})
}

func TestOffset2insns(t *testing.T) {
	c := prepareCompiler(t)

	const reg = asm.R8

	t.Run("no offsets", func(t *testing.T) {
		c.offset2insns(nil, asm.R8)
		test.AssertEmptySlice(t, c.insns)
	})

	t.Run("all address", func(t *testing.T) {
		defer c.reset()

		offsets := []accessOffset{
			{address: true, offset: 4},
			{address: true, offset: 8},
		}

		err := c.offset2insns(offsets, reg)
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Add.Imm(reg, 4),
			asm.Add.Imm(reg, 8),
		})
	})

	t.Run("core read", func(t *testing.T) {
		defer c.reset()

		c.memMode = MemoryReadModeCoreRead

		e, err := cc.ParseExpr("skb->dev->ifindex")
		test.AssertNoErr(t, err)

		res, err := c.accessMemory(e)
		test.AssertNoErr(t, err)

		c.offset2insns(res.offsets, reg)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Mov.Reg(asm.R1, reg),
			asm.Mov.Imm(asm.R2, 1875),
			bpfKfuncCall(41126),
			asm.LoadMem(asm.R1, asm.R0, 16, asm.DWord),
			asm.JEq.Imm(asm.R1, 0, c.labelExit),
			asm.Mov.Imm(asm.R2, 6973),
			bpfKfuncCall(41126),
			asm.LoadMem(reg, asm.R0, 224, asm.Word),
		})
	})

	t.Run("direct read", func(t *testing.T) {
		defer c.reset()

		c.memMode = MemoryReadModeDirectRead

		c.offset2insns([]accessOffset{
			{offset: 4, address: true},
			{offset: 8},
		}, reg)

		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Add.Imm(reg, 4),
			asm.LoadMem(reg, reg, 8, asm.DWord),
		})
	})

	t.Run("probe read", func(t *testing.T) {
		defer c.reset()

		c.memMode = MemoryReadModeProbeRead

		c.offset2insns([]accessOffset{
			{offset: 4, address: true},
			{offset: 8},
		}, reg)

		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.Mov.Reg(asm.R3, reg),
			asm.Add.Imm(asm.R3, 4),
			asm.Add.Imm(asm.R3, 8),
			asm.Mov.Imm(asm.R2, 8),
			asm.Mov.Reg(asm.R1, asm.RFP),
			asm.Add.Imm(asm.R1, -8),
			asm.FnProbeReadKernel.Call(),
			asm.LoadMem(reg, asm.RFP, -8, asm.DWord),
		})
	})
}

func TestBitfield2insns(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("non-zero offset", func(t *testing.T) {
		defer c.reset()
		c.bitfield2insns(&btf.Member{
			Offset:       4,
			BitfieldSize: 3,
		}, asm.R8)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.RSh.Imm(asm.R8, 4),
			asm.And.Imm(asm.R8, 0x7),
		})
	})

	t.Run("zero offset", func(t *testing.T) {
		defer c.reset()
		c.bitfield2insns(&btf.Member{
			Offset:       0,
			BitfieldSize: 3,
		}, asm.R8)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.And.Imm(asm.R8, 0x7),
		})
	})
}

func TestAdjustRegisterBitwise(t *testing.T) {
	c := prepareCompiler(t)

	t.Run("no btf", func(t *testing.T) {
		var eval evalValue
		eval.typ = evalValueTypeNum

		err := c.adjustRegisterBitwise(eval)
		test.AssertNoErr(t, err)
		test.AssertEmptySlice(t, c.insns)
	})

	t.Run("invalid btf type", func(t *testing.T) {
		var eval evalValue
		eval.typ = evalValueTypeRegBtf
		eval.btf = &btf.Func{}

		err := c.adjustRegisterBitwise(eval)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "failed to get size of")
		test.AssertEmptySlice(t, c.insns)
	})

	t.Run("char", func(t *testing.T) {
		defer c.reset()

		char, err := testBtf.AnyTypeByName("char")
		test.AssertNoErr(t, err)

		var eval evalValue
		eval.typ = evalValueTypeRegBtf
		eval.reg = asm.R8
		eval.btf = char

		err = c.adjustRegisterBitwise(eval)
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.And.Imm(asm.R8, 0xFF),
		})
	})

	t.Run("u16", func(t *testing.T) {
		defer c.reset()

		u16, err := testBtf.AnyTypeByName("u16")
		test.AssertNoErr(t, err)

		var eval evalValue
		eval.typ = evalValueTypeRegBtf
		eval.reg = asm.R8
		eval.btf = u16

		err = c.adjustRegisterBitwise(eval)
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.And.Imm(asm.R8, 0xFFFF),
		})
	})

	t.Run("u32", func(t *testing.T) {
		defer c.reset()

		u32, err := testBtf.AnyTypeByName("u32")
		test.AssertNoErr(t, err)

		var eval evalValue
		eval.typ = evalValueTypeRegBtf
		eval.reg = asm.R8
		eval.btf = u32

		err = c.adjustRegisterBitwise(eval)
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, c.insns, asm.Instructions{
			asm.LSh.Imm(asm.R8, 32),
			asm.RSh.Imm(asm.R8, 32),
		})
	})

	t.Run("u64", func(t *testing.T) {
		defer c.reset()

		u64, err := testBtf.AnyTypeByName("u64")
		test.AssertNoErr(t, err)

		var eval evalValue
		eval.typ = evalValueTypeRegBtf
		eval.reg = asm.R8
		eval.btf = u64

		err = c.adjustRegisterBitwise(eval)
		test.AssertNoErr(t, err)
		test.AssertEmptySlice(t, c.insns)
	})

	t.Run("unsupported size", func(t *testing.T) {
		defer c.reset()

		skb, err := testBtf.AnyTypeByName("sk_buff")
		test.AssertNoErr(t, err)

		var eval evalValue
		eval.typ = evalValueTypeRegBtf
		eval.reg = asm.R8
		eval.btf = skb

		err = c.adjustRegisterBitwise(eval)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "unsupported size")
		test.AssertEmptySlice(t, c.insns)
	})
}
