// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"testing"

	"github.com/bpfsnoop/bpfsnoop/internal/test"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

func TestGetPointerTypeID(t *testing.T) {
	t.Run("skb", func(t *testing.T) {
		skb, err := testBtf.AnyTypeByName("sk_buff")
		test.AssertNoErr(t, err)
		skbID, err := testBtf.TypeID(skb)
		test.AssertNoErr(t, err)

		id, err := getPointerTypeID(testBtf, skb, false, false)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, id, skbID)
	})

	t.Run("struct", func(t *testing.T) {
		skb := &btf.Struct{
			Name: "sk_buff",
		}

		__skb, err := testBtf.AnyTypeByName("sk_buff")
		test.AssertNoErr(t, err)
		skbID, err := testBtf.TypeID(__skb)
		test.AssertNoErr(t, err)

		id, err := getPointerTypeID(testBtf, skb, true, false)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, id, skbID)
	})

	t.Run("union", func(t *testing.T) {
		attr := &btf.Union{
			Name: "bpf_attr",
		}

		__attr, err := testBtf.AnyTypeByName("bpf_attr")
		test.AssertNoErr(t, err)
		attrID, err := testBtf.TypeID(__attr)
		test.AssertNoErr(t, err)

		id, err := getPointerTypeID(testBtf, attr, false, true)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, id, attrID)
	})

	t.Run("not found", func(t *testing.T) {
		notFound := &btf.Struct{
			Name: "not_found",
		}

		_, err := getPointerTypeID(testBtf, notFound, true, false)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "failed to find pointer type for")
	})
}

func TestSizeof(t *testing.T) {
	t.Run("failed to get size", func(t *testing.T) {
		typ := &btf.FuncProto{}

		_, err := sizeof(typ)
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "failed to get size of")
	})

	u128, err := testBtf.AnyTypeByName("__u128")
	test.AssertNoErr(t, err)

	tests := []struct {
		n string
		t btf.Type
		s asm.Size
	}{
		{"__u8", getU8Btf(t), asm.Byte},
		{"__u16", getU16Btf(t), asm.Half},
		{"__u32", getU32Btf(t), asm.Word},
		{"__u64", getU64Btf(t), asm.DWord},
		{"__u128", u128, asm.DWord},
	}

	for _, tt := range tests {
		t.Run(tt.n, func(t *testing.T) {
			s, err := sizeof(tt.t)
			test.AssertNoErr(t, err)
			test.AssertEqual(t, s, tt.s)
		})
	}
}
