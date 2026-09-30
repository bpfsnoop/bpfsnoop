// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"testing"

	"github.com/bpfsnoop/bpfsnoop/internal/test"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

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
