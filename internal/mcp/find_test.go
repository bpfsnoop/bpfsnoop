// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package mcp

import "testing"

func TestFindKsymOptions(t *testing.T) {
	for _, kind := range []string{"", FindKindKsym} {
		options := FindOptions{Pattern: "__per_cpu_offset", Kind: kind}
		if err := validateFindOptions(&options); err != nil {
			t.Fatal(err)
		}
		if !wantsFindKind(options.Kind, FindKindKsym) {
			t.Fatal("symbol discovery was not selected")
		}
	}
}

func TestFindCollectorDuplicateSymbols(t *testing.T) {
	collector := newFindCollector(2)
	for _, address := range []uint64{0xffff000000000020, 0xffff000000000010, 0xffff000000000020, 0xffff000000000030} {
		collector.add(findMatch{Kind: FindKindKsym, Name: "duplicate", Module: "vmlinux", Address: address, SymbolType: "d"})
	}
	result := collector.result()
	if result.Total != 3 || !result.Truncated || len(result.Matches) != 2 {
		t.Fatalf("unexpected bounded result: %+v", result)
	}
	if result.Matches[0].Address != 0xffff000000000010 || result.Matches[1].Address != 0xffff000000000020 {
		t.Fatalf("symbols not ordered by exact address: %+v", result.Matches)
	}
}
