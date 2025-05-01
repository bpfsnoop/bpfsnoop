// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"errors"
	"strconv"
	"testing"

	"github.com/bpfsnoop/bpfsnoop/internal/test"
)

func TestParseUnsigned(t *testing.T) {
	tests := []struct {
		input    string
		expected uint64
	}{
		{"0x1", 1},
		{"0o1", 1},
		{"0b1", 1},
		{"01", 1},
		{"1", 1},
		{"'a'", 97},
		{"'A'", 65},
	}

	for _, tt := range tests {
		result, err := parseUnsigned(tt.input)
		test.AssertNoErr(t, err)
		test.AssertEqual(t, result, tt.expected)
	}

	t.Run("'a", func(t *testing.T) {
		_, err := parseUnsigned("'a")
		test.AssertHaveErr(t, err)
		test.AssertTrue(t, errors.Is(err, strconv.ErrSyntax))
	})
}

func TestParseNumber(t *testing.T) {
	t.Run("-1", func(t *testing.T) {
		result, err := parseNumber("-1")
		test.AssertNoErr(t, err)
		test.AssertEqual(t, result, -1)
	})

	t.Run("+1", func(t *testing.T) {
		result, err := parseNumber("+1")
		test.AssertNoErr(t, err)
		test.AssertEqual(t, result, 1)
	})

	t.Run("1", func(t *testing.T) {
		result, err := parseNumber("1")
		test.AssertNoErr(t, err)
		test.AssertEqual(t, result, 1)
	})

	t.Run("0xl", func(t *testing.T) {
		_, err := parseNumber("0xl")
		test.AssertHaveErr(t, err)
	})
}
