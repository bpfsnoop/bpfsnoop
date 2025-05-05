// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"testing"

	"github.com/bpfsnoop/bpfsnoop/internal/test"
)

func TestExtractVarNames(t *testing.T) {
	t.Run("parse expr", func(t *testing.T) {
		_, err := ExtractVarNames("a ^^ b")
		test.AssertHaveErr(t, err)
		test.AssertStrPrefix(t, err.Error(), "failed to parse expression")
	})

	t.Run("no var", func(t *testing.T) {
		names, err := ExtractVarNames("1 > 2")
		test.AssertNoErr(t, err)
		test.AssertEmptySlice(t, names)
	})

	t.Run("one var", func(t *testing.T) {
		names, err := ExtractVarNames("a > 2")
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, names, []string{"a"})
	})

	t.Run("two vars", func(t *testing.T) {
		names, err := ExtractVarNames("a > b")
		test.AssertNoErr(t, err)
		test.AssertEqualSlice(t, names, []string{"a", "b"})
	})
}
