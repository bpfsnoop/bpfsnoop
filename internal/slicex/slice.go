// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package slicex

import (
	"cmp"
	"slices"
)

func SortCompact[T cmp.Ordered](s []T) []T {
	slices.Sort(s)
	return slices.Compact(s)
}
