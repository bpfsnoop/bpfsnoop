// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"cmp"
	"slices"
)

func sortCompact[S ~[]E, E cmp.Ordered](x S) S {
	slices.Sort(x)
	return slices.Compact(x)
}
