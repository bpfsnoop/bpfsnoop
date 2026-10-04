// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package mathx

import (
	"math"

	"golang.org/x/exp/constraints"
)

func Mask(v int) int {
	if v == math.MaxInt {
		return math.MaxInt
	}

	n := 1
	for n < v {
		n <<= 1
	}
	return n - 1
}

// Align rounds n up to the nearest multiple of align.
// n must be nonnegative, align must be positive, and the result must fit in T.
func Align[T constraints.Integer](n, align T) T {
	if remainder := n % align; remainder != 0 {
		return n + (align - remainder)
	}
	return n
}
