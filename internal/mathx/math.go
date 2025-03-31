// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package mathx

import "math"

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
