// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"
	"io"
	"math/bits"
	"strings"
)

type histogram struct {
	log2  [64]uint64
	total uint64

	expr string
}

func newHistogram(expr string) *histogram {
	return &histogram{
		expr: expr,
	}
}

func bytes2i(b []byte, size int) uint64 {
	if size <= 0 || size > len(b) {
		return 0
	}

	var v uint64
	// Note: This assumes that the byte slice is in little-endian order.
	for i := 0; i < size; i++ {
		v |= uint64(b[i]) << (8 * i)
	}
	return v
}

func (h *histogram) i2h(v uint64) int {
	// Convert a value to a histogram index.
	index := bits.LeadingZeros64(v)
	return 63 - index
}

func (h *histogram) add(data []byte, size int) {
	h.log2[h.i2h(bytes2i(data, size))]++
	h.total++
}

func (h *histogram) render(w io.Writer) {
	if h.total == 0 {
		return
	}

	fmt.Fprintf(w, "Histogram for '%s' (total %d):\n", h.expr, h.total)
	h.log2hist(w, h.log2[:])
	fmt.Fprintln(w)
}

func printStars(w io.Writer, val, maxVal uint64, width int) {
	var nStars, nSpaces int
	var needPlus bool

	nStars = int(min(val, maxVal) * uint64(width) / maxVal)
	nSpaces = width - nStars
	needPlus = val > maxVal

	fmt.Fprint(w, strings.Repeat("*", nStars))
	fmt.Fprint(w, strings.Repeat(" ", nSpaces))

	if needPlus {
		fmt.Fprint(w, "+")
	}
}

func (h *histogram) log2hist(w io.Writer, vals []uint64) {
	var idxMax int = -1
	var valMax uint64

	for i, v := range vals {
		if v > 0 {
			idxMax = i
		}
		if v > valMax {
			valMax = v
		}
	}

	if idxMax < 0 {
		return
	}

	var stars int
	if idxMax <= 32 {
		stars = 40
	} else {
		stars = 20
	}

	for i := 0; i <= idxMax; i++ {
		low, high := (uint64(1)<<(i+1))>>1, (uint64(1)<<(i+1))-1
		if low == high {
			low -= 1
		}

		val := vals[i]
		if idxMax <= 32 {
			fmt.Fprintf(w, "%10d -> %-10d : %-13d |", low, high, val)
		} else {
			fmt.Fprintf(w, "%20d -> %-20d : %-13d |", low, high, val)
		}

		printStars(w, val, valMax, stars)

		fmt.Fprint(w, "|\n")
	}
}
