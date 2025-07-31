// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"
	"io"

	tdigest "github.com/caio/go-tdigest/v4"
)

type TDigest struct {
	*tdigest.TDigest

	expr string
}

func newTDigest(expr string) *TDigest {
	t, _ := tdigest.New(tdigest.Compression(100))
	return &TDigest{
		TDigest: t,
		expr:    expr,
	}
}

func (t *TDigest) add(data []byte, size int) {
	if size <= 0 || size > len(data) {
		return
	}

	v := bytes2i(data, size)
	_ = t.Add(float64(v))
}

func (t *TDigest) render(w io.Writer) {
	if t.Count() == 0 {
		return
	}

	var means []uint64
	var counts []uint64

	t.ForEachCentroid(func(mean float64, count uint64) bool {
		if count != 0 {
			means = append(means, uint64(mean))
			counts = append(counts, count)
		}
		return true
	})

	i, j := 1, 0
	for ; i < len(means); i++ {
		if means[i-1] == means[i] {
			counts[j] += counts[i]
		} else {
			j++
			means[j] = means[i]
			counts[j] = counts[i]
		}
	}
	means = means[:j+1]
	counts = counts[:j+1]

	fmt.Fprintf(w, "T-Digest for '%s' (total %d):\n", t.expr, t.Count())
	t.tdigest2hist(w, means, counts)
	fmt.Fprintln(w)
}

func (t *TDigest) tdigest2hist(w io.Writer, vals, counts []uint64) {
	valMax := counts[0]
	for _, val := range counts {
		if val > valMax {
			valMax = val
		}
	}

	for i := range vals {
		val := counts[i]
		fmt.Fprintf(w, "%10d : %-13d |", vals[i], val)
		printStars(w, val, valMax, 40)
		fmt.Fprint(w, "|\n")
	}
}
