// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"
)

const (
	maxArgsAmd64 = 6
	maxArgsArm64 = 8
)

var maxArgsKmulti int = maxArgsAmd64

func init() {
	if onArm64 {
		maxArgsKmulti = maxArgsArm64
	}
}

type kfuncInfoMulti struct {
	kfn string
	fns KFuncs
}

func FindKernelFuncsMulti(kfuncs []string, ksyms *Kallsyms) ([]kfuncInfoMulti, error) {
	if len(kfuncs) == 0 {
		return nil, nil
	}

	if !hasKprobeMulti {
		return nil, fmt.Errorf("kprobe.multi is not supported")
	}

	kmulti := make([]kfuncInfoMulti, 0, len(kfuncs))

	kmods, err := prepareKmods(kfuncs, ksyms)
	if err != nil {
		return nil, err
	}

	for _, kf := range kfuncs {
		fns, err := searchKernelFuncs([]string{kf}, kmods, ksyms, maxArgsKmulti)
		if err != nil {
			return nil, fmt.Errorf("failed to search kernel functions for '%s': %w", kf, err)
		}

		kmulti = append(kmulti, kfuncInfoMulti{
			kfn: kf,
			fns: fns,
		})
	}

	return kmulti, nil
}
