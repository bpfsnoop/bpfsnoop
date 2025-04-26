// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf/btf"
)

func canCalculate(t btf.Type) bool {
	switch mybtf.UnderlyingType(t).(type) {
	case *btf.Int, *btf.Enum, *btf.Pointer, *btf.Array:
		return true

	default:
		return false
	}
}
