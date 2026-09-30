// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"fmt"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf/asm"
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

func sizeof(t btf.Type) (asm.Size, error) {
	size, err := btf.Sizeof(t)
	if err != nil {
		return 0, fmt.Errorf("failed to get size of %v: %w", t, err)
	}

	switch size {
	case 1:
		return asm.Byte, nil
	case 2:
		return asm.Half, nil
	case 4:
		return asm.Word, nil
	case 8:
		return asm.DWord, nil
	default:
		return asm.DWord, nil
	}
}
