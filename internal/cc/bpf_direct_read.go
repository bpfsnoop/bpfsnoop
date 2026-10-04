// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import "github.com/cilium/ebpf/asm"

type directReadOptions struct {
	useBTFSize bool
	checkImm   bool
	checkLast  bool
}

// emitDirectRead emits offset chain using direct memory access.
func (c *compiler) emitDirectRead(offsets []pendingOffset, reg asm.Register, opts directReadOptions) error {
	lastIdx := len(offsets) - 1
	for i, offset := range offsets {
		if !offset.deref {
			// Address-only
			if offset.offset != 0 {
				c.emit(asm.Add.Imm(reg, int32(offset.offset)))
			}
		} else {
			// Dereference
			size := asm.DWord
			if opts.useBTFSize {
				var err error
				size, err = sizeof(offset.btf)
				if err != nil {
					return err
				}
			}
			c.emit(
				asm.LoadMem(reg, reg, int16(offset.offset), size),
			)
			checkNull := (i != lastIdx && opts.checkImm) || (i == lastIdx && opts.checkLast)
			if checkNull {
				c.labelExitUsed = true
				c.emit(
					asm.JEq.Imm(reg, 0, c.labelExit),
				)
			}
		}
	}
	return nil
}
