// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import "github.com/cilium/ebpf/asm"

func (c *compiler) directReadOffsets(offsets []accessOffset, reg asm.Register) {
	lastIdx := len(offsets) - 1
	for i, offset := range offsets {
		if offset.address {
			if offset.offset != 0 {
				c.emit(asm.Add.Imm(reg, int32(offset.offset)))
			}
		} else {
			c.emit(
				asm.LoadMem(reg, reg, int16(offset.offset), asm.DWord), // reg = *(reg + offset)
			)
			if i != lastIdx {
				c.emit(
					asm.JEq.Imm(reg, 0, c.labelExit), // if reg == 0 goto exit
				)
			}
		}
	}
}
