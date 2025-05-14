// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import "github.com/cilium/ebpf/asm"

func (c *compiler) probeReadOffsets(offsets []accessOffset, reg asm.Register) {
	allAddress := offsets[0].address
	for i := range offsets {
		allAddress = allAddress && offsets[i].address
	}
	if allAddress {
		for i := range offsets {
			c.emit(asm.Add.Imm(reg, int32(offsets[i].offset)))
		}
		return
	}

	c.pushUsedCallerSavedRegs()
	defer c.popUsedCallerSavedRegs()

	if reg != asm.R3 {
		c.emit(asm.Mov.Reg(asm.R3, reg))
	}

	lastIndex := len(offsets) - 1
	for i, offset := range offsets {
		if offset.offset != 0 {
			c.emit(asm.Add.Imm(asm.R3, int32(offset.offset)))
		}
		if offset.address {
			if i == lastIndex && reg != asm.R3 {
				c.emit(asm.Mov.Reg(reg, asm.R3))
			}
			continue
		}

		c.emit(
			asm.Mov.Imm(asm.R2, 8),       // r2 = 8; always read 8 bytes
			asm.Mov.Reg(asm.R1, asm.RFP), // r1 = r10
			asm.Add.Imm(asm.R1, -8),      // r1 = r10 - 8
			asm.FnProbeReadKernel.Call(), // bpf_probe_read_kernel(r1, 8, r3)
		)

		if i != lastIndex {
			c.labelExitUsed = true
			c.emit(
				asm.LoadMem(asm.R3, asm.RFP, -8, asm.DWord), // r3 = *(r10 - 8)
				asm.JEq.Imm(asm.R3, 0, c.labelExit),
			)
		} else {
			c.emit(asm.LoadMem(reg, asm.RFP, -8, asm.DWord))
		}
	}
}
