// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"fmt"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

const kfuncBpfRdonlyCast = "bpf_rdonly_cast"

func canRdonlyCast(spec *btf.Spec, t btf.Type) (bool, btf.TypeID, error) {
	t = mybtf.UnderlyingType(t)
	ptr, ok := t.(*btf.Pointer)
	if !ok {
		return false, 0, nil
	}

	t = mybtf.UnderlyingType(ptr.Target)
	_, isStruct := t.(*btf.Struct)
	_, isUnion := t.(*btf.Union)
	if !isStruct && !isUnion {
		return false, 0, nil
	}

	typID, err := getPointerTypeID(spec, t, isStruct, isUnion)
	return err == nil, typID, err
}

func canReadByRdonlyCast(t btf.Type) bool {
	switch mybtf.UnderlyingType(t).(type) {
	case *btf.Pointer, *btf.Int, *btf.Enum:
		return true
	default:
		return false
	}
}

func bpfKfuncCall(id btf.TypeID) asm.Instruction {
	return asm.Instruction{
		OpCode:   asm.Call.Op(asm.ImmSource),
		Src:      asm.PseudoKfuncCall,
		Constant: int64(id),
	}
}

func (c *compiler) coreReadOffsets(offsets []accessOffset, reg asm.Register) error {
	typ, err := c.kernelBtf.AnyTypeByName(kfuncBpfRdonlyCast)
	if err != nil {
		return fmt.Errorf("failed to find kfunc %s: %w", kfuncBpfRdonlyCast, err)
	}
	fn, ok := typ.(*btf.Func)
	if !ok {
		return fmt.Errorf("%s should be a function", kfuncBpfRdonlyCast)
	}

	rdonlyCastID, err := c.kernelBtf.TypeID(fn)
	if err != nil {
		return fmt.Errorf("failed to get type ID for kfunc %s: %w", kfuncBpfRdonlyCast, err)
	}

	c.pushUsedCallerSavedRegs()
	defer c.popUsedCallerSavedRegs()

	immReg := asm.R1
	if reg != immReg {
		c.emit(asm.Mov.Reg(immReg, reg))
	}

	lastIdx := len(offsets) - 1
	for i, offset := range offsets {
		if offset.address {
			if offset.offset != 0 {
				c.emit(asm.Add.Imm(immReg, int32(offset.offset)))
			}
			if i == lastIdx && reg != immReg {
				c.emit(asm.Mov.Reg(reg, immReg))
			}
			continue
		}

		canCast, typID, err := canRdonlyCast(c.kernelBtf, offset.prev)
		if err != nil {
			return fmt.Errorf("failed to check if %v can be bpf_rdonly_cast: %w", offset.prev, err)
		}
		if !canCast {
			return fmt.Errorf("type %v cannot be bpf_rdonly_cast", offset.prev)
		}

		size, err := sizeof(offset.btf)
		if err != nil {
			return fmt.Errorf("failed to get size of btf type %v: %w", offset.btf, err)
		}

		if !canReadByRdonlyCast(offset.btf) || offset.inArray {
			resReg := immReg
			if i == lastIdx && reg != immReg {
				resReg = reg
			}
			c.emit(
				asm.Mov.Reg(asm.R3, immReg),  // r3 = r1
				asm.Mov.Imm(asm.R2, 8),       // r2 = 8
				asm.Mov.Reg(asm.R1, asm.RFP), // r1 = rfp
				asm.Add.Imm(asm.R1, -8),      // r1 -= 8
				asm.FnProbeReadKernel.Call(),
				asm.LoadMem(resReg, asm.RFP, -8, asm.DWord), // immReg = *(u64 *)(rfp - 8)
			)
			continue
		}

		if i != lastIdx {
			c.emit(
				asm.Mov.Imm(asm.R2, int32(typID)), // r2 = type ID
				bpfKfuncCall(rdonlyCastID),        // bpf_rdonly_cast(r1, r2)
				asm.LoadMem(immReg, asm.R0, int16(offset.offset), size),
				asm.JEq.Imm(immReg, 0, c.labelExit),
			)
			c.labelExitUsed = true
		} else {
			c.emit(
				asm.Mov.Imm(asm.R2, int32(typID)), // r2 = type ID
				bpfKfuncCall(rdonlyCastID),        // bpf_rdonly_cast(r1, r2)
				asm.LoadMem(reg, asm.R0, int16(offset.offset), size),
			)
		}
	}

	return nil
}
