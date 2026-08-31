// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"fmt"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// materialize converts an exprValue to Materialized state by emitting
// necessary instructions to load the value into a register.
func (c *compiler) materialize(val exprValue) (exprValue, error) {
	switch val.kind {
	case exprValueKindMaterialized:
		return val, nil

	case exprValueKindConstant:
		return c.materializeConstant(val)

	case exprValueKindPending:
		return c.materializePending(val)

	case exprValueKindEnumMaybe:
		return exprValue{}, fmt.Errorf("cannot materialize unresolved enum '%s'", val.name)

	default:
		return exprValue{}, fmt.Errorf("cannot materialize unknown value kind: %v", val.kind)
	}
}

// materializeConstant loads a constant value into a register.
func (c *compiler) materializeConstant(val exprValue) (exprValue, error) {
	reg, err := c.regalloc.Alloc()
	if err != nil {
		return exprValue{}, fmt.Errorf("failed to allocate register for constant: %w", err)
	}

	// Use 64-bit immediate instruction for large constants
	c.emit(asm.Instruction{
		OpCode:   asm.Mov.Op(asm.ImmSource),
		Dst:      reg,
		Constant: val.num,
	})

	return newMaterialized(reg, val.btf), nil
}

// materializePending emits instructions to load a pending value into a register.
func (c *compiler) materializePending(val exprValue) (exprValue, error) {
	reg, err := c.regalloc.Alloc()
	if err != nil {
		return exprValue{}, fmt.Errorf("failed to allocate register for pending value: %w", err)
	}

	// Load base address
	if val.varIndex >= 0 {
		// Load from args array
		c.emitLoadArg(val.varIndex, reg)
	} else if val.uptr != 0 {
		// Load user pointer constant
		c.emit(asm.Instruction{
			OpCode:   asm.Mov.Op(asm.ImmSource),
			Dst:      reg,
			Constant: int64(val.uptr),
		})
	} else {
		// Copy from base register
		c.emit(asm.Mov.Reg(reg, val.baseReg))
	}

	// Process offset chain
	if len(val.offsets) > 0 {
		if err := c.emitOffsetChain(val.offsets, reg); err != nil {
			c.regalloc.Free(reg)
			return exprValue{}, fmt.Errorf("failed to emit offset chain: %w", err)
		}
	}

	result := newMaterialized(reg, val.btf)
	result.mem = val.mem

	// Handle bitfield extraction or register size adjustment
	if isMemberBitfield(val.mem) {
		c.emitBitfieldExtract(val.mem, reg)
	} else {
		// Adjust register size for non-pointer types (mask to proper width)
		c.adjustRegisterSize(result)
	}

	return result, nil
}

// emitOffsetChain emits instructions for a chain of offsets.
// Uses the appropriate memory read mode (probe/core/direct).
func (c *compiler) emitOffsetChain(offsets []pendingOffset, reg asm.Register) error {
	// Check if all offsets are address-only (no derefs needed)
	allAddress := true
	for _, off := range offsets {
		if off.deref {
			allAddress = false
			break
		}
	}

	if allAddress {
		// Just add up all offsets
		for _, off := range offsets {
			if off.offset != 0 {
				c.emit(asm.Add.Imm(reg, int32(off.offset)))
			}
		}
		return nil
	}

	// Need to do actual memory reads
	switch c.memMode {
	case MemoryReadModeCoreRead:
		return c.emitCoreRead(offsets, reg)
	case MemoryReadModeDirectRead:
		c.emitDirectRead(offsets, reg)
		return nil
	default:
		c.emitProbeRead(offsets, reg)
		return nil
	}
}

// emitBitfieldExtract emits instructions to extract a bitfield value.
func (c *compiler) emitBitfieldExtract(member *btf.Member, reg asm.Register) {
	delta := member.Offset & 0x7
	if delta != 0 {
		c.emit(asm.RSh.Imm(reg, int32(delta)))
	}

	mask := (uint64(1) << uint64(member.BitfieldSize)) - 1
	c.emit(asm.And.Imm(reg, int32(mask)))
}

// adjustRegisterSize emits instructions to mask a register based on type size.
func (c *compiler) adjustRegisterSize(val exprValue) {
	if !val.isMaterialized() {
		return
	}

	size, err := btf.Sizeof(val.btf)
	if err != nil {
		return
	}

	switch size {
	case 1:
		if isSignedBTFType(val.btf) {
			c.emit(asm.LSh.Imm(val.reg, 56))
			c.emit(asm.ArSh.Imm(val.reg, 56))
		} else {
			c.emit(asm.And.Imm(val.reg, 0xFF))
		}
	case 2:
		if isSignedBTFType(val.btf) {
			c.emit(asm.LSh.Imm(val.reg, 48))
			c.emit(asm.ArSh.Imm(val.reg, 48))
		} else {
			c.emit(asm.And.Imm(val.reg, 0xFFFF))
		}
	case 4:
		c.emit(asm.LSh.Imm(val.reg, 32))
		if isSignedBTFType(val.btf) {
			c.emit(asm.ArSh.Imm(val.reg, 32))
		} else {
			c.emit(asm.RSh.Imm(val.reg, 32))
		}
	}
}
