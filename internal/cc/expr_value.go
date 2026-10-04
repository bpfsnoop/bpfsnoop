// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"fmt"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// exprValueKind represents the state of an evaluated expression.
type exprValueKind int

const (
	// exprValueKindConstant represents a compile-time known number.
	exprValueKindConstant exprValueKind = iota
	// exprValueKindPending represents an address computation not yet emitted.
	// Offsets are accumulated lazily until materialization is needed.
	exprValueKindPending
	// exprValueKindMaterialized represents a value that has been loaded into a register.
	exprValueKindMaterialized
	// exprValueKindEnumMaybe represents a name that might be an enum value.
	exprValueKindEnumMaybe
)

func (k exprValueKind) String() string {
	switch k {
	case exprValueKindConstant:
		return "Constant"
	case exprValueKindPending:
		return "Pending"
	case exprValueKindMaterialized:
		return "Materialized"
	case exprValueKindEnumMaybe:
		return "EnumMaybe"
	default:
		return "Unknown"
	}
}

// pendingOffset represents a single offset in a pending address computation chain.
type pendingOffset struct {
	directRead bool     // source address is within a map value
	offset     int64    // byte offset to add
	deref      bool     // if true, dereference pointer after adding offset
	btf        btf.Type // type after this offset is applied
	prevBtf    btf.Type // type before this offset (used for CO-RE)
	inArray    bool     // if true, this offset is within an array
	bitfield   bool     // if true, this offset is a bitfield access
}

// exprValue represents the result of evaluating an expression.
// It can be in one of three states: Constant, Pending, or Materialized.
type exprValue struct {
	kind exprValueKind

	// For Constant: compile-time known value
	num int64

	// For EnumMaybe: name that might be an enum
	name string

	// For Pending: address computation not yet emitted
	varIndex int             // index into args array, -1 if base is a register or constant
	baseReg  asm.Register    // valid if varIndex == -1 and kind == Pending
	offsets  []pendingOffset // accumulated offsets
	addrOnly bool            // if true, want address not value (for & operator)
	uptr     uint64          // user pointer value (for cast from constant)
	uptrSet  bool            // distinguishes a literal NULL pointer from baseReg R0

	// For Materialized: value in register
	reg asm.Register

	// Common: type information
	btf btf.Type
	mem *btf.Member // if accessing a struct member (for bitfield info)

	mapValue  bool // address within a map value, or an embedded aggregate
	mapLookup bool // materialized pointer returned by bpf_map_lookup_elem, possibly NULL
}

// String returns a string representation of the exprValue for debugging.
func (v exprValue) String() string {
	switch v.kind {
	case exprValueKindConstant:
		return fmt.Sprintf("Constant(%d)", v.num)
	case exprValueKindPending:
		if v.varIndex >= 0 {
			return fmt.Sprintf("Pending(var[%d], offsets=%d, btf=%v)", v.varIndex, len(v.offsets), v.btf)
		}
		if v.uptrSet || v.uptr != 0 {
			return fmt.Sprintf("Pending(uptr=0x%x, offsets=%d, btf=%v)", v.uptr, len(v.offsets), v.btf)
		}
		return fmt.Sprintf("Pending(reg=R%d, offsets=%d, btf=%v)", v.baseReg, len(v.offsets), v.btf)
	case exprValueKindMaterialized:
		return fmt.Sprintf("Materialized(R%d, btf=%v)", v.reg, v.btf)
	case exprValueKindEnumMaybe:
		return fmt.Sprintf("EnumMaybe(%s)", v.name)
	default:
		return "Unknown"
	}
}

// isConstant returns true if the value is a compile-time constant.
func (v exprValue) isConstant() bool {
	return v.kind == exprValueKindConstant
}

// isPending returns true if the value has not yet been loaded into a register.
func (v exprValue) isPending() bool {
	return v.kind == exprValueKindPending
}

// isMaterialized returns true if the value is in a register.
func (v exprValue) isMaterialized() bool {
	return v.kind == exprValueKindMaterialized
}

// isEnumMaybe returns true if the value might be an enum.
func (v exprValue) isEnumMaybe() bool {
	return v.kind == exprValueKindEnumMaybe
}

// addOffset appends an offset to a pending value's offset chain.
func (v *exprValue) addOffset(off pendingOffset) {
	v.offsets = append(v.offsets, off)
}

// lastOffset returns the last offset in the chain, or nil if empty.
func (v *exprValue) lastOffset() *pendingOffset {
	if len(v.offsets) == 0 {
		return nil
	}
	return &v.offsets[len(v.offsets)-1]
}

// prevBtf returns the BTF type before the last offset, or nil.
func (v *exprValue) prevBtf() btf.Type {
	if len(v.offsets) == 0 {
		return nil
	}
	return v.offsets[len(v.offsets)-1].prevBtf
}

// newConstant creates a new constant exprValue.
func newConstant(num int64) exprValue {
	return exprValue{
		kind: exprValueKindConstant,
		num:  num,
	}
}

// newPendingVar creates a new pending exprValue from a variable index.
func newPendingVar(varIndex int, typ btf.Type) exprValue {
	return exprValue{
		kind:     exprValueKindPending,
		varIndex: varIndex,
		btf:      typ,
	}
}

// newPendingReg transfers ownership of an allocated register to a pending
// exprValue. Materialization releases it after loading the result.
func newPendingReg(reg asm.Register, typ btf.Type) exprValue {
	return exprValue{
		kind:     exprValueKindPending,
		varIndex: -1,
		baseReg:  reg,
		btf:      typ,
	}
}

// newPendingUptr creates a new pending exprValue from a user pointer constant.
func newPendingUptr(uptr uint64, typ btf.Type) exprValue {
	return exprValue{
		kind:     exprValueKindPending,
		varIndex: -1,
		uptr:     uptr,
		uptrSet:  true,
		btf:      typ,
	}
}

// newMaterialized creates a new materialized exprValue.
func newMaterialized(reg asm.Register, typ btf.Type) exprValue {
	return exprValue{
		kind: exprValueKindMaterialized,
		reg:  reg,
		btf:  typ,
	}
}

// newEnumMaybe creates a new exprValue that might be an enum.
func newEnumMaybe(name string) exprValue {
	return exprValue{
		kind: exprValueKindEnumMaybe,
		name: name,
	}
}

// allOffsetsAreAddress returns true if all offsets in the chain are address-only
// (no dereference needed).
func (v *exprValue) allOffsetsAreAddress() bool {
	if len(v.offsets) == 0 {
		return true
	}
	for _, off := range v.offsets {
		if off.deref {
			return false
		}
	}
	return true
}

// totalStaticOffset returns the sum of all offsets in the chain.
// Only valid when all offsets are address-only.
func (v *exprValue) totalStaticOffset() int64 {
	var total int64
	for _, off := range v.offsets {
		total += off.offset
	}
	return total
}
