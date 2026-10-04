// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"fmt"
	"slices"
	"strconv"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"rsc.io/c2go/cc"

	"github.com/bpfsnoop/bpfsnoop/internal/mathx"
)

const (
	bpfMaxStackSize = 512
)

// BPFMap describes an open map used by an expression. The caller must keep
// FD open until the compiled BPF program has been loaded.
type BPFMap struct {
	FD      int
	KeySize uint32
	Key     btf.Type
	Value   btf.Type
}

// BPFMapID selects a map by either a positive ID or a literal name.
// Names and IDs remain distinct even when the name contains only digits.
type BPFMapID struct {
	Name string
	ID   uint32
}

func (m BPFMapID) String() string {
	if m.ID != 0 {
		return strconv.FormatUint(uint64(m.ID), 10)
	}
	return strconv.Quote(m.Name)
}

func validateMapExpr(expr *cc.Expr) error {
	switch expr.Left.Text {
	case mapLookupFn, bpfMapLookupElemHelper:
		if !slices.Contains([]int{2, 3}, len(expr.List)) {
			return fmt.Errorf("bpf_map_lookup_elem() must have 2 or 3 arguments")
		}
		return nil

	default:
		return nil
	}
}

func expr2mapID(expr *cc.Expr) (BPFMapID, error) {
	if err := validateMapExpr(expr); err != nil {
		return BPFMapID{}, err
	}

	arg := expr.List[0]
	switch arg.Op {
	case cc.Number:
		id, err := parseUnsigned(arg.Text)
		if err != nil || id == 0 || id > uint64(^uint32(0)) {
			return BPFMapID{}, fmt.Errorf("invalid map ID %q: expected a positive uint32", arg.Text)
		}
		return BPFMapID{ID: uint32(id)}, nil

	case cc.String:
		if len(arg.Texts) != 1 {
			return BPFMapID{}, fmt.Errorf("map name must be a single string literal")
		}

		name, err := strconv.Unquote(arg.Texts[0])
		if err != nil {
			return BPFMapID{}, fmt.Errorf("invalid map name: %w", err)
		}
		if name == "" {
			return BPFMapID{}, fmt.Errorf("map name must not be empty")
		}
		return BPFMapID{Name: name}, nil

	default:
		return BPFMapID{}, fmt.Errorf("first argument must be an integer ID or a string name")
	}
}

func (c *compiler) evaluateMapCall(expr *cc.Expr) (exprValue, error) {
	mapID, err := expr2mapID(expr)
	if err != nil {
		return exprValue{}, err
	}

	fnName := expr.Left.Text
	m, ok := c.maps[mapID]
	if !ok {
		return exprValue{}, fmt.Errorf("%s(%s): map has not been opened", fnName, mapID)
	}

	if m.FD < 0 || m.Value == nil || m.KeySize == 0 {
		return exprValue{}, fmt.Errorf("%s(%s): invalid map metadata or missing value BTF", fnName, mapID)
	}

	key, err := c.evaluate(expr.List[1])
	if err != nil {
		return exprValue{}, fmt.Errorf("failed to evaluate %s() key: %w", fnName, err)
	}

	_, ok = btf.UnderlyingType(key.btf).(*btf.Pointer)
	if !ok {
		return exprValue{}, fmt.Errorf("%s() key must be a pointer, got %v", fnName, key.btf)
	}

	// Infer the size from the map's key BTF, independently of the source pointer
	// type. The helper always consumes exactly the map's key size.
	var size int64
	if len(expr.List) == 3 {
		size, err = parseExprNumber(expr.List[2])
		if err != nil {
			return exprValue{}, fmt.Errorf("invalid %s() key size: %w", fnName, err)
		}
	} else {
		if m.Key == nil {
			return exprValue{}, fmt.Errorf("%s(%s): cannot infer key size without map key BTF; specify the key size", fnName, mapID)
		}

		keySize, err := btf.Sizeof(m.Key)
		if err != nil {
			return exprValue{}, fmt.Errorf("failed to infer %s() key size from map key BTF: %w", fnName, err)
		}

		size = int64(keySize)
	}
	if size < int64(m.KeySize) {
		return exprValue{}, fmt.Errorf("%s() key size %d must be at least map key size %d", fnName, size, m.KeySize)
	}

	key, err = c.materialize(key)
	if err != nil {
		return exprValue{}, fmt.Errorf("failed to materialize %s() key: %w", fnName, err)
	}

	// The source may be an untrusted kernel pointer. Copy the key to the stack
	// before passing it to bpf_map_lookup_elem, which requires readable key
	// memory.

	keyOffset := c.reservedStack + int(mathx.Align(m.KeySize, 8))
	stackOffset := keyOffset
	type spill struct {
		reg    asm.Register
		offset int16
	}

	var spills []spill
	for reg := asm.R0; reg <= asm.R5; reg++ {
		if reg != key.reg && c.regalloc.IsUsed(reg) {
			stackOffset += 8
			spills = append(spills, spill{reg, int16(-stackOffset)})
		}
	}
	if stackOffset > bpfMaxStackSize {
		return exprValue{}, fmt.Errorf("%s() key and saved registers require %d stack bytes, maximum is %d", fnName, stackOffset, bpfMaxStackSize)
	}

	for _, saved := range spills {
		c.emit(asm.StoreMem(asm.RFP, saved.offset, saved.reg, asm.DWord))
	}

	switch expr.Left.Text {
	case mapLookupFn, bpfMapLookupElemHelper:
		c.emitMapLookupCall(m, key, keyOffset)
	}

	slices.Reverse(spills)
	for _, saved := range spills {
		c.emit(asm.LoadMem(saved.reg, asm.RFP, saved.offset, asm.DWord))
	}

	result := newMaterialized(key.reg, &btf.Pointer{Target: m.Value})
	result.mapLookup = true
	result.mapValue = true
	return result, nil
}

func (c *compiler) emitMapLookupCall(m BPFMap, key exprValue, keyOffset int) {
	c.mapLookupLabel++
	lookupLabel := fmt.Sprintf("%s_map_lookup_%d", c.labelExit, c.mapLookupLabel)
	doneLabel := lookupLabel + "_done"

	c.emit(
		asm.Mov.Reg(asm.R3, key.reg),
		asm.Mov.Imm(asm.R2, int32(m.KeySize)),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, int32(-keyOffset)),
		asm.FnProbeReadKernel.Call(),
		asm.JEq.Imm(asm.R0, 0, lookupLabel),
		asm.Mov.Imm(asm.R0, 0),
		asm.Ja.Label(doneLabel),
		asm.LoadMapPtr(asm.R1, m.FD).WithSymbol(lookupLabel),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, int32(-keyOffset)),
		asm.FnMapLookupElem.Call(),
		asm.Mov.Reg(key.reg, asm.R0).WithSymbol(doneLabel),
	)
}

// Pointer arithmetic and memory access require the verifier to know that a
// lookup succeeded. Bare lookup results remain nullable for comparisons.
func (c *compiler) checkMapLookupPointer(value *exprValue) {
	if value.mapLookup {
		c.emit(asm.JEq.Imm(value.reg, 0, c.labelExit))
		c.labelExitUsed = true
		value.mapLookup = false
	}
}
