// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"fmt"
	"slices"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"rsc.io/c2go/cc"
)

// evaluate returns an exprValue in one of three states: Constant, Pending, or
// Materialized. Lazy materialization is used to defer instruction emission as
// long as possible.
func (c *compiler) evaluate(expr *cc.Expr) (exprValue, error) {
	switch expr.Op {
	// === Value Sources ===
	case cc.Name:
		return c.evaluateName(expr)

	case cc.Number:
		return c.evaluateNumber(expr)

	// === Memory Access ===
	case cc.Arrow:
		return c.evaluateArrow(expr)

	case cc.Dot:
		return c.evaluateDot(expr)

	case cc.Index:
		return c.evaluateIndex(expr)

	case cc.Indir:
		return c.evaluateIndir(expr)

	case cc.Addr:
		return c.evaluateAddr(expr)

	// === Type Operations ===
	case cc.Cast:
		return c.evaluateCast(expr)

	case cc.Paren:
		return c.evaluate(expr.Left)

	// === Arithmetic ===
	case cc.Add:
		return c.evaluateAdd(expr)

	case cc.Sub:
		return c.evaluateSub(expr)

	case cc.Mul:
		return c.evaluateMul(expr)

	case cc.Div:
		return c.evaluateDiv(expr)

	case cc.Mod:
		return c.evaluateMod(expr)

	// === Bitwise ===
	case cc.And:
		return c.evaluateAnd(expr)

	case cc.Or:
		return c.evaluateOr(expr)

	case cc.Xor:
		return c.evaluateXor(expr)

	case cc.Lsh:
		return c.evaluateLsh(expr)

	case cc.Rsh:
		return c.evaluateRsh(expr)

	case cc.Twid:
		return c.evaluateTwid(expr)

	// === Comparison ===
	case cc.EqEq:
		return c.evaluateEqEq(expr)

	case cc.NotEq:
		return c.evaluateNotEq(expr)

	case cc.Lt:
		return c.evaluateLt(expr)

	case cc.LtEq:
		return c.evaluateLtEq(expr)

	case cc.Gt:
		return c.evaluateGt(expr)

	case cc.GtEq:
		return c.evaluateGtEq(expr)

	// === Logical ===
	case cc.AndAnd:
		return c.evaluateAndAnd(expr)

	case cc.OrOr:
		return c.evaluateOrOr(expr)

	case cc.Not:
		return c.evaluateNot(expr)

	// === Unary ===
	case cc.Minus:
		return c.evaluateMinus(expr)

	case cc.Plus:
		return c.evaluate(expr.Left)

	case cc.PreInc:
		return c.evaluatePreInc(expr)

	case cc.PreDec:
		return c.evaluatePreDec(expr)

	// === Conditional ===
	case cc.Cond:
		return c.evaluateCond(expr)

	default:
		return exprValue{}, fmt.Errorf("unsupported expression operator: %s", expr.Op)
	}
}

// evaluateName handles variable name lookup.
// Returns Pending if it's a known variable, EnumMaybe otherwise.
func (c *compiler) evaluateName(expr *cc.Expr) (exprValue, error) {
	// Check for special constants
	if slices.Contains([]string{"NULL", "false"}, expr.Text) {
		return newConstant(0), nil
	}
	if expr.Text == "true" {
		return newConstant(1), nil
	}

	// Look up variable
	idx := slices.Index(c.vars, expr.Text)
	if idx == -1 {
		// Not a variable, might be an enum
		return newEnumMaybe(expr.Text), nil
	}

	// Return Pending - don't load yet
	return newPendingVar(idx, c.btfs[idx]), nil
}

// evaluateNumber parses a numeric literal.
func (c *compiler) evaluateNumber(expr *cc.Expr) (exprValue, error) {
	num, err := parseNumber(expr.Text)
	if err != nil {
		return exprValue{}, fmt.Errorf("failed to parse number: %w", err)
	}
	return newConstant(num), nil
}

// evaluateArrow handles member access via pointer (->).
func (c *compiler) evaluateArrow(expr *cc.Expr) (exprValue, error) {
	base, err := c.evaluate(expr.Left)
	if err != nil {
		return exprValue{}, err
	}

	// Handle EnumMaybe - it might be an unknown variable
	if base.isEnumMaybe() {
		return exprValue{}, fmt.Errorf("variable %s: %w", base.name, ErrVarNotFound)
	}

	return c.accessMember(base, expr.Text, true)
}

// evaluateDot handles member access via value (.).
func (c *compiler) evaluateDot(expr *cc.Expr) (exprValue, error) {
	base, err := c.evaluate(expr.Left)
	if err != nil {
		return exprValue{}, err
	}

	if base.isEnumMaybe() {
		return exprValue{}, fmt.Errorf("variable %s: %w", base.name, ErrVarNotFound)
	}

	return c.accessMember(base, expr.Text, false)
}

// accessMember handles member access for both arrow and dot operators.
func (c *compiler) accessMember(base exprValue, memberName string, useArrow bool) (exprValue, error) {
	// Check if base member is a bitfield
	if isMemberBitfield(base.mem) {
		return exprValue{}, fmt.Errorf("cannot access member of a bitfield type")
	}

	t := mybtf.UnderlyingType(base.btf)

	// For arrow, we need to dereference the pointer first
	if useArrow {
		ptr, ok := t.(*btf.Pointer)
		if !ok {
			return exprValue{}, fmt.Errorf("arrow access requires pointer type, got %v", t)
		}
		t = mybtf.UnderlyingType(ptr.Target)
	}

	// Look up member
	var member *btf.Member
	var offset uint32
	var err error

	switch v := t.(type) {
	case *btf.Struct:
		member, err = mybtf.FindStructMember(v, memberName)
		if err == nil {
			offset, err = mybtf.StructMemberOffset(v, memberName)
		}
	case *btf.Union:
		member, err = mybtf.FindUnionMember(v, memberName)
		if err == nil {
			offset, err = mybtf.UnionMemberOffset(v, memberName)
		}
	default:
		return exprValue{}, fmt.Errorf("cannot access member of type %T", v)
	}
	if err != nil {
		return exprValue{}, fmt.Errorf("failed to find member %s: %w", memberName, err)
	}

	// Handle based on base value state
	switch base.kind {
	case exprValueKindPending:
		return c.accessMemberPending(base, member, offset, useArrow)

	case exprValueKindMaterialized:
		return c.accessMemberMaterialized(base, member, offset, useArrow)

	default:
		return exprValue{}, fmt.Errorf("cannot access member on %s value", base.kind)
	}
}

// accessMemberPending adds a member access to a pending value's offset chain.
func (c *compiler) accessMemberPending(base exprValue, member *btf.Member, offset uint32, useArrow bool) (exprValue, error) {
	if !useArrow {
		// Dot access - add offset to last entry if possible
		if len(base.offsets) > 0 {
			base.offsets[len(base.offsets)-1].offset += int64(offset)
			base.offsets[len(base.offsets)-1].btf = member.Type
			base.offsets[len(base.offsets)-1].bitfield = isMemberBitfield(member)
		} else {
			return exprValue{}, fmt.Errorf("disallow accessing member via dot on base variable")
		}
	} else {
		// Arrow access - add new offset entry with deref
		base.addOffset(pendingOffset{
			offset:   int64(offset),
			deref:    true,
			btf:      member.Type,
			prevBtf:  base.btf,
			bitfield: isMemberBitfield(member),
		})
	}

	// Check if result is an array (becomes address)
	t := mybtf.UnderlyingType(member.Type)
	if _, ok := t.(*btf.Array); ok {
		if len(base.offsets) > 0 {
			base.offsets[len(base.offsets)-1].deref = false
		}
		base.btf = member.Type
		base.mem = nil
	} else {
		base.btf = member.Type
		base.mem = member
	}

	return base, nil
}

// accessMemberMaterialized emits instructions to access a member from a materialized base.
func (c *compiler) accessMemberMaterialized(base exprValue, member *btf.Member, offset uint32, useArrow bool) (exprValue, error) {
	if !useArrow {
		return exprValue{}, fmt.Errorf("disallow dot access on materialized value")
	}

	// Create pending with the register as base and add the member offset
	result := newPendingReg(base.reg, base.btf)
	result.addOffset(pendingOffset{
		offset:   int64(offset),
		deref:    true,
		btf:      member.Type,
		prevBtf:  base.btf,
		bitfield: isMemberBitfield(member),
	})

	// Check if result is an array
	t := mybtf.UnderlyingType(member.Type)
	if _, ok := t.(*btf.Array); ok {
		result.offsets[len(result.offsets)-1].deref = false
		result.btf = member.Type
		result.mem = nil
	} else {
		result.btf = member.Type
		result.mem = member
	}

	return result, nil
}

// evaluateIndex handles array/pointer indexing.
func (c *compiler) evaluateIndex(expr *cc.Expr) (exprValue, error) {
	base, err := c.evaluate(expr.Left)
	if err != nil {
		return exprValue{}, fmt.Errorf("failed to evaluate index base: %w", err)
	}

	if isMemberBitfield(base.mem) {
		return exprValue{}, fmt.Errorf("disallow using bitfield for index")
	}

	if expr.Right.Op != cc.Number {
		return exprValue{}, fmt.Errorf("index must be a constant number, got %s", expr.Right.Op)
	}

	index, err := parseNumber(expr.Right.Text)
	if err != nil {
		return exprValue{}, fmt.Errorf("failed to parse index: %w", err)
	}

	// Get element size and type
	var elemType btf.Type
	var elemSize int
	var inArray bool

	t := mybtf.UnderlyingType(base.btf)
	switch v := t.(type) {
	case *btf.Pointer:
		elemType = v.Target
		elemSize, _ = btf.Sizeof(elemType)
	case *btf.Array:
		elemType = v.Type
		elemSize, _ = btf.Sizeof(elemType)
		inArray = true
	default:
		return exprValue{}, fmt.Errorf("cannot index type %v", t)
	}

	if elemSize == 0 {
		return exprValue{}, fmt.Errorf("cannot index element of zero size")
	}

	offset := index * int64(elemSize)

	switch base.kind {
	case exprValueKindPending:
		base.addOffset(pendingOffset{
			offset:  offset,
			deref:   false,
			btf:     elemType,
			prevBtf: base.prevBtf(),
			inArray: inArray,
		})
		base.btf = elemType
		base.mem = nil
		return base, nil

	case exprValueKindMaterialized:
		result := newPendingReg(base.reg, base.btf)
		result.addOffset(pendingOffset{
			offset:  offset,
			deref:   false,
			btf:     elemType,
			prevBtf: base.btf,
			inArray: inArray,
		})
		result.btf = elemType
		result.mem = nil
		return result, nil

	default:
		return exprValue{}, fmt.Errorf("cannot index %s value", base.kind)
	}
}

// evaluateIndir handles pointer dereference (*).
func (c *compiler) evaluateIndir(expr *cc.Expr) (exprValue, error) {
	base, err := c.evaluate(expr.Left)
	if err != nil {
		return exprValue{}, err
	}

	if isMemberBitfield(base.mem) {
		return exprValue{}, fmt.Errorf("cannot dereference bitfield")
	}

	t := mybtf.UnderlyingType(base.btf)
	ptr, ok := t.(*btf.Pointer)
	if !ok {
		return exprValue{}, fmt.Errorf("cannot dereference non-pointer type %v", t)
	}

	switch base.kind {
	case exprValueKindPending:
		base.addOffset(pendingOffset{
			offset:  0,
			deref:   true,
			btf:     ptr.Target,
			prevBtf: base.btf,
		})
		base.btf = ptr.Target
		base.mem = nil
		return base, nil

	case exprValueKindMaterialized:
		result := newPendingReg(base.reg, base.btf)
		result.addOffset(pendingOffset{
			offset:  0,
			deref:   true,
			btf:     ptr.Target,
			prevBtf: base.btf,
		})
		result.btf = ptr.Target
		result.mem = nil
		return result, nil

	default:
		return exprValue{}, fmt.Errorf("cannot dereference %s value", base.kind)
	}
}

// evaluateAddr handles address-of (&).
func (c *compiler) evaluateAddr(expr *cc.Expr) (exprValue, error) {
	base, err := c.evaluate(expr.Left)
	if err != nil {
		return exprValue{}, err
	}

	if !base.isPending() {
		return exprValue{}, fmt.Errorf("cannot take address of %s value", base.kind)
	}

	if len(base.offsets) == 0 {
		return exprValue{}, fmt.Errorf("cannot take address of variable directly")
	}

	// Mark last offset as address-only (no deref)
	base.offsets[len(base.offsets)-1].deref = false
	base.btf = &btf.Pointer{Target: base.btf}
	base.offsets[len(base.offsets)-1].btf = base.btf
	base.mem = nil
	return base, nil
}

// evaluateCast handles type casting.
func (c *compiler) evaluateCast(expr *cc.Expr) (exprValue, error) {
	// Handle cast of literal number
	if expr.Left.Op == cc.Number {
		n, err := parseUnsigned(expr.Left.Text)
		if err != nil {
			return exprValue{}, fmt.Errorf("failed to parse number for cast: %w", err)
		}
		targetType, err := c.cc2btf(expr)
		if err != nil {
			return exprValue{}, fmt.Errorf("failed to get cast target type: %w", err)
		}
		return newPendingUptr(n, targetType), nil
	}

	inner, err := c.evaluate(expr.Left)
	if err != nil {
		return exprValue{}, err
	}

	// Get target type
	targetType, err := c.cc2btf(expr)
	if err != nil {
		return exprValue{}, fmt.Errorf("failed to get cast target type: %w", err)
	}

	// Cast just changes the type annotation
	inner.btf = targetType

	// Update last offset's type if pending
	if inner.isPending() && len(inner.offsets) > 0 {
		inner.offsets[len(inner.offsets)-1].btf = targetType
	}

	return inner, nil
}

// evaluateAdd handles addition.
func (c *compiler) evaluateAdd(expr *cc.Expr) (exprValue, error) {
	left, err := c.evaluate(expr.Left)
	if err != nil {
		return exprValue{}, fmt.Errorf("failed to evaluate left operand of add: %w", err)
	}

	right, err := c.evaluate(expr.Right)
	if err != nil {
		return exprValue{}, fmt.Errorf("failed to evaluate right operand of add: %w", err)
	}

	return c.addValues(left, right)
}

// addValues performs addition on two exprValues.
func (c *compiler) addValues(left, right exprValue) (exprValue, error) {
	// Handle enum resolution
	left, right, err := c.resolveEnums(left, right)
	if err != nil {
		return exprValue{}, err
	}

	// Case 1: Both constants - fold at compile time
	if left.isConstant() && right.isConstant() {
		return newConstant(left.num + right.num), nil
	}

	if left.isPending() && !canCalculate(left.btf) {
		return exprValue{}, fmt.Errorf("left operand cannot be used for add")
	}

	if right.isPending() && !canCalculate(right.btf) {
		return exprValue{}, fmt.Errorf("right operand cannot be used for add")
	}

	// Case 2: Pending + Constant - fold into offset chain
	if left.isPending() && right.isConstant() {
		return c.addConstantToPending(left, right.num)
	}
	if right.isPending() && left.isConstant() {
		return c.addConstantToPending(right, left.num)
	}

	// Case 3: Both runtime values - must materialize both
	left, err = c.materialize(left)
	if err != nil {
		return exprValue{}, fmt.Errorf("failed to materialize left operand: %w", err)
	}

	right, err = c.materialize(right)
	if err != nil {
		return exprValue{}, fmt.Errorf("failed to materialize right operand: %w", err)
	}

	// Handle pointer arithmetic: scale right by element size
	t := mybtf.UnderlyingType(left.btf)
	if ptr, ok := t.(*btf.Pointer); ok {
		size, _ := btf.Sizeof(ptr.Target)
		if size > 1 {
			c.emit(asm.Mul.Imm(right.reg, int32(size)))
		}
	} else if arr, ok := t.(*btf.Array); ok {
		size, _ := btf.Sizeof(arr.Type)
		if size > 1 {
			c.emit(asm.Mul.Imm(right.reg, int32(size)))
		}
	}

	c.emit(asm.Add.Reg(left.reg, right.reg))
	c.regalloc.Free(right.reg)

	return newMaterialized(left.reg, left.btf), nil
}

// addConstantToPending adds a constant offset to a pending value.
func (c *compiler) addConstantToPending(pending exprValue, num int64) (exprValue, error) {
	if num == 0 {
		return pending, nil
	}

	// Calculate actual offset based on pointer arithmetic
	t := mybtf.UnderlyingType(pending.btf)
	var offset int64
	var resultType btf.Type

	if ptr, ok := t.(*btf.Pointer); ok {
		if _, ok := mybtf.UnderlyingType(ptr.Target).(*btf.Void); ok {
			offset = num
		} else {
			size, _ := btf.Sizeof(ptr.Target)
			if size == 0 {
				return exprValue{}, fmt.Errorf("cannot add to pointer of zero-size element")
			}
			offset = num * int64(size)
		}
		resultType = pending.btf
	} else if arr, ok := t.(*btf.Array); ok {
		size, _ := btf.Sizeof(arr.Type)
		if size == 0 {
			return exprValue{}, fmt.Errorf("cannot add to array of zero-size element")
		}
		offset = num * int64(size)
		resultType = &btf.Pointer{Target: arr.Type}
	} else {
		offset = num
		resultType = pending.btf
	}

	pending.addOffset(pendingOffset{
		offset:  offset,
		deref:   false, // address arithmetic, no deref
		btf:     resultType,
		prevBtf: pending.prevBtf(),
	})
	pending.mem = nil

	return pending, nil
}

// evaluateSub handles subtraction.
func (c *compiler) evaluateSub(expr *cc.Expr) (exprValue, error) {
	left, err := c.evaluate(expr.Left)
	if err != nil {
		return exprValue{}, fmt.Errorf("failed to evaluate left operand of sub: %w", err)
	}

	right, err := c.evaluate(expr.Right)
	if err != nil {
		return exprValue{}, fmt.Errorf("failed to evaluate right operand of sub: %w", err)
	}

	return c.subValues(left, right)
}

// subValues performs subtraction on two exprValues.
func (c *compiler) subValues(left, right exprValue) (exprValue, error) {
	left, right, err := c.resolveEnums(left, right)
	if err != nil {
		return exprValue{}, err
	}

	// Case 1: Both constants
	if left.isConstant() && right.isConstant() {
		return newConstant(left.num - right.num), nil
	}

	if left.isPending() && !canCalculate(left.btf) {
		return exprValue{}, fmt.Errorf("left operand cannot be used for sub")
	}

	if right.isPending() && !canCalculate(right.btf) {
		return exprValue{}, fmt.Errorf("right operand cannot be used for sub")
	}

	// Case 2: Pending - Constant
	if left.isPending() && right.isConstant() {
		return c.addConstantToPending(left, -right.num)
	}

	// Case 3: Runtime subtraction
	left, err = c.materialize(left)
	if err != nil {
		return exprValue{}, err
	}

	right, err = c.materialize(right)
	if err != nil {
		return exprValue{}, err
	}

	// Handle pointer arithmetic
	t := mybtf.UnderlyingType(left.btf)
	if ptr, ok := t.(*btf.Pointer); ok {
		size, _ := btf.Sizeof(ptr.Target)
		if size > 1 {
			c.emit(asm.Mul.Imm(right.reg, int32(size)))
		}
	} else if arr, ok := t.(*btf.Array); ok {
		size, _ := btf.Sizeof(arr.Type)
		if size > 1 {
			c.emit(asm.Mul.Imm(right.reg, int32(size)))
		}
	}

	c.emit(asm.Sub.Reg(left.reg, right.reg))
	c.regalloc.Free(right.reg)

	return newMaterialized(left.reg, left.btf), nil
}

// evaluateMul handles multiplication.
func (c *compiler) evaluateMul(expr *cc.Expr) (exprValue, error) {
	left, err := c.evaluate(expr.Left)
	if err != nil {
		return exprValue{}, err
	}

	right, err := c.evaluate(expr.Right)
	if err != nil {
		return exprValue{}, err
	}

	left, right, err = c.resolveEnums(left, right)
	if err != nil {
		return exprValue{}, err
	}

	if left.isConstant() && right.isConstant() {
		return newConstant(left.num * right.num), nil
	}

	if left.isPending() && !canCalculate(left.btf) {
		return exprValue{}, fmt.Errorf("left operand cannot be used for multiply")
	}

	if right.isPending() && !canCalculate(right.btf) {
		return exprValue{}, fmt.Errorf("right operand cannot be used for multiply")
	}

	left, err = c.materialize(left)
	if err != nil {
		return exprValue{}, err
	}

	right, err = c.materialize(right)
	if err != nil {
		return exprValue{}, err
	}

	c.emit(asm.Mul.Reg(left.reg, right.reg))
	c.regalloc.Free(right.reg)

	return newMaterialized(left.reg, left.btf), nil
}

// evaluateDiv handles division.
func (c *compiler) evaluateDiv(expr *cc.Expr) (exprValue, error) {
	left, err := c.evaluate(expr.Left)
	if err != nil {
		return exprValue{}, err
	}

	right, err := c.evaluate(expr.Right)
	if err != nil {
		return exprValue{}, err
	}

	left, right, err = c.resolveEnums(left, right)
	if err != nil {
		return exprValue{}, err
	}

	if right.isConstant() && right.num == 0 {
		return exprValue{}, fmt.Errorf("division by zero")
	}

	if left.isConstant() && right.isConstant() {
		return newConstant(left.num / right.num), nil
	}

	if left.isPending() && !canCalculate(left.btf) {
		return exprValue{}, fmt.Errorf("left operand cannot be used for div")
	}

	if right.isPending() && !canCalculate(right.btf) {
		return exprValue{}, fmt.Errorf("right operand cannot be used for div")
	}

	left, err = c.materialize(left)
	if err != nil {
		return exprValue{}, err
	}

	if right.isConstant() {
		c.emit(asm.Div.Imm(left.reg, int32(right.num)))
		return newMaterialized(left.reg, left.btf), nil
	}

	right, err = c.materialize(right)
	if err != nil {
		return exprValue{}, err
	}

	// Guard against runtime division by zero
	c.emit(JmpOff(asm.JNE, right.reg, 0, 2))
	c.emit(asm.Mov.Imm(left.reg, 0))
	c.emit(Ja(1))
	c.emit(asm.Div.Reg(left.reg, right.reg))
	c.regalloc.Free(right.reg)

	return newMaterialized(left.reg, left.btf), nil
}

// evaluateMod handles modulo.
func (c *compiler) evaluateMod(expr *cc.Expr) (exprValue, error) {
	left, err := c.evaluate(expr.Left)
	if err != nil {
		return exprValue{}, err
	}

	right, err := c.evaluate(expr.Right)
	if err != nil {
		return exprValue{}, err
	}

	left, right, err = c.resolveEnums(left, right)
	if err != nil {
		return exprValue{}, err
	}

	if right.isConstant() && right.num == 0 {
		return exprValue{}, fmt.Errorf("modulo by zero")
	}

	if left.isConstant() && right.isConstant() {
		return newConstant(left.num % right.num), nil
	}

	if left.isPending() && !canCalculate(left.btf) {
		return exprValue{}, fmt.Errorf("left operand cannot be used for mod")
	}

	if right.isPending() && !canCalculate(right.btf) {
		return exprValue{}, fmt.Errorf("right operand cannot be used for mod")
	}

	left, err = c.materialize(left)
	if err != nil {
		return exprValue{}, err
	}

	if right.isConstant() {
		if right.num == 1 {
			c.emit(asm.Mov.Imm(left.reg, 0))
			return newMaterialized(left.reg, left.btf), nil
		}
		c.emit(asm.Mod.Imm(left.reg, int32(right.num)))
		return newMaterialized(left.reg, left.btf), nil
	}

	right, err = c.materialize(right)
	if err != nil {
		return exprValue{}, err
	}

	c.emit(JmpOff(asm.JNE, right.reg, 0, 2))
	c.emit(asm.Mov.Imm(left.reg, 0))
	c.emit(Ja(1))
	c.emit(asm.Mod.Reg(left.reg, right.reg))
	c.regalloc.Free(right.reg)

	return newMaterialized(left.reg, left.btf), nil
}

// evaluateAnd handles bitwise AND.
func (c *compiler) evaluateAnd(expr *cc.Expr) (exprValue, error) {
	left, err := c.evaluate(expr.Left)
	if err != nil {
		return exprValue{}, err
	}

	right, err := c.evaluate(expr.Right)
	if err != nil {
		return exprValue{}, err
	}

	left, right, err = c.resolveEnums(left, right)
	if err != nil {
		return exprValue{}, err
	}

	if left.isConstant() && right.isConstant() {
		return newConstant(left.num & right.num), nil
	}

	if left.isPending() && !canCalculate(left.btf) {
		return exprValue{}, fmt.Errorf("left operand cannot be used for and")
	}

	if right.isPending() && !canCalculate(right.btf) {
		return exprValue{}, fmt.Errorf("right operand cannot be used for and")
	}

	left, err = c.materialize(left)
	if err != nil {
		return exprValue{}, err
	}

	if right.isConstant() {
		c.emit(asm.And.Imm(left.reg, int32(right.num)))
		return newMaterialized(left.reg, left.btf), nil
	}

	right, err = c.materialize(right)
	if err != nil {
		return exprValue{}, err
	}

	c.emit(asm.And.Reg(left.reg, right.reg))
	c.regalloc.Free(right.reg)

	return newMaterialized(left.reg, left.btf), nil
}

// evaluateOr handles bitwise OR.
func (c *compiler) evaluateOr(expr *cc.Expr) (exprValue, error) {
	left, err := c.evaluate(expr.Left)
	if err != nil {
		return exprValue{}, err
	}

	right, err := c.evaluate(expr.Right)
	if err != nil {
		return exprValue{}, err
	}

	left, right, err = c.resolveEnums(left, right)
	if err != nil {
		return exprValue{}, err
	}

	if left.isConstant() && right.isConstant() {
		return newConstant(left.num | right.num), nil
	}

	if left.isPending() && !canCalculate(left.btf) {
		return exprValue{}, fmt.Errorf("left operand cannot be used for or")
	}

	if right.isPending() && !canCalculate(right.btf) {
		return exprValue{}, fmt.Errorf("right operand cannot be used for or")
	}

	left, err = c.materialize(left)
	if err != nil {
		return exprValue{}, err
	}

	if right.isConstant() {
		c.emit(asm.Or.Imm(left.reg, int32(right.num)))
		return newMaterialized(left.reg, left.btf), nil
	}

	right, err = c.materialize(right)
	if err != nil {
		return exprValue{}, err
	}

	c.emit(asm.Or.Reg(left.reg, right.reg))
	c.regalloc.Free(right.reg)

	return newMaterialized(left.reg, left.btf), nil
}

// evaluateXor handles bitwise XOR.
func (c *compiler) evaluateXor(expr *cc.Expr) (exprValue, error) {
	left, err := c.evaluate(expr.Left)
	if err != nil {
		return exprValue{}, err
	}

	right, err := c.evaluate(expr.Right)
	if err != nil {
		return exprValue{}, err
	}

	left, right, err = c.resolveEnums(left, right)
	if err != nil {
		return exprValue{}, err
	}

	if left.isConstant() && right.isConstant() {
		return newConstant(left.num ^ right.num), nil
	}

	if left.isPending() && !canCalculate(left.btf) {
		return exprValue{}, fmt.Errorf("left operand cannot be used for xor")
	}

	if right.isPending() && !canCalculate(right.btf) {
		return exprValue{}, fmt.Errorf("right operand cannot be used for xor")
	}

	left, err = c.materialize(left)
	if err != nil {
		return exprValue{}, err
	}

	if right.isConstant() {
		c.emit(asm.Xor.Imm(left.reg, int32(right.num)))
		return newMaterialized(left.reg, left.btf), nil
	}

	right, err = c.materialize(right)
	if err != nil {
		return exprValue{}, err
	}

	c.emit(asm.Xor.Reg(left.reg, right.reg))
	c.regalloc.Free(right.reg)

	return newMaterialized(left.reg, left.btf), nil
}

// evaluateLsh handles left shift.
func (c *compiler) evaluateLsh(expr *cc.Expr) (exprValue, error) {
	left, err := c.evaluate(expr.Left)
	if err != nil {
		return exprValue{}, err
	}

	right, err := c.evaluate(expr.Right)
	if err != nil {
		return exprValue{}, err
	}

	left, right, err = c.resolveEnums(left, right)
	if err != nil {
		return exprValue{}, err
	}

	if left.isConstant() && right.isConstant() {
		return newConstant(left.num << right.num), nil
	}

	if left.isPending() && !canCalculate(left.btf) {
		return exprValue{}, fmt.Errorf("left operand cannot be used for lsh")
	}

	if right.isPending() && !canCalculate(right.btf) {
		return exprValue{}, fmt.Errorf("right operand cannot be used for lsh")
	}

	left, err = c.materialize(left)
	if err != nil {
		return exprValue{}, err
	}

	if right.isConstant() {
		if right.num < 0 {
			return exprValue{}, fmt.Errorf("shift count is negative")
		}
		if right.num == 0 {
			return left, nil
		}
		c.emit(asm.LSh.Imm(left.reg, int32(right.num)))
		return newMaterialized(left.reg, left.btf), nil
	}

	right, err = c.materialize(right)
	if err != nil {
		return exprValue{}, err
	}

	c.emit(JmpOff(asm.JLE, right.reg, 0, 1))
	c.emit(asm.LSh.Reg(left.reg, right.reg))
	c.regalloc.Free(right.reg)

	return newMaterialized(left.reg, left.btf), nil
}

// evaluateRsh handles right shift.
func (c *compiler) evaluateRsh(expr *cc.Expr) (exprValue, error) {
	left, err := c.evaluate(expr.Left)
	if err != nil {
		return exprValue{}, err
	}

	right, err := c.evaluate(expr.Right)
	if err != nil {
		return exprValue{}, err
	}

	left, right, err = c.resolveEnums(left, right)
	if err != nil {
		return exprValue{}, err
	}

	if left.isConstant() && right.isConstant() {
		return newConstant(left.num >> right.num), nil
	}

	if left.isPending() && !canCalculate(left.btf) {
		return exprValue{}, fmt.Errorf("left operand cannot be used for rsh")
	}

	if right.isPending() && !canCalculate(right.btf) {
		return exprValue{}, fmt.Errorf("right operand cannot be used for rsh")
	}

	left, err = c.materialize(left)
	if err != nil {
		return exprValue{}, err
	}

	if right.isConstant() {
		if right.num < 0 {
			return exprValue{}, fmt.Errorf("shift count is negative")
		}
		if right.num == 0 {
			return left, nil
		}
		c.emit(asm.RSh.Imm(left.reg, int32(right.num)))
		return newMaterialized(left.reg, left.btf), nil
	}

	right, err = c.materialize(right)
	if err != nil {
		return exprValue{}, err
	}

	c.emit(JmpOff(asm.JLE, right.reg, 0, 1))
	c.emit(asm.RSh.Reg(left.reg, right.reg))
	c.regalloc.Free(right.reg)

	return newMaterialized(left.reg, left.btf), nil
}

// evaluateTwid handles bitwise NOT (~).
func (c *compiler) evaluateTwid(expr *cc.Expr) (exprValue, error) {
	val, err := c.evaluate(expr.Left)
	if err != nil {
		return exprValue{}, err
	}

	if val.isConstant() {
		return newConstant(^val.num), nil
	}

	if val.isPending() && !canCalculate(val.btf) {
		return exprValue{}, fmt.Errorf("the operand cannot be used for twid")
	}

	val, err = c.materialize(val)
	if err != nil {
		return exprValue{}, err
	}

	c.emit(asm.Xor.Imm(val.reg, -1))
	return newMaterialized(val.reg, val.btf), nil
}

// evaluateEqEq handles equality comparison.
func (c *compiler) evaluateEqEq(expr *cc.Expr) (exprValue, error) {
	left, err := c.evaluate(expr.Left)
	if err != nil {
		return exprValue{}, err
	}

	right, err := c.evaluate(expr.Right)
	if err != nil {
		return exprValue{}, err
	}

	left, right, err = c.resolveEnums(left, right)
	if err != nil {
		return exprValue{}, err
	}

	left, right = c.adjustNums(left, right)

	if left.isConstant() && right.isConstant() {
		return newConstant(int64(bool2int(left.num == right.num))), nil
	}

	if left.isPending() && !canCalculate(left.btf) {
		return exprValue{}, fmt.Errorf("left operand cannot be used for eqeq")
	}

	if right.isPending() && !canCalculate(right.btf) {
		return exprValue{}, fmt.Errorf("right operand cannot be used for eqeq")
	}

	left, err = c.materialize(left)
	if err != nil {
		return exprValue{}, err
	}

	if right.isConstant() {
		c.emit(JmpOff(asm.JNE, left.reg, right.num, 2))
		c.emitReg2bool(left.reg)
		return newMaterialized(left.reg, left.btf), nil
	}

	right, err = c.materialize(right)
	if err != nil {
		return exprValue{}, err
	}

	c.emit(JmpReg(asm.JNE, left.reg, right.reg, 2))
	c.emitReg2bool(left.reg)
	c.regalloc.Free(right.reg)

	return newMaterialized(left.reg, left.btf), nil
}

// evaluateNotEq handles inequality comparison.
func (c *compiler) evaluateNotEq(expr *cc.Expr) (exprValue, error) {
	left, err := c.evaluate(expr.Left)
	if err != nil {
		return exprValue{}, err
	}

	right, err := c.evaluate(expr.Right)
	if err != nil {
		return exprValue{}, err
	}

	left, right, err = c.resolveEnums(left, right)
	if err != nil {
		return exprValue{}, err
	}

	left, right = c.adjustNums(left, right)

	if left.isConstant() && right.isConstant() {
		return newConstant(int64(bool2int(left.num != right.num))), nil
	}

	if left.isPending() && !canCalculate(left.btf) {
		return exprValue{}, fmt.Errorf("left operand cannot be used for noteq")
	}

	if right.isPending() && !canCalculate(right.btf) {
		return exprValue{}, fmt.Errorf("right operand cannot be used for noteq")
	}

	left, err = c.materialize(left)
	if err != nil {
		return exprValue{}, err
	}

	if right.isConstant() {
		c.emit(JmpOff(asm.JEq, left.reg, right.num, 2))
		c.emitReg2bool(left.reg)
		return newMaterialized(left.reg, left.btf), nil
	}

	right, err = c.materialize(right)
	if err != nil {
		return exprValue{}, err
	}

	c.emit(JmpReg(asm.JEq, left.reg, right.reg, 2))
	c.emitReg2bool(left.reg)
	c.regalloc.Free(right.reg)

	return newMaterialized(left.reg, left.btf), nil
}

// evaluateLt handles less-than comparison.
func (c *compiler) evaluateLt(expr *cc.Expr) (exprValue, error) {
	left, err := c.evaluate(expr.Left)
	if err != nil {
		return exprValue{}, err
	}

	right, err := c.evaluate(expr.Right)
	if err != nil {
		return exprValue{}, err
	}

	left, right, err = c.resolveEnums(left, right)
	if err != nil {
		return exprValue{}, err
	}

	left, right = c.adjustNums(left, right)
	jumpOp := asm.JGE
	if comparisonIsSigned(left, right) {
		jumpOp = asm.JSGE
	}

	if left.isConstant() && right.isConstant() {
		return newConstant(int64(bool2int(left.num < right.num))), nil
	}

	if left.isPending() && !canCalculate(left.btf) {
		return exprValue{}, fmt.Errorf("left operand cannot be used for lt")
	}

	if right.isPending() && !canCalculate(right.btf) {
		return exprValue{}, fmt.Errorf("right operand cannot be used for lt")
	}

	left, err = c.materialize(left)
	if err != nil {
		return exprValue{}, err
	}

	if right.isConstant() {
		c.emit(JmpOff(jumpOp, left.reg, right.num, 2))
		c.emitReg2bool(left.reg)
		return newMaterialized(left.reg, left.btf), nil
	}

	right, err = c.materialize(right)
	if err != nil {
		return exprValue{}, err
	}

	c.emit(JmpReg(jumpOp, left.reg, right.reg, 2))
	c.emitReg2bool(left.reg)
	c.regalloc.Free(right.reg)

	return newMaterialized(left.reg, left.btf), nil
}

// evaluateLtEq handles less-than-or-equal comparison.
func (c *compiler) evaluateLtEq(expr *cc.Expr) (exprValue, error) {
	left, err := c.evaluate(expr.Left)
	if err != nil {
		return exprValue{}, err
	}

	right, err := c.evaluate(expr.Right)
	if err != nil {
		return exprValue{}, err
	}

	left, right, err = c.resolveEnums(left, right)
	if err != nil {
		return exprValue{}, err
	}

	left, right = c.adjustNums(left, right)
	jumpOp := asm.JGT
	if comparisonIsSigned(left, right) {
		jumpOp = asm.JSGT
	}

	if left.isConstant() && right.isConstant() {
		return newConstant(int64(bool2int(left.num <= right.num))), nil
	}

	if left.isPending() && !canCalculate(left.btf) {
		return exprValue{}, fmt.Errorf("left operand cannot be used for lteq")
	}

	if right.isPending() && !canCalculate(right.btf) {
		return exprValue{}, fmt.Errorf("right operand cannot be used for lteq")
	}

	left, err = c.materialize(left)
	if err != nil {
		return exprValue{}, err
	}

	if right.isConstant() {
		c.emit(JmpOff(jumpOp, left.reg, right.num, 2))
		c.emitReg2bool(left.reg)
		return newMaterialized(left.reg, left.btf), nil
	}

	right, err = c.materialize(right)
	if err != nil {
		return exprValue{}, err
	}

	c.emit(JmpReg(jumpOp, left.reg, right.reg, 2))
	c.emitReg2bool(left.reg)
	c.regalloc.Free(right.reg)

	return newMaterialized(left.reg, left.btf), nil
}

// evaluateGt handles greater-than comparison.
func (c *compiler) evaluateGt(expr *cc.Expr) (exprValue, error) {
	left, err := c.evaluate(expr.Left)
	if err != nil {
		return exprValue{}, err
	}

	right, err := c.evaluate(expr.Right)
	if err != nil {
		return exprValue{}, err
	}

	left, right, err = c.resolveEnums(left, right)
	if err != nil {
		return exprValue{}, err
	}

	left, right = c.adjustNums(left, right)
	jumpOp := asm.JLE
	if comparisonIsSigned(left, right) {
		jumpOp = asm.JSLE
	}

	if left.isConstant() && right.isConstant() {
		return newConstant(int64(bool2int(left.num > right.num))), nil
	}

	if left.isPending() && !canCalculate(left.btf) {
		return exprValue{}, fmt.Errorf("left operand cannot be used for gt")
	}

	if right.isPending() && !canCalculate(right.btf) {
		return exprValue{}, fmt.Errorf("right operand cannot be used for gt")
	}

	left, err = c.materialize(left)
	if err != nil {
		return exprValue{}, err
	}

	if right.isConstant() {
		c.emit(JmpOff(jumpOp, left.reg, right.num, 2))
		c.emitReg2bool(left.reg)
		return newMaterialized(left.reg, left.btf), nil
	}

	right, err = c.materialize(right)
	if err != nil {
		return exprValue{}, err
	}

	c.emit(JmpReg(jumpOp, left.reg, right.reg, 2))
	c.emitReg2bool(left.reg)
	c.regalloc.Free(right.reg)

	return newMaterialized(left.reg, left.btf), nil
}

// evaluateGtEq handles greater-than-or-equal comparison.
func (c *compiler) evaluateGtEq(expr *cc.Expr) (exprValue, error) {
	left, err := c.evaluate(expr.Left)
	if err != nil {
		return exprValue{}, err
	}

	right, err := c.evaluate(expr.Right)
	if err != nil {
		return exprValue{}, err
	}

	left, right, err = c.resolveEnums(left, right)
	if err != nil {
		return exprValue{}, err
	}

	left, right = c.adjustNums(left, right)
	jumpOp := asm.JLT
	if comparisonIsSigned(left, right) {
		jumpOp = asm.JSLT
	}

	if left.isConstant() && right.isConstant() {
		return newConstant(int64(bool2int(left.num >= right.num))), nil
	}

	if left.isPending() && !canCalculate(left.btf) {
		return exprValue{}, fmt.Errorf("left operand cannot be used for gteq")
	}

	if right.isPending() && !canCalculate(right.btf) {
		return exprValue{}, fmt.Errorf("right operand cannot be used for gteq")
	}

	left, err = c.materialize(left)
	if err != nil {
		return exprValue{}, err
	}

	if right.isConstant() {
		c.emit(JmpOff(jumpOp, left.reg, right.num, 2))
		c.emitReg2bool(left.reg)
		return newMaterialized(left.reg, left.btf), nil
	}

	right, err = c.materialize(right)
	if err != nil {
		return exprValue{}, err
	}

	c.emit(JmpReg(jumpOp, left.reg, right.reg, 2))
	c.emitReg2bool(left.reg)
	c.regalloc.Free(right.reg)

	return newMaterialized(left.reg, left.btf), nil
}

// evaluateAndAnd handles logical AND.
func (c *compiler) evaluateAndAnd(expr *cc.Expr) (exprValue, error) {
	left, err := c.evaluate(expr.Left)
	if err != nil {
		return exprValue{}, err
	}

	right, err := c.evaluate(expr.Right)
	if err != nil {
		return exprValue{}, err
	}

	left, right, err = c.resolveEnums(left, right)
	if err != nil {
		return exprValue{}, err
	}

	if left.isConstant() && right.isConstant() {
		return newConstant(int64(bool2int(left.num != 0 && right.num != 0))), nil
	}

	if left.isPending() && !canCalculate(left.btf) {
		return exprValue{}, fmt.Errorf("left operand cannot be used for andand")
	}

	if right.isPending() && !canCalculate(right.btf) {
		return exprValue{}, fmt.Errorf("right operand cannot be used for andand")
	}

	// Short-circuit evaluation
	if left.isConstant() {
		if left.num == 0 {
			return newConstant(0), nil
		}
		right, err = c.materialize(right)
		if err != nil {
			return exprValue{}, err
		}
		c.emit(JmpOff(asm.JEq, right.reg, 0, 2))
		c.emitReg2bool(right.reg)
		return newMaterialized(right.reg, right.btf), nil
	}

	if right.isConstant() {
		if right.num == 0 {
			// Free left if materialized
			if left.isMaterialized() {
				c.regalloc.Free(left.reg)
			}
			return newConstant(0), nil
		}
		left, err = c.materialize(left)
		if err != nil {
			return exprValue{}, err
		}
		c.emit(JmpOff(asm.JEq, left.reg, 0, 2))
		c.emitReg2bool(left.reg)
		return newMaterialized(left.reg, left.btf), nil
	}

	left, err = c.materialize(left)
	if err != nil {
		return exprValue{}, err
	}

	right, err = c.materialize(right)
	if err != nil {
		return exprValue{}, err
	}

	c.emit(JmpOff(asm.JEq, left.reg, 0, 3))
	c.emit(JmpOff(asm.JEq, right.reg, 0, 2))
	c.emitReg2bool(left.reg)
	c.regalloc.Free(right.reg)

	return newMaterialized(left.reg, left.btf), nil
}

// evaluateOrOr handles logical OR.
func (c *compiler) evaluateOrOr(expr *cc.Expr) (exprValue, error) {
	left, err := c.evaluate(expr.Left)
	if err != nil {
		return exprValue{}, err
	}

	right, err := c.evaluate(expr.Right)
	if err != nil {
		return exprValue{}, err
	}

	left, right, err = c.resolveEnums(left, right)
	if err != nil {
		return exprValue{}, err
	}

	if left.isConstant() && right.isConstant() {
		return newConstant(int64(bool2int(left.num != 0 || right.num != 0))), nil
	}

	if left.isPending() && !canCalculate(left.btf) {
		return exprValue{}, fmt.Errorf("left operand cannot be used for oror")
	}

	if right.isPending() && !canCalculate(right.btf) {
		return exprValue{}, fmt.Errorf("right operand cannot be used for oror")
	}

	// Short-circuit evaluation
	if left.isConstant() {
		if left.num != 0 {
			return newConstant(1), nil
		}
		right, err = c.materialize(right)
		if err != nil {
			return exprValue{}, err
		}
		c.emit(JmpOff(asm.JEq, right.reg, 0, 2))
		c.emitReg2bool(right.reg)
		return newMaterialized(right.reg, right.btf), nil
	}

	if right.isConstant() {
		if right.num != 0 {
			if left.isMaterialized() {
				c.regalloc.Free(left.reg)
			}
			return newConstant(1), nil
		}
		left, err = c.materialize(left)
		if err != nil {
			return exprValue{}, err
		}
		c.emit(JmpOff(asm.JEq, left.reg, 0, 2))
		c.emitReg2bool(left.reg)
		return newMaterialized(left.reg, left.btf), nil
	}

	left, err = c.materialize(left)
	if err != nil {
		return exprValue{}, err
	}

	right, err = c.materialize(right)
	if err != nil {
		return exprValue{}, err
	}

	c.emit(JmpOff(asm.JNE, left.reg, 0, 3))
	c.emit(JmpOff(asm.JNE, right.reg, 0, 2))
	c.emit(asm.Xor.Reg(left.reg, left.reg))
	c.emit(Ja(1))
	c.emit(asm.Mov.Imm(left.reg, 1))
	c.regalloc.Free(right.reg)

	return newMaterialized(left.reg, left.btf), nil
}

// evaluateNot handles logical NOT.
func (c *compiler) evaluateNot(expr *cc.Expr) (exprValue, error) {
	val, err := c.evaluate(expr.Left)
	if err != nil {
		return exprValue{}, err
	}

	if val.isConstant() {
		return newConstant(int64(bool2int(val.num == 0))), nil
	}

	val, err = c.materialize(val)
	if err != nil {
		return exprValue{}, err
	}

	c.emit(JmpOff(asm.JNE, val.reg, 0, 2))
	c.emitReg2bool(val.reg)

	return newMaterialized(val.reg, val.btf), nil
}

// evaluateMinus handles unary minus.
func (c *compiler) evaluateMinus(expr *cc.Expr) (exprValue, error) {
	val, err := c.evaluate(expr.Left)
	if err != nil {
		return exprValue{}, err
	}

	if val.isConstant() {
		return newConstant(-val.num), nil
	}

	val, err = c.materialize(val)
	if err != nil {
		return exprValue{}, err
	}

	c.emit(asm.Neg.Reg(val.reg, val.reg))
	return newMaterialized(val.reg, val.btf), nil
}

// evaluatePreInc handles pre-increment.
func (c *compiler) evaluatePreInc(expr *cc.Expr) (exprValue, error) {
	val, err := c.evaluate(expr.Left)
	if err != nil {
		return exprValue{}, err
	}

	if val.isConstant() {
		return newConstant(val.num + 1), nil
	}

	val, err = c.materialize(val)
	if err != nil {
		return exprValue{}, err
	}

	c.emit(asm.Add.Imm(val.reg, 1))
	return newMaterialized(val.reg, val.btf), nil
}

// evaluatePreDec handles pre-decrement.
func (c *compiler) evaluatePreDec(expr *cc.Expr) (exprValue, error) {
	val, err := c.evaluate(expr.Left)
	if err != nil {
		return exprValue{}, err
	}

	if val.isConstant() {
		return newConstant(val.num - 1), nil
	}

	val, err = c.materialize(val)
	if err != nil {
		return exprValue{}, err
	}

	c.emit(asm.Sub.Imm(val.reg, 1))
	return newMaterialized(val.reg, val.btf), nil
}

// evaluateCond handles the ternary conditional operator.
func (c *compiler) evaluateCond(expr *cc.Expr) (exprValue, error) {
	if len(expr.List) != 3 {
		return exprValue{}, fmt.Errorf("conditional expression requires 3 operands")
	}

	cond, err := c.evaluate(expr.List[0])
	if err != nil {
		return exprValue{}, err
	}

	// Evaluate both branches (we need their values regardless)
	left, err := c.evaluate(expr.List[1])
	if err != nil {
		return exprValue{}, err
	}

	right, err := c.evaluate(expr.List[2])
	if err != nil {
		return exprValue{}, err
	}

	if cond.isPending() && !canCalculate(cond.btf) {
		return exprValue{}, fmt.Errorf("invalid cond operand")
	}

	if left.isPending() && !canCalculate(left.btf) {
		return exprValue{}, fmt.Errorf("left operand cannot be used for cond")
	}

	if right.isPending() && !canCalculate(right.btf) {
		return exprValue{}, fmt.Errorf("right operand cannot be used for cond")
	}

	// Constant condition - select branch at compile time
	if cond.isConstant() {
		if cond.num != 0 {
			return left, nil
		}
		return right, nil
	}

	// Runtime condition
	cond, err = c.materialize(cond)
	if err != nil {
		return exprValue{}, err
	}

	jmpInsnIdx := len(c.insns)
	c.emit(JmpOff(asm.JEq, cond.reg, 0, 2))

	if left.isConstant() {
		c.emit(asm.Mov.Imm(cond.reg, int32(left.num)))
	} else {
		left, err = c.materialize(left)
		if err != nil {
			return exprValue{}, err
		}
		c.emit(asm.Mov.Reg(cond.reg, left.reg))
		c.regalloc.Free(left.reg)
	}

	jaInsnIdx := len(c.insns)
	c.emit(Ja(1))

	// update jmp off
	c.insns[jmpInsnIdx].Offset = int16(len(c.insns) - jmpInsnIdx - 1)

	if right.isConstant() {
		c.emit(asm.Mov.Imm(cond.reg, int32(right.num)))
	} else {
		right, err = c.materialize(right)
		if err != nil {
			return exprValue{}, err
		}
		c.emit(asm.Mov.Reg(cond.reg, right.reg))
		c.regalloc.Free(right.reg)
	}

	// update ja off
	c.insns[jaInsnIdx].Offset = int16(len(c.insns) - jaInsnIdx - 1)

	return newMaterialized(cond.reg, cond.btf), nil
}

// resolveEnums handles the case where one operand might be an enum.
func (c *compiler) resolveEnums(left, right exprValue) (exprValue, exprValue, error) {
	if left.isEnumMaybe() && right.isMaterialized() {
		num, err := c.extractEnum(right.btf, left.name)
		if err != nil {
			return left, right, fmt.Errorf("failed to resolve enum '%s': %w", left.name, err)
		}
		left = newConstant(int64(num))
	}

	if right.isEnumMaybe() && left.isMaterialized() {
		num, err := c.extractEnum(left.btf, right.name)
		if err != nil {
			return left, right, fmt.Errorf("failed to resolve enum '%s': %w", right.name, err)
		}
		right = newConstant(int64(num))
	}

	// Try to resolve against pending values too
	if left.isEnumMaybe() && right.isPending() {
		num, err := c.extractEnum(right.btf, left.name)
		if err != nil {
			return left, right, fmt.Errorf("failed to resolve enum '%s': %w", left.name, err)
		}
		left = newConstant(int64(num))
	}

	if right.isEnumMaybe() && left.isPending() {
		num, err := c.extractEnum(left.btf, right.name)
		if err != nil {
			return left, right, fmt.Errorf("failed to resolve enum '%s': %w", right.name, err)
		}
		right = newConstant(int64(num))
	}

	return left, right, nil
}

// adjustNums adjusts constant values based on the type of the other operand.
func (c *compiler) adjustNums(left, right exprValue) (exprValue, exprValue) {
	if left.isConstant() && (right.isMaterialized() || right.isPending()) {
		left.num = c.adjustNumForType(left.num, right.btf, right.mem)
	}
	if right.isConstant() && (left.isMaterialized() || left.isPending()) {
		right.num = c.adjustNumForType(right.num, left.btf, left.mem)
	}
	return left, right
}

func isSignedBTFType(typ btf.Type) bool {
	switch typ := mybtf.UnderlyingType(typ).(type) {
	case *btf.Int:
		return typ.Encoding == btf.Signed
	case *btf.Enum:
		return typ.Signed
	default:
		return false
	}
}

func comparisonIsSigned(left, right exprValue) bool {
	if left.isConstant() {
		return !right.isConstant() && isSignedBTFType(right.btf)
	}
	if right.isConstant() {
		return isSignedBTFType(left.btf)
	}
	return isSignedBTFType(left.btf) && isSignedBTFType(right.btf)
}

// adjustNumForType adjusts a number based on the target type's size.
func (c *compiler) adjustNumForType(num int64, typ btf.Type, mem *btf.Member) int64 {
	if isMemberBitfield(mem) {
		mask := (int64(1) << uint64(mem.BitfieldSize)) - 1
		return num & mask
	}

	size, _ := btf.Sizeof(typ)
	if isSignedBTFType(typ) {
		switch size {
		case 1:
			return int64(int8(num))
		case 2:
			return int64(int16(num))
		case 4:
			return int64(int32(num))
		default:
			return num
		}
	}
	switch size {
	case 1:
		return num & 0xFF
	case 2:
		return num & 0xFFFF
	case 4:
		return num & 0xFFFFFFFF
	default:
		return num
	}
}

// isMemberBitfield reports whether the member is a bitfield attribute.
func isMemberBitfield(member *btf.Member) bool {
	return member != nil && member.BitfieldSize != 0
}

func (c *compiler) cc2btf(expr *cc.Expr) (btf.Type, error) {
	ccType := expr.Type
	isPointer := ccType.Kind == cc.Ptr
	if isPointer {
		ccType = ccType.Base
	}

	var typ btf.Type
	var err error

	if ccType.Kind == cc.Struct {
		typeName := ccType.Tag
		typ, err = c.findType(typeName)
		if err != nil {
			return nil, fmt.Errorf("failed to find type '%s': %w", typeName, err)
		}

		t := mybtf.UnderlyingType(typ)
		_, isStruct := t.(*btf.Struct)
		_, isUnion := t.(*btf.Union)
		if !isStruct && !isUnion {
			return nil, fmt.Errorf("expected struct/union type for cast, got %T", t)
		}
	} else {
		typeName := ccType.String()
		switch typeName {
		case "void":
			typ = &btf.Void{}

		case "uchar":
			typ, err = c.krnlSpec.AnyTypeByName("unsigned char")

		case "short":
			typ, err = c.krnlSpec.AnyTypeByName("s16")

		case "ushort":
			typ, err = c.krnlSpec.AnyTypeByName("u16")

		case "long", "longlong":
			typ, err = c.krnlSpec.AnyTypeByName("s64")

		case "ulonglong":
			typ, err = c.krnlSpec.AnyTypeByName("u64")

		default:
			typ, err = c.krnlSpec.AnyTypeByName(typeName)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to find type '%s': %w", typeName, err)
		}
	}

	if isPointer {
		return &btf.Pointer{Target: typ}, nil
	} else {
		return typ, nil
	}
}

func (c *compiler) extractEnum(typ btf.Type, enum string) (int, error) {
	t := mybtf.UnderlyingType(typ)

	e, ok := t.(*btf.Enum)
	if !ok {
		return 0, fmt.Errorf("type %v is not an enum for '%s'", typ, enum)
	}

	for _, v := range e.Values {
		if v.Name == enum {
			return int(v.Value), nil
		}
	}

	return 0, fmt.Errorf("enum '%s' not found in type %v", enum, typ)
}
