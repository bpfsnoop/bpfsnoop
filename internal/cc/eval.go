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

const (
	evalValueTypeUnspec int = iota
	evalValueTypeNum
	evalValueTypeRegBtf
	evalValueTypeEnumMaybe
)

type evalValue struct {
	typ  int
	reg  asm.Register
	num  int64
	name string
	btf  btf.Type
	mem  *btf.Member
}

func (v evalValue) String() string {
	switch v.typ {
	case evalValueTypeNum:
		return fmt.Sprintf("%d", v.num)
	case evalValueTypeRegBtf:
		return fmt.Sprintf("r%d(%v)", v.reg, v.btf)
	case evalValueTypeEnumMaybe:
		return v.name
	default:
		return "unspecified"
	}
}

func (c *compiler) emitReg2bool(reg asm.Register) {
	c.emit(
		asm.Mov.Imm(reg, 1),
		Ja(1),
		asm.Xor.Reg(reg, reg),
	)
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

func (c *compiler) adjustNum(num int64, ref evalValue) int64 {
	if ref.typ != evalValueTypeRegBtf {
		return num
	}

	if isMemberBitfield(ref.mem) {
		mask := (int64(1) << uint64(ref.mem.BitfieldSize)) - 1
		return num & mask
	}

	size, _ := btf.Sizeof(ref.btf)
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

func (c *compiler) preHandleBinaryOp(a, b evalValue) (evalValue, evalValue, error) {
	if a.typ == evalValueTypeRegBtf && !canCalculate(a.btf) {
		return a, b, fmt.Errorf("disallow type %v for binary op", a.btf)
	}

	if b.typ == evalValueTypeRegBtf && !canCalculate(b.btf) {
		return a, b, fmt.Errorf("disallow type %v for binary op", b.btf)
	}

	if a.typ == evalValueTypeEnumMaybe && b.typ == evalValueTypeRegBtf {
		num, err := c.extractEnum(b.btf, a.name)
		if err != nil {
			return a, b, fmt.Errorf("failed to extract enum: %w", err)
		}

		a.num = c.adjustNum(int64(num), b)
		a.typ = evalValueTypeNum
		return a, b, nil
	}

	if a.typ == evalValueTypeRegBtf && b.typ == evalValueTypeEnumMaybe {
		num, err := c.extractEnum(a.btf, b.name)
		if err != nil {
			return a, b, fmt.Errorf("failed to extract enum: %w", err)
		}

		b.num = c.adjustNum(int64(num), a)
		b.typ = evalValueTypeNum
		return a, b, nil
	}

	a.num = c.adjustNum(a.num, b)
	b.num = c.adjustNum(b.num, a)

	return a, b, nil
}

func (c *compiler) add(left, right evalValue) (evalValue, error) {
	left, right, err := c.preHandleBinaryOp(left, right)
	if err != nil {
		return evalValue{}, err
	}

	switch {
	case left.typ == evalValueTypeNum && right.typ == evalValueTypeNum:
		left.num += right.num
		return left, nil

	case left.typ == evalValueTypeRegBtf && right.typ == evalValueTypeRegBtf:
		var size int
		t := mybtf.UnderlyingType(left.btf)
		if ptr, ok := t.(*btf.Pointer); ok {
			size, _ = btf.Sizeof(ptr.Target)
		} else if arr, ok := t.(*btf.Array); ok {
			size, _ = btf.Sizeof(arr.Type)
		}
		if size != 0 {
			c.emit(asm.Mul.Imm(right.reg, int32(size)))
		}

		c.emit(asm.Add.Reg(left.reg, right.reg))
		c.regalloc.Free(right.reg)
		return left, nil

	case left.typ == evalValueTypeNum && right.typ == evalValueTypeRegBtf:
		if left.num == 0 {
			return right, nil
		}

		t := mybtf.UnderlyingType(right.btf)
		if ptr, ok := t.(*btf.Pointer); ok {
			if _, ok := mybtf.UnderlyingType(ptr.Target).(*btf.Void); ok {
				c.emit(asm.Add.Imm(right.reg, int32(left.num)))
			} else {
				size, _ := btf.Sizeof(ptr.Target)
				if size == 0 {
					c.regalloc.Free(right.reg)
					return right, fmt.Errorf("disallow type %v for add", right.btf)
				}

				c.emit(asm.Add.Imm(right.reg, int32(left.num)*int32(size)))
			}
		} else if arr, ok := t.(*btf.Array); ok {
			size, _ := btf.Sizeof(arr.Type)
			if size == 0 {
				c.regalloc.Free(right.reg)
				return right, fmt.Errorf("disallow type %v for add", right.btf)
			}

			c.emit(asm.Add.Imm(right.reg, int32(left.num)*int32(size)))
		} else {
			c.emit(asm.Add.Imm(right.reg, int32(left.num)))
		}

		return right, nil

	case left.typ == evalValueTypeRegBtf && right.typ == evalValueTypeNum:
		if right.num == 0 {
			return left, nil
		}

		t := mybtf.UnderlyingType(left.btf)
		if ptr, ok := t.(*btf.Pointer); ok {
			if _, ok := mybtf.UnderlyingType(ptr.Target).(*btf.Void); ok {
				c.emit(asm.Add.Imm(left.reg, int32(right.num)))
			} else {
				size, _ := btf.Sizeof(ptr.Target)
				if size == 0 {
					c.regalloc.Free(left.reg)
					return left, fmt.Errorf("disallow type %v for add", left.btf)
				}

				c.emit(asm.Add.Imm(left.reg, int32(right.num)*int32(size)))
			}
		} else if arr, ok := t.(*btf.Array); ok {
			size, _ := btf.Sizeof(arr.Type)
			if size == 0 {
				c.regalloc.Free(left.reg)
				return left, fmt.Errorf("disallow type %v for add", left.btf)
			}

			c.emit(asm.Add.Imm(left.reg, int32(right.num)*int32(size)))
		} else {
			c.emit(asm.Add.Imm(left.reg, int32(right.num)))
		}

		return left, nil

	default:
		return evalValue{}, ErrNotImplemented
	}
}

func (c *compiler) and(left, right evalValue) (evalValue, error) {
	left, right, err := c.preHandleBinaryOp(left, right)
	if err != nil {
		return evalValue{}, err
	}

	switch {
	case left.typ == evalValueTypeNum && right.typ == evalValueTypeNum:
		left.num &= right.num
		return left, nil

	case left.typ == evalValueTypeRegBtf && right.typ == evalValueTypeRegBtf:
		c.emit(asm.And.Reg(left.reg, right.reg))
		c.regalloc.Free(right.reg)
		return left, nil

	case left.typ == evalValueTypeNum && right.typ == evalValueTypeRegBtf:
		c.emit(asm.And.Imm(right.reg, int32(left.num)))
		return right, nil

	case left.typ == evalValueTypeRegBtf && right.typ == evalValueTypeNum:
		c.emit(asm.And.Imm(left.reg, int32(right.num)))
		return left, nil

	default:
		return evalValue{}, ErrNotImplemented
	}
}

func (c *compiler) andand(left, right evalValue) (evalValue, error) {
	left, right, err := c.preHandleBinaryOp(left, right)
	if err != nil {
		return evalValue{}, err
	}

	switch {
	case left.typ == evalValueTypeNum && right.typ == evalValueTypeNum:
		left.num = int64(bool2int(left.num != 0 && right.num != 0))
		return left, nil

	case left.typ == evalValueTypeRegBtf && right.typ == evalValueTypeRegBtf:
		c.emit(JmpOff(asm.JEq, left.reg, 0, 3))
		c.emit(JmpOff(asm.JEq, right.reg, 0, 2))
		c.emitReg2bool(left.reg)
		c.regalloc.Free(right.reg)
		return left, nil

	case left.typ == evalValueTypeNum && right.typ == evalValueTypeRegBtf:
		if left.num == 0 {
			c.regalloc.Free(right.reg)
			return left, nil
		}

		c.emit(JmpOff(asm.JEq, right.reg, 0, 2))
		c.emitReg2bool(right.reg)
		return right, nil

	case left.typ == evalValueTypeRegBtf && right.typ == evalValueTypeNum:
		if right.num == 0 {
			c.regalloc.Free(left.reg)
			return right, nil
		}

		c.emit(JmpOff(asm.JEq, left.reg, 0, 2))
		c.emitReg2bool(left.reg)
		return left, nil

	default:
		return evalValue{}, ErrNotImplemented
	}
}

func (c *compiler) cond(cond, left, right evalValue) (evalValue, error) {
	if cond.typ == evalValueTypeRegBtf && !canCalculate(cond.btf) {
		c.regalloc.Free(cond.reg)
		return cond, fmt.Errorf("disallow type %v for cond", cond.btf)
	}

	if left.typ == evalValueTypeRegBtf && !canCalculate(left.btf) {
		c.regalloc.Free(left.reg)
		return left, fmt.Errorf("disallow type %v for cond", left.btf)
	}

	if right.typ == evalValueTypeRegBtf && !canCalculate(right.btf) {
		c.regalloc.Free(right.reg)
		return right, fmt.Errorf("disallow type %v for cond", right.btf)
	}

	if cond.typ == evalValueTypeNum {
		if cond.num == 0 {
			return right, nil
		}
		return left, nil
	}

	c.emit(JmpOff(asm.JEq, cond.reg, 0, 2))

	if left.typ == evalValueTypeNum {
		c.emit(asm.Mov.Imm(cond.reg, int32(left.num)))
	} else {
		c.emit(asm.Mov.Reg(cond.reg, left.reg))
		c.regalloc.Free(left.reg)
	}
	c.emit(Ja(1))

	if right.typ == evalValueTypeNum {
		c.emit(asm.Mov.Imm(cond.reg, int32(right.num)))
	} else {
		c.emit(asm.Mov.Reg(cond.reg, right.reg))
		c.regalloc.Free(right.reg)
	}

	return cond, nil
}

func (c *compiler) div(left, right evalValue) (evalValue, error) {
	left, right, err := c.preHandleBinaryOp(left, right)
	if err != nil {
		return evalValue{}, err
	}

	if right.typ == evalValueTypeNum && right.num == 0 {
		return evalValue{}, fmt.Errorf("division by zero")
	}

	if left.typ == evalValueTypeNum && right.typ == evalValueTypeNum {
		left.num /= right.num
		return left, nil
	}

	if left.typ == evalValueTypeNum && right.typ == evalValueTypeRegBtf {
		reg, err := c.regalloc.Alloc()
		if err != nil {
			return evalValue{}, err
		}

		c.emit(JmpOff(asm.JEq, right.reg, 0, 2))
		c.emit(asm.Mov.Imm(reg, 0))
		c.emit(Ja(2))
		c.emit(asm.Mov.Imm(reg, int32(left.num)))
		c.emit(asm.Div.Reg(reg, right.reg))
		c.regalloc.Free(right.reg)
		return evalValue{typ: evalValueTypeRegBtf, reg: reg, btf: right.btf}, nil
	}

	if left.typ == evalValueTypeRegBtf && right.typ == evalValueTypeNum {
		c.emit(asm.Div.Imm(left.reg, int32(right.num)))
		return left, nil
	}

	if left.typ == evalValueTypeRegBtf && right.typ == evalValueTypeRegBtf {
		c.emit(JmpOff(asm.JEq, right.reg, 0, 2))
		c.emit(asm.Mov.Imm(left.reg, 0))
		c.emit(Ja(1))
		c.emit(asm.Div.Reg(left.reg, right.reg))
		c.regalloc.Free(right.reg)
		return left, nil
	}

	return evalValue{}, ErrNotImplemented
}

func (c *compiler) eqeq(left, right evalValue) (evalValue, error) {
	left, right, err := c.preHandleBinaryOp(left, right)
	if err != nil {
		return evalValue{}, err
	}

	switch {
	case left.typ == evalValueTypeNum && right.typ == evalValueTypeNum:
		left.num = int64(bool2int(left.num == right.num))
		return left, nil

	case left.typ == evalValueTypeNum && right.typ == evalValueTypeRegBtf:
		c.emit(JmpOff(asm.JNE, right.reg, int64(left.num), 2))
		c.emitReg2bool(right.reg)
		return right, nil

	case left.typ == evalValueTypeRegBtf && right.typ == evalValueTypeNum:
		c.emit(JmpOff(asm.JNE, left.reg, int64(right.num), 2))
		c.emitReg2bool(left.reg)
		return left, nil

	case left.typ == evalValueTypeRegBtf && right.typ == evalValueTypeRegBtf:
		c.emit(JmpReg(asm.JNE, left.reg, right.reg, 2))
		c.emitReg2bool(left.reg)
		c.regalloc.Free(right.reg)
		return left, nil

	default:
		return evalValue{}, ErrNotImplemented
	}
}

func (c *compiler) gt(left, right evalValue) (evalValue, error) {
	left, right, err := c.preHandleBinaryOp(left, right)
	if err != nil {
		return evalValue{}, err
	}

	switch {
	case left.typ == evalValueTypeNum && right.typ == evalValueTypeNum:
		left.num = int64(bool2int(left.num > right.num))
		return left, nil

	case left.typ == evalValueTypeNum && right.typ == evalValueTypeRegBtf:
		c.emit(JmpOff(asm.JLE, right.reg, int64(left.num), 2))
		c.emitReg2bool(right.reg)
		return right, nil

	case left.typ == evalValueTypeRegBtf && right.typ == evalValueTypeNum:
		c.emit(JmpOff(asm.JLE, left.reg, int64(right.num), 2))
		c.emitReg2bool(left.reg)
		return left, nil

	case left.typ == evalValueTypeRegBtf && right.typ == evalValueTypeRegBtf:
		c.emit(JmpReg(asm.JLE, left.reg, right.reg, 2))
		c.emitReg2bool(left.reg)
		c.regalloc.Free(right.reg)
		return left, nil

	default:
		return evalValue{}, ErrNotImplemented
	}
}

func (c *compiler) gteq(left, right evalValue) (evalValue, error) {
	left, right, err := c.preHandleBinaryOp(left, right)
	if err != nil {
		return evalValue{}, err
	}

	switch {
	case left.typ == evalValueTypeNum && right.typ == evalValueTypeNum:
		left.num = int64(bool2int(left.num >= right.num))
		return left, nil

	case left.typ == evalValueTypeNum && right.typ == evalValueTypeRegBtf:
		c.emit(JmpOff(asm.JLT, right.reg, int64(left.num), 2))
		c.emitReg2bool(right.reg)
		return right, nil

	case left.typ == evalValueTypeRegBtf && right.typ == evalValueTypeNum:
		c.emit(JmpOff(asm.JLT, left.reg, int64(right.num), 2))
		c.emitReg2bool(left.reg)
		return left, nil

	case left.typ == evalValueTypeRegBtf && right.typ == evalValueTypeRegBtf:
		c.emit(JmpReg(asm.JLT, left.reg, right.reg, 2))
		c.emitReg2bool(left.reg)
		c.regalloc.Free(right.reg)
		return left, nil

	default:
		return evalValue{}, ErrNotImplemented
	}
}

func (c *compiler) lsh(left, right evalValue) (evalValue, error) {
	left, right, err := c.preHandleBinaryOp(left, right)
	if err != nil {
		return evalValue{}, err
	}

	if left.typ == evalValueTypeNum && right.typ == evalValueTypeNum {
		left.num <<= right.num
		return left, nil
	}

	if left.typ == evalValueTypeNum && right.typ == evalValueTypeRegBtf {
		num := left.num
		if num == 0 {
			c.regalloc.Free(right.reg)
			return left, nil
		}

		reg, err := c.regalloc.Alloc()
		if err != nil {
			return evalValue{}, err
		}

		c.emit(asm.Mov.Imm(reg, int32(num)))
		c.emit(asm.LSh.Reg(reg, right.reg))
		c.regalloc.Free(right.reg)
		return evalValue{typ: evalValueTypeRegBtf, reg: reg, btf: right.btf}, nil
	}

	if left.typ == evalValueTypeRegBtf && right.typ == evalValueTypeNum {
		num := right.num
		if num < 0 {
			return evalValue{}, fmt.Errorf("shift count is negative")
		}
		if num == 0 {
			return left, nil
		}

		c.emit(asm.LSh.Imm(left.reg, int32(num)))
		return left, nil
	}

	if left.typ == evalValueTypeRegBtf && right.typ == evalValueTypeRegBtf {
		c.emit(JmpOff(asm.JLE, right.reg, 0, 1))
		c.emit(asm.LSh.Reg(left.reg, right.reg))
		c.regalloc.Free(right.reg)
		return left, nil
	}

	return evalValue{}, ErrNotImplemented
}

func (c *compiler) lt(left, right evalValue) (evalValue, error) {
	left, right, err := c.preHandleBinaryOp(left, right)
	if err != nil {
		return evalValue{}, err
	}

	switch {
	case left.typ == evalValueTypeNum && right.typ == evalValueTypeNum:
		left.num = int64(bool2int(left.num < right.num))
		return left, nil

	case left.typ == evalValueTypeNum && right.typ == evalValueTypeRegBtf:
		c.emit(JmpOff(asm.JGE, right.reg, int64(left.num), 2))
		c.emitReg2bool(right.reg)
		return right, nil

	case left.typ == evalValueTypeRegBtf && right.typ == evalValueTypeNum:
		c.emit(JmpOff(asm.JGE, left.reg, int64(right.num), 2))
		c.emitReg2bool(left.reg)
		return left, nil

	case left.typ == evalValueTypeRegBtf && right.typ == evalValueTypeRegBtf:
		c.emit(JmpReg(asm.JGE, left.reg, right.reg, 2))
		c.emitReg2bool(left.reg)
		c.regalloc.Free(right.reg)
		return left, nil

	default:
		return evalValue{}, ErrNotImplemented
	}
}

func (c *compiler) lteq(left, right evalValue) (evalValue, error) {
	left, right, err := c.preHandleBinaryOp(left, right)
	if err != nil {
		return evalValue{}, err
	}

	switch {
	case left.typ == evalValueTypeNum && right.typ == evalValueTypeNum:
		left.num = int64(bool2int(left.num <= right.num))
		return left, nil

	case left.typ == evalValueTypeNum && right.typ == evalValueTypeRegBtf:
		c.emit(JmpOff(asm.JGT, right.reg, int64(left.num), 2))
		c.emitReg2bool(right.reg)
		return right, nil

	case left.typ == evalValueTypeRegBtf && right.typ == evalValueTypeNum:
		c.emit(JmpOff(asm.JGT, left.reg, int64(right.num), 2))
		c.emitReg2bool(left.reg)
		return left, nil

	case left.typ == evalValueTypeRegBtf && right.typ == evalValueTypeRegBtf:
		c.emit(JmpReg(asm.JGT, left.reg, right.reg, 2))
		c.emitReg2bool(left.reg)
		c.regalloc.Free(right.reg)
		return left, nil

	default:
		return evalValue{}, ErrNotImplemented
	}
}

func (c *compiler) minus(val evalValue) (evalValue, error) {
	switch val.typ {
	case evalValueTypeNum:
		val.num = -val.num
		return val, nil

	case evalValueTypeRegBtf:
		c.emit(asm.Neg.Reg(val.reg, val.reg))
		return val, nil

	default:
		return evalValue{}, ErrNotImplemented
	}
}

func (c *compiler) mod(left, right evalValue) (evalValue, error) {
	left, right, err := c.preHandleBinaryOp(left, right)
	if err != nil {
		return evalValue{}, err
	}

	if right.typ == evalValueTypeNum && right.num == 0 {
		return evalValue{}, fmt.Errorf("mod by zero")
	}

	switch {
	case left.typ == evalValueTypeNum && right.typ == evalValueTypeNum:
		left.num = left.num % right.num
		return left, nil

	case left.typ == evalValueTypeNum && right.typ == evalValueTypeRegBtf:
		if left.num == 0 {
			c.regalloc.Free(right.reg)
			return left, nil
		}

		reg, err := c.regalloc.Alloc()
		if err != nil {
			return evalValue{}, err
		}

		c.emit(asm.Mov.Imm(reg, int32(left.num)))
		c.emit(asm.Mod.Reg(reg, right.reg))
		c.regalloc.Free(right.reg)
		return evalValue{typ: evalValueTypeRegBtf, reg: reg, btf: right.btf}, nil

	case left.typ == evalValueTypeRegBtf && right.typ == evalValueTypeNum:
		if right.num == 1 {
			c.emit(asm.Mov.Imm(left.reg, 0))
			return left, nil
		}

		c.emit(asm.Mod.Imm(left.reg, int32(right.num)))
		return left, nil

	case left.typ == evalValueTypeRegBtf && right.typ == evalValueTypeRegBtf:
		c.emit(JmpOff(asm.JEq, right.reg, 0, 1))
		c.emit(asm.Mod.Reg(left.reg, right.reg))
		c.regalloc.Free(right.reg)
		return left, nil

	default:
		return evalValue{}, ErrNotImplemented
	}
}

func (c *compiler) mul(left, right evalValue) (evalValue, error) {
	left, right, err := c.preHandleBinaryOp(left, right)
	if err != nil {
		return evalValue{}, err
	}

	if left.typ == evalValueTypeNum && right.typ == evalValueTypeNum {
		left.num *= right.num
		return left, nil
	}

	if left.typ == evalValueTypeRegBtf && right.typ == evalValueTypeRegBtf {
		c.emit(asm.Mul.Reg(left.reg, right.reg))
		c.regalloc.Free(right.reg)
		return left, nil
	}

	if right.typ == evalValueTypeRegBtf {
		left, right = right, left
	}

	if left.typ == evalValueTypeRegBtf && right.typ == evalValueTypeNum {
		if right.num == 0 {
			c.regalloc.Free(left.reg)
			return right, nil
		}
		if right.num == 1 {
			return left, nil
		}

		c.emit(asm.Mul.Imm(left.reg, int32(right.num)))
		return left, nil
	}

	return evalValue{}, ErrNotImplemented
}

func (c *compiler) not(val evalValue) (evalValue, error) {
	switch val.typ {
	case evalValueTypeNum:
		val.num = int64(bool2int(val.num == 0))
		return val, nil

	case evalValueTypeRegBtf:
		if !canCalculate(val.btf) {
			c.regalloc.Free(val.reg)
			return val, fmt.Errorf("disallow type %v for not", val.btf)
		}

		c.emit(JmpOff(asm.JNE, val.reg, 0, 2))
		c.emitReg2bool(val.reg)
		return val, nil

	default:
		return evalValue{}, ErrNotImplemented
	}
}

func (c *compiler) noteq(left, right evalValue) (evalValue, error) {
	left, right, err := c.preHandleBinaryOp(left, right)
	if err != nil {
		return evalValue{}, err
	}

	switch {
	case left.typ == evalValueTypeNum && right.typ == evalValueTypeNum:
		left.num = int64(bool2int(left.num != right.num))
		return left, nil

	case left.typ == evalValueTypeNum && right.typ == evalValueTypeRegBtf:
		c.emit(JmpOff(asm.JEq, right.reg, int64(left.num), 2))
		c.emitReg2bool(right.reg)
		return right, nil

	case left.typ == evalValueTypeRegBtf && right.typ == evalValueTypeNum:
		c.emit(JmpOff(asm.JEq, left.reg, int64(right.num), 2))
		c.emitReg2bool(left.reg)
		return left, nil

	case left.typ == evalValueTypeRegBtf && right.typ == evalValueTypeRegBtf:
		c.emit(JmpReg(asm.JEq, left.reg, right.reg, 2))
		c.emitReg2bool(left.reg)
		c.regalloc.Free(right.reg)
		return left, nil

	default:
		return evalValue{}, ErrNotImplemented
	}
}

func (c *compiler) or(left, right evalValue) (evalValue, error) {
	left, right, err := c.preHandleBinaryOp(left, right)
	if err != nil {
		return evalValue{}, err
	}

	switch {
	case left.typ == evalValueTypeNum && right.typ == evalValueTypeNum:
		left.num |= right.num
		return left, nil

	case left.typ == evalValueTypeRegBtf && right.typ == evalValueTypeRegBtf:
		c.emit(asm.Or.Reg(left.reg, right.reg))
		c.regalloc.Free(right.reg)
		return left, nil

	case left.typ == evalValueTypeNum && right.typ == evalValueTypeRegBtf:
		if left.num == 0 {
			c.regalloc.Free(right.reg)
			return left, nil
		}

		c.emit(asm.Or.Imm(right.reg, int32(left.num)))
		return right, nil

	case left.typ == evalValueTypeRegBtf && right.typ == evalValueTypeNum:
		if right.num == 0 {
			c.regalloc.Free(left.reg)
			return right, nil
		}

		c.emit(asm.Or.Imm(left.reg, int32(right.num)))
		return left, nil

	default:
		return evalValue{}, ErrNotImplemented
	}
}

func (c *compiler) oror(left, right evalValue) (evalValue, error) {
	left, right, err := c.preHandleBinaryOp(left, right)
	if err != nil {
		return evalValue{}, err
	}

	switch {
	case left.typ == evalValueTypeNum && right.typ == evalValueTypeNum:
		left.num = int64(bool2int(left.num != 0 || right.num != 0))
		return left, nil

	case left.typ == evalValueTypeRegBtf && right.typ == evalValueTypeRegBtf:
		c.emit(JmpOff(asm.JNE, left.reg, 0, 3))
		c.emit(JmpOff(asm.JNE, right.reg, 0, 2))
		c.emit(asm.Xor.Reg(left.reg, left.reg))
		c.emit(Ja(1))
		c.emit(asm.Mov.Imm(left.reg, 1))
		c.regalloc.Free(right.reg)
		return left, nil

	case left.typ == evalValueTypeNum && right.typ == evalValueTypeRegBtf:
		if left.num != 0 {
			left.num = 1
			c.regalloc.Free(right.reg)
			return left, nil
		}

		c.emit(JmpOff(asm.JEq, right.reg, 0, 2))
		c.emitReg2bool(right.reg)
		return right, nil

	case left.typ == evalValueTypeRegBtf && right.typ == evalValueTypeNum:
		if right.num != 0 {
			right.num = 1
			c.regalloc.Free(left.reg)
			return right, nil
		}

		c.emit(JmpOff(asm.JEq, left.reg, 0, 2))
		c.emitReg2bool(left.reg)
		return left, nil

	default:
		return evalValue{}, ErrNotImplemented
	}
}

func (c *compiler) preDec(val evalValue) (evalValue, error) {
	switch val.typ {
	case evalValueTypeNum:
		val.num--
		return val, nil

	case evalValueTypeRegBtf:
		if !canCalculate(val.btf) {
			c.regalloc.Free(val.reg)
			return val, fmt.Errorf("disallow type %v for pre-decrement", val.btf)
		}

		c.emit(asm.Sub.Imm(val.reg, 1))
		return val, nil

	default:
		return evalValue{}, ErrNotImplemented
	}
}

func (c *compiler) preInc(val evalValue) (evalValue, error) {
	switch val.typ {
	case evalValueTypeNum:
		val.num++
		return val, nil

	case evalValueTypeRegBtf:
		if !canCalculate(val.btf) {
			c.regalloc.Free(val.reg)
			return val, fmt.Errorf("disallow type %v for pre-increment", val.btf)
		}

		c.emit(asm.Add.Imm(val.reg, 1))
		return val, nil

	default:
		return evalValue{}, ErrNotImplemented
	}
}

func (c *compiler) rsh(left, right evalValue) (evalValue, error) {
	left, right, err := c.preHandleBinaryOp(left, right)
	if err != nil {
		return evalValue{}, err
	}

	if left.typ == evalValueTypeNum && right.typ == evalValueTypeNum {
		left.num >>= right.num
		return left, nil
	}

	if left.typ == evalValueTypeNum && right.typ == evalValueTypeRegBtf {
		if left.num == 0 {
			c.regalloc.Free(right.reg)
			return left, nil
		}

		reg, err := c.regalloc.Alloc()
		if err != nil {
			return evalValue{}, err
		}

		c.emit(asm.Mov.Imm(reg, int32(left.num)))
		c.emit(asm.RSh.Reg(reg, right.reg))
		c.regalloc.Free(right.reg)
		return evalValue{typ: evalValueTypeRegBtf, reg: reg, btf: right.btf}, nil
	}

	if left.typ == evalValueTypeRegBtf && right.typ == evalValueTypeNum {
		if right.num < 0 {
			return evalValue{}, fmt.Errorf("shift count is negative")
		}
		if right.num == 0 {
			return left, nil
		}

		c.emit(asm.RSh.Imm(left.reg, int32(right.num)))
		return left, nil
	}

	if left.typ == evalValueTypeRegBtf && right.typ == evalValueTypeRegBtf {
		c.emit(asm.RSh.Reg(left.reg, right.reg))
		c.regalloc.Free(right.reg)
		return left, nil
	}

	return evalValue{}, ErrNotImplemented
}

func (c *compiler) sub(left, right evalValue) (evalValue, error) {
	left, right, err := c.preHandleBinaryOp(left, right)
	if err != nil {
		return evalValue{}, err
	}

	if left.typ == evalValueTypeNum && right.typ == evalValueTypeNum {
		left.num -= right.num
		return left, nil
	}

	if left.typ == evalValueTypeNum && right.typ == evalValueTypeRegBtf {
		t := mybtf.UnderlyingType(right.btf)
		_, isInt := t.(*btf.Int)
		_, isEnum := t.(*btf.Enum)
		if !isInt && !isEnum {
			c.regalloc.Free(right.reg)
			return right, fmt.Errorf("disallow type %v for sub", right.btf)
		}

		if left.num == 0 {
			c.emit(asm.Neg.Reg(right.reg, right.reg))
			return right, nil
		}

		c.emit(asm.Sub.Imm(right.reg, int32(left.num)))
		return right, nil
	}

	if left.typ == evalValueTypeRegBtf && right.typ == evalValueTypeNum {
		if right.num == 0 {
			return left, nil
		}

		t := mybtf.UnderlyingType(left.btf)
		if ptr, ok := t.(*btf.Pointer); ok {
			size, _ := btf.Sizeof(ptr.Target)
			if size == 0 {
				c.emit(asm.Sub.Imm(left.reg, int32(right.num)))
				return left, nil
			}

			c.emit(asm.Sub.Imm(left.reg, int32(right.num)*int32(size)))
		} else if arr, ok := t.(*btf.Array); ok {
			size, _ := btf.Sizeof(arr.Type)
			if size == 0 {
				c.regalloc.Free(left.reg)
				return left, fmt.Errorf("disallow type %v for sub", left.btf)
			}

			c.emit(asm.Sub.Imm(left.reg, int32(right.num)*int32(size)))
		} else {
			c.emit(asm.Sub.Imm(left.reg, int32(right.num)))
		}
		return left, nil
	}

	if left.typ == evalValueTypeRegBtf && right.typ == evalValueTypeRegBtf {
		var size int
		t := mybtf.UnderlyingType(left.btf)
		if ptr, ok := t.(*btf.Pointer); ok {
			size, _ = btf.Sizeof(ptr.Target)
		} else if arr, ok := t.(*btf.Array); ok {
			size, _ = btf.Sizeof(arr.Type)
		}
		if size != 0 {
			c.emit(asm.Mul.Imm(right.reg, int32(size)))
		}

		c.emit(asm.Sub.Reg(left.reg, right.reg))
		c.regalloc.Free(right.reg)
		return left, nil
	}

	return evalValue{}, ErrNotImplemented
}

func (c *compiler) twid(val evalValue) (evalValue, error) {
	switch val.typ {
	case evalValueTypeNum:
		val.num = ^val.num
		return val, nil

	case evalValueTypeRegBtf:
		if !canCalculate(val.btf) {
			c.regalloc.Free(val.reg)
			return val, fmt.Errorf("disallow type %v for twid", val.btf)
		}

		c.emit(asm.Xor.Imm(val.reg, -1))
		return val, nil

	default:
		return evalValue{}, ErrNotImplemented
	}
}

func (c *compiler) xor(left, right evalValue) (evalValue, error) {
	left, right, err := c.preHandleBinaryOp(left, right)
	if err != nil {
		return evalValue{}, err
	}

	switch {
	case left.typ == evalValueTypeNum && right.typ == evalValueTypeNum:
		left.num ^= right.num
		return left, nil

	case left.typ == evalValueTypeRegBtf && right.typ == evalValueTypeRegBtf:
		c.emit(asm.Xor.Reg(left.reg, right.reg))
		c.regalloc.Free(right.reg)
		return left, nil

	case left.typ == evalValueTypeNum && right.typ == evalValueTypeRegBtf:
		if left.num == 0 {
			c.regalloc.Free(right.reg)
			return left, nil
		}

		c.emit(asm.Xor.Imm(right.reg, int32(left.num)))
		return right, nil

	case left.typ == evalValueTypeRegBtf && right.typ == evalValueTypeNum:
		if right.num == 0 {
			c.regalloc.Free(left.reg)
			return right, nil
		}

		c.emit(asm.Xor.Imm(left.reg, int32(right.num)))
		return left, nil

	default:
		return evalValue{}, ErrNotImplemented
	}
}

func (c *compiler) eval(expr *cc.Expr) (evalValue, error) {
	switch expr.Op {
	case cc.Dot, cc.Arrow, cc.Index, cc.Addr, cc.Indir:
		return c.access(expr)

	case cc.Add:
		l, err := c.eval(expr.Left)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate left operand: %w", err)
		}

		r, err := c.eval(expr.Right)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate right operand: %w", err)
		}

		return c.add(l, r)

	case cc.And:
		l, err := c.eval(expr.Left)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate left operand: %w", err)
		}

		r, err := c.eval(expr.Right)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate right operand: %w", err)
		}

		return c.and(l, r)

	case cc.AndAnd:
		l, err := c.eval(expr.Left)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate left operand: %w", err)
		}

		r, err := c.eval(expr.Right)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate right operand: %w", err)
		}

		return c.andand(l, r)

	case cc.Cond:
		cond, err := c.eval(expr.List[0])
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate cond operand: %w", err)
		}

		l, err := c.eval(expr.List[1])
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate true operand: %w", err)
		}

		r, err := c.eval(expr.List[2])
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate false operand: %w", err)
		}

		return c.cond(cond, l, r)

	case cc.Div:
		l, err := c.eval(expr.Left)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate left operand: %w", err)
		}

		r, err := c.eval(expr.Right)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate right operand: %w", err)
		}

		return c.div(l, r)

	case cc.EqEq:
		l, err := c.eval(expr.Left)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate left operand: %w", err)
		}

		r, err := c.eval(expr.Right)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate right operand: %w", err)
		}

		return c.eqeq(l, r)

	case cc.Gt:
		l, err := c.eval(expr.Left)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate left operand: %w", err)
		}

		r, err := c.eval(expr.Right)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate right operand: %w", err)
		}

		return c.gt(l, r)

	case cc.GtEq:
		l, err := c.eval(expr.Left)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate left operand: %w", err)
		}

		r, err := c.eval(expr.Right)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate right operand: %w", err)
		}

		return c.gteq(l, r)

	case cc.Lsh:
		l, err := c.eval(expr.Left)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate left operand: %w", err)
		}

		r, err := c.eval(expr.Right)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate right operand: %w", err)
		}

		return c.lsh(l, r)

	case cc.Lt:
		l, err := c.eval(expr.Left)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate left operand: %w", err)
		}

		r, err := c.eval(expr.Right)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate right operand: %w", err)
		}

		return c.lt(l, r)

	case cc.LtEq:
		l, err := c.eval(expr.Left)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate left operand: %w", err)
		}

		r, err := c.eval(expr.Right)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate right operand: %w", err)
		}

		return c.lteq(l, r)

	case cc.Minus:
		val, err := c.eval(expr.Left)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate operand: %w", err)
		}

		return c.minus(val)

	case cc.Mod:
		l, err := c.eval(expr.Left)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate left operand: %w", err)
		}

		r, err := c.eval(expr.Right)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate right operand: %w", err)
		}

		return c.mod(l, r)

	case cc.Mul:
		l, err := c.eval(expr.Left)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate left operand: %w", err)
		}

		r, err := c.eval(expr.Right)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate right operand: %w", err)
		}

		return c.mul(l, r)

	case cc.Name:
		if slices.Contains([]string{"NULL", "false"}, expr.Text) {
			return evalValue{
				typ: evalValueTypeNum,
				num: 0,
			}, nil
		}
		if expr.Text == "true" {
			return evalValue{
				typ: evalValueTypeNum,
				num: 1,
			}, nil
		}

		idx := slices.Index(c.vars, expr.Text)
		if idx == -1 {
			return evalValue{
				typ:  evalValueTypeEnumMaybe,
				name: expr.Text,
			}, nil
		}

		// variable

		reg, err := c.regalloc.Alloc()
		if err != nil {
			return evalValue{}, err
		}

		c.emitLoadArg(idx, reg)
		return evalValue{
			typ: evalValueTypeRegBtf,
			reg: reg,
			btf: c.btfs[idx],
		}, nil

	case cc.Not:
		v, err := c.eval(expr.Left)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate operand: %w", err)
		}

		return c.not(v)

	case cc.NotEq:
		l, err := c.eval(expr.Left)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate left operand: %w", err)
		}

		r, err := c.eval(expr.Right)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate right operand: %w", err)
		}

		return c.noteq(l, r)

	case cc.Number:
		num, err := parseNumber(expr.Text)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to parse number: %w", err)
		}

		return evalValue{
			typ: evalValueTypeNum,
			num: num,
		}, nil

	case cc.Or:
		l, err := c.eval(expr.Left)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate left operand: %w", err)
		}

		r, err := c.eval(expr.Right)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate right operand: %w", err)
		}

		return c.or(l, r)

	case cc.OrOr:
		l, err := c.eval(expr.Left)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate left operand: %w", err)
		}

		r, err := c.eval(expr.Right)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate right operand: %w", err)
		}

		return c.oror(l, r)

	case cc.Paren:
		return c.eval(expr.Left)

	case cc.Plus:
		return c.eval(expr.Left)

	case cc.PreDec:
		v, err := c.eval(expr.Left)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate operand: %w", err)
		}

		return c.preDec(v)

	case cc.PreInc:
		v, err := c.eval(expr.Left)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate operand: %w", err)
		}

		return c.preInc(v)

	case cc.Rsh:
		l, err := c.eval(expr.Left)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate left operand: %w", err)
		}

		r, err := c.eval(expr.Right)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate right operand: %w", err)
		}

		return c.rsh(l, r)

	case cc.Sub:
		l, err := c.eval(expr.Left)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate left operand: %w", err)
		}

		r, err := c.eval(expr.Right)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate right operand: %w", err)
		}

		return c.sub(l, r)

	case cc.Twid:
		v, err := c.eval(expr.Left)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate operand: %w", err)
		}

		return c.twid(v)

	case cc.Xor:
		l, err := c.eval(expr.Left)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate left operand: %w", err)
		}

		r, err := c.eval(expr.Right)
		if err != nil {
			return evalValue{}, fmt.Errorf("failed to evaluate right operand: %w", err)
		}

		return c.xor(l, r)

	default:
		return evalValue{}, fmt.Errorf("unsupported operator: %s", expr.Op)
	}
}
