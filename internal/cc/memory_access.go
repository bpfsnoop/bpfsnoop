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

type accessOffset struct {
	offset  int64
	address bool
}

type accessResult struct {
	raw btf.Type
	idx int

	btf btf.Type
	mem *btf.Member

	offsets []accessOffset
}

// isMemberBitfield reports whether the member is a bitfield attribute.
func isMemberBitfield(member *btf.Member) bool {
	return member != nil && member.BitfieldSize != 0
}

func (c *compiler) accessMemory(expr *cc.Expr) (accessResult, error) {
	switch expr.Op {
	case cc.Name:
		idx := slices.Index(c.vars, expr.Text)
		if idx == -1 {
			return accessResult{}, fmt.Errorf("variable %s: %w", expr.Text, ErrVarNotFound)
		}

		return accessResult{
			raw: c.btfs[idx],
			idx: idx,
			btf: c.btfs[idx],
		}, nil

	case cc.Dot, cc.Arrow:
		res, err := c.accessMemory(expr.Left)
		if err != nil {
			return accessResult{}, err
		}
		if isMemberBitfield(res.mem) {
			return accessResult{}, fmt.Errorf("cannot access member of a bitfield type")
		}

		t := mybtf.UnderlyingType(res.btf)
		ptr, useArrow := t.(*btf.Pointer)

		var member *btf.Member
		var offset uint32

		if useArrow {
			t = mybtf.UnderlyingType(ptr.Target)
		}

		switch v := t.(type) {
		case *btf.Struct:
			member, err = mybtf.FindStructMember(v, expr.Text)
			if err == nil {
				offset, err = mybtf.StructMemberOffset(v, expr.Text)
			}
		case *btf.Union:
			member, err = mybtf.FindUnionMember(v, expr.Text)
			if err == nil {
				offset, err = mybtf.UnionMemberOffset(v, expr.Text)
			}
		default:
			return accessResult{}, fmt.Errorf("unsupported type %T", v)
		}
		if err != nil {
			return accessResult{}, fmt.Errorf("failed to find member %s: %w", expr.Text, err)
		}

		if !useArrow {
			// access via .
			if len(res.offsets) > 0 {
				res.offsets[len(res.offsets)-1].offset += int64(offset)
			} else {
				return accessResult{}, fmt.Errorf("disallow accessing member %s of %s via dot", expr.Text, expr.Left.Text)
			}
		} else {
			// access via ->
			res.offsets = append(res.offsets, accessOffset{
				offset: int64(offset),
			})
		}

		t = mybtf.UnderlyingType(member.Type)
		if _, ok := t.(*btf.Array); ok {
			res.offsets[len(res.offsets)-1].address = true
			res.btf = member.Type
			res.mem = nil
		} else {
			res.btf = member.Type
			res.mem = member
		}

		return res, nil

	case cc.Add:
		var (
			err error
			num int64
			res accessResult
		)
		if expr.Left.Op == cc.Number {
			num, err = parseNumber(expr.Left.Text)
			if err != nil {
				return accessResult{}, fmt.Errorf("failed to parse number of add.left: %w", err)
			}

			res, err = c.accessMemory(expr.Right)
			if err != nil {
				return accessResult{}, fmt.Errorf("failed to parse right of add: %w", err)
			}
		} else if expr.Right.Op == cc.Number {
			num, err = parseNumber(expr.Right.Text)
			if err != nil {
				return accessResult{}, fmt.Errorf("failed to parse number of add.right: %w", err)
			}

			res, err = c.accessMemory(expr.Left)
			if err != nil {
				return accessResult{}, fmt.Errorf("failed to parse left of add: %w", err)
			}
		} else {
			return accessResult{}, fmt.Errorf("number is required for add")
		}

		if isMemberBitfield(res.mem) {
			return accessResult{}, fmt.Errorf("disallow using bitfield for add")
		}

		t := mybtf.UnderlyingType(res.btf)
		if ptr, ok := t.(*btf.Pointer); ok {
			if _, ok := mybtf.UnderlyingType(ptr.Target).(*btf.Void); ok { // void *
				res.offsets = append(res.offsets, accessOffset{
					offset:  int64(num),
					address: true,
				})
			} else {
				size, err := btf.Sizeof(ptr.Target)
				if err != nil {
					return res, fmt.Errorf("disallow type %v for adding", ptr.Target)
				}

				res.offsets = append(res.offsets, accessOffset{
					offset:  int64(size * int(num)),
					address: true,
				})
			}
		} else if arr, ok := t.(*btf.Array); ok {
			size, err := btf.Sizeof(arr.Type)
			if err != nil {
				return res, fmt.Errorf("disallow type %v for adding", arr.Type)
			}

			res.offsets = append(res.offsets, accessOffset{
				offset:  int64(size * int(num)),
				address: true,
			})
		} else {
			return res, fmt.Errorf("disallow using non-{pointer,array} for add")
		}

		res.mem = nil
		return res, nil

	case cc.Addr:
		// &skb->dev ==> skb ptr + offsetof(skb, dev)

		res, err := c.accessMemory(expr.Left)
		if err != nil {
			return accessResult{}, fmt.Errorf("failed to access memory for addr: %w", err)
		}

		if len(res.offsets) == 0 {
			return accessResult{}, fmt.Errorf("disallow address '%s'", expr.Left.Text)
		}

		res.offsets[len(res.offsets)-1].address = true
		res.mem = nil
		return res, nil

	case cc.Cast:
		res, err := c.accessMemory(expr.Left)
		if err != nil {
			return accessResult{}, fmt.Errorf("failed to access memory for cast: %w", err)
		}

		ccType := expr.Type
		isPointer := ccType.Kind == cc.Ptr
		if isPointer {
			ccType = ccType.Base
		}

		var typ btf.Type

		if ccType.Kind == cc.Struct {
			typeName := ccType.Tag
			typ, err = c.kernelBtf.AnyTypeByName(typeName)
			if err != nil {
				return accessResult{}, fmt.Errorf("failed to find type '%s': %w", typeName, err)
			}

			t := mybtf.UnderlyingType(typ)
			_, isStruct := t.(*btf.Struct)
			_, isUnion := t.(*btf.Union)
			if !isStruct && !isUnion {
				return accessResult{}, fmt.Errorf("expected struct/union type for cast, got %T", t)
			}
		} else {
			typeName := ccType.String()
			typ, err = c.kernelBtf.AnyTypeByName(typeName)
			if err != nil {
				return accessResult{}, fmt.Errorf("failed to find type '%s': %w", typeName, err)
			}
		}

		if isPointer {
			res.btf = &btf.Pointer{Target: typ}
		} else {
			res.btf = typ
		}

		res.mem = nil
		return res, nil

	case cc.Index:
		// index of array is same as index of pointer
		//
		// skb->cb[3] ==> *(skb->cb + 3)

		res, err := c.accessMemory(expr.Left)
		if err != nil {
			return accessResult{}, fmt.Errorf("failed to access memory for index: %w", err)
		}
		if isMemberBitfield(res.mem) {
			return accessResult{}, fmt.Errorf("disallow using bitfield for index")
		}

		if expr.Right.Op != cc.Number {
			return accessResult{}, fmt.Errorf("op of index expected number type, got %s", expr.Right.Op)
		}

		index, err := parseNumber(expr.Right.Text)
		if err != nil {
			return accessResult{}, fmt.Errorf("failed to parse number: %w", err)
		}

		var size int

		t := mybtf.UnderlyingType(res.btf)
		if ptr, ok := t.(*btf.Pointer); ok {
			size, _ = btf.Sizeof(ptr.Target)
			if size == 0 {
				return accessResult{}, fmt.Errorf("disallow indexing pointer of type %v", t)
			}

			res.btf = ptr.Target
		} else if arr, ok := t.(*btf.Array); ok {
			size, _ = btf.Sizeof(arr.Type)
			if size == 0 {
				return accessResult{}, fmt.Errorf("disallow indexing array of type %v", t)
			}

			res.btf = arr.Type
		} else {
			return accessResult{}, fmt.Errorf("disallow indexing type %v", t)
		}

		res.offsets = append(res.offsets, accessOffset{
			offset: int64(index * int64(size)),
		})
		res.mem = nil
		return res, nil

	case cc.Indir:
		// *skb->dev ==> *(*(skb ptr + offsetof(skb, dev))

		res, err := c.accessMemory(expr.Left)
		if err != nil {
			return accessResult{}, fmt.Errorf("failed to access memory for indir: %w", err)
		}
		if isMemberBitfield(res.mem) {
			return accessResult{}, fmt.Errorf("disallow indirecting bitfield")
		}

		t := mybtf.UnderlyingType(res.btf)
		ptr, ok := t.(*btf.Pointer)
		if !ok {
			return accessResult{}, fmt.Errorf("disallow indirecting type %v", t)
		}

		res.offsets = append(res.offsets, accessOffset{
			offset: 0,
		})
		res.btf = ptr.Target
		res.mem = nil
		return res, nil

	case cc.Paren:
		return c.accessMemory(expr.Left)

	case cc.Sub:
		if expr.Right.Op != cc.Number {
			return accessResult{}, fmt.Errorf("sub.right must be number")
		}
		num, err := parseNumber(expr.Right.Text)
		if err != nil {
			return accessResult{}, fmt.Errorf("failed to parse number of sub.right: %w", err)
		}

		res, err := c.accessMemory(expr.Left)
		if err != nil {
			return res, fmt.Errorf("failed to parse sub.left: %w", err)
		}
		if isMemberBitfield(res.mem) {
			return res, fmt.Errorf("disallow using bitfield for sub")
		}

		t := mybtf.UnderlyingType(res.btf)
		if ptr, ok := t.(*btf.Pointer); ok {
			if _, ok := mybtf.UnderlyingType(ptr.Target).(*btf.Void); ok { // void *
				res.offsets = append(res.offsets, accessOffset{
					offset:  -int64(num),
					address: true,
				})
			} else {
				size, err := btf.Sizeof(ptr.Target)
				if err != nil {
					return res, fmt.Errorf("disallow type %v for subing", ptr.Target)
				}

				res.offsets = append(res.offsets, accessOffset{
					offset:  -int64(size * int(num)),
					address: true,
				})
			}
		} else if arr, ok := t.(*btf.Array); ok {
			size, err := btf.Sizeof(arr.Type)
			if err != nil {
				return res, fmt.Errorf("disallow type %v for subing", arr.Type)
			}

			res.offsets = append(res.offsets, accessOffset{
				offset:  int64(-size * int(num)),
				address: true,
			})
		} else {
			return res, fmt.Errorf("disallow using non-{pointer,array} for sub")
		}

		res.mem = nil
		return res, nil

	}

	return accessResult{}, fmt.Errorf("unsupported expression op %s", expr.Op)
}

func (c *compiler) access(expr *cc.Expr) (evalValue, error) {
	res, err := c.accessMemory(expr)
	if err != nil {
		return evalValue{}, err
	}

	c.pushUsedCallerSavedRegs()
	defer c.popUsedCallerSavedRegs()

	var eval evalValue

	reg, err := c.regalloc.Alloc()
	if err != nil {
		return eval, fmt.Errorf("failed to alloc register for memory access: %w", err)
	}

	eval.typ = evalValueTypeRegBtf
	eval.btf = res.btf
	eval.mem = res.mem
	eval.reg = reg

	c.emitLoadArg(res.idx, reg)
	c.offset2insns(res.offsets, reg)
	if isMemberBitfield(res.mem) {
		c.bitfield2insns(res.mem, reg)
	} else {
		c.adjustRegisterBitwise(eval)
	}

	return eval, nil
}

func (c *compiler) offset2insns(offsets []accessOffset, reg asm.Register) {
	if len(offsets) == 0 {
		return
	}

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

		c.emit(asm.Mov.Imm(asm.R2, 8))       // r2 = 8; always read 8 bytes
		c.emit(asm.Mov.Reg(asm.R1, asm.RFP)) // r1 = r10
		c.emit(asm.Add.Imm(asm.R1, -8))      // r1 = r10 - 8
		c.emit(asm.FnProbeReadKernel.Call()) // bpf_probe_read_kernel(r1, 8, r3)

		if i != lastIndex {
			c.labelExitUsed = true
			c.emit(asm.LoadMem(asm.R3, asm.RFP, -8, asm.DWord)) // r3 = *(r10 - 8)
			c.emit(asm.JEq.Imm(asm.R3, 0, c.labelExit))
		} else {
			c.emit(asm.LoadMem(reg, asm.RFP, -8, asm.DWord))
		}
	}
}

func (c *compiler) bitfield2insns(member *btf.Member, reg asm.Register) {
	delta := member.Offset & 0x7
	if delta != 0 {
		c.emit(asm.RSh.Imm(reg, int32(delta))) // reg >>= delta
	}

	mask := (uint64(1) << uint64(member.BitfieldSize)) - 1
	c.emit(asm.And.Imm(reg, int32(mask))) // reg &= mask
}

func (c *compiler) adjustRegisterBitwise(val evalValue) error {
	if val.typ != evalValueTypeRegBtf {
		return nil
	}

	size, err := btf.Sizeof(val.btf)
	if err != nil {
		return fmt.Errorf("failed to get size of %v: %w", val.btf, err)
	}

	switch size {
	case 1:
		c.emit(asm.And.Imm(val.reg, 0xFF))

	case 2:
		c.emit(asm.And.Imm(val.reg, 0xFFFF))

	case 4:
		c.emit(asm.LSh.Imm(val.reg, 32))
		c.emit(asm.RSh.Imm(val.reg, 32))

	case 8:

	default:
		return fmt.Errorf("unsupported size %d for %v", size, val.btf)
	}

	return nil
}
