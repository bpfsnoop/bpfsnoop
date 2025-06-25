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
	argsReg = asm.R9
)

type MemoryReadMode int

const (
	MemoryReadModeProbeRead MemoryReadMode = iota
	MemoryReadModeCoreRead
	MemoryReadModeDirectRead
)

type CompileExprOptions struct {
	Expr          string
	Params        []btf.FuncParam
	Spec          *btf.Spec
	LabelExit     string
	ReservedStack int
	UsedRegisters []asm.Register

	MemoryReadMode MemoryReadMode
}

func CompileFilterExpr(opts CompileExprOptions) (asm.Instructions, error) {
	c, err := newCompiler(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create compiler: %w", err)
	}

	c.emit(asm.Mov.Reg(argsReg, asm.R1)) // cache args to r9
	c.regalloc.registers[asm.R9] = true

	if err := c.compile(opts.Expr); err != nil {
		return nil, err
	}

	c.emit(asm.Return())

	return c.insns, nil
}

func (c *compiler) compile(expr string) error {
	e, err := cc.ParseExpr(expr)
	if err != nil {
		return fmt.Errorf("failed to parse expression: %w", err)
	}

	supportedOps := []cc.ExprOp{
		cc.AndAnd,
		cc.EqEq,
		cc.Gt,
		cc.GtEq,
		cc.Lt,
		cc.LtEq,
		cc.Not,
		cc.NotEq,
		cc.OrOr,
	}
	if !slices.Contains(supportedOps, e.Op) {
		return fmt.Errorf("top op '%s' of expression must be one of %v", e.Op, supportedOps)
	}

	val, err := c.eval(e)
	if err != nil {
		return fmt.Errorf("failed to evaluate expression: %w", err)
	}
	if val.typ == evalValueTypeNum {
		return fmt.Errorf("disallow constant value (%d) expression: '%s'", val.num, expr)
	}

	if c.labelExitUsed {
		c.insns[len(c.insns)-1] = c.insns[len(c.insns)-1].WithSymbol(c.labelExit)
	}

	if val.reg != asm.R0 {
		c.emit(asm.Mov.Reg(asm.R0, val.reg))
	}

	return nil
}

type EvalResultType int

const (
	EvalResultTypeDefault EvalResultType = iota
	EvalResultTypeDeref
	EvalResultTypeBuf
	EvalResultTypeString
	EvalResultTypePkt
)

type EvalResult struct {
	Insns asm.Instructions
	Reg   asm.Register
	Btf   btf.Type
	Mem   *btf.Member
	Type  EvalResultType
	Size  int
	Off   int
	Pkt   string // pkt type, e.g. "eth", "ip4", "ip6", "icmp", "icmp6", "tcp" and "udp"

	LabelUsed bool
}

func CompileEvalExpr(opts CompileExprOptions) (EvalResult, error) {
	var res EvalResult

	c, err := newCompiler(opts)
	if err != nil {
		return res, fmt.Errorf("failed to create compiler: %w", err)
	}

	e, err := cc.ParseExpr(opts.Expr)
	if err != nil {
		return res, fmt.Errorf("failed to parse expression: %w", err)
	}

	// r9 must be used as args

	for _, reg := range opts.UsedRegisters {
		c.regalloc.MarkUsed(reg)
	}

	dataOffset := int64(0)
	dataSize := int64(0)

	var fnName string
	evaluatingExpr := e
	switch e.Op {
	case cc.Indir:
		res.Type = EvalResultTypeDeref
		evaluatingExpr = e.Left

	case cc.Call:
		if e.Left.Op != cc.Name {
			return res, fmt.Errorf("function call must have a constant name")
		}

		val, err := compileFuncCall(e)
		if err != nil {
			return res, fmt.Errorf("failed to compile function call: %w", err)
		}

		res.Type = val.typ
		res.Pkt = val.pkt
		dataSize = val.dataSize
		dataOffset = val.dataOffset
		evaluatingExpr = val.expr
		fnName = e.Left.Text
	}

	val, err := c.eval(evaluatingExpr)
	if err != nil {
		return res, fmt.Errorf("failed to evaluate expression: %w", err)
	}
	if val.typ == evalValueTypeNum {
		return res, fmt.Errorf("disallow constant value (%d) expression: '%s'", val.num, opts.Expr)
	}

	switch res.Type {
	case EvalResultTypeDeref:
		t := mybtf.UnderlyingType(val.btf)
		ptr, ok := t.(*btf.Pointer)
		if !ok {
			return res, fmt.Errorf("disallow non-pointer type %v for struct/union pointer dereference", t)
		}

		size, _ := btf.Sizeof(ptr.Target)
		if size == 0 {
			return res, fmt.Errorf("disallow zero size type %v for struct/union pointer dereference", ptr.Target)
		}

		res.Btf = ptr.Target
		res.Size = size

	case EvalResultTypeBuf:
		t := mybtf.UnderlyingType(val.btf)
		_, isPtr := t.(*btf.Pointer)
		_, isArray := t.(*btf.Array)
		if !isPtr && !isArray {
			return res, fmt.Errorf("disallow non-{pointer,array} type %v for %s()", t, fnName)
		}

		res.Off = int(dataOffset)
		res.Size = int(dataSize)
		res.Btf = t

	case EvalResultTypeString:
		t := mybtf.UnderlyingType(val.btf)
		_, isPtr := t.(*btf.Pointer)
		arr, isArray := t.(*btf.Array)
		if !isPtr && !isArray {
			return res, fmt.Errorf("disallow non-{pointer,array} type %v for %s()", t, fnName)
		}

		if dataSize == -1 {
			if isPtr {
				dataSize = 64
			} else {
				dataSize = int64(arr.Nelems)
			}
		}

		res.Size = int(dataSize)
		res.Btf = t

	case EvalResultTypePkt:
		t := mybtf.UnderlyingType(val.btf)
		_, isPtr := t.(*btf.Pointer)
		if !isPtr {
			return res, fmt.Errorf("disallow non-pointer type %v for %s()", t, fnName)
		}

		res.Off = int(dataOffset)
		res.Size = int(dataSize)
		res.Btf = t

	default:
		res.Btf = val.btf
		res.Mem = val.mem
	}

	res.Insns = c.insns
	res.Reg = val.reg
	res.LabelUsed = c.labelExitUsed

	return res, nil
}

func (c *compiler) emit(insns ...asm.Instruction) {
	c.insns = append(c.insns, insns...)
}

func (c *compiler) emitLoadArg(index int, dst asm.Register) {
	c.emit(asm.LoadMem(dst, argsReg, int16(index*8), asm.DWord))
}

func (c *compiler) pushUsedCallerSavedRegsN(n int) {
	usedRegNr := 0
	for i := range n {
		reg := asm.R1 + asm.Register(i)
		if c.regalloc.IsUsed(reg) {
			usedRegNr++
		}
	}

	offset := c.reservedStack + usedRegNr*8
	if c.regalloc.IsUsed(asm.R0) {
		c.emit(asm.StoreMem(asm.RFP, int16(-offset-8), asm.R0, asm.DWord))
	}

	for i := range usedRegNr {
		reg := asm.R1 + asm.Register(i)
		c.emit(asm.StoreMem(asm.RFP, int16(-offset+i*8), reg, asm.DWord))
	}
}

func (c *compiler) pushUsedCallerSavedRegs() {
	c.pushUsedCallerSavedRegsN(5)
}

func (c *compiler) popUsedCallerSavedRegsN(n int) {
	usedRegNr := 0
	for i := range n {
		reg := asm.R1 + asm.Register(i)
		if c.regalloc.IsUsed(reg) {
			usedRegNr++
		}
	}

	offset := c.reservedStack + usedRegNr*8

	for i := range usedRegNr {
		reg := asm.R1 + asm.Register(i)
		c.emit(asm.LoadMem(reg, asm.RFP, int16(-offset+i*8), asm.DWord))
	}

	if c.regalloc.IsUsed(asm.R0) {
		c.emit(asm.LoadMem(asm.R0, asm.RFP, int16(-offset-8), asm.DWord))
	}
}

func (c *compiler) popUsedCallerSavedRegs() {
	c.popUsedCallerSavedRegsN(5)
}
