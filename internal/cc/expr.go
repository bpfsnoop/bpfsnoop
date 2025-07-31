// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"fmt"
	"slices"

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
	Spec, Kernel  *btf.Spec
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
	EvalResultTypeAddr
	EvalResultTypePort
	EvalResultTypeSlice
	EvalResultTypeHex
	EvalResultTypeInt
	EvalResultTypeHist
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
	Addr  string // addr type, e.g. "eth", "eth2", "ip4", "ip42", "ip6", "ip62"
	Port  string // port type, e.g. "port", "port2"
	Int   string // number type, e.g. "u8", "u16", "u32", "u64", "s8", "s16", "s32", "s64", "le16", "le32", "le64", "be16", "be32" and "be64"

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
		res.Addr = val.addr
		res.Port = val.port
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

	if err := postCheckFuncCall(&res, val, dataOffset, dataSize, fnName); err != nil {
		return res, err
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
