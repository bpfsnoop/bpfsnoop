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

type compiler struct {
	regalloc RegisterAllocator
	insns    asm.Instructions

	vars []string
	btfs []btf.Type

	kernelBtf *btf.Spec

	labelExit     string
	labelExitUsed bool

	reservedStack int
}

type CompileExprOptions struct {
	Expr          string
	Params        []btf.FuncParam
	Spec          *btf.Spec
	LabelExit     string
	ReservedStack int
}

func CompileFilterExpr(opts CompileExprOptions) (asm.Instructions, error) {
	if opts.Expr == "" || opts.LabelExit == "" {
		return nil, fmt.Errorf("expression and label exit cannot be empty")
	}
	if opts.Spec == nil {
		return nil, fmt.Errorf("btf spec cannot be empty")
	}

	c := &compiler{
		kernelBtf:     opts.Spec,
		labelExit:     opts.LabelExit,
		reservedStack: opts.ReservedStack,
	}

	c.vars = make([]string, len(opts.Params))
	c.btfs = make([]btf.Type, len(opts.Params))
	for i := range opts.Params {
		c.vars[i] = opts.Params[i].Name
		c.btfs[i] = opts.Params[i].Type
	}

	if c.reservedStack <= 0 {
		c.reservedStack = 8
	} else {
		c.reservedStack = (c.reservedStack + 7) & -8 // align to 8 bytes
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

func (c *compiler) emit(insn asm.Instruction) {
	c.insns = append(c.insns, insn)
}

func (c *compiler) emitLoadArg(index int, dst asm.Register) {
	c.emit(asm.LoadMem(dst, argsReg, int16(index*8), asm.DWord))
}

func (c *compiler) pushUsedCallerSavedRegs() {
	for reg, i := asm.R0, 1; reg <= asm.R5; reg++ {
		if c.regalloc.IsUsed(reg) {
			c.emit(asm.StoreMem(asm.RFP, int16(-c.reservedStack-i*8), reg, asm.DWord))
		}
	}
}

func (c *compiler) popUsedCallerSavedRegs() {
	for reg, i := asm.R0, 1; reg <= asm.R5; reg++ {
		if c.regalloc.IsUsed(reg) {
			c.emit(asm.LoadMem(reg, asm.RFP, int16(-c.reservedStack-i*8), asm.DWord))
		}
	}
}
