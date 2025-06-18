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
	EvalResultTypeEthAddr
	EvalResultTypeIP4Addr
	EvalResultTypeIP6Addr
	EvalResultTypePort
	EvalResultTypeSlice
	EvalResultTypeHex
	EvalResultTypeNum
)

const (
	PktTypeEth   = "eth"
	PktTypeIP    = "ip"
	PktTypeIP4   = "ip4"
	PktTypeIP6   = "ip6"
	PktTypeICMP  = "icmp"
	PktTypeICMP6 = "icmp6"
	PktTypeTCP   = "tcp"
	PktTypeUDP   = "udp"
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
	Num   string // number type, e.g. "u8", "u16", "u32", "u64", "s8", "s16", "s32", "s64", "le16", "le32", "le64", "be16", "be32" and "be64"
	Addr  int    // address number for EvalResultTypeEthAddr, EvalResultTypeIP4Addr, EvalResultTypeIP6Addr and EvalResultTypePort

	LabelUsed bool
}

const (
	EthAddrSize = 6
	IP4AddrSize = 4
	IP6AddrSize = 16
	PortSize    = 2
)

type funcCallValue struct {
	typ        EvalResultType
	expr       *cc.Expr
	dataOffset int64
	dataSize   int64
	pktType    string
	addr       int // address number for EvalResultTypeEthAddr, EvalResultTypeIP4Addr and EvalResultTypeIP6Addr
}

func compileFuncCall(expr *cc.Expr) (funcCallValue, error) {
	var val funcCallValue
	var err error

	val.expr = expr.List[0]

	fnName := expr.Left.Text
	switch fnName {
	case "buf", "slice", "hex":
		switch len(expr.List) {
		case 2, 3:
			if expr.List[1].Op != cc.Number {
				return val, fmt.Errorf("%s() second argument must be a number", fnName)
			}

			val.dataSize, err = parseNumber(expr.List[1].Text)
			if err != nil {
				return val, fmt.Errorf("%s() second argument must be a number: %w", fnName, err)
			}

			if len(expr.List) == 3 {
				val.dataOffset = val.dataSize

				if expr.List[2].Op != cc.Number {
					return val, fmt.Errorf("%s() third argument must be a number", fnName)
				}
				val.dataSize, err = parseNumber(expr.List[2].Text)
				if err != nil {
					return val, fmt.Errorf("%s() third argument must be a number: %w", fnName, err)
				}
			}

		default:
			return val, fmt.Errorf("%s() must have 2 or 3 arguments", fnName)
		}

		if val.dataSize <= 0 {
			return val, fmt.Errorf("%s() size must be greater than 0", fnName)
		}

		val.typ = EvalResultTypeBuf
		if fnName == "slice" {
			val.typ = EvalResultTypeSlice
		} else if fnName == "hex" {
			val.typ = EvalResultTypeHex
		}

	case "pkt":
		allowedPktTypes := []string{
			PktTypeEth,
			PktTypeIP, PktTypeIP4, PktTypeIP6,
			PktTypeICMP, PktTypeICMP6,
			PktTypeTCP, PktTypeUDP,
		}

		switch len(expr.List) {
		case 2:
			if expr.List[1].Op != cc.Number {
				return val, fmt.Errorf("pkt() second argument must be a number")
			}

			val.dataSize, err = parseNumber(expr.List[1].Text)
			if err != nil {
				return val, fmt.Errorf("pkt() second argument must be a number: %w", err)
			}

			val.pktType = PktTypeEth // default pkt type

		case 3:
			if expr.List[1].Op != cc.Number {
				return val, fmt.Errorf("pkt() second argument must be a number")
			}

			val.dataSize, err = parseNumber(expr.List[1].Text)
			if err != nil {
				return val, fmt.Errorf("%s() second argument must be a number: %w", fnName, err)
			}

			switch expr.List[2].Op {
			case cc.Name:
				pktType := expr.List[2].Text
				if !slices.Contains(allowedPktTypes, pktType) {
					return val, fmt.Errorf("pkt() third argument as pkt type must be one of %v", allowedPktTypes)
				}

				val.pktType = pktType

			case cc.Number:
				val.dataOffset = val.dataSize
				val.dataSize, err = parseNumber(expr.List[2].Text)
				if err != nil {
					return val, fmt.Errorf("pkt() third argument must be a number: %w", err)
				}

				val.pktType = PktTypeEth // default pkt type

			default:
				return val, fmt.Errorf("pkt() third argument must be a name or a number")
			}

		case 4:
			if expr.List[1].Op != cc.Number {
				return val, fmt.Errorf("pkt() second argument must be a number")
			}
			val.dataOffset, err = parseNumber(expr.List[1].Text)
			if err != nil {
				return val, fmt.Errorf("pkt() second argument must be a number: %w", err)
			}

			if expr.List[2].Op != cc.Number {
				return val, fmt.Errorf("pkt() third argument must be a number")
			}
			val.dataSize, err = parseNumber(expr.List[2].Text)
			if err != nil {
				return val, fmt.Errorf("pkt() third argument must be a number: %w", err)
			}

			if expr.List[3].Op != cc.Name {
				return val, fmt.Errorf("pkt() fourth argument must be a name")
			}
			pktType := expr.List[3].Text
			if !slices.Contains(allowedPktTypes, pktType) {
				return val, fmt.Errorf("pkt() fourth argument as pkt type must be one of %v", allowedPktTypes)
			}

			val.pktType = pktType

		default:
			return val, fmt.Errorf("pkt() must have 2, 3 or 4 arguments")
		}

		if val.dataSize <= 0 {
			return val, fmt.Errorf("pkt() size must be greater than 0")
		}

		val.typ = EvalResultTypePkt

	case "str":
		if len(expr.List) != 1 && len(expr.List) != 2 {
			return val, fmt.Errorf("str() must have 1 or 2 arguments")
		}

		val.dataSize = -1
		if len(expr.List) == 2 {
			if expr.List[1].Op != cc.Number {
				return val, fmt.Errorf("str() second argument must be a number")
			}
			val.dataSize, err = parseNumber(expr.List[1].Text)
			if err != nil {
				return val, fmt.Errorf("str() second argument must be a number: %w", err)
			}
			if val.dataSize <= 0 {
				return val, fmt.Errorf("str() size must be greater than 0")
			}
		}

		val.typ = EvalResultTypeString

	case "eth", "eth2", "ip4", "ip42", "ip6", "ip62", "port", "port2":
		switch len(expr.List) {
		case 1:
			break

		case 2:
			if expr.List[1].Op != cc.Number {
				return val, fmt.Errorf("eth() second argument must be a number")
			}

			val.dataOffset, err = parseNumber(expr.List[1].Text)
			if err != nil {
				return val, fmt.Errorf("eth() second argument must be a number: %w", err)
			}

		default:
			return val, fmt.Errorf("eth() must have 1 or 2 arguments")
		}

		switch fnName {
		case "eth":
			val.dataSize = EthAddrSize // ethernet address size
			val.typ = EvalResultTypeEthAddr
			val.addr = 1

		case "eth2":
			val.dataSize = EthAddrSize * 2 // ethernet address size * 2
			val.typ = EvalResultTypeEthAddr
			val.addr = 2

		case "ip4":
			val.dataSize = IP4AddrSize // IPv4 address size
			val.typ = EvalResultTypeIP4Addr
			val.addr = 1

		case "ip42":
			val.dataSize = IP4AddrSize * 2 // IPv4 address size * 2
			val.typ = EvalResultTypeIP4Addr
			val.addr = 2

		case "ip6":
			val.dataSize = IP6AddrSize // IPv6 address size
			val.typ = EvalResultTypeIP6Addr
			val.addr = 1

		case "ip62":
			val.dataSize = IP6AddrSize * 2 // IPv6 address size * 2
			val.typ = EvalResultTypeIP6Addr
			val.addr = 2

		case "port":
			val.dataSize = PortSize // port size
			val.typ = EvalResultTypePort
			val.addr = 1

		case "port2":
			val.dataSize = PortSize * 2 // port size * 2
			val.typ = EvalResultTypePort
			val.addr = 2
		}

	case "u8", "u16", "u32", "u64",
		"s8", "s16", "s32", "s64",
		"le16", "le32", "le64",
		"be16", "be32", "be64":
		switch len(expr.List) {
		case 1:
			break

		case 2:
			if expr.List[1].Op != cc.Number {
				return val, fmt.Errorf("%s() second argument must be a number", fnName)
			}

			val.dataOffset, err = parseNumber(expr.List[1].Text)
			if err != nil {
				return val, fmt.Errorf("%s() second argument must be a number: %w", fnName, err)
			}

		default:
			return val, fmt.Errorf("%s() must have 1 or 2 arguments", fnName)
		}

		val.typ = EvalResultTypeNum
		switch fnName {
		case "u8", "s8":
			val.dataSize = 1

		case "u16", "s16", "le16", "be16":
			val.dataSize = 2

		case "u32", "s32", "le32", "be32":
			val.dataSize = 4

		case "u64", "s64", "le64", "be64":
			val.dataSize = 8
		}

	default:
		return val, fmt.Errorf("unsupported function call: %s", fnName)
	}

	return val, nil
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
	fnName := ""

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
		res.Addr = val.addr
		res.Pkt = val.pktType
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

	case EvalResultTypeBuf, EvalResultTypeHex:
		t := mybtf.UnderlyingType(val.btf)
		_, isPtr := t.(*btf.Pointer)
		_, isArray := t.(*btf.Array)
		if !isPtr && !isArray {
			return res, fmt.Errorf("disallow non-{pointer,array} type %v for %s()", t, fnName)
		}

		res.Off = int(dataOffset)
		res.Size = int(dataSize)
		res.Btf = t

	case EvalResultTypeSlice:
		t := mybtf.UnderlyingType(val.btf)
		ptr, isPtr := t.(*btf.Pointer)
		arr, isArray := t.(*btf.Array)
		if !isPtr && !isArray {
			return res, fmt.Errorf("disallow non-{pointer,array} type %v for %s()", t, fnName)
		}

		if isPtr {
			res.Btf = ptr.Target
		} else if isArray {
			res.Btf = arr.Type
		}
		size, _ := btf.Sizeof(res.Btf)
		if size == 0 {
			return res, fmt.Errorf("disallow zero size type %v for %s()", res.Btf, fnName)
		}

		res.Off = int(dataOffset) * size
		res.Size = int(dataSize) * size

	case EvalResultTypePkt, EvalResultTypeEthAddr, EvalResultTypeIP4Addr, EvalResultTypeIP6Addr, EvalResultTypePort:
		// pkt(), eth(), eth2(), ip4(), ip42(), ip6() and ip62() functions
		t := mybtf.UnderlyingType(val.btf)
		_, isPtr := t.(*btf.Pointer)
		if !isPtr {
			return res, fmt.Errorf("disallow non-pointer type %v for %s()", t, fnName)
		}

		res.Off = int(dataOffset)
		res.Size = int(dataSize)
		res.Btf = t

	case EvalResultTypeNum:
		// u8(), u16(), u32(), u64(), s8(), s16(), s32(), s64(),
		// le16(), le32(), le64(), be16(), be32() and be64() functions
		t := mybtf.UnderlyingType(val.btf)
		_, isPtr := t.(*btf.Pointer)
		_, isArray := t.(*btf.Array)
		if !isPtr && !isArray {
			return res, fmt.Errorf("disallow non-{pointer,array} type %v for %s()", t, fnName)
		}

		res.Btf = t
		res.Off = int(dataOffset)
		res.Size = int(dataSize)
		res.Num = fnName

	case EvalResultTypeString:
		t := mybtf.UnderlyingType(val.btf)
		_, isPtr := t.(*btf.Pointer)
		arr, isArray := t.(*btf.Array)
		if !isPtr && !isArray {
			return res, fmt.Errorf("disallow non-{pointer,array} type %v for str()", t)
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
