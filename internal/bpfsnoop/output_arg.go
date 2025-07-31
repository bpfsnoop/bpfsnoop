// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"
	"log"
	"slices"
	"strings"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"

	"github.com/bpfsnoop/bpfsnoop/internal/btfx"
	"github.com/bpfsnoop/bpfsnoop/internal/cc"
)

const (
	outputArgRegArgs = asm.R9
	outputArgRegBuff = asm.R8

	outputArgStub      = "output_arg"
	outputArgLabelExit = "__output_arg_fail"

	argOutputStackOff = 16
)

var argOutput argDataOutput

type funcArgumentOutput struct {
	expr string
	t    btf.Type
	mem  *btf.Member
	insn asm.Instructions

	size         int
	trueDataSize int

	vars []string

	isNumPtr bool
	isStr    bool
	isDeref  bool
	isBuf    bool
	isString bool
	isPkt    bool
	pktType  string
	isAddr   bool
	addrType string
	isPort   bool
	portType string
	isSlice  bool
	isHex    bool
	isInt    bool
	intType  string
	isHist   bool
	isTDig   bool
}

type argDataOutput struct {
	args []funcArgumentOutput

	labelCnt int
}

func prepareArgOutput(expr string) (funcArgumentOutput, error) {
	var arg funcArgumentOutput
	arg.expr = strings.TrimSpace(expr)

	var err error
	arg.vars, err = cc.ExtractVarNames(arg.expr)
	if err != nil {
		return arg, fmt.Errorf("failed to extract var names from '%s': %w", arg.expr, err)
	}
	if len(arg.vars) == 0 {
		return arg, fmt.Errorf("'%s' has no var names", arg.expr)
	}

	return arg, nil
}

func prepareFuncArgOutput(exprs []string) argDataOutput {
	var arg argDataOutput
	arg.args = make([]funcArgumentOutput, 0, len(exprs))

	for _, expr := range exprs {
		a, err := prepareArgOutput(expr)
		if err != nil {
			log.Fatalf("failed to prepare arg output: %v", err)
		}

		arg.args = append(arg.args, a)
	}

	return arg
}

func (arg *funcArgumentOutput) emit(insns ...asm.Instruction) {
	arg.insn = append(arg.insn, insns...)
}

func (arg *funcArgumentOutput) genDerefInsns(res *cc.EvalResult, offset, size int, labelExit string) (int, error) {
	res.LabelUsed = true

	arg.emit(
		asm.JEq.Imm(res.Reg, 0, labelExit),
	)

	if res.Reg != asm.R3 {
		arg.emit(
			asm.Mov.Reg(asm.R3, res.Reg),
		)
	}

	if offset != 0 {
		arg.emit(
			asm.Mov.Imm(asm.R2, int32(size)),
			asm.Mov.Reg(asm.R1, outputArgRegBuff),
			asm.Add.Imm(asm.R1, int32(offset)),
			asm.FnProbeReadKernel.Call(),
		)
	} else {
		arg.emit(
			asm.Mov.Imm(asm.R2, int32(size)),
			asm.Mov.Reg(asm.R1, outputArgRegBuff),
			asm.FnProbeReadKernel.Call(),
		)
	}

	return offset + size, nil
}

func (arg *funcArgumentOutput) genBufInsns(res *cc.EvalResult, offset, size int, labelExit string) (int, error) {
	res.LabelUsed = true

	arg.emit(
		asm.JEq.Imm(res.Reg, 0, labelExit),
	)

	if res.Off != 0 {
		arg.emit(
			asm.Add.Imm(res.Reg, int32(res.Off)),
		)
	}

	if res.Reg != asm.R3 {
		arg.emit(
			asm.Mov.Reg(asm.R3, res.Reg),
		)
	}

	probeReadFn := asm.FnProbeReadKernel
	if arg.isString {
		probeReadFn = asm.FnProbeReadKernelStr
	}
	if offset != 0 {
		arg.emit(
			asm.Mov.Imm(asm.R2, int32(res.Size)),
			asm.Mov.Reg(asm.R1, outputArgRegBuff),
			asm.Add.Imm(asm.R1, int32(offset)),
			probeReadFn.Call(),
		)
	} else {
		arg.emit(
			asm.Mov.Imm(asm.R2, int32(res.Size)),
			asm.Mov.Reg(asm.R1, outputArgRegBuff),
			probeReadFn.Call(),
		)
	}

	return offset + res.Size, nil
}

func (arg *funcArgumentOutput) genDefaultInsns(res *cc.EvalResult, offset, size int, labelExit string) (int, error) {
	if !arg.isStr && (size == 0 || size > 8 || (res.Mem != nil && res.Mem.BitfieldSize > 64)) {
		return 0, fmt.Errorf("invalid size of btf type %v: %d", res.Btf, size)
	}

	if !arg.isStr {
		arg.emit(
			asm.StoreMem(outputArgRegBuff, int16(offset), res.Reg, asm.DWord),
		)
		offset += 8

		if arg.isNumPtr {
			if res.Reg != asm.R3 {
				arg.emit(
					asm.Mov.Reg(asm.R3, res.Reg),
				)
			}

			arg.emit(
				cc.JmpOff(asm.JEq, asm.R3, 0, 5),
				asm.Mov.Imm(asm.R2, 8),
				asm.Mov.Reg(asm.R1, outputArgRegBuff),
				asm.Add.Imm(asm.R1, int32(offset)),
				asm.FnProbeReadKernel.Call(),
				cc.Ja(1),
				asm.StoreMem(outputArgRegBuff, int16(offset), asm.R3, asm.DWord),
			)

			offset += 8
		}
	} else /* isStr */ {
		strSize := maxOutputStrLen
		if mybtf.IsCharArray(res.Btf) {
			arr, _ := mybtf.UnderlyingType(res.Btf).(*btf.Array)
			strSize = int(arr.Nelems)
		} else {
			res.LabelUsed = true
			arg.emit(
				asm.JEq.Imm(res.Reg, 0, labelExit),
			)
		}

		if res.Reg != asm.R3 {
			arg.emit(
				asm.Mov.Reg(asm.R3, res.Reg),
			)
		}
		if offset != 0 {
			arg.emit(
				asm.Mov.Imm(asm.R2, int32(strSize)),
				asm.Mov.Reg(asm.R1, outputArgRegBuff),
				asm.Add.Imm(asm.R1, int32(offset)),
				asm.FnProbeReadKernelStr.Call(),
			)
		} else {
			arg.emit(
				asm.Mov.Imm(asm.R2, int32(strSize)),
				asm.Mov.Reg(asm.R1, outputArgRegBuff),
				asm.FnProbeReadKernelStr.Call(),
			)
		}
		offset += strSize
	}

	return offset, nil
}

func (arg *funcArgumentOutput) compile(params []btf.FuncParam, krnl, spec *btf.Spec, offset int, labelExit string) (int, error) {
	mode := cc.MemoryReadModeProbeRead
	if _, err := spec.AnyTypeByName("bpf_rdonly_cast"); err == nil {
		mode = cc.MemoryReadModeCoreRead
	}

	res, err := cc.CompileEvalExpr(cc.CompileExprOptions{
		Expr:          arg.expr,
		Params:        params,
		Spec:          spec,
		Kernel:        krnl,
		LabelExit:     labelExit,
		ReservedStack: argOutputStackOff,
		UsedRegisters: []asm.Register{outputArgRegBuff, outputArgRegArgs},

		MemoryReadMode: mode,
	})
	if err != nil {
		return 0, fmt.Errorf("failed to compile expr '%s': %w", arg.expr, err)
	}
	size, err := btf.Sizeof(res.Btf)
	if err != nil {
		return 0, fmt.Errorf("failed to get size of btf type %v: %w", res.Btf, err)
	}

	arg.t = res.Btf
	arg.mem = res.Mem
	arg.isNumPtr = btfx.IsNumberPointer(res.Btf)
	arg.isStr = mybtf.IsConstCharPtr(res.Btf) || mybtf.IsCharArray(res.Btf)

	orgOffset := offset

	arg.insn = res.Insns
	switch res.Type {
	case cc.EvalResultTypeDeref:
		arg.isDeref = true
		offset, err = arg.genDerefInsns(&res, offset, size, labelExit)

	case cc.EvalResultTypeBuf, cc.EvalResultTypeString, cc.EvalResultTypePkt,
		cc.EvalResultTypeAddr, cc.EvalResultTypePort, cc.EvalResultTypeSlice,
		cc.EvalResultTypeHex, cc.EvalResultTypeInt:
		arg.isBuf = res.Type == cc.EvalResultTypeBuf
		arg.isString = res.Type == cc.EvalResultTypeString
		arg.isPkt = res.Type == cc.EvalResultTypePkt
		arg.pktType = res.Pkt
		arg.isAddr = res.Type == cc.EvalResultTypeAddr
		arg.addrType = res.Addr
		arg.isPort = res.Type == cc.EvalResultTypePort
		arg.portType = res.Port
		arg.isSlice = res.Type == cc.EvalResultTypeSlice
		arg.isHex = res.Type == cc.EvalResultTypeHex
		arg.isInt = res.Type == cc.EvalResultTypeInt
		arg.intType = res.Int
		offset, err = arg.genBufInsns(&res, offset, size, labelExit)

	default:
		arg.isHist = res.Type == cc.EvalResultTypeHist
		arg.isTDig = res.Type == cc.EvalResultTypeTDigest
		offset, err = arg.genDefaultInsns(&res, offset, size, labelExit)
	}
	if err != nil {
		return 0, fmt.Errorf("failed to generate insns: %w", err)
	}

	arg.trueDataSize = offset - orgOffset

	if res.LabelUsed {
		arg.emit(
			asm.Mov.Imm(asm.R0, 0),
			cc.Ja(1),
			asm.Mov.Imm(asm.R0, 1).WithSymbol(labelExit), // null-pointer dereferencing exception
			asm.StoreMem(outputArgRegBuff, int16(offset), asm.R0, asm.Byte),
		)
	} else {
		arg.emit(
			asm.Mov.Imm(asm.R0, 0),
			asm.StoreMem(outputArgRegBuff, int16(offset), asm.R0, asm.Byte),
		)
	}
	offset += 1

	arg.size = offset - orgOffset
	return offset, nil
}

func (arg *funcArgumentOutput) match(params []btf.FuncParam) bool {
	for _, p := range params {
		if slices.Contains(arg.vars, p.Name) {
			return true
		}
	}

	return false
}

func (arg *argDataOutput) correctArgType(t btf.Type) (btf.Type, error) {
	ptr, ok := mybtf.UnderlyingType(t).(*btf.Pointer)
	if !ok {
		return t, nil
	}

	stt, ok := ptr.Target.(*btf.Struct)
	if !ok {
		return t, nil
	}

	var err error
	switch stt.Name {
	case "__sk_buff":
		t, err = btfx.GetStructBtfPointer("sk_buff", getKernelBTF())
		if err != nil {
			return nil, fmt.Errorf("failed to get sk_buff btf pointer: %w", err)
		}

	case "xdp_md":
		t, err = btfx.GetStructBtfPointer("xdp_buff", getKernelBTF())
		if err != nil {
			return nil, fmt.Errorf("failed to get xdp_buff btf pointer: %w", err)
		}
	}

	return t, nil
}

func (arg *argDataOutput) genExitLabel() string {
	label := fmt.Sprintf("%s_%d", outputArgLabelExit, arg.labelCnt)
	arg.labelCnt++
	return label
}

func (arg *argDataOutput) matchParams(params []btf.FuncParam, spec *btf.Spec, checkArgType bool) ([]funcArgumentOutput, int, error) {
	args := make([]funcArgumentOutput, 0, 12)

	params = slices.Clone(params)
	if checkArgType {
		for i, p := range params {
			t, err := arg.correctArgType(p.Type)
			if err != nil {
				return nil, 0, fmt.Errorf("failed to correct arg type: %w", err)
			}

			params[i].Type = t
		}
	}

	krnl := getKernelBTF()
	offset := 0
	for _, a := range arg.args {
		if !a.match(params) {
			continue
		}

		a := a
		var err error
		offset, err = a.compile(params, krnl, spec, offset, arg.genExitLabel())
		if err != nil {
			return nil, 0, fmt.Errorf("failed to compile expr '%s': %w", a.expr, err)
		}

		args = append(args, a)
	}

	return args, offset, nil
}

func (arg *argDataOutput) genInsns(args []funcArgumentOutput) asm.Instructions {
	// output_arg(__u64 *args, void *buff)

	var insns asm.Instructions
	insns = append(insns,
		asm.Mov.Reg(asm.R9, asm.R1), // R9 = args
		asm.Mov.Reg(asm.R8, asm.R2), // R8 = buff
	)

	argsInsns := make([]asm.Instructions, 0, len(args)+1)
	argsInsns = append(argsInsns, insns)
	for _, a := range args {
		argsInsns = append(argsInsns, a.insn)
	}
	insns = slices.Concat(argsInsns...)

	insns = append(insns,
		asm.Return(),
	)

	return insns
}

func (arg *argDataOutput) clear(prog *ebpf.ProgramSpec) {
	clearOutputSubprog(prog, outputArgStub)
}

func (arg *argDataOutput) inject(prog *ebpf.ProgramSpec, args []funcArgumentOutput) {
	if len(args) == 0 {
		arg.clear(prog)
		return
	}

	insns := arg.genInsns(args)
	injectInsns(prog, outputArgStub, insns)
}
