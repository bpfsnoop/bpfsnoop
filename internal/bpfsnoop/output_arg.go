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
	outputFuncArgData         = "output_arg_data"
	outputFuncArgDataInternal = "__output_arg_data"

	outputFuncArgDataLabelExit = "__output_arg_data_fail"

	dataReg = asm.R8
	argsReg = asm.R9

	argOutputStackOff = 16
)

var argOutput argDataOutput

type funcArgumentOutput struct {
	expr string
	t    btf.Type
	mem  *btf.Member
	insn asm.Instructions

	vars []string

	isNumPtr bool
	isStr    bool
}

type argDataOutput struct {
	args []funcArgumentOutput
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

func (arg *funcArgumentOutput) compile(params []btf.FuncParam, spec *btf.Spec, offset int) (int, error) {
	var insns asm.Instructions

	res, err := cc.CompileEvalExpr(cc.CompileExprOptions{
		Expr:          arg.expr,
		Params:        params,
		Spec:          spec,
		LabelExit:     outputFuncArgDataLabelExit,
		ReservedStack: argOutputStackOff,
		UsedRegisters: []asm.Register{dataReg, argsReg},
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

	if !arg.isStr && (size == 0 || size > 8 || (res.Mem != nil && res.Mem.BitfieldSize > 64)) {
		return 0, fmt.Errorf("invalid size of btf type %v: %d", res.Btf, size)
	}

	dataSize := 16
	if !arg.isStr {
		insns = append(res.Insns,
			asm.StoreMem(dataReg, int16(offset), res.Reg, asm.DWord),
		)

		if arg.isNumPtr {
			if res.Reg != asm.R3 {
				insns = append(insns,
					asm.Mov.Reg(asm.R3, res.Reg),
				)
			}
			insns = append(insns,
				// R3 is ready to be used as a pointer to the data
				asm.Mov.Imm(asm.R2, 8),
				asm.Mov.Reg(asm.R1, dataReg),
				asm.Add.Imm(asm.R1, int32(offset)),
				asm.FnProbeReadKernel.Call(),
			)
		}
	} else {
		if res.Reg != asm.R3 {
			insns = append(insns,
				asm.Mov.Reg(asm.R3, res.Reg),
			)
		}
		offset = 2 * maxOutputArgCnt * 8
		insns = append(res.Insns,
			// R3 is ready to be used as a pointer to the string
			asm.Mov.Imm(asm.R2, maxOutputStrLen),
			asm.Mov.Reg(asm.R1, dataReg),
			asm.Add.Imm(asm.R1, int32(offset)),
			asm.FnProbeReadKernelStr.Call(),
		)

		dataSize = 0
	}

	arg.insn = insns
	return dataSize, nil
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
		t, err = btfx.GetStructBtfPointer("sk_buff")
		if err != nil {
			return nil, fmt.Errorf("failed to get sk_buff btf pointer: %w", err)
		}

	case "xdp_md":
		t, err = btfx.GetStructBtfPointer("xdp_buff")
		if err != nil {
			return nil, fmt.Errorf("failed to get xdp_buff btf pointer: %w", err)
		}
	}

	return t, nil
}

func (arg *argDataOutput) matchParams(params []btf.FuncParam, checkArgType bool) ([]funcArgumentOutput, error) {
	args := make([]funcArgumentOutput, 0, maxOutputArgCnt)

	strUsed := false
	dataCnt := 0
	offset := 0

	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, fmt.Errorf("failed to load kernel spec: %w", err)
	}

	params = slices.Clone(params)
	if checkArgType {
		for i, p := range params {
			t, err := arg.correctArgType(p.Type)
			if err != nil {
				return nil, fmt.Errorf("failed to correct arg type: %w", err)
			}

			params[i].Type = t
		}
	}

	for _, a := range arg.args {
		if !a.match(params) {
			continue
		}

		a := a
		size, err := a.compile(params, spec, offset)
		if err != nil {
			return nil, fmt.Errorf("failed to compile expr '%s': %w", a.expr, err)
		}

		if strUsed && a.isStr {
			return nil, fmt.Errorf("only one string data is allowed")
		}
		strUsed = strUsed || a.isStr
		if !a.isStr {
			dataCnt++
		}
		if dataCnt > maxOutputArgCnt {
			return nil, fmt.Errorf("up-to-%d arg-data is allowed", maxOutputArgCnt)
		}

		offset += size
		args = append(args, a)
	}

	return args, nil
}

func (arg *argDataOutput) injectArgs(args []funcArgumentOutput) asm.Instructions {
	var insns asm.Instructions
	insns = append(insns,
		asm.Mov.Reg(argsReg, asm.R1),                                 // R9 = args
		asm.Mov.Reg(dataReg, asm.R2),                                 // R8 = data
		asm.StoreMem(asm.RFP, -argOutputStackOff, asm.R3, asm.DWord), // R10-16 = session_id
	)

	argsInsns := make([]asm.Instructions, 0, len(args)+1)
	argsInsns = append(argsInsns, insns)
	for _, a := range args {
		argsInsns = append(argsInsns, a.insn)
	}
	insns = slices.Concat(argsInsns...)

	insns = append(insns,
		asm.LoadMem(asm.R2, asm.RFP, -argOutputStackOff, asm.DWord), // R2 = session_id
		asm.Mov.Reg(asm.R1, dataReg),                                // R1 = data
		asm.Call.Label(outputFuncArgDataInternal),
		asm.Return().WithSymbol(outputFuncArgDataLabelExit),
	)

	return insns
}

func (arg *argDataOutput) clear(prog *ebpf.ProgramSpec) {
	clearOutputSubprog(prog, outputFuncArgDataInternal)
	clearOutputSubprog(prog, outputFuncArgData)
}

func (arg *argDataOutput) inject(prog *ebpf.ProgramSpec, args []funcArgumentOutput) {
	if len(args) == 0 {
		arg.clear(prog)
		return
	}

	insns := arg.injectArgs(args)
	injectInsns(prog, outputFuncArgData, insns)
}
