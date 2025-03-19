// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"
	"log"
	"strings"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/leonhwangprojects/bice"

	"github.com/bpfsnoop/bpfsnoop/internal/btfx"
)

const (
	outputFuncArgData         = "output_arg_data"
	outputFuncArgDataInternal = "__output_arg_data"

	outputFuncArgDataLabelExit = "__output_arg_data_fail"
)

var argOutput argDataOutput

type funcArgumentOutput struct {
	expr string
	typ  string
	name string
	last string
	t    btf.Type
	insn asm.Instructions

	isNumPtr bool
	isStr    bool
}

type argDataOutput struct {
	args []funcArgumentOutput
}

func prepareArgOutput(expr string) funcArgumentOutput {
	var arg funcArgumentOutput

	typ, err := getTypeDescFrom(expr)
	if err != nil {
		log.Fatalf("Failed to get type description for function argument: %v", err)
	}

	arg.typ = strings.TrimSpace(typ)
	arg.expr = strings.TrimSpace(expr)
	if arg.typ != "" {
		arg.expr = strings.TrimSpace(expr[len(arg.typ)+2:])
	}

	expr = arg.expr
	for i := 0; i < len(expr); i++ {
		if !isValidChar(expr[i]) {
			arg.name = expr[:i]
			break
		}
	}

	for i := len(expr) - 1; i >= 0; i-- {
		if !isValidChar(expr[i]) {
			arg.last = expr[i+1:]
			break
		}
	}

	return arg
}

func prepareFuncArgOutput(exprs []string) argDataOutput {
	var arg argDataOutput
	arg.args = make([]funcArgumentOutput, 0, len(exprs))

	for _, expr := range exprs {
		arg.args = append(arg.args, prepareArgOutput(expr))
	}

	return arg
}

func (arg *funcArgumentOutput) compile(idx int, t btf.Type, offset int, ctxStale, getFuncArg bool) (int, error) {
	var insns asm.Instructions
	if ctxStale {
		insns = append(insns,
			asm.Mov.Reg(asm.R1, asm.R8), // R1 = ctx
		)
	}
	if getFuncArg {
		insns = append(insns, genGetFuncArg(idx, asm.R3)...)
	} else {
		insns = append(insns, genAccessArg(idx, asm.R3)...)
	}

	res, err := bice.Access(bice.AccessOptions{
		Insns:     insns,
		Expr:      arg.expr,
		Type:      t,
		Src:       asm.R3, // R3 = the idx-th argument
		Dst:       asm.R3,
		LabelExit: outputFuncArgDataLabelExit,
	})
	if err != nil {
		return 0, fmt.Errorf("failed to compile expr %s: %w", arg.expr, err)
	}

	arg.t = res.LastField
	arg.isNumPtr = btfx.IsNumberPointer(res.LastField)
	arg.isStr = mybtf.IsConstCharPtr(res.LastField) || mybtf.IsCharArray(res.LastField)

	dataSize := 16
	if !arg.isStr {
		insns = append(res.Insns,
			asm.StoreMem(asm.R6, int16(offset), asm.R3, asm.DWord),
		)

		if arg.isNumPtr {
			insns = append(insns,
				// R3 is ready to be used as a pointer to the data
				asm.Mov.Imm(asm.R2, 8),
				asm.Mov.Reg(asm.R1, asm.R6),
				asm.Add.Imm(asm.R1, int32(offset)),
				asm.FnProbeReadKernel.Call(),
			)
		}
	} else {
		offset = 2 * maxOutputArgCnt * 8
		insns = append(res.Insns,
			// R3 is ready to be used as a pointer to the string
			asm.Mov.Imm(asm.R2, maxOutputStrLen),
			asm.Mov.Reg(asm.R1, asm.R6),
			asm.Add.Imm(asm.R1, int32(offset)),
			asm.FnProbeReadKernelStr.Call(),
		)

		dataSize = 0
	}

	arg.insn = insns
	return dataSize, nil
}

func (arg *funcArgumentOutput) match(p btf.FuncParam) bool {
	if arg.expr == "" {
		return false
	}
	if arg.name != p.Name {
		return false
	}
	if arg.typ != "" && arg.typ != btfx.Repr(p.Type) {
		return false
	}

	return true
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

func (arg *argDataOutput) matchParams(params []btf.FuncParam, checkArgType, getFuncArg bool) ([]funcArgumentOutput, error) {
	args := make([]funcArgumentOutput, 0, maxOutputArgCnt)

	ctxStale := false
	strUsed := false
	dataCnt := 0
	offset := 0

	for i, p := range params {
		for _, a := range arg.args {
			if !a.match(p) {
				continue
			}

			t := p.Type
			if checkArgType {
				var err error
				t, err = arg.correctArgType(p.Type)
				if err != nil {
					return nil, fmt.Errorf("failed to correct arg type: %w", err)
				}
			}

			a := a
			size, err := a.compile(i, t, offset, ctxStale, getFuncArg)
			if err != nil {
				return nil, fmt.Errorf("failed to compile arg %s with expr %s: %w", p.Name, a.expr, err)
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
			ctxStale = true
		}
	}

	return args, nil
}

func (arg *argDataOutput) injectArgs(args []funcArgumentOutput) asm.Instructions {
	var insns asm.Instructions
	if len(args) > 1 {
		insns = append(insns,
			asm.Mov.Reg(asm.R8, asm.R1), // R8 = ctx
		)
	}
	insns = append(insns,
		asm.Mov.Reg(asm.R6, asm.R2), // R6 = data
		asm.Mov.Reg(asm.R7, asm.R3), // R7 = session_id
	)

	for i, a := range args {
		if i != 0 {
			insns = append(insns,
				asm.Mov.Reg(asm.R1, asm.R8), // R1 = ctx
			)
		}
		insns = append(insns, a.insn...)
	}

	insns = append(insns,
		asm.Mov.Reg(asm.R2, asm.R7), // R2 = session_id
		asm.Mov.Reg(asm.R1, asm.R6), // R1 = data
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
