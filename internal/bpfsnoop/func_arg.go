// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

const (
	outputFnArgsStub = "output_fn_args"
)

func clearOutputFuncArgs(prog *ebpf.ProgramSpec) {
	clearOutputSubprog(prog, outputFnArgsStub)
}

func genOutputFuncArgs(prog *ebpf.ProgramSpec, prms []FuncParamFlags, ret FuncParamFlags, withRetval bool) (asm.Instructions, int, error) {
	// output_fn_args(__u64 *args, void *buff, __u64 retval)

	var insns asm.Instructions
	var offset int

	const (
		regArg  = asm.R3
		regArgs = asm.R6
		regBuff = asm.R7
		regRet  = asm.R8
	)

	// backup regs
	insns = append(insns,
		asm.Mov.Reg(regArgs, asm.R1),
		asm.Mov.Reg(regBuff, asm.R2),
		asm.Mov.Reg(regRet, asm.R3),
	)

	for i := range prms {
		prm := prms[i]

		insns = append(insns,
			asm.LoadMem(regArg, regArgs, int16(i*8), asm.DWord),
		)

		if !prm.IsStr {
			insns = append(insns,
				asm.StoreMem(regBuff, int16(offset), regArg, asm.DWord),
			)
			offset += 8

			if prm.IsNumberPtr {
				insns = append(insns,
					asm.Mov.Imm(asm.R2, 8),
					asm.Mov.Reg(asm.R1, asm.RFP),
					asm.Add.Imm(asm.R1, -8),
					asm.FnProbeReadKernel.Call(),
					asm.LoadMem(regArg, asm.RFP, -8, asm.DWord),
					asm.StoreMem(regBuff, int16(offset), regArg, asm.DWord),
				)
				offset += 8
			}
		} else /* IsStr */ {
			if offset != 0 {
				insns = append(insns,
					asm.Mov.Imm(asm.R2, maxOutputStrLen),
					asm.Mov.Reg(asm.R1, regBuff),
					asm.Add.Imm(asm.R1, int32(offset)),
					asm.FnProbeReadKernelStr.Call(),
				)
			} else {
				insns = append(insns,
					asm.Mov.Imm(asm.R2, maxOutputStrLen),
					asm.Mov.Reg(asm.R1, regBuff),
					asm.FnProbeReadKernelStr.Call(),
				)
			}
			offset += maxOutputStrLen
		}
	}

	if !withRetval {
		insns = append(insns,
			asm.Return(),
		)
		return insns, offset, nil
	}

	if !ret.IsStr {
		insns = append(insns,
			asm.StoreMem(regBuff, int16(offset), regRet, asm.DWord),
		)
		offset += 8

		if ret.IsNumberPtr {
			insns = append(insns,
				asm.Mov.Reg(asm.R3, regRet),
				asm.Mov.Imm(asm.R2, 8),
				asm.Mov.Reg(asm.R1, asm.RFP),
				asm.Add.Imm(asm.R1, -8),
				asm.FnProbeReadKernel.Call(),
				asm.LoadMem(regRet, asm.RFP, -8, asm.DWord),
				asm.StoreMem(regBuff, int16(offset), regRet, asm.DWord),
			)
			offset += 8
		}
	} else /* IsStr */ {
		if offset != 0 {
			insns = append(insns,
				asm.Mov.Reg(asm.R3, regRet),
				asm.Mov.Imm(asm.R2, maxOutputStrLen),
				asm.Mov.Reg(asm.R1, regBuff),
				asm.Add.Imm(asm.R1, int32(offset)),
				asm.FnProbeReadKernelStr.Call(),
			)
		} else {
			insns = append(insns,
				asm.Mov.Reg(asm.R3, regRet),
				asm.Mov.Imm(asm.R2, maxOutputStrLen),
				asm.Mov.Reg(asm.R1, regBuff),
				asm.FnProbeReadKernelStr.Call(),
			)
		}
		offset += maxOutputStrLen
	}

	insns = append(insns,
		asm.Return(),
	)

	return insns, offset, nil
}

func injectOutputFuncArgs(prog *ebpf.ProgramSpec, prms []FuncParamFlags, ret FuncParamFlags, withRetval bool) (int, error) {
	if len(prms) == 0 && !withRetval {
		clearOutputFuncArgs(prog)
		return 0, nil
	}

	insns, size, err := genOutputFuncArgs(prog, prms, ret, withRetval)
	if err != nil {
		return 0, err
	}

	injectInsns(prog, outputFnArgsStub, insns)

	return size, nil
}

func genOutputKmultiFnArgs(argsNr int, withRetval bool) (asm.Instructions, int) {
	// output_fn_args(__u64 *args, void *buff, __u64 retval)
	// For kprobe.multi, use fixed raw argument slots only.
	const regArg = asm.R3

	var insns asm.Instructions
	var off int16 = 0

	for i := 0; i < argsNr; i++ {
		insns = append(insns,
			asm.LoadMem(regArg, asm.R1, off, asm.DWord),
			asm.StoreMem(asm.R2, off, regArg, asm.DWord),
		)
		off += 8
	}

	if withRetval {
		insns = append(insns,
			asm.StoreMem(asm.R2, off, regArg, asm.DWord),
		)
		off += 8
	}

	insns = append(insns, asm.Return())
	return insns, int(off)
}

func injectOutputKmultiFnArgs(prog *ebpf.ProgramSpec, argsNr int, withRetval bool) (int, error) {
	if argsNr == 0 {
		clearOutputFuncArgs(prog)
		return 0, nil
	}

	insns, size := genOutputKmultiFnArgs(argsNr, withRetval)
	injectInsns(prog, outputFnArgsStub, insns)
	return size, nil
}
