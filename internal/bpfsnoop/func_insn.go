// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"bytes"
	"fmt"

	"github.com/bpfsnoop/gapstone"
)

type FuncInsn struct {
	Func string
	Off  uint64
	IP   uint64
	Insn gapstone.Instruction
	Desc string
}

type FuncInsns map[uint64]FuncInsn

func (i FuncInsns) parseFuncInsns(kfunc *KFunc, engine *gapstone.Engine, ksyms *Kallsyms) error {
	kaddr := kfunc.Ksym.addr
	bytesCnt := guessBytes(uintptr(kaddr), ksyms, 0)
	if bytesCnt > readLimit {
		return fmt.Errorf("func %s insn count %d is larger than limit %d", kfunc.Ksym.name, bytesCnt, readLimit)
	}

	insns, err := disasmKfuncAt(kaddr, bytesCnt, ksyms, engine)
	if err != nil {
		return fmt.Errorf("failed to disassemble insns: %w", err)
	}

	insns = insns[4:] // Skip several insns as they should not be traced.
	if debugTraceInsnCnt != 0 && len(insns) > int(debugTraceInsnCnt) {
		insns = insns[:debugTraceInsnCnt]
	}

	for _, insn := range insns {
		if bytes.Equal(insn.Bytes, []byte{0xc3}) /* retq */ {
			continue
		}

		offset := uint64(insn.Address) - kaddr
		i[uint64(insn.Address)] = FuncInsn{
			Func: kfunc.Ksym.name,
			Off:  offset,
			IP:   uint64(insn.Address),
			Insn: insn,
			Desc: printInsnInfo(uint64(insn.Address), offset, insn.Bytes, insn.Mnemonic, insn.OpStr),
		}
	}

	return nil
}

func NewFuncInsns(kfuncs KFuncs, ksyms *Kallsyms) (FuncInsns, error) {
	var kfs []*KFunc
	for _, kf := range kfuncs {
		if kf.Insn {
			kfs = append(kfs, kf)
		}
	}
	if len(kfs) == 0 {
		return FuncInsns{}, nil
	}

	engine, err := createGapstoneEngine()
	if err != nil {
		return FuncInsns{}, fmt.Errorf("failed to create capstone engine: %w", err)
	}
	defer engine.Close()

	insns := FuncInsns{}

	for _, kfunc := range kfs {
		if !kfunc.Insn {
			continue
		}

		if err := insns.parseFuncInsns(kfunc, engine, ksyms); err != nil {
			return FuncInsns{}, fmt.Errorf("failed to parse insns of func %s: %w", kfunc.Ksym.name, err)
		}
	}

	return insns, nil
}
