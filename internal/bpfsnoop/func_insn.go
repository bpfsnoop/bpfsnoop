// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"bytes"
	"fmt"

	"github.com/bpfsnoop/gapstone"
	"github.com/cilium/ebpf"
)

type FuncInsn struct {
	Func string
	Off  uint64
	IP   uint64
	Insn gapstone.Instruction
	Desc string
}

type FuncInsns struct {
	Insns map[uint64]FuncInsn
}

func (f *FuncInsns) parseFuncInsns(kfunc *KFunc, engine *gapstone.Engine, ksyms *Kallsyms, readSpec *ebpf.CollectionSpec) error {
	kaddr := kfunc.Ksym.addr
	bytesCnt := guessBytes(uintptr(kaddr), ksyms, 0)
	if bytesCnt > readLimit {
		return fmt.Errorf("func %s insn count %d is larger than limit %d", kfunc.Ksym.name, bytesCnt, readLimit)
	}

	data, err := readKernel(readSpec, kaddr, uint32(bytesCnt))
	if err != nil {
		return fmt.Errorf("failed to read kernel memory from %#x: %w", kaddr, err)
	}

	data = trimTailingInsns(data)
	insns, err := engine.Disasm(data, kaddr, 0)
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
		f.Insns[uint64(insn.Address)] = FuncInsn{
			Func: kfunc.Ksym.name,
			Off:  offset,
			IP:   uint64(insn.Address),
			Insn: insn,
			Desc: printInsnInfo(uint64(insn.Address), offset, insn.Bytes, insn.Mnemonic, insn.OpStr),
		}
	}

	return nil
}

func NewFuncInsns(kfuncs KFuncs, ksyms *Kallsyms, readSpec *ebpf.CollectionSpec) (*FuncInsns, error) {
	if len(kfuncs) == 0 {
		return &FuncInsns{}, nil
	}

	engine, err := createGapstoneEngine()
	if err != nil {
		return &FuncInsns{}, fmt.Errorf("failed to create capstone engine: %w", err)
	}
	defer engine.Close()

	var insns FuncInsns
	insns.Insns = make(map[uint64]FuncInsn)

	for _, kfunc := range kfuncs {
		if !kfunc.Insn {
			continue
		}

		if err := insns.parseFuncInsns(kfunc, engine, ksyms, readSpec); err != nil {
			return &FuncInsns{}, fmt.Errorf("failed to parse insns of func %s: %w", kfunc.Ksym.name, err)
		}
	}

	return &insns, nil
}
