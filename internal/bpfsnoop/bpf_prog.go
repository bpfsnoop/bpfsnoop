// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"

	"github.com/cilium/ebpf"
	"golang.org/x/exp/maps"
)

type bpfProgs struct {
	progs map[ebpf.ProgramID]*ebpf.Program     // ID -> prog
	infos map[ebpf.ProgramID]*ebpf.ProgramInfo // ID -> prog info
	funcs map[uintptr]*bpfProgFuncInfo         // func IP -> prog func info

	tracings map[string]bpfTracingInfo // id:func -> prog, func

	links *bpfLinks

	disasm bool // disassemble BPF programs instead of tracing them
}

func NewBPFProgs(pflags []ProgFlag, onlyPrepare, disasm bool) (*bpfProgs, error) {
	var progs bpfProgs
	progs.progs = make(map[ebpf.ProgramID]*ebpf.Program, len(pflags))
	progs.infos = make(map[ebpf.ProgramID]*ebpf.ProgramInfo, len(pflags))
	progs.funcs = make(map[uintptr]*bpfProgFuncInfo, len(pflags))
	progs.tracings = make(map[string]bpfTracingInfo, len(pflags))
	progs.disasm = disasm

	var err error
	defer func() {
		if err != nil {
			progs.Close()
		}
	}()

	progs.links, err = newBPFLinks()
	if err != nil {
		return nil, fmt.Errorf("failed to prepare bpf links info: %w", err)
	}

	err = progs.prepareProgInfos(pflags)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare BPF program infos: %w", err)
	}

	if onlyPrepare {
		return &progs, nil
	}

	for id, prog := range progs.progs {
		if err := progs.addProg(prog, id, nil, false); err != nil {
			return nil, err
		}
	}

	return &progs, nil
}

func (b *bpfProgs) addProg(prog *ebpf.Program, id ebpf.ProgramID, info *ebpf.ProgramInfo, isBpfsnoop bool) error {
	progInfo, err := b.newBPFProgInfo(prog, id, info)
	if err != nil {
		return fmt.Errorf("failed to create BPF program info for ID(%d): %w", id, err)
	}

	progInfo.isBpfsnoopProg = isBpfsnoop
	for _, p := range progInfo.progs {
		b.funcs[p.kaddrRange.start] = p
	}
	return nil
}

func (b *bpfProgs) AddProgs(progs []*ebpf.Program, isBpfsnoop bool) error {
	for _, prog := range progs {
		info, err := prog.Info()
		if err != nil {
			return fmt.Errorf("failed to get prog info: %w", err)
		}

		id, ok := info.ID()
		if !ok {
			return fmt.Errorf("failed to get prog ID")
		}

		err = b.addProg(prog, id, info, isBpfsnoop)
		if err != nil {
			return fmt.Errorf("failed to add BPF program: %w", err)
		}
	}

	return nil
}

func (b *bpfProgs) Close() {
	for _, prog := range b.progs {
		_ = prog.Close()
	}
}

func (b *bpfProgs) Tracings() []bpfTracingInfo {
	return maps.Values(b.tracings)
}

func (b *bpfProgs) get(addr uintptr) (*bpfProgLineInfo, bool) {
	for _, info := range b.funcs {
		if li, ok := info.get(addr); ok {
			return li, true
		}
	}

	return nil, false
}

func (b *bpfProgs) contains(addr uintptr) bool {
	for _, info := range b.funcs {
		if info.contains(addr) {
			return true
		}
	}

	return false
}
