// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"
	"maps"
	"slices"
	"sync"

	"github.com/cilium/ebpf"
	"golang.org/x/sync/errgroup"
)

type bpfProgs struct {
	progs map[ebpf.ProgramID]*ebpf.Program // ID -> prog
	infos map[ebpf.ProgramID]*progInfo     // ID -> prog info

	flock sync.Mutex
	funcs map[uintptr]*bpfProgFuncInfo // func IP -> prog func info

	tracings map[string]*bpfTracingInfo // id:func -> prog, func

	traceable sync.Map // program ID -> verifier probe result

	disasm bool // disassemble BPF programs instead of tracing them
}

func NewBPFProgs(pflags []ProgFlag, noParseProgs, disasm bool) (*bpfProgs, error) {
	var progs bpfProgs
	progs.progs = make(map[ebpf.ProgramID]*ebpf.Program, len(pflags))
	progs.infos = make(map[ebpf.ProgramID]*progInfo, len(pflags))
	progs.funcs = make(map[uintptr]*bpfProgFuncInfo, len(pflags))
	progs.tracings = make(map[string]*bpfTracingInfo, len(pflags))
	progs.disasm = disasm

	var err error
	defer func() {
		if err != nil {
			progs.Close()
		}
	}()

	err = progs.prepareProgInfos(pflags)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare BPF program infos: %w", err)
	}

	if doParseProg := !noParseProgs; doParseProg {
		err = progs.parseProgs()
	}

	return &progs, err
}

func (b *bpfProgs) parseProgs() error {
	var wg errgroup.Group
	for id, prog := range b.progs {
		wg.Go(func() error {
			return b.addProg(prog, id, nil, false)
		})
	}
	if err := wg.Wait(); err != nil {
		return err
	}

	for _, t := range b.tracings {
		info, ok := b.funcs[t.funcIP]
		if !ok {
			return fmt.Errorf("missing parsed function %s at %#x", t.funcName, t.funcIP)
		}
		info.flag = t.flag
	}

	return nil
}

func (b *bpfProgs) addProg(prog *ebpf.Program, id ebpf.ProgramID, info *progInfo, isBpfsnoop bool) error {
	progInfo, err := b.newBPFProgInfo(prog, id, info)
	if err != nil {
		return fmt.Errorf("failed to create BPF program info for ID(%d): %w", id, err)
	}

	b.flock.Lock()
	defer b.flock.Unlock()

	progInfo.isBpfsnoopProg = isBpfsnoop
	for _, p := range progInfo.progs {
		b.funcs[p.kaddrRange.start] = p
	}
	return nil
}

func (b *bpfProgs) AddProgs(progs []*ebpf.Program, isBpfsnoop bool) error {
	for _, prog := range progs {
		info, err := fetchBPFProgInfo(prog)
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

func (b *bpfProgs) Tracings() []*bpfTracingInfo {
	return slices.Collect(maps.Values(b.tracings))
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
