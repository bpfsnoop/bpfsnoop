// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"golang.org/x/exp/maps"
	"golang.org/x/sync/errgroup"

	"github.com/bpfsnoop/bpfsnoop/internal/assert"
)

type bpfProgs struct {
	ready bool
	err   error
	done  chan struct{}

	progs map[ebpf.ProgramID]*ebpf.Program     // ID -> prog
	infos map[ebpf.ProgramID]*ebpf.ProgramInfo // ID -> prog info

	flock sync.Mutex
	funcs map[uintptr]*bpfProgFuncInfo // func IP -> prog func info

	tracings map[string]*bpfTracingInfo // id:func -> prog, func

	links *bpfLinks

	disasm bool // disassemble BPF programs instead of tracing them
}

func NewBPFProgs(pflags []ProgFlag, noParseProgs, disasm bool) (*bpfProgs, error) {
	var progs bpfProgs
	progs.done = make(chan struct{})
	progs.progs = make(map[ebpf.ProgramID]*ebpf.Program, len(pflags))
	progs.infos = make(map[ebpf.ProgramID]*ebpf.ProgramInfo, len(pflags))
	progs.funcs = make(map[uintptr]*bpfProgFuncInfo, len(pflags))
	progs.tracings = make(map[string]*bpfTracingInfo, len(pflags))
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

	if !noParseProgs {
		go progs.parseProgs()
	}

	return &progs, nil
}

func (b *bpfProgs) parseProgs() {
	var wg errgroup.Group
	for id, prog := range b.progs {
		id, prog := id, prog // capture range variables
		wg.Go(func() error {
			return b.addProg(prog, id, nil, false)
		})
	}
	b.err = wg.Wait()

	for _, t := range b.tracings {
		b.funcs[t.funcIP].fgraph = t.graph
	}

	close(b.done)
	b.ready = true
}

func (b *bpfProgs) addProg(prog *ebpf.Program, id ebpf.ProgramID, info *ebpf.ProgramInfo, isBpfsnoop bool) error {
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

func (b *bpfProgs) Tracings() []*bpfTracingInfo {
	return maps.Values(b.tracings)
}

func (b *bpfProgs) wait() error {
	if !b.ready {
		<-b.done
	}

	return b.err
}

func (b *bpfProgs) get(addr uintptr) (*bpfProgLineInfo, bool) {
	if err := b.wait(); err != nil {
		assert.NoErr(err, "Failed to parse bpf progs info: %v")
		return nil, false
	}

	for _, info := range b.funcs {
		if li, ok := info.get(addr); ok {
			return li, true
		}
	}

	return nil, false
}

func (b *bpfProgs) contains(addr uintptr) bool {
	if err := b.wait(); err != nil {
		assert.NoErr(err, "Failed to parse bpf progs info: %v")
		return false
	}

	for _, info := range b.funcs {
		if info.contains(addr) {
			return true
		}
	}

	return false
}
