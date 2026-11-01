// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

type bpfProgKaddrRange struct {
	start, end uintptr
}

func (r *bpfProgKaddrRange) contains(addr uintptr) bool {
	return r.start <= addr && addr < r.end
}

type bpfProgFuncInfo struct {
	prog       *ebpf.Program
	progID     ebpf.ProgramID
	kaddrRange bpfProgKaddrRange
	funcName   string
	funcProto  *btf.Func
	funcParams []FuncParamFlags
	retParam   FuncParamFlags
	funcArgs   []funcArgumentOutput
	argEntrySz int
	argExitSz  int
	argDataSz  int
	isRetStr   bool
	pktOutput  bool
	flag       progFlagImmInfo
	progType   ebpf.ProgramType

	jitedLineInfo []uintptr        // ordered
	lineInfos     []btf.LineOffset // mapping 1:1 with jitedLineInfo
}

type bpfProgLineInfo struct {
	funcName string
	ksymAddr uintptr

	fileName string
	fileLine uint32
}

func (b *bpfProgFuncInfo) contains(addr uintptr) bool {
	return b.kaddrRange.contains(addr)
}

func (b *bpfProgFuncInfo) get(addr uintptr) (*bpfProgLineInfo, bool) {
	if !b.kaddrRange.contains(addr) {
		return nil, false
	}

	idx, found := -1, false
	for i, li := range b.jitedLineInfo {
		if li == addr {
			idx, found = i, true
			break
		}
	}
	if !found {
		return nil, false
	}

	fileName := b.lineInfos[idx].Line.FileName()
	if fileName != "" && fileName[0] == '.' {
		fileName = strings.TrimLeft(fileName, "./")
	}

	var line bpfProgLineInfo
	line.funcName = b.funcName
	line.ksymAddr = b.kaddrRange.start
	line.fileName = fileName
	line.fileLine = b.lineInfos[idx].Line.LineNumber()
	return &line, true
}

type bpfProgInfo struct {
	progs []*bpfProgFuncInfo

	isBpfsnoopProg bool
}

func (b *bpfProgs) newBPFProgInfo(prog *ebpf.Program, id ebpf.ProgramID, pinfo *progInfo) (*bpfProgInfo, error) {
	if pinfo == nil {
		var ok bool
		pinfo, ok = b.infos[id]
		if !ok {
			var err error
			pinfo, err = fetchBPFProgInfo(prog)
			if err != nil {
				return nil, fmt.Errorf("failed to get prog info: %w", err)
			}
		}
	}

	funcInfos, err := pinfo.FuncInfos()
	if err != nil {
		return nil, fmt.Errorf("failed to get func infos: %w", err)
	}

	lines, _ := pinfo.LineInfos()
	jitedKsyms, _ := pinfo.JitedKsymAddrs()
	jitedFuncLens, _ := pinfo.JitedFuncLens()
	jitedLineInfos, _ := pinfo.JitedLineInfos()

	if len(funcInfos) != len(jitedFuncLens) {
		return nil, fmt.Errorf("func info number %d != jited func lens number %d", len(funcInfos), len(jitedFuncLens))
	}

	if len(jitedKsyms) != len(jitedFuncLens) {
		return nil, fmt.Errorf("jited ksyms number %d != jited func lens number %d", len(jitedKsyms), len(jitedFuncLens))
	}

	if len(jitedLineInfos) != len(lines) {
		return nil, fmt.Errorf("line info number %d != jited line info number %d", len(lines), len(jitedLineInfos))
	}

	var progInfo bpfProgInfo
	progInfo.progs = make([]*bpfProgFuncInfo, 0, len(jitedFuncLens))

	for i, funcLen := range jitedFuncLens {
		var info bpfProgFuncInfo
		info.prog = prog
		info.progID = id
		info.kaddrRange.start = jitedKsyms[i]
		info.kaddrRange.end = info.kaddrRange.start + uintptr(funcLen)
		info.funcName = strings.TrimSpace(funcInfos[i].Func.Name)
		info.funcProto = funcInfos[i].Func
		info.funcParams, info.retParam, _ /* won't fail for bpf progs */ = getFuncParams(funcInfos[i].Func)
		info.isRetStr = mybtf.IsConstCharPtr(funcInfos[i].Func.Type.(*btf.FuncProto).Return)
		info.progType = pinfo.Type

		for i, kaddr := range jitedLineInfos {
			if info.kaddrRange.start <= uintptr(kaddr) && uintptr(kaddr) < info.kaddrRange.end {
				info.jitedLineInfo = append(info.jitedLineInfo, uintptr(kaddr))
				info.lineInfos = append(info.lineInfos, lines[i])
			}
		}

		progInfo.progs = append(progInfo.progs, &info)

	}

	return &progInfo, nil
}

func (b *bpfProgInfo) get(addr uintptr) (*bpfProgLineInfo, bool) {
	for _, prog := range b.progs {
		if li, ok := prog.get(addr); ok {
			return li, true
		}
	}

	return nil, false
}

func (b *bpfProgInfo) contains(addr uintptr) bool {
	for _, prog := range b.progs {
		if prog.kaddrRange.contains(addr) {
			return true
		}
	}

	return false
}

func (b *bpfProgInfo) funcName() string {
	return b.progs[0].funcName
}

// openArena opens the arena map of the prog, among its maps, or returns nil if
// it uses none. A prog can use one arena at most.
func (p *progInfo) openArena() (*ebpf.Map, error) {
	for _, id := range p.mapIDs {
		m, err := ebpf.NewMapFromID(id)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("failed to open map %d: %w", id, err)
		}

		info, err := m.Info()
		if err != nil {
			err = fmt.Errorf("failed to get info of map %d: %w", id, err)
			return nil, errors.Join(err, m.Close())
		}
		if info.Type == ebpf.Arena {
			return m, nil
		}

		if err := m.Close(); err != nil {
			return nil, err
		}
	}

	return nil, nil
}
