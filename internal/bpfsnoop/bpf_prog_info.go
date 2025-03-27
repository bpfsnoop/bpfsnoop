// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"
	"slices"
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
	kaddrRange bpfProgKaddrRange
	funcName   string
	funcProto  *btf.Func
	funcParams []FuncParamFlags
	funcArgs   []funcArgumentOutput
	isRetStr   bool

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

	idx, ok := slices.BinarySearch(b.jitedLineInfo, addr)
	if !ok {
		idx--
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

func (b *bpfProgs) newBPFProgInfo(prog *ebpf.Program, id ebpf.ProgramID, pinfo *ebpf.ProgramInfo) (*bpfProgInfo, error) {
	if pinfo == nil {
		var ok bool
		pinfo, ok = b.infos[id]
		if !ok {
			var err error
			pinfo, err = prog.Info()
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
	jitedInsns, _ := pinfo.JitedInsns()
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

	insns := jitedInsns
	for i, funcLen := range jitedFuncLens {
		var info bpfProgFuncInfo
		info.kaddrRange.start = jitedKsyms[i]
		info.kaddrRange.end = info.kaddrRange.start + uintptr(funcLen)
		info.funcName = strings.TrimSpace(funcInfos[i].Func.Name)
		info.funcProto = funcInfos[i].Func
		info.funcParams, _ /* won't fail for bpf progs */ = getFuncParams(funcInfos[i].Func)
		info.isRetStr = mybtf.IsConstCharPtr(funcInfos[i].Func.Type.(*btf.FuncProto).Return)

		for i, kaddr := range jitedLineInfos {
			if info.kaddrRange.start <= uintptr(kaddr) && uintptr(kaddr) < info.kaddrRange.end {
				info.jitedLineInfo = append(info.jitedLineInfo, uintptr(kaddr))
				info.lineInfos = append(info.lineInfos, lines[i])
			}
		}

		progInfo.progs = append(progInfo.progs, &info)

		insns = insns[funcLen:]
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
