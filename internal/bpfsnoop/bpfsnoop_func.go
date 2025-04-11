// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"

	"github.com/cilium/ebpf/btf"
)

type funcInfo struct {
	name     string
	proto    *btf.Func
	args     []funcArgumentOutput
	params   []FuncParamFlags
	retParam FuncParamFlags
	insnMode bool
	pktTuple bool
	isTp     bool
	isProg   bool
}

func getFuncInfo(event *Event, helpers *Helpers) *funcInfo {
	var info funcInfo

	if progInfo, ok := helpers.Progs.funcs[event.FuncIP]; ok {
		info.name = progInfo.funcName + "[bpf]"
		info.proto = progInfo.funcProto
		info.args = progInfo.funcArgs
		info.params = progInfo.funcParams
		info.retParam = progInfo.retParam
		info.pktTuple = progInfo.pktOutput
		info.isProg = true
		return &info
	}

	ksym, ok := helpers.Ksyms.find(event.FuncIP)
	if ok {
		info.name = ksym.name
	} else {
		info.name = fmt.Sprintf("0x%x", event.FuncIP)
	}

	fn, ok := helpers.Kfuncs[event.FuncIP]
	if !ok {
		return &info
	}

	info.proto = fn.Func
	info.args = fn.Args
	info.params = fn.Prms
	info.retParam = fn.Ret
	info.insnMode = fn.Insn
	info.pktTuple = fn.Pkt

	if fn.IsTp {
		info.name = fn.Func.Name + "[tp]"
		info.isTp = true
	}

	return &info
}
