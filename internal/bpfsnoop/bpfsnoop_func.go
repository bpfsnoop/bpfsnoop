// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/fatih/color"
)

type funcInfo struct {
	funcIP   uintptr
	name     string
	proto    *btf.Func
	args     []funcArgumentOutput
	params   []FuncParamFlags
	retParam FuncParamFlags
	progType ebpf.ProgramType
}

func findKfuncInMulti(funcIP uintptr, helpers *Helpers) *KFunc {
	for _, km := range helpers.KfnsMulti {
		if fn, ok := km.fns[funcIP]; ok {
			return fn
		}
	}
	return nil
}

func getFuncInfo(funcIP uintptr, helpers *Helpers, graph *FuncGraph, traceeFlags uint32) *funcInfo {
	var info funcInfo
	info.funcIP = funcIP

	progInfo, ok := helpers.Progs.funcs[funcIP]
	if !ok && graph != nil {
		progInfo = graph.Bprog
	}
	if progInfo != nil {
		info.name = progInfo.funcName + "[bpf]"
		info.proto = progInfo.funcProto
		info.args = progInfo.funcArgs
		info.params = progInfo.funcParams
		info.retParam = progInfo.retParam
		info.progType = progInfo.progType
		return &info
	}

	ksym, ok := helpers.Ksyms.find(funcIP)
	if ok {
		info.name = ksym.name
	} else {
		info.name = fmt.Sprintf("0x%x", funcIP)
	}

	var fn *KFunc
	if haveFlag(traceeFlags, traceeFlagKmultiMode) {
		fn = findKfuncInMulti(funcIP, helpers)
	}
	if fn == nil {
		var ok bool
		fn, ok = helpers.Kfuncs[funcIP]
		if !ok && graph != nil {
			fn = graph.Kfunc
		}
	}
	if fn == nil {
		return &info
	}

	info.proto = fn.Func
	info.args = fn.Args
	info.params = fn.Prms
	info.retParam = fn.Ret

	if fn.IsTp {
		info.name = fn.Func.Name + "[tp]"
	}

	return &info
}

func outputFuncInfo(sb *strings.Builder, fnInfo *funcInfo, helpers *Helpers, entrySz, exitSz int, exit, isTp, isKmulti bool, data []byte) []byte {
	fnName := fnInfo.name
	if exit {
		fnName = "← " + fnName
	} else if !exit {
		if !isTp {
			fnName = "→ " + fnName
		} else {
			fnName = "- " + fnName
		}
	}

	if colorfulOutput {
		color.New(color.FgYellow, color.Bold).Fprint(sb, fnName, " ")
		color.New(color.FgBlue).Fprintf(sb, "args")
	} else {
		fmt.Fprint(sb, fnName, " args")
	}

	withRetval := exit
	argSz := getArgSize(entrySz, exitSz, withRetval)
	if argSz == 0 {
		outputEmptyArgs(sb, withRetval, isKmulti)
		return data
	}

	argsData := data[:argSz]
	if isKmulti {
		outputFuncArgsKmulti(sb, fnInfo, helpers, argsData, withRetval)
	} else {
		outputFnArgs(sb, fnInfo, helpers, argsData, withRetval)
	}

	data = data[argSz:]

	return data
}

func getArgSize(entrySz, exitSz int, withRetval bool) int {
	if withRetval {
		return exitSz
	}
	return entrySz
}

func outputEmptyArgs(sb *strings.Builder, withRetval, isKmulti bool) {
	fmt.Fprint(sb, "=()")
	if withRetval && !isKmulti {
		fmt.Fprint(sb, " retval=(void)")
	}
}

func outputFuncArgsKmulti(sb *strings.Builder, fnInfo *funcInfo, helpers *Helpers, argsData []byte, withRetval bool) {
	outputFnArgsKmulti(sb, fnInfo, helpers, argsData)

	if !withRetval || len(argsData) < (maxArgsKmulti+1)*8 {
		return
	}

	f := findSymbolHelper(uint64(fnInfo.funcIP), helpers)
	outputFnRetvalKmulti(sb, fnInfo, argsData[maxArgsKmulti*8:], f)
}
