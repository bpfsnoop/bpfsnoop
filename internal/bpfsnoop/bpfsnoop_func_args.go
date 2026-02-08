// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/fatih/color"

	"github.com/bpfsnoop/bpfsnoop/internal/btfx"
	"github.com/bpfsnoop/bpfsnoop/internal/strx"
)

const (
	maxOutputStrLen = 64
)

type (
	xdpAction int
	tcAction  int
)

const (
	xdpAborted xdpAction = iota
	xdpDrop
	xdpPass
	xdpTx
	xdpRedirect
)

var xdpActions = []string{
	"XDP_ABORTED",
	"XDP_DROP",
	"XDP_PASS",
	"XDP_TX",
	"XDP_REDIRECT",
}

func (a xdpAction) Action() string {
	var action string
	if xdpAborted <= a && a <= xdpRedirect {
		action = xdpActions[a]
	} else {
		action = fmt.Sprintf("%d", a)
	}

	return action
}

const (
	tcUnspec tcAction = -1 + iota
	tcOK
	tcReclass
	tcShot
	tcPipe
	tcStolen
	tcQueue
	tcRepeat
	tcRedir
	tcTrap
)

var tcActions = []string{
	"TC_ACT_UNSPEC",
	"TC_ACT_OK",
	"TC_ACT_RECLASSIFY",
	"TC_ACT_SHOT",
	"TC_ACT_PIPE",
	"TC_ACT_STOLEN",
	"TC_ACT_QUEUED",
	"TC_ACT_REPEAT",
	"TC_ACT_REDIRECT",
	"TC_ACT_TRAP",
}

func (a tcAction) Action() string {
	var action string
	if tcUnspec <= a && a <= tcTrap {
		action = tcActions[a+1]
	} else {
		action = fmt.Sprintf("%d", a)
	}

	return action
}

func outputFnRetval(sb *strings.Builder, info *funcInfo, s string, data []byte, f btfx.FindSymbol) {
	var retval string

	if info.progType == ebpf.XDP {
		u32 := *(*uint32)(unsafe.Pointer(&data[0]))
		retval = xdpAction(u32).Action()
		goto L_output
	}

	if info.progType == ebpf.SchedCLS {
		u32 := *(*uint32)(unsafe.Pointer(&data[0]))
		retval = tcAction(u32).Action()
		goto L_output
	}

	if info.proto != nil {
		var b [24]byte
		copy(b[:], data)
		num1 := *(*uint64)(unsafe.Pointer(&b[0]))
		num2 := *(*uint64)(unsafe.Pointer(&b[8]))
		rettyp := info.proto.Type.(*btf.FuncProto).Return
		retval = btfx.ReprFuncReturn(rettyp, info.retParam.IsStr,
			info.retParam.IsNumberPtr, num1, num2, s, f)
	} else {
		num := *(*uint64)(unsafe.Pointer(&data[0]))
		retval = fmt.Sprintf("%#x/%s", num, num)
	}

L_output:
	if colorfulOutput {
		color.New(color.FgGreen).Fprintf(sb, " retval")
		fmt.Fprint(sb, "=")
		color.New(color.FgRed).Fprintf(sb, "%s", retval)
	} else {
		fmt.Fprintf(sb, " retval=%s", retval)
	}
}

func getU64(data []byte) uint64 {
	return *(*uint64)(unsafe.Pointer(&data[0]))
}

func readUint64(data []byte) (uint64, []byte) {
	return getU64(data), data[8:]
}

func readStrN(data []byte, n int) (string, []byte) {
	str := strx.NullTerminated(data[:n])
	return str, data[n:]
}

func readStr(data []byte) (string, []byte) {
	return readStrN(data, maxOutputStrLen)
}

func outputFnArgs(sb *strings.Builder, info *funcInfo, helpers *Helpers, data []byte, withRetval bool) {
	funcParamColors := []*color.Color{
		color.RGB(0x9d, 0x9d, 0x9d),
		color.RGB(0x7a, 0x7a, 0x7a),
		color.RGB(0x54, 0x54, 0x54),
		color.RGB(0x9c, 0x91, 0x91),
		color.RGB(0x7c, 0x74, 0x74),
		color.RGB(0x5c, 0x54, 0x54),
		color.RGB(0x9d, 0x9d, 0x9d),
		color.RGB(0x7a, 0x7a, 0x7a),
		color.RGB(0x54, 0x54, 0x54),
		color.RGB(0x9c, 0x91, 0x91),
		color.RGB(0x7c, 0x74, 0x74),
		color.RGB(0x5c, 0x54, 0x54),
	}

	fmt.Fprintf(sb, "=(")

	f := findSymbolHelper(uint64(info.funcIP), helpers)
	params := info.proto.Type.(*btf.FuncProto).Params
	lastIdx, idx := len(params)-1, 0
	for i, param := range info.params {
		if param.partOfPrevParam {
			continue
		}

		if idx != 0 {
			fmt.Fprint(sb, ", ")
		}

		arg, argVal := uint64(0), uint64(0)
		argStr := ""
		if param.IsStr {
			argStr, data = readStr(data)
		} else {
			arg, data = readUint64(data)
			if param.IsNumberPtr {
				argVal, data = readUint64(data)
			}
		}

		valNext := uint64(0)
		if i < lastIdx {
			valNext = getU64(data)
		}

		fp := btfx.ReprFuncParam(&params[idx], i, param.IsStr, param.IsNumberPtr, arg, argVal, valNext, argStr, f)
		if colorfulOutput {
			funcParamColors[i].Fprint(sb, fp)
		} else {
			fmt.Fprintf(sb, "%s", fp)
		}

		idx++
	}
	fmt.Fprintf(sb, ")")

	if !withRetval {
		return
	}

	retStr := ""
	if info.retParam.IsStr && len(data) >= maxOutputStrLen {
		retStr = strx.NullTerminated(data[:maxOutputStrLen])
	}
	outputFnRetval(sb, info, retStr, data, f)
}

func findSymbolHelper(addr uint64, helpers *Helpers) btfx.FindSymbol {
	return func(addr uint64) string {
		if prog, ok := helpers.Progs.funcs[uintptr(addr)]; ok {
			return prog.funcName + "[bpf]"
		}

		return helpers.Ksyms.findSymbol(addr)
	}
}
