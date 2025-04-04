// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/fatih/color"

	"github.com/bpfsnoop/bpfsnoop/internal/btfx"
	"github.com/bpfsnoop/bpfsnoop/internal/strx"
)

type StrData struct {
	Arg [32]byte
	Ret [32]byte
}

func (s *StrData) arg() string {
	return strx.NullTerminated(s.Arg[:])
}

func (s *StrData) ret() string {
	return strx.NullTerminated(s.Ret[:])
}

type FnData struct {
	Retval [2]uint64
	Args   [MAX_BPF_FUNC_ARGS][2]uint64 // raw data + pointed data
}

func outputFnRetval(sb *strings.Builder, s string, info *funcInfo, event *Event, f btfx.FindSymbol) {
	var retval string
	if info.proto != nil {
		rettyp := info.proto.Type.(*btf.FuncProto).Return
		retval = btfx.ReprFuncReturn(rettyp, info.retParam.IsStr,
			info.retParam.IsNumberPtr, event.Func.Retval[0], event.Func.Retval[1],
			s, f)
	} else {
		retval = fmt.Sprintf("%#x/%s", uint64(event.Func.Retval[0]), event.Func.Retval[0])
	}

	if !noColorOutput {
		color.New(color.FgGreen).Fprintf(sb, " retval")
		fmt.Fprint(sb, "=")
		color.New(color.FgRed).Fprintf(sb, "%s", retval)
	} else {
		fmt.Fprintf(sb, " retval=%s", retval)
	}
}

func outputFnArgs(sb *strings.Builder, info *funcInfo, helpers *Helpers, strData *StrData, strs *ebpf.Map, event *Event, f btfx.FindSymbol) error {
	if info.proto == nil {
		fmt.Fprint(sb, "args=(..UNK..)")
		outputFnRetval(sb, "", info, event, f)
		return nil
	}

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

	hasStrData := info.retParam.IsStr
	if !hasStrData {
		for _, prm := range info.params {
			hasStrData = hasStrData || prm.IsStr
		}
	}

	var argStr, retStr string
	var notFound bool

	if hasStrData {
		b := ptr2bytes(unsafe.Pointer(strData), int(unsafe.Sizeof(*strData)))
		err := strs.LookupAndDelete(event.SessID, b)
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("failed to lookup str data: %w", err)
		}

		if err == nil {
			argStr, retStr = strData.arg(), strData.ret()
		} else {
			retStr = fmt.Sprintf("%#16x", uint64(event.Func.Retval[0]))
			notFound = true
		}
	}

	fmt.Fprintf(sb, "=(")

	params := info.proto.Type.(*btf.FuncProto).Params
	lastIdx, idx := len(params)-1, 0
	strUsed := false
	for i, fnParam := range info.params {
		if fnParam.partOfPrevParam {
			continue
		}

		if idx != 0 {
			fmt.Fprint(sb, ", ")
		}

		arg := event.Func.Args[i]

		if strUsed {
			argStr = ""
		}
		strUsed = strUsed || fnParam.IsStr
		if fnParam.IsStr && notFound {
			argStr = fmt.Sprintf("%#16x", arg[0])
		}

		valNext := arg[0]
		if i < lastIdx {
			valNext = event.Func.Args[i+1][0]
		}

		fp := btfx.ReprFuncParam(&params[idx], i, fnParam.IsStr, fnParam.IsNumberPtr, arg[0], arg[1], valNext, argStr, f)
		if !noColorOutput {
			funcParamColors[i].Fprint(sb, fp)
		} else {
			fmt.Fprintf(sb, "%s", fp)
		}

		idx++
	}
	fmt.Fprintf(sb, ")")

	if mode == TracingModeExit && !info.isTp {
		outputFnRetval(sb, retStr, info, event, f)
	}

	return nil
}
