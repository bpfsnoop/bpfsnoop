// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/fatih/color"

	"github.com/bpfsnoop/bpfsnoop/internal/btfx"
	"github.com/bpfsnoop/bpfsnoop/internal/strx"
)

const (
	maxOutputArgCnt = 4
	maxOutputStrLen = 32
)

type ArgData struct {
	Args [maxOutputArgCnt][2]uint64
	Str  [maxOutputStrLen]byte
}

func (a *ArgData) str() string {
	return strx.NullTerminated(a.Str[:])
}

func (a *ArgData) repr(sb *strings.Builder, args []funcArgumentOutput, f btfx.FindSymbol) {
	idx := 0
	str := a.str()
	for i, arg := range args {
		if i != 0 {
			fmt.Fprint(sb, ", ")
		}

		data := a.Args[idx]
		s := btfx.ReprExprType(arg.expr, arg.t, arg.mem, arg.isStr, arg.isNumPtr, data[0], data[1], 0, str, f)
		if !noColorOutput {
			color.RGB(0x88, 0x88, 0x88 /* gray */).Fprint(sb, s)
		} else {
			fmt.Fprint(sb, s)
		}

		if !arg.isStr {
			idx++
		}
	}
	fmt.Fprintln(sb)
}

func outputFuncArgAttrs(sb *strings.Builder, info *funcInfo, argData *ArgData, args *ebpf.Map, event *Event, f btfx.FindSymbol) error {
	if len(info.args) == 0 {
		return nil
	}

	b := ptr2bytes(unsafe.Pointer(argData), int(unsafe.Sizeof(*argData)))
	err := args.LookupAndDelete(event.SessID, b)
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf("failed to lookup arg data: %w", err)
	}

	fmt.Fprint(sb, "Arg attrs: ")
	argData.repr(sb, info.args, f)

	return nil
}
