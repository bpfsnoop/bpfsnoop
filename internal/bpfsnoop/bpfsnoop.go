// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/fatih/color"

	"github.com/bpfsnoop/bpfsnoop/internal/strx"
)

const (
	MAX_STACK_DEPTH = 50
)

type Event struct {
	SessID  uint64
	FuncIP  uintptr
	CPU     uint32
	Pid     uint32
	Comm    [16]byte
	StackID int64
	Func    FnData
}

func ptr2bytes(p unsafe.Pointer, size int) []byte {
	return unsafe.Slice((*byte)(p), size)
}

type Helpers struct {
	Progs     *bpfProgs
	Addr2line *Addr2Line
	Ksyms     *Kallsyms
	Kfuncs    KFuncs
}

func Run(reader *ringbuf.Reader, helpers *Helpers, maps map[string]*ebpf.Map, w io.Writer) error {
	lbrStack := newLBRStack()
	fnStack := newFnStack()

	stacks := maps["bpfsnoop_stacks"]
	lbrs := maps["bpfsnoop_lbrs"]
	strs := maps["bpfsnoop_strs"]
	pkts := maps["bpfsnoop_pkts"]
	args := maps["bpfsnoop_args"]

	var lbrData LbrData
	var strData StrData
	var pktData PktData
	var argData ArgData

	fg := NewFlameGraph()
	defer fg.Save(outputFlameGraph)

	findSymbol := func(addr uint64) string {
		if prog, ok := helpers.Progs.funcs[uintptr(addr)]; ok {
			return prog.funcName + "[bpf]"
		}

		return helpers.Ksyms.findSymbol(addr)
	}

	var sb strings.Builder

	var record ringbuf.Record
	record.RawSample = make([]byte, int(unsafe.Sizeof(Event{})))

	unlimited := limitEvents == 0
	for i := int64(limitEvents); unlimited || i > 0; i-- {
		err := reader.ReadInto(&record)
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}

			return fmt.Errorf("failed to read ringbuf: %w", err)
		}

		if len(record.RawSample) < int(unsafe.Sizeof(Event{}))-int(unsafe.Sizeof(FnData{})) {
			continue
		}

		event := (*Event)(unsafe.Pointer(&record.RawSample[0]))
		fnInfo := getFuncInfo(event, helpers)

		if !noColorOutput {
			color.New(color.FgYellow, color.Bold).Fprint(&sb, fnInfo.name, " ")
			color.New(color.FgBlue).Fprintf(&sb, "args")
		} else {
			fmt.Fprint(&sb, fnInfo.name, " args")
		}

		err = outputFnArgs(&sb, fnInfo, helpers, &strData, strs, event, findSymbol)
		if err != nil {
			return fmt.Errorf("failed to output function data: %w", err)
		}

		if !noColorOutput {
			color.New(color.FgCyan).Fprintf(&sb, " cpu=%d", event.CPU)
			color.New(color.FgMagenta).Fprintf(&sb, " process=(%d:%s)", event.Pid, strx.NullTerminated(event.Comm[:]))
		} else {
			fmt.Fprintf(&sb, " cpu=%d process=(%d:%s)", event.CPU, event.Pid, strx.NullTerminated(event.Comm[:]))
		}
		fmt.Fprintln(&sb)

		err = outputPktTuple(&sb, fnInfo, &pktData, pkts, event)
		if err != nil {
			return fmt.Errorf("failed to output packet tuple: %w", err)
		}

		err = outputFuncArgAttrs(&sb, fnInfo, &argData, args, event, findSymbol)
		if err != nil {
			return fmt.Errorf("failed to output function arguments: %w", err)
		}

		err = lbrStack.outputStack(&sb, helpers, &lbrData, lbrs, event)
		if err != nil {
			return fmt.Errorf("failed to output LBR stack: %w", err)
		}

		err = fnStack.output(&sb, helpers, stacks, fg, event)
		if err != nil {
			return fmt.Errorf("failed to output function stack: %w", err)
		}

		fmt.Fprintln(w, sb.String())

		sb.Reset()
		lbrStack.reset()
		fnStack.reset()
	}

	return ErrFinished
}
