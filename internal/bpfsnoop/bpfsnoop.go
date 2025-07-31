// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/fatih/color"

	"github.com/bpfsnoop/bpfsnoop/internal/strx"
)

const (
	sizeOfEvent = int(unsafe.Sizeof(Event{}))
)

const (
	eventTypeUnspec uint16 = iota
	eventTypeFuncEntry
	eventTypeFuncExit
	eventTypeInsn
	eventTypeGraphEntry
	eventTypeGraphExit
)

type Event struct {
	Type    uint16
	Length  uint16
	KernNs  uint32
	SessID  uint64
	FuncIP  uintptr
	CPU     uint32
	Pid     uint32
	Comm    [16]byte
	StackID int64
}

func ptr2bytes(p unsafe.Pointer, size int) []byte {
	return unsafe.Slice((*byte)(p), size)
}

type Helpers struct {
	Flags     *Flags
	Progs     *bpfProgs
	Addr2line *Addr2Line
	Ksyms     *Kallsyms
	Kfuncs    KFuncs
	Insns     FuncInsns
	Graphs    FuncGraphs
}

func Run(reader *ringbuf.Reader, maps map[string]*ebpf.Map, w io.Writer, helpers *Helpers) error {
	lbrStack := newLBRStack()
	fnStack := newFnStack()
	sessions := NewSessions()

	stacks := maps["bpfsnoop_stacks"]
	lbrs := maps["bpfsnoop_lbrs"]

	runDelta := runDurationThreshold
	debugLogIf(runDelta > 0, "Run duration threshold: %s", runDelta)

	var lbrData LbrData

	fg := NewFlameGraph()
	defer fg.Save(outputFlameGraph)

	hist := newHistogram(helpers.Flags.histExpr)
	defer hist.render(w)

	tdigest := newTDigest(helpers.Flags.tdigestExpr)
	defer tdigest.render(w)

	var sb strings.Builder

	var record ringbuf.Record
	record.RawSample = make([]byte, 4096)

	fgraphMaxDepth := helpers.Flags.fgraphDepth
	unlimited := limitEvents == 0
	for i := int64(limitEvents); unlimited || i > 0; {
		err := reader.ReadInto(&record)
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}

			return fmt.Errorf("failed to read ringbuf: %w", err)
		}

		currts := time.Now()

		typ := *(*uint16)(unsafe.Pointer(&record.RawSample[0]))
		if typ == eventTypeInsn {
			event := (*InsnEvent)(unsafe.Pointer(&record.RawSample[0]))
			outputInsnEvent(&sb, sessions, helpers.Insns, event)
			sb.Reset()
			continue
		}

		if typ == eventTypeGraphEntry || typ == eventTypeGraphExit {
			event := (*GraphEvent)(unsafe.Pointer(&record.RawSample[0]))
			graph, ok := helpers.Graphs[event.FuncIP]
			if !ok {
				continue
			}

			isExit := typ == eventTypeGraphExit
			fnInfo := getFuncInfo(uintptr(event.FuncIP), helpers, graph)
			data := record.RawSample[sizeOfGraphEvent : sizeOfGraphEvent+int(event.Length)]
			outputFuncInfo(&sb, fnInfo, helpers, graph.ArgsEnSz, graph.ArgsExSz, isExit, true, data)
			s := sb.String()
			sb.Reset()

			outputGraphEvent(&sb, sessions, helpers.Graphs, event, s, !isExit)
			sb.Reset()
			continue
		}

		if len(record.RawSample) < sizeOfEvent {
			continue
		}

		event := (*Event)(unsafe.Pointer(&record.RawSample[0]))
		fnInfo := getFuncInfo(event.FuncIP, helpers, nil)
		data := record.RawSample[sizeOfEvent:]

		var sess *Session
		var duration time.Duration
		requiredSession := fnInfo.insnMode || fnInfo.grphMode || (fnInfo.bothMode && !fnInfo.isTp)
		if requiredSession {
			if event.Type == eventTypeFuncEntry {
				sess = sessions.Add(event.SessID, event.KernNs, fgraphMaxDepth, fnInfo.grphMode)
			} else {
				s, ok := sessions.GetAndDel(event.SessID + 1)
				if ok {
					sess = s
					duration = time.Duration(event.KernNs - s.started)
					if duration < runDelta {
						continue
					}
				} else {
					continue // skip if session not found
				}
			}
		}

		data = outputFuncInfo(&sb, fnInfo, helpers, fnInfo.argEntry, fnInfo.argExit, event.Type == eventTypeFuncExit, false, data)

		haveRetval := event.Type == eventTypeFuncExit
		if colorfulOutput {
			color.New(color.FgCyan).Fprintf(&sb, " cpu=%d", event.CPU)
			color.New(color.FgMagenta).Fprintf(&sb, " process=(%d:%s)", event.Pid, strx.NullTerminated(event.Comm[:]))
			if requiredSession && haveRetval {
				color.RGB(0xFF, 0x00, 0x7F /* rose red */).Fprintf(&sb, " duration=%s", duration)
			}
			color.RGB(0x90, 0xEE, 0x90 /* light green */).Fprintf(&sb, " timestamp=%s", currts.Format("15:04:05.999999999"))
		} else {
			fmt.Fprintf(&sb, " cpu=%d process=(%d:%s)", event.CPU, event.Pid, strx.NullTerminated(event.Comm[:]))
			if requiredSession && haveRetval {
				fmt.Fprintf(&sb, " duration=%s", duration)
			}
			fmt.Fprintf(&sb, " timestamp=%s", currts.Format("15:04:05.999999999"))
		}
		fmt.Fprintln(&sb)

		if fnInfo.pktTuple {
			outputPktTuple(&sb, fnInfo, data[:sizeOfPktData], event)
			data = data[sizeOfPktData:]
		}

		if fnInfo.argData != 0 {
			f := findSymbolHelper(uint64(event.FuncIP), helpers)
			err := outputFuncArgAttrs(&sb, fnInfo, data[:fnInfo.argData], hist, tdigest, f)
			if err != nil {
				return fmt.Errorf("failed to output function arg attrs: %w", err)
			}

			data = data[fnInfo.argData:]
		}

		if fnInfo.lbrMode {
			err = lbrStack.outputStack(&sb, helpers, &lbrData, lbrs, event)
			if err != nil {
				return fmt.Errorf("failed to output LBR stack: %w", err)
			}
		}

		if fnInfo.stckMode && event.StackID >= 0 {
			err = fnStack.output(&sb, helpers, stacks, fg, event)
			if err != nil {
				return fmt.Errorf("failed to output function stack: %w", err)
			}
		}

		if sess != nil {
			sess.outputs = append(sess.outputs, sb.String())
			if haveRetval {
				for _, output := range sess.outputs {
					fmt.Fprint(w, output)
				}
				fmt.Fprintln(w)
				i--
			}
		} else {
			fmt.Fprintln(w, sb.String())
			i--
		}

		sb.Reset()
		lbrStack.reset()
		fnStack.reset()
	}

	return ErrFinished
}
