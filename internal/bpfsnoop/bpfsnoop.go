// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
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
	Type             uint16
	Length           uint16
	KernNs           uint32
	SessID           uint64
	FuncIP           uintptr
	CPU              uint32
	Pid              uint32
	Comm             [16]byte
	LBRRetval        int64
	TraceeFlags      uint32
	TraceeArgEntrySz uint32
	TraceeArgExitSz  uint32
	TraceeArgDataSz  uint32
	StackSize        int32
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
	KfnsMulti []kfuncInfoMulti
}

// parsedOutputEvent owns its data after the ring-buffer record is released.
type parsedOutputEvent struct {
	event     *Event
	insn      *InsnEvent
	graph     *GraphEvent
	function  string
	details   string
	timestamp time.Time
	derived   *Session
}

// outputEventHandler decodes CLI records concurrently and handles output serially.
type outputEventHandler struct {
	helpers  *Helpers
	output   io.Writer
	lbrs     *ebpf.Map
	sessions *Sessions
	runDelta time.Duration
	flame    *FlameGraph
	hist     *histogram
	tdigest  *TDigest
}

func NewOutputEventHandler(maps map[string]*ebpf.Map, w io.Writer, helpers *Helpers) *outputEventHandler {
	debugLogIf(runDurationThreshold > 0, "Run duration threshold: %s", runDurationThreshold)
	return &outputEventHandler{
		helpers:  helpers,
		output:   w,
		lbrs:     maps["bpfsnoop_lbrs"],
		sessions: NewSessions(),
		runDelta: runDurationThreshold,
		flame:    NewFlameGraph(),
		hist:     newHistogram(helpers.Flags.histExpr),
		tdigest:  newTDigest(helpers.Flags.tdigestExpr),
	}
}

// parse copies fixed headers by value and formats borrowed payloads into owned
// strings. Neither the returned event nor its aggregates reference the sample.
func (h *outputEventHandler) parse(data []byte) (*parsedOutputEvent, error) {
	helpers, lbrs := h.helpers, h.lbrs
	if len(data) < 2 {
		return nil, nil
	}

	parsed := &parsedOutputEvent{timestamp: time.Now()}
	var sb strings.Builder

	typ := *(*uint16)(unsafe.Pointer(&data[0]))
	if typ == eventTypeInsn {
		if len(data) < sizeOfInsnEvent {
			return nil, fmt.Errorf("truncated instruction event")
		}

		parsed.insn = (*InsnEvent)(unsafe.Pointer(&slices.Clone(data[:sizeOfInsnEvent])[0]))
		return parsed, nil
	}

	if typ == eventTypeGraphEntry || typ == eventTypeGraphExit {
		if len(data) < sizeOfGraphEvent {
			return nil, fmt.Errorf("truncated function graph event")
		}

		parsed.graph = (*GraphEvent)(unsafe.Pointer(&slices.Clone(data[:sizeOfGraphEvent])[0]))
		event := parsed.graph
		graph, ok := helpers.Graphs[event.FuncIP]
		if !ok {
			return nil, nil
		}

		isExit := typ == eventTypeGraphExit
		fnInfo := getFuncInfo(uintptr(event.FuncIP), helpers, graph, 0)
		argSize := getArgSize(graph.ArgsEnSz, graph.ArgsExSz, isExit)
		if argSize > len(data)-sizeOfGraphEvent {
			return nil, fmt.Errorf("truncated function graph arguments")
		}

		data := data[sizeOfGraphEvent:]
		outputFuncInfo(&sb, fnInfo, helpers, graph.ArgsEnSz, graph.ArgsExSz, isExit, false, false, data)
		parsed.function = sb.String()
		return parsed, nil
	}

	if len(data) < sizeOfEvent {
		return nil, nil
	}

	parsed.event = (*Event)(unsafe.Pointer(&slices.Clone(data[:sizeOfEvent])[0]))
	event := parsed.event
	if event.Type != eventTypeFuncEntry && event.Type != eventTypeFuncExit {
		return nil, nil
	}

	fnInfo := getFuncInfo(event.FuncIP, helpers, nil, event.TraceeFlags)
	data = data[sizeOfEvent:]

	entrySz, exitSz, isExit := event.TraceeArgEntrySz, event.TraceeArgExitSz, event.Type == eventTypeFuncExit
	if getArgSize(int(entrySz), int(exitSz), isExit) > len(data) {
		return nil, fmt.Errorf("truncated function arguments")
	}

	data = outputFuncInfo(&sb, fnInfo, helpers, int(entrySz), int(exitSz), isExit,
		haveFlag(event.TraceeFlags, traceeFlagIsTp), haveFlag(event.TraceeFlags, traceeFlagKmultiMode), data)
	parsed.function = sb.String()

	sb.Reset()
	// Keep aggregates local until the consumer applies session filters.
	if event.TraceeArgDataSz != 0 || (outputFlameGraph != "" && haveFlag(event.TraceeFlags, traceeFlagOutputStack) && event.StackSize >= 0) {
		parsed.derived = &Session{}
		parsed.derived.deferDerived(helpers.Flags.histExpr, helpers.Flags.tdigestExpr)
	}

	if argDataSz := int(event.TraceeArgDataSz); argDataSz != 0 {
		f := findSymbolHelper(uint64(event.FuncIP), helpers)
		if argDataSz > len(data) {
			return nil, fmt.Errorf("truncated selected arguments")
		}

		outputHist, outputTDigest := parsed.derived.hist, parsed.derived.tdigest
		err := outputFuncArgAttrs(&sb, fnInfo.args, data[:argDataSz], isExit, outputHist, outputTDigest, f)
		if err != nil {
			return nil, fmt.Errorf("failed to output function arg attrs: %w", err)
		}

		data = data[argDataSz:]
	}

	if haveFlag(event.TraceeFlags, traceeFlagOutputPkt) {
		if len(data) < sizeOfPktData {
			return nil, fmt.Errorf("truncated packet tuple")
		}

		outputPktTuple(&sb, fnInfo, data[:sizeOfPktData], event)
		data = data[sizeOfPktData:]
	}

	if haveFlag(event.TraceeFlags, traceeFlagOutputStack) && event.StackSize >= 0 {
		var outputFlame *FlameGraph
		if parsed.derived != nil {
			outputFlame = parsed.derived.flame
		}
		err := newFnStack().output(&sb, helpers, data, int(event.StackSize), outputFlame, event)
		if err != nil {
			return nil, fmt.Errorf("failed to output function stack: %w", err)
		}
	}

	if haveFlag(event.TraceeFlags, traceeFlagOutputLbr) && event.LBRRetval > 0 {
		var lbrData LbrData
		err := newLBRStack().outputStack(&sb, helpers, &lbrData, lbrs, event)
		if err != nil {
			return nil, fmt.Errorf("failed to output LBR stack: %w", err)
		}
	}

	parsed.details = sb.String()
	return parsed, nil
}

func (h *outputEventHandler) handle(parsed *parsedOutputEvent) (bool, error) {
	helpers, sessions := h.helpers, h.sessions
	runDelta, fgraphMaxDepth := h.runDelta, h.helpers.Flags.fgraphDepth
	hist, tdigest, fg := h.hist, h.tdigest, h.flame
	w := h.output

	var sb strings.Builder
	if parsed.insn != nil {
		outputInsnEvent(&sb, sessions, helpers.Insns, parsed.insn)
		return false, nil
	}

	if parsed.graph != nil {
		outputGraphEvent(&sb, sessions, helpers.Graphs, parsed.graph, parsed.function, parsed.graph.Type == eventTypeGraphEntry)
		return false, nil
	}

	var (
		event    = parsed.event
		sess     *Session
		duration time.Duration
	)

	isTp := haveFlag(event.TraceeFlags, traceeFlagIsTp)
	isGraph := haveFlag(event.TraceeFlags, traceeFlagGraphMode)
	requiredSession := haveFlag(event.TraceeFlags, traceeFlagInsnMode) ||
		(isGraph && !isTp) ||
		(haveFlag(event.TraceeFlags, traceeFlagBothMode) && !isTp) ||
		haveFlag(event.TraceeFlags, traceeFlagSession)
	if requiredSession {
		if event.Type == eventTypeFuncEntry {
			sess = sessions.Add(event.SessID, event.KernNs, fgraphMaxDepth, isGraph)
			if haveFlag(event.TraceeFlags, traceeFlagExitFilter) {
				sess.deferDerived(helpers.Flags.histExpr, helpers.Flags.tdigestExpr)
			}
		} else {
			s, ok := sessions.GetAndDel(event.SessID + 1)
			if ok {
				sess = s
				duration = time.Duration(event.KernNs - s.started)
				if duration < runDelta {
					return false, nil
				}
				if s.deferred && !haveFlag(event.TraceeFlags, traceeFlagExitFilter) {
					return false, nil
				}
			} else {
				return false, nil // skip if session not found
			}
		}
	}

	sb.WriteString(parsed.function)
	haveRetval := event.Type == eventTypeFuncExit
	if colorfulOutput {
		color.New(color.FgCyan).Fprintf(&sb, " cpu=%d", event.CPU)
		color.New(color.FgMagenta).Fprintf(&sb, " process=(%d:%s)", event.Pid, strx.NullTerminated(event.Comm[:]))
		if requiredSession && haveRetval {
			color.RGB(0xFF, 0x00, 0x7F /* rose red */).Fprintf(&sb, " duration=%s", duration)
		}
		color.RGB(0x90, 0xEE, 0x90 /* light green */).Fprintf(&sb, " timestamp=%s", parsed.timestamp.Format("15:04:05.999999999"))
	} else {
		fmt.Fprintf(&sb, " cpu=%d process=(%d:%s)", event.CPU, event.Pid, strx.NullTerminated(event.Comm[:]))
		if requiredSession && haveRetval {
			fmt.Fprintf(&sb, " duration=%s", duration)
		}
		fmt.Fprintf(&sb, " timestamp=%s", parsed.timestamp.Format("15:04:05.999999999"))
	}
	fmt.Fprintln(&sb)

	sb.WriteString(parsed.details)
	if parsed.derived != nil {
		if sess != nil && sess.deferred {
			parsed.derived.commitDerived(sess.hist, sess.tdigest, sess.flame)
		} else {
			parsed.derived.commitDerived(hist, tdigest, fg)
		}
	}

	outputEvent := false
	if sess != nil {
		sess.outputs = append(sess.outputs, sb.String())
		if haveRetval {
			sess.commitDerived(hist, tdigest, fg)
			for _, output := range sess.outputs {
				fmt.Fprint(w, output)
			}
			fmt.Fprintln(w)
			outputEvent = true
		}
	} else {
		fmt.Fprintln(w, sb.String())
		outputEvent = true
	}

	return outputEvent, nil
}

func (h *outputEventHandler) cleanup() {
	h.tdigest.render(h.output)
	h.hist.render(h.output)
	h.flame.Save(outputFlameGraph)
}
