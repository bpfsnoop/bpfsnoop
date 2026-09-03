// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"

	"github.com/bpfsnoop/bpfsnoop/internal/btfx"
	"github.com/bpfsnoop/bpfsnoop/internal/strx"
)

type traceStreamCapture struct {
	arguments         bool
	retval            bool
	duration          bool
	kernelStack       bool
	selectedArguments bool
	packet            bool
	flameGraph        bool
	functionGraph     bool
	instructions      bool
}

// TraceValue is one decoded typed value.
type TraceValue struct {
	Type  string
	Value any
}

// TraceArgument is one decoded function argument.
type TraceArgument struct {
	Name  string
	Type  string
	Value any
}

// TraceSelectedArgument is one decoded argument expression.
type TraceSelectedArgument struct {
	Expression string
	Type       string
	Value      any
}

// TracePacket is one decoded packet tuple.
type TracePacket struct {
	SourceAddress      string
	DestinationAddress string
	Protocol           string
	SourcePort         uint16
	DestinationPort    uint16
	TCPFlags           string
}

// TraceFunctionGraphEvent is one decoded child function event.
type TraceFunctionGraphEvent struct {
	Target     TraceTarget
	Phase      string
	CPU        uint32
	Depth      uint32
	DurationNS uint64
	Arguments  []TraceArgument
	Retval     *TraceValue
}

// TraceInstructionEvent is one executed native instruction.
type TraceInstructionEvent struct {
	Function    string
	Address     string
	OffsetBytes uint64
	Bytes       string
	Mnemonic    string
	Operands    string
	CPU         uint32
	DurationNS  uint64
}

// TraceStackFrame is one resolved kernel stack frame.
type TraceStackFrame struct {
	Address     string
	Function    string
	OffsetBytes uint64
	Module      string
	File        string
	Line        uint32
}

// TraceEvent is one decoded top-level function event.
type TraceEvent struct {
	TimestampUnixNS   string
	CPU               uint32
	PID               uint32
	Comm              string
	Target            TraceTarget
	Phase             string
	Arguments         []TraceArgument
	SelectedArguments []TraceSelectedArgument
	Retval            *TraceValue
	DurationNS        *uint64
	Packet            *TracePacket
	KernelStack       []TraceStackFrame
	FunctionGraph     []TraceFunctionGraphEvent
	Instructions      []TraceInstructionEvent
}

func decodeTraceRegister(typ btf.Type, data []byte) any {
	size, err := btf.Sizeof(typ)
	if err == nil && size > 0 && size <= len(data) {
		value, decodeErr := btfx.DecodeValue(typ, data[:size])
		if decodeErr == nil {
			return value
		}
	}
	return map[string]any{"raw_hex": hex.EncodeToString(data)}
}

func decodeTraceParam(typ btf.Type, flags FuncParamFlags, data []byte) (any, int, error) {
	if flags.IsStr {
		if len(data) < maxOutputStrLen {
			return nil, 0, fmt.Errorf("string argument is truncated: got %d bytes", len(data))
		}
		return strings.Clone(strx.NullTerminated(data[:maxOutputStrLen])), maxOutputStrLen, nil
	}

	need := 8
	if flags.IsNumberPtr {
		need += 8
	}
	if len(data) < need {
		return nil, 0, fmt.Errorf("argument is truncated: got %d bytes, need %d", len(data), need)
	}
	if !flags.IsNumberPtr {
		return decodeTraceRegister(typ, data[:8]), 8, nil
	}

	pointer, ok := mybtf.UnderlyingType(typ).(*btf.Pointer)
	if !ok {
		return decodeTraceRegister(typ, data[:8]), need, nil
	}
	address := decodeTraceRegister(typ, data[:8])
	value := decodeTraceRegister(pointer.Target, data[8:16])
	return map[string]any{"address": address, "value": value}, need, nil
}

func decodeTraceFunctionValues(info *funcInfo, data []byte, withRetval bool) ([]TraceArgument, *TraceValue, error) {
	if info.proto == nil {
		return nil, nil, nil
	}
	proto, ok := info.proto.Type.(*btf.FuncProto)
	if !ok {
		return nil, nil, fmt.Errorf("function %s has invalid BTF prototype", info.name)
	}

	arguments := make([]TraceArgument, 0, len(proto.Params))
	paramIndex := 0
	offset := 0
	for _, flags := range info.params {
		if flags.partOfPrevParam {
			continue
		}
		if paramIndex >= len(proto.Params) {
			return nil, nil, fmt.Errorf("function %s argument metadata is inconsistent", info.name)
		}
		param := proto.Params[paramIndex]
		value, consumed, err := decodeTraceParam(param.Type, flags, data[offset:])
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode argument %d of %s: %w", paramIndex, info.name, err)
		}
		name := param.Name
		if name == "" {
			name = fmt.Sprintf("$arg%d", paramIndex)
		}
		arguments = append(arguments, TraceArgument{Name: name, Type: btfx.Repr(param.Type), Value: value})
		offset += consumed
		paramIndex++
	}

	if !withRetval {
		return arguments, nil, nil
	}
	if _, isVoid := mybtf.UnderlyingType(proto.Return).(*btf.Void); isVoid {
		return arguments, &TraceValue{Type: "void", Value: nil}, nil
	}
	value, _, err := decodeTraceParam(proto.Return, info.retParam, data[offset:])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode return value of %s: %w", info.name, err)
	}
	return arguments, &TraceValue{Type: btfx.Repr(proto.Return), Value: value}, nil
}

func decodeTraceKprobeMultiValues(info *funcInfo, data []byte, withRetval bool) ([]TraceArgument, *TraceValue, error) {
	if info.proto == nil {
		return nil, nil, nil
	}
	proto, ok := info.proto.Type.(*btf.FuncProto)
	if !ok {
		return nil, nil, fmt.Errorf("function %s has invalid BTF prototype", info.name)
	}

	count := min(len(proto.Params), maxArgsKmulti)
	need := maxArgsKmulti * 8
	if withRetval {
		need += 8
	}
	if len(data) < need {
		return nil, nil, fmt.Errorf("kprobe.multi event for %s is truncated: got %d bytes, need %d", info.name, len(data), need)
	}
	arguments := make([]TraceArgument, 0, count)
	for i, param := range proto.Params[:count] {
		name := param.Name
		if name == "" {
			name = fmt.Sprintf("$arg%d", i)
		}
		arguments = append(arguments, TraceArgument{
			Name:  name,
			Type:  btfx.Repr(param.Type),
			Value: decodeTraceRegister(param.Type, data[i*8:(i+1)*8]),
		})
	}
	if !withRetval {
		return arguments, nil, nil
	}
	if _, isVoid := mybtf.UnderlyingType(proto.Return).(*btf.Void); isVoid {
		return arguments, &TraceValue{Type: "void", Value: nil}, nil
	}
	return arguments, &TraceValue{
		Type:  btfx.Repr(proto.Return),
		Value: decodeTraceRegister(proto.Return, data[maxArgsKmulti*8:(maxArgsKmulti+1)*8]),
	}, nil
}

func traceStackFrames(event *Event, helpers *Helpers, stacks *ebpf.Map) ([]TraceStackFrame, error) {
	if event.StackID < 0 {
		return nil, nil
	}
	ips := make([]uint64, kernelPerfEventMaxStack)
	id := uint32(event.StackID)
	if err := stacks.Lookup(id, &ips); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read kernel stack: %w", err)
	}
	_ = stacks.Delete(id)

	frames := make([]TraceStackFrame, 0, len(ips))
	for _, ip := range ips {
		if ip == 0 {
			continue
		}
		line := getLineInfo(uintptr(ip), helpers.Progs, helpers.Addr2line, helpers.Ksyms)
		if strings.HasPrefix(line.funcName, "bpf_trampoline_") || strings.HasPrefix(line.funcName, "bpf_trace_run") {
			continue
		}
		if strings.Contains(line.funcName, "_bpfsnoop_fn") {
			continue
		}
		frame := TraceStackFrame{
			Address:     fmt.Sprintf("%#x", ip),
			Function:    line.funcName,
			OffsetBytes: uint64(line.offset),
			File:        line.fileName,
			Line:        line.fileLine,
		}
		if symbol, ok := helpers.Ksyms.find(uintptr(ip)); ok {
			frame.Module = symbol.mod
		}
		frames = append(frames, frame)
	}
	return frames, nil
}

type pendingTraceEvent struct {
	arguments     []TraceArgument
	kernNS        uint32
	functionGraph []TraceFunctionGraphEvent
	instructions  []TraceInstructionEvent
}

func traceTarget(info *funcInfo, flags uint32) TraceTarget {
	target := TraceTarget{Kind: TraceTargetFunction, Name: info.name}
	switch {
	case haveFlag(flags, traceeFlagIsProg):
		target.Kind = TraceTargetBPFProgram
		target.Name = strings.TrimSuffix(info.name, "[bpf]")
		target.ID = info.progID
	case haveFlag(flags, traceeFlagIsTp):
		target.Kind = TraceTargetTracepoint
		target.Name = strings.TrimSuffix(info.name, "[tp]")
	}
	return target
}

func decodeTracePacket(data []byte) (*TracePacket, error) {
	if len(data) < sizeOfPktData {
		return nil, fmt.Errorf("packet tuple is truncated: got %d bytes, need %d", len(data), sizeOfPktData)
	}
	pkt := (*PktData)(unsafe.Pointer(&data[0]))
	if pkt.zero() {
		return nil, nil
	}
	result := &TracePacket{
		SourceAddress:      pkt.saddr().String(),
		DestinationAddress: pkt.daddr().String(),
	}
	switch pkt.Proto {
	case 6:
		result.Protocol = "tcp"
		result.SourcePort = pkt.sport()
		result.DestinationPort = pkt.dport()
		result.TCPFlags = pkt.tcpFlags()
	case 17:
		result.Protocol = "udp"
		result.SourcePort = pkt.sport()
		result.DestinationPort = pkt.dport()
	case 1:
		result.Protocol = "icmp"
	default:
		result.Protocol = fmt.Sprintf("ip_%d", pkt.Proto)
	}
	return result, nil
}

func decodeTraceSelectedArguments(info *funcInfo, data []byte) ([]TraceSelectedArgument, error) {
	selected := make([]TraceSelectedArgument, 0, len(info.args))
	offset := 0
	for i := range info.args {
		arg := &info.args[i]
		if arg.size <= 0 || offset+arg.size > len(data) {
			return nil, fmt.Errorf("selected argument %q is truncated", arg.expr)
		}
		value, err := kernelReadValue(arg, data[offset:offset+arg.size])
		if err != nil {
			return nil, fmt.Errorf("failed to decode selected argument %q: %w", arg.expr, err)
		}
		selected = append(selected, TraceSelectedArgument{
			Expression: arg.expr,
			Type:       btfx.Repr(arg.t),
			Value:      value,
		})
		offset += arg.size
	}
	return selected, nil
}

func makeTraceEvent(raw *Event, info *funcInfo, capture traceStreamCapture, arguments []TraceArgument, retval *TraceValue, duration *uint64, stack []TraceStackFrame) TraceEvent {
	phase := TracingModeEntry
	if raw.Type == eventTypeFuncExit {
		phase = TracingModeExit
	}
	event := TraceEvent{
		TimestampUnixNS: fmt.Sprintf("%d", time.Now().UnixNano()),
		CPU:             raw.CPU,
		PID:             raw.Pid,
		Comm:            strings.Clone(strx.NullTerminated(raw.Comm[:])),
		Target:          traceTarget(info, raw.TraceeFlags),
		Phase:           phase,
	}
	if capture.arguments {
		event.Arguments = arguments
	}
	if capture.retval {
		event.Retval = retval
	}
	if capture.duration {
		event.DurationNS = duration
	}
	if capture.kernelStack || capture.flameGraph {
		event.KernelStack = stack
	}
	return event
}

func NewTraceEventHandler(maps map[string]*ebpf.Map, helpers *Helpers, capture traceStreamCapture, output func(TraceEvent) error) EventHandler {
	pending := make(map[uint64]pendingTraceEvent)
	stacks := maps["bpfsnoop_stacks"]
	return func(data []byte) (bool, error) {
		if len(data) < 2 {
			return false, nil
		}
		typ := *(*uint16)(unsafe.Pointer(&data[0]))
		if typ == eventTypeInsn {
			if !capture.instructions || len(data) < int(unsafe.Sizeof(InsnEvent{})) {
				return false, nil
			}
			raw := (*InsnEvent)(unsafe.Pointer(&data[0]))
			entry, ok := pending[raw.SessID]
			insn, found := helpers.Insns[raw.InsnIP]
			if !ok || !found {
				return false, nil
			}
			entry.instructions = append(entry.instructions, TraceInstructionEvent{
				Function: insn.Func, Address: fmt.Sprintf("%#x", insn.IP), OffsetBytes: insn.Off,
				Bytes: hex.EncodeToString(insn.Insn.Bytes), Mnemonic: insn.Insn.Mnemonic,
				Operands: insn.Insn.OpStr, CPU: raw.CPU, DurationNS: uint64(uint32(raw.KernNs - entry.kernNS)),
			})
			pending[raw.SessID] = entry
			return false, nil
		}
		if typ == eventTypeGraphEntry || typ == eventTypeGraphExit {
			if !capture.functionGraph || len(data) < sizeOfGraphEvent {
				return false, nil
			}
			raw := (*GraphEvent)(unsafe.Pointer(&data[0]))
			entry, ok := pending[raw.SessID]
			graph, found := helpers.Graphs[raw.FuncIP]
			if !ok || !found {
				return false, nil
			}
			info := getFuncInfo(uintptr(raw.FuncIP), helpers, graph, 0)
			isExit := typ == eventTypeGraphExit
			argSize := graph.ArgsEnSz
			if isExit {
				argSize = graph.ArgsExSz
			}
			payload := data[sizeOfGraphEvent:]
			if argSize > len(payload) {
				return false, fmt.Errorf("function graph event for %s is truncated", info.name)
			}
			arguments, retval, err := decodeTraceFunctionValues(info, payload[:argSize], isExit)
			if err != nil {
				return false, err
			}
			phase := TracingModeEntry
			if isExit {
				phase = TracingModeExit
			}
			flags := uint32(0)
			if graph.Bprog != nil {
				flags = traceeFlagIsProg
			}
			entry.functionGraph = append(entry.functionGraph, TraceFunctionGraphEvent{
				Target: traceTarget(info, flags), Phase: phase,
				CPU: raw.CPU, Depth: raw.Depth, DurationNS: uint64(uint32(raw.KernNs - entry.kernNS)),
				Arguments: arguments, Retval: retval,
			})
			pending[raw.SessID] = entry
			return false, nil
		}
		if len(data) < sizeOfEvent {
			return false, nil
		}
		raw := (*Event)(unsafe.Pointer(&data[0]))
		if raw.Type != eventTypeFuncEntry && raw.Type != eventTypeFuncExit {
			return false, nil
		}
		info := getFuncInfo(raw.FuncIP, helpers, nil, raw.TraceeFlags)
		argSize := int(raw.TraceeArgEntrySz)
		if raw.Type == eventTypeFuncExit {
			argSize = int(raw.TraceeArgExitSz)
		}
		payload := data[sizeOfEvent:]
		if argSize < 0 || len(payload) < argSize {
			return false, fmt.Errorf("trace event for %s has truncated argument data", info.name)
		}
		var arguments []TraceArgument
		var retval *TraceValue
		var err error
		if haveFlag(raw.TraceeFlags, traceeFlagKmultiMode) {
			arguments, retval, err = decodeTraceKprobeMultiValues(info, payload[:argSize], raw.Type == eventTypeFuncExit)
		} else {
			arguments, retval, err = decodeTraceFunctionValues(info, payload[:argSize], raw.Type == eventTypeFuncExit)
		}
		if err != nil {
			return false, err
		}
		payload = payload[argSize:]

		var packet *TracePacket
		if haveFlag(raw.TraceeFlags, traceeFlagOutputPkt) {
			packet, err = decodeTracePacket(payload)
			if err != nil {
				return false, err
			}
			payload = payload[sizeOfPktData:]
		}
		var selected []TraceSelectedArgument
		if raw.TraceeArgDataSz != 0 {
			argDataSize := int(raw.TraceeArgDataSz)
			if argDataSize > len(payload) {
				return false, fmt.Errorf("selected argument data for %s is truncated", info.name)
			}
			selected, err = decodeTraceSelectedArguments(info, payload[:argDataSize])
			if err != nil {
				return false, err
			}
		}

		requiredSession := haveFlag(raw.TraceeFlags, traceeFlagBothMode) || haveFlag(raw.TraceeFlags, traceeFlagSession)
		if requiredSession && raw.Type == eventTypeFuncEntry {
			pending[raw.SessID] = pendingTraceEvent{arguments: arguments, kernNS: raw.KernNs}
			return false, nil
		}

		var entry pendingTraceEvent
		var duration *uint64
		if requiredSession {
			var ok bool
			entry, ok = pending[raw.SessID+1]
			if !ok {
				return false, nil
			}
			delete(pending, raw.SessID+1)
			arguments = entry.arguments
			value := uint64(uint32(raw.KernNs - entry.kernNS))
			duration = &value
		}

		var stack []TraceStackFrame
		if capture.kernelStack || capture.flameGraph {
			stack, err = traceStackFrames(raw, helpers, stacks)
			if err != nil {
				return false, err
			}
		}
		event := makeTraceEvent(raw, info, capture, arguments, retval, duration, stack)
		event.SelectedArguments = selected
		event.Packet = packet
		if requiredSession {
			event.FunctionGraph = entry.functionGraph
			event.Instructions = entry.instructions
		}
		if err := output(event); err != nil {
			return false, err
		}
		return true, nil
	}
}
