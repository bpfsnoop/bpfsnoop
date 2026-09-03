// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"

	"github.com/bpfsnoop/bpfsnoop/internal/bpfsnoop"
)

type traceTargetOutput struct {
	Kind string `json:"kind" jsonschema:"target kind: function, tracepoint, or bpf_program"`
	Name string `json:"name" jsonschema:"resolved function, tracepoint, or BPF program name"`
	ID   uint32 `json:"id,omitempty" jsonschema:"loaded BPF program ID"`
}

type traceValueOutput struct {
	Type  string `json:"type" jsonschema:"resolved BTF type"`
	Value any    `json:"value" jsonschema:"decoded value using native JSON types when possible"`
}

type traceArgumentOutput struct {
	Name  string `json:"name" jsonschema:"function parameter name"`
	Type  string `json:"type" jsonschema:"resolved BTF parameter type"`
	Value any    `json:"value" jsonschema:"decoded parameter value"`
}

type traceSelectedArgumentOutput struct {
	Expression string `json:"expression" jsonschema:"requested bpfsnoop C expression"`
	Type       string `json:"type" jsonschema:"resolved BTF expression type"`
	Value      any    `json:"value" jsonschema:"decoded expression value"`
}

type tracePacketOutput struct {
	SourceAddress      string `json:"source_address" jsonschema:"source IP address"`
	DestinationAddress string `json:"destination_address" jsonschema:"destination IP address"`
	Protocol           string `json:"protocol" jsonschema:"transport or IP protocol"`
	SourcePort         uint16 `json:"source_port,omitempty" jsonschema:"source transport port"`
	DestinationPort    uint16 `json:"destination_port,omitempty" jsonschema:"destination transport port"`
	TCPFlags           string `json:"tcp_flags,omitempty" jsonschema:"TCP flags when protocol is tcp"`
}

type traceFunctionGraphEventOutput struct {
	Target     traceTargetOutput     `json:"target" jsonschema:"called function target"`
	Phase      string                `json:"phase" jsonschema:"entry or exit"`
	CPU        uint32                `json:"cpu" jsonschema:"CPU that emitted the graph event"`
	Depth      uint32                `json:"depth" jsonschema:"call depth below the traced function"`
	DurationNS uint64                `json:"duration_ns" jsonschema:"elapsed kernel time from the traced entry"`
	Arguments  []traceArgumentOutput `json:"arguments,omitempty" jsonschema:"typed child function arguments"`
	Retval     *traceValueOutput     `json:"retval,omitempty" jsonschema:"typed child function return value"`
}

type traceInstructionOutput struct {
	Function    string `json:"function" jsonschema:"function containing the instruction"`
	Address     string `json:"address" jsonschema:"exact instruction address"`
	OffsetBytes uint64 `json:"offset_bytes" jsonschema:"instruction offset from the function start"`
	Bytes       string `json:"bytes" jsonschema:"native instruction bytes as hexadecimal"`
	Mnemonic    string `json:"mnemonic" jsonschema:"native instruction mnemonic"`
	Operands    string `json:"operands,omitempty" jsonschema:"architecture-specific operands"`
	CPU         uint32 `json:"cpu" jsonschema:"CPU that executed the instruction"`
	DurationNS  uint64 `json:"duration_ns" jsonschema:"elapsed kernel time from the traced entry"`
}

type traceStackFrameOutput struct {
	Address     string `json:"address" jsonschema:"exact stack instruction address"`
	Function    string `json:"function,omitempty" jsonschema:"resolved function name"`
	OffsetBytes uint64 `json:"offset_bytes,omitempty" jsonschema:"offset from the resolved function"`
	Module      string `json:"module,omitempty" jsonschema:"kernel module containing the frame"`
	File        string `json:"file,omitempty" jsonschema:"source file from debug metadata"`
	Line        uint32 `json:"line,omitempty" jsonschema:"source line from debug metadata"`
}

type traceEventOutput struct {
	TimestampUnixNS   string                          `json:"timestamp_unix_ns" jsonschema:"event timestamp in Unix nanoseconds"`
	CPU               uint32                          `json:"cpu" jsonschema:"CPU that emitted the event"`
	PID               uint32                          `json:"pid" jsonschema:"traced process ID"`
	Comm              string                          `json:"comm" jsonschema:"traced Linux task name"`
	Target            traceTargetOutput               `json:"target" jsonschema:"resolved trace target"`
	Phase             string                          `json:"phase" jsonschema:"entry or exit"`
	Arguments         []traceArgumentOutput           `json:"arguments,omitempty" jsonschema:"typed function arguments"`
	SelectedArguments []traceSelectedArgumentOutput   `json:"selected_arguments,omitempty" jsonschema:"requested expression values"`
	Retval            *traceValueOutput               `json:"retval,omitempty" jsonschema:"typed function return value"`
	DurationNS        *uint64                         `json:"duration_ns,omitempty" jsonschema:"entry-to-exit duration"`
	Packet            *tracePacketOutput              `json:"packet,omitempty" jsonschema:"decoded packet tuple"`
	KernelStack       []traceStackFrameOutput         `json:"kernel_stack,omitempty" jsonschema:"resolved kernel stack frames"`
	FunctionGraph     []traceFunctionGraphEventOutput `json:"function_graph,omitempty" jsonschema:"child function events"`
	Instructions      []traceInstructionOutput        `json:"instructions,omitempty" jsonschema:"executed native instructions"`
}

type traceStatsOutput struct {
	Returned   int   `json:"returned" jsonschema:"number of returned events"`
	DurationMS int64 `json:"duration_ms" jsonschema:"duration after tracing became ready"`
}

type traceFlameGraphEntryOutput struct {
	Stack []string `json:"stack" jsonschema:"root-to-leaf function stack"`
	Count int      `json:"count" jsonschema:"number of matching events"`
}

// TraceOutput contains one bounded structured tracing experiment.
type TraceOutput struct {
	Status     string                       `json:"status" jsonschema:"completed when the bounded experiment ended normally"`
	StoppedBy  string                       `json:"stopped_by" jsonschema:"limit that ended the experiment: duration or max_events"`
	Stats      traceStatsOutput             `json:"stats" jsonschema:"bounded trace statistics"`
	Events     []traceEventOutput           `json:"events" jsonschema:"ordered structured function events"`
	FlameGraph []traceFlameGraphEntryOutput `json:"flame_graph,omitempty" jsonschema:"aggregated root-to-leaf kernel stacks"`
	Truncated  bool                         `json:"truncated" jsonschema:"true when max_events ended the experiment"`
}

func makeTraceTargetOutput(target bpfsnoop.TraceTarget) traceTargetOutput {
	output := traceTargetOutput{Name: target.Name, ID: target.ID}
	switch target.Kind {
	case bpfsnoop.TraceTargetFunction:
		output.Kind = TraceKindFunction
	case bpfsnoop.TraceTargetBPFProgram:
		output.Kind = TraceKindBPFProgram
	case bpfsnoop.TraceTargetTracepoint:
		output.Kind = TraceKindTracepoint
	}
	return output
}

func makeTraceValueOutput(value *bpfsnoop.TraceValue) *traceValueOutput {
	if value == nil {
		return nil
	}
	return &traceValueOutput{Type: value.Type, Value: value.Value}
}

func makeTraceArgumentsOutput(arguments []bpfsnoop.TraceArgument) []traceArgumentOutput {
	if len(arguments) == 0 {
		return nil
	}
	output := make([]traceArgumentOutput, 0, len(arguments))
	for _, argument := range arguments {
		output = append(output, traceArgumentOutput{
			Name:  argument.Name,
			Type:  argument.Type,
			Value: argument.Value,
		})
	}
	return output
}

func makeTraceSelectedArgumentsOutput(arguments []bpfsnoop.TraceSelectedArgument) []traceSelectedArgumentOutput {
	if len(arguments) == 0 {
		return nil
	}
	output := make([]traceSelectedArgumentOutput, 0, len(arguments))
	for _, argument := range arguments {
		output = append(output, traceSelectedArgumentOutput{
			Expression: argument.Expression,
			Type:       argument.Type,
			Value:      argument.Value,
		})
	}
	return output
}

func makeTracePacketOutput(packet *bpfsnoop.TracePacket) *tracePacketOutput {
	if packet == nil {
		return nil
	}
	return &tracePacketOutput{
		SourceAddress:      packet.SourceAddress,
		DestinationAddress: packet.DestinationAddress,
		Protocol:           packet.Protocol,
		SourcePort:         packet.SourcePort,
		DestinationPort:    packet.DestinationPort,
		TCPFlags:           packet.TCPFlags,
	}
}

func makeTraceFunctionGraphOutput(events []bpfsnoop.TraceFunctionGraphEvent) []traceFunctionGraphEventOutput {
	if len(events) == 0 {
		return nil
	}
	output := make([]traceFunctionGraphEventOutput, 0, len(events))
	for _, event := range events {
		output = append(output, traceFunctionGraphEventOutput{
			Target:     makeTraceTargetOutput(event.Target),
			Phase:      event.Phase,
			CPU:        event.CPU,
			Depth:      event.Depth,
			DurationNS: event.DurationNS,
			Arguments:  makeTraceArgumentsOutput(event.Arguments),
			Retval:     makeTraceValueOutput(event.Retval),
		})
	}
	return output
}

func makeTraceInstructionsOutput(instructions []bpfsnoop.TraceInstructionEvent) []traceInstructionOutput {
	if len(instructions) == 0 {
		return nil
	}
	output := make([]traceInstructionOutput, 0, len(instructions))
	for _, instruction := range instructions {
		output = append(output, traceInstructionOutput{
			Function:    instruction.Function,
			Address:     instruction.Address,
			OffsetBytes: instruction.OffsetBytes,
			Bytes:       instruction.Bytes,
			Mnemonic:    instruction.Mnemonic,
			Operands:    instruction.Operands,
			CPU:         instruction.CPU,
			DurationNS:  instruction.DurationNS,
		})
	}
	return output
}

func makeTraceStackOutput(frames []bpfsnoop.TraceStackFrame) []traceStackFrameOutput {
	if len(frames) == 0 {
		return nil
	}
	output := make([]traceStackFrameOutput, 0, len(frames))
	for _, frame := range frames {
		output = append(output, traceStackFrameOutput{
			Address:     frame.Address,
			Function:    frame.Function,
			OffsetBytes: frame.OffsetBytes,
			Module:      frame.Module,
			File:        frame.File,
			Line:        frame.Line,
		})
	}
	return output
}

func makeTraceEventOutput(event bpfsnoop.TraceEvent) traceEventOutput {
	return traceEventOutput{
		TimestampUnixNS:   event.TimestampUnixNS,
		CPU:               event.CPU,
		PID:               event.PID,
		Comm:              event.Comm,
		Target:            makeTraceTargetOutput(event.Target),
		Phase:             event.Phase,
		Arguments:         makeTraceArgumentsOutput(event.Arguments),
		SelectedArguments: makeTraceSelectedArgumentsOutput(event.SelectedArguments),
		Retval:            makeTraceValueOutput(event.Retval),
		DurationNS:        event.DurationNS,
		Packet:            makeTracePacketOutput(event.Packet),
		KernelStack:       makeTraceStackOutput(event.KernelStack),
		FunctionGraph:     makeTraceFunctionGraphOutput(event.FunctionGraph),
		Instructions:      makeTraceInstructionsOutput(event.Instructions),
	}
}

// Trace validates, runs, and converts one bounded tracing experiment.
func Trace(ctx context.Context, options TraceOptions) (TraceOutput, error) {
	result, err := runTrace(ctx, options)
	if err != nil {
		return TraceOutput{}, err
	}

	output := TraceOutput{
		Status:    result.status,
		StoppedBy: result.stoppedBy,
		Stats: traceStatsOutput{
			Returned:   result.stats.returned,
			DurationMS: result.stats.durationMS,
		},
		Events:    make([]traceEventOutput, 0, len(result.events)),
		Truncated: result.truncated,
	}
	for _, event := range result.events {
		output.Events = append(output.Events, makeTraceEventOutput(event))
	}
	if len(result.flameGraph) != 0 {
		output.FlameGraph = make([]traceFlameGraphEntryOutput, 0, len(result.flameGraph))
		for _, entry := range result.flameGraph {
			output.FlameGraph = append(output.FlameGraph, traceFlameGraphEntryOutput{
				Stack: entry.stack,
				Count: entry.count,
			})
		}
	}
	return output, nil
}
