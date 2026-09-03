// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"context"
	"fmt"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	mcpapi "github.com/bpfsnoop/bpfsnoop/internal/mcp"
)

type traceFilter struct {
	PID          uint32 `json:"pid,omitempty"`
	Comm         string `json:"comm,omitempty"`
	Expr         string `json:"expr,omitempty"`
	Packet       string `json:"packet,omitempty"`
	PacketSource string `json:"packet_source,omitempty"`
}

type traceLimits struct {
	DurationMS int `json:"duration_ms,omitempty"`
	MaxEvents  int `json:"max_events,omitempty"`
}

type traceInput struct {
	Action             string               `json:"action,omitempty"`
	Targets            []mcpapi.TraceTarget `json:"targets"`
	Filter             *traceFilter         `json:"filter,omitempty"`
	Capture            *mcpapi.TraceCapture `json:"capture,omitempty"`
	Limits             *traceLimits         `json:"limits,omitempty"`
	FunctionGraphDepth int                  `json:"function_graph_depth,omitempty"`
}

func traceInputSchema() *jsonschema.Schema {
	minOne := 1.0
	minDuration := float64(mcpapi.MinTraceDuration / time.Millisecond)
	maxDuration := float64(mcpapi.MaxTraceDuration / time.Millisecond)
	maxEvents := float64(mcpapi.MaxTraceEvents)
	maxGraphDepth := float64(mcpapi.MaxTraceFunctionDepth)
	minItems := 1
	minLength, maxCommLength := 1, mcpapi.MaxTraceCommLength
	return &jsonschema.Schema{
		Type: "object",
		Properties: map[string]*jsonschema.Schema{
			"action": {Type: "string", Enum: []any{mcpapi.TraceActionStart, mcpapi.TraceActionWait, mcpapi.TraceActionAbort}},
			"targets": {
				Type:     "array",
				MinItems: &minItems,
				Items: &jsonschema.Schema{
					Type:     "object",
					Required: []string{"kind"},
					Properties: map[string]*jsonschema.Schema{
						"kind":         {Type: "string", Enum: []any{mcpapi.TraceKindFunction, mcpapi.TraceKindTracepoint, mcpapi.TraceKindBPFProgram}},
						"name":         {Type: "string", MinLength: &minLength},
						"id":           {Type: "integer", Minimum: &minOne},
						"program_name": {Type: "string", MinLength: &minLength},
						"attach": {
							Type: "string",
							Enum: []any{mcpapi.TraceAttachFentry, mcpapi.TraceAttachKprobe},
						},
					},
				},
			},
			"filter": {
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"pid":           {Type: "integer", Minimum: &minOne},
					"comm":          {Type: "string", MinLength: &minLength, MaxLength: &maxCommLength},
					"expr":          {Type: "string", MinLength: &minLength},
					"packet":        {Type: "string", MinLength: &minLength},
					"packet_source": {Type: "string", Enum: []any{mcpapi.TracePacketSourceArgument, mcpapi.TracePacketSourceRetval}},
				},
			},
			"capture": {
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"arguments":    {Type: "boolean"},
					"retval":       {Type: "boolean"},
					"duration":     {Type: "boolean"},
					"kernel_stack": {Type: "boolean"},
					"argument_expressions": {
						Type: "array", MinItems: &minItems,
						Items: &jsonschema.Schema{Type: "string", MinLength: &minLength},
					},
					"packet":         {Type: "boolean"},
					"packet_source":  {Type: "string", Enum: []any{mcpapi.TracePacketSourceArgument, mcpapi.TracePacketSourceRetval}},
					"flame_graph":    {Type: "boolean"},
					"function_graph": {Type: "boolean"},
					"instructions":   {Type: "boolean"},
				},
			},
			"limits": {
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"duration_ms": {
						Type:    "integer",
						Minimum: &minDuration,
						Maximum: &maxDuration,
						Default: []byte("3000"),
					},
					"max_events": {
						Type:    "integer",
						Minimum: &minOne,
						Maximum: &maxEvents,
						Default: []byte("100"),
					},
				},
			},
			"function_graph_depth": {Type: "integer", Minimum: &minOne, Maximum: &maxGraphDepth},
		},
	}
}

func traceOptions(input traceInput) mcpapi.TraceOptions {
	options := mcpapi.TraceOptions{Targets: input.Targets}
	if input.Filter != nil {
		options.PID = input.Filter.PID
		options.Comm = input.Filter.Comm
		options.Expr = input.Filter.Expr
		options.PacketExpr = input.Filter.Packet
		options.PacketSource = input.Filter.PacketSource
	}
	if input.Capture == nil {
		options.Capture.Arguments = true
		options.Capture.Retval = true
	} else {
		options.Capture = *input.Capture
	}
	options.FunctionGraphDepth = input.FunctionGraphDepth
	if input.Limits != nil {
		options.Duration = time.Duration(input.Limits.DurationMS) * time.Millisecond
		options.MaxEvents = input.Limits.MaxEvents
	}

	return options
}

func trace(ctx context.Context, _ *mcp.CallToolRequest, input traceInput) (*mcp.CallToolResult, mcpapi.TraceOutput, error) {
	switch input.Action {
	case mcpapi.TraceActionStart:
		started, err := mcpapi.StartTrace(ctx, traceOptions(input))
		if err != nil {
			return nil, mcpapi.TraceOutput{}, err
		}
		return nil, mcpapi.TraceOutput{Action: mcpapi.TraceActionStart, State: started.State, ReadyAt: started.ReadyAt, Deadline: started.Deadline, Warnings: started.Warnings}, nil
	case mcpapi.TraceActionWait:
		output, err := mcpapi.WaitTrace(ctx)
		if err != nil {
			return nil, mcpapi.TraceOutput{}, err
		}
		output.Action = mcpapi.TraceActionWait
		return nil, output, nil
	case mcpapi.TraceActionAbort:
		aborted, err := mcpapi.AbortTrace(ctx)
		if err != nil {
			return nil, mcpapi.TraceOutput{}, err
		}
		return nil, mcpapi.TraceOutput{Action: mcpapi.TraceActionAbort, Aborted: aborted.Aborted}, nil
	case "":
		if _, err := mcpapi.StartTrace(ctx, traceOptions(input)); err != nil {
			return nil, mcpapi.TraceOutput{}, err
		}
		output, err := mcpapi.WaitTrace(ctx)
		return nil, output, err
	default:
		return nil, mcpapi.TraceOutput{}, fmt.Errorf("unsupported trace action %q", input.Action)
	}
}

func init() {
	notDestructive := false
	mcp.AddTool(server, &mcp.Tool{
		Name:        "trace",
		Title:       "Run a bounded bpfsnoop trace",
		InputSchema: traceInputSchema(),
		Description: "Run one bounded kernel-function, tracepoint, or loaded-BPF-program tracing experiment. Use action=start to attach and return only when tracing is ready, generate the event, then use action=wait to return structured typed arguments, selected argument expressions, return values, durations, packet tuples, kernel stacks, flame graphs, function graphs, or executed native instructions. Typed return-value filters and argument expressions use $retval with an explicit concrete cast, such as (int)$retval. Set packet_source to retval in filter or capture to select a packet-typed function return; packet_source defaults to argument. Always render every trace result for human review: use a concise chronological list for events and an indented call tree for function graphs. Use action=abort to cancel the active trace. Omitting action preserves the synchronous trace behavior. " +
			"Function selectors may be exact names or globs; fentry/fexit is capped at 200 resolved functions, while kprobe_multi has no function-count cap. Loaded BPF program targets have no count cap. " +
			"Executed instructions require fentry kernel-function targets, and cannot be combined with a function graph. " +
			"Duration and event-count limits are mandatory server invariants even when omitted by the caller. " +
			"Only one trace runs at a time; a concurrent request is rejected. Issue another trace to refine the investigation.",
		Annotations: &mcp.ToolAnnotations{
			DestructiveHint: &notDestructive,
			ReadOnlyHint:    false,
		},
	}, trace)
}
