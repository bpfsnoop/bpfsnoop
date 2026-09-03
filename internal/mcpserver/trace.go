// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"context"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	mcpapi "github.com/bpfsnoop/bpfsnoop/internal/mcp"
)

type traceFilter struct {
	PID    uint32 `json:"pid,omitempty"`
	Comm   string `json:"comm,omitempty"`
	Expr   string `json:"expr,omitempty"`
	Packet string `json:"packet,omitempty"`
}

type traceLimits struct {
	DurationMS int `json:"duration_ms,omitempty"`
	MaxEvents  int `json:"max_events,omitempty"`
}

type traceInput struct {
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
		Type:     "object",
		Required: []string{"targets"},
		Properties: map[string]*jsonschema.Schema{
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
					"pid":    {Type: "integer", Minimum: &minOne},
					"comm":   {Type: "string", MinLength: &minLength, MaxLength: &maxCommLength},
					"expr":   {Type: "string", MinLength: &minLength},
					"packet": {Type: "string", MinLength: &minLength},
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

func trace(ctx context.Context, _ *mcp.CallToolRequest, input traceInput) (*mcp.CallToolResult, mcpapi.TraceOutput, error) {
	options := mcpapi.TraceOptions{Targets: input.Targets}
	if input.Filter != nil {
		options.PID = input.Filter.PID
		options.Comm = input.Filter.Comm
		options.Expr = input.Filter.Expr
		options.PacketExpr = input.Filter.Packet
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

	result, err := mcpapi.Trace(ctx, options)
	return nil, result, err
}

func init() {
	notDestructive := false
	mcp.AddTool(server, &mcp.Tool{
		Name:        "trace",
		Title:       "Run a bounded bpfsnoop trace",
		InputSchema: traceInputSchema(),
		Description: "Run one bounded kernel-function, tracepoint, or loaded-BPF-program tracing experiment. Return structured typed arguments, selected argument expressions, return values, durations, packet tuples, kernel stacks, flame graphs, function graphs, or executed native instructions. " +
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
