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

type traceTarget struct {
	Kind        string `json:"kind" jsonschema:"target kind: function, tracepoint, or bpf_program"`
	Name        string `json:"name,omitempty" jsonschema:"kernel function or tracepoint name, or optional exact BPF subprogram name"`
	ID          uint32 `json:"id,omitempty" jsonschema:"loaded BPF program ID"`
	ProgramName string `json:"program_name,omitempty" jsonschema:"loaded BPF program name; alternative to id"`
	Attach      string `json:"attach,omitempty" jsonschema:"function attachment: fentry or kprobe_multi; defaults to fentry"`
}

type traceFilter struct {
	PID    uint32 `json:"pid,omitempty" jsonschema:"only trace this process ID"`
	Comm   string `json:"comm,omitempty" jsonschema:"only trace this exact Linux task name, at most 15 bytes"`
	Expr   string `json:"expr,omitempty" jsonschema:"bpfsnoop argument filter expression applied to every target"`
	Packet string `json:"packet,omitempty" jsonschema:"pcap filter applied to skb or XDP packet arguments"`
}

type traceCapture struct {
	Arguments           bool     `json:"arguments,omitempty" jsonschema:"include typed function arguments"`
	Retval              bool     `json:"retval,omitempty" jsonschema:"include the typed function return value"`
	Duration            bool     `json:"duration,omitempty" jsonschema:"pair entry and exit and include duration_ns; implies retval"`
	KernelStack         bool     `json:"kernel_stack,omitempty" jsonschema:"include structured kernel stack frames"`
	ArgumentExpressions []string `json:"argument_expressions,omitempty" jsonschema:"evaluate selected bpfsnoop C expressions for matching targets"`
	Packet              bool     `json:"packet,omitempty" jsonschema:"include a structured packet tuple"`
	FlameGraph          bool     `json:"flame_graph,omitempty" jsonschema:"aggregate kernel stacks into structured flame-graph entries"`
	FunctionGraph       bool     `json:"function_graph,omitempty" jsonschema:"include structured child function calls"`
	Instructions        bool     `json:"instructions,omitempty" jsonschema:"include the executed native instruction path for kernel functions"`
}

type traceLimits struct {
	DurationMS int `json:"duration_ms,omitempty" jsonschema:"trace duration after attachment; defaults to 3000, minimum 100, maximum 30000"`
	MaxEvents  int `json:"max_events,omitempty" jsonschema:"maximum returned events; defaults to 100, maximum 1000"`
}

type traceInput struct {
	Targets            []traceTarget `json:"targets" jsonschema:"one or more kernel-function, tracepoint, or loaded-BPF-program selectors"`
	Filter             *traceFilter  `json:"filter,omitempty" jsonschema:"optional filters combined with AND semantics"`
	Capture            *traceCapture `json:"capture,omitempty" jsonschema:"fields to capture; defaults to arguments and retval"`
	Limits             *traceLimits  `json:"limits,omitempty" jsonschema:"bounded execution limits"`
	FunctionGraphDepth int           `json:"function_graph_depth,omitempty" jsonschema:"maximum function graph depth; defaults to 3, maximum 20"`
}

func traceInputSchema() *jsonschema.Schema {
	minOne := 1.0
	minDuration := float64(mcpapi.MinTraceDuration / time.Millisecond)
	maxDuration := float64(mcpapi.MaxTraceDuration / time.Millisecond)
	maxEvents := float64(mcpapi.MaxTraceEvents)
	maxGraphDepth := float64(mcpapi.MaxTraceFunctionDepth)
	minItems := 1
	minLength, maxCommLength := 1, 15
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
	options := mcpapi.TraceOptions{Targets: make([]mcpapi.TraceTarget, 0, len(input.Targets))}
	for _, target := range input.Targets {
		options.Targets = append(options.Targets, mcpapi.TraceTarget{
			Kind:        target.Kind,
			Name:        target.Name,
			ID:          target.ID,
			ProgramName: target.ProgramName,
			Attach:      target.Attach,
		})
	}
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
		options.Capture = mcpapi.TraceCapture{
			Arguments:           input.Capture.Arguments,
			Retval:              input.Capture.Retval,
			Duration:            input.Capture.Duration,
			KernelStack:         input.Capture.KernelStack,
			ArgumentExpressions: input.Capture.ArgumentExpressions,
			Packet:              input.Capture.Packet,
			FlameGraph:          input.Capture.FlameGraph,
			FunctionGraph:       input.Capture.FunctionGraph,
			Instructions:        input.Capture.Instructions,
		}
	}
	options.FunctionGraphDepth = input.FunctionGraphDepth
	if input.Limits != nil {
		options.Duration = time.Duration(input.Limits.DurationMS) * time.Millisecond
		options.MaxEvents = input.Limits.MaxEvents
	}

	result, err := mcpapi.Trace(ctx, options)
	if err != nil {
		return nil, mcpapi.TraceOutput{}, err
	}
	return nil, result, nil
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
