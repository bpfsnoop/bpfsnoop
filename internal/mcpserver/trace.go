// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package mcpserver

import "github.com/modelcontextprotocol/go-sdk/mcp"

type traceTarget struct {
	Kind string `json:"kind" jsonschema:"target kind: function, tracepoint, or bpf_program"`
	Name string `json:"name" jsonschema:"target name"`
	ID   uint32 `json:"id,omitempty" jsonschema:"optional loaded BPF program ID"`
}

type traceFilter struct {
	PID  uint32 `json:"pid,omitempty" jsonschema:"only trace this process ID"`
	Comm string `json:"comm,omitempty" jsonschema:"only trace this exact Linux task name"`
	Expr string `json:"expr,omitempty" jsonschema:"bpfsnoop argument filter expression"`
}

type traceCapture struct {
	Arguments   bool `json:"arguments,omitempty" jsonschema:"include function arguments"`
	Retval      bool `json:"retval,omitempty" jsonschema:"include function return values"`
	Duration    bool `json:"duration,omitempty" jsonschema:"include function duration"`
	KernelStack bool `json:"kernel_stack,omitempty" jsonschema:"include the kernel stack"`
}

type traceLimits struct {
	DurationMS int `json:"duration_ms,omitempty" jsonschema:"maximum trace duration in milliseconds"`
	MaxEvents  int `json:"max_events,omitempty" jsonschema:"maximum number of events to return"`
}

type traceInput struct {
	Targets []traceTarget `json:"targets" jsonschema:"one or more kernel or BPF tracing targets"`
	Filter  *traceFilter  `json:"filter,omitempty" jsonschema:"optional filters combined with AND semantics"`
	Capture *traceCapture `json:"capture,omitempty" jsonschema:"data to capture for each event"`
	Limits  *traceLimits  `json:"limits,omitempty" jsonschema:"execution limits for the tracing experiment"`
}

func init() {
	notDestructive := false
	mcp.AddTool(server, &mcp.Tool{
		Name:  "trace",
		Title: "Run a bounded bpfsnoop trace",
		Description: "Run one bounded kernel or BPF tracing experiment and return structured events. " +
			"Provide explicit targets; the server always enforces execution limits. Use find first if a target is uncertain. " +
			"Issue another trace to refine the investigation. The bpfsnoop MCP server must be running as root.",
		Annotations: &mcp.ToolAnnotations{
			DestructiveHint: &notDestructive,
			ReadOnlyHint:    false,
		},
	}, notImplemented[traceInput])
}
