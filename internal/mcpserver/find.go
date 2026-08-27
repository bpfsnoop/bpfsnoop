// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package mcpserver

import "github.com/modelcontextprotocol/go-sdk/mcp"

type findInput struct {
	Pattern string `json:"pattern" jsonschema:"kernel object name or glob pattern to search for"`
	Kind    string `json:"kind,omitempty" jsonschema:"optional object kind: function, tracepoint, bpf_program, or btf_type"`
	Limit   int    `json:"limit,omitempty" jsonschema:"maximum number of matches to return"`
}

func init() {
	mcp.AddTool(server, &mcp.Tool{
		Name:  "find",
		Title: "Find traceable kernel objects",
		Description: "Discover kernel functions, tracepoints, loaded BPF programs, or BTF types by name or glob. " +
			"Use this before trace when the exact target name or BPF program ID is unknown. " +
			"The bpfsnoop MCP server must be running as root.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint: true,
		},
	}, notImplemented[findInput])
}
