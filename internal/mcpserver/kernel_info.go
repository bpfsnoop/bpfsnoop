// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package mcpserver

import "github.com/modelcontextprotocol/go-sdk/mcp"

type kernelInfoInput struct{}

func init() {
	mcp.AddTool(server, &mcp.Tool{
		Name:  "kernel_info",
		Title: "Inspect kernel tracing capabilities",
		Description: "Return the running kernel identity and the tracing capabilities available to bpfsnoop. " +
			"Call this first when an investigation depends on a particular BPF attachment or capture feature. " +
			"The bpfsnoop MCP server must be running as root.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint: true,
		},
	}, notImplemented[kernelInfoInput])
}
