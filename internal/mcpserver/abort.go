// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	mcpapi "github.com/bpfsnoop/bpfsnoop/internal/mcp"
)

type abortInput struct{}

func abort(ctx context.Context, _ *mcp.CallToolRequest, _ abortInput) (*mcp.CallToolResult, mcpapi.AbortOutput, error) {
	output, err := mcpapi.Abort(ctx)
	return nil, output, err
}

func init() {
	notDestructive := false
	mcp.AddTool(server, &mcp.Tool{
		Name:        "abort",
		Title:       "Abort the active trace",
		Description: "Cancel the active MCP trace and wait for its tracing resources to be released. The MCP session remains open. Returns aborted=false when no trace is active.",
		Annotations: &mcp.ToolAnnotations{
			DestructiveHint: &notDestructive,
			ReadOnlyHint:    false,
		},
	}, abort)
}
