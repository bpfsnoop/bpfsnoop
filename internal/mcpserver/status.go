// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	mcpapi "github.com/bpfsnoop/bpfsnoop/internal/mcp"
)

type statusInput struct{}

func status(context.Context, *mcp.CallToolRequest, statusInput) (*mcp.CallToolResult, mcpapi.StatusOutput, error) {
	return nil, mcpapi.Status(), nil
}

func init() {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "status",
		Title:       "Inspect MCP daemon status",
		Description: "Report whether the MCP daemon is idle or has an active trace. An active session includes its state, elapsed time, collected-event count, targets, filters, captures, and limits. Use this before abort when the state of a long-running trace is uncertain.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint: true,
		},
	}, status)
}
