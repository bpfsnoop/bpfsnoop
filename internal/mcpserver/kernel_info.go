// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	mcpapi "github.com/bpfsnoop/bpfsnoop/internal/mcp"
)

type kernelInfoInput struct{}

func kernelInfo(context.Context, *mcp.CallToolRequest, kernelInfoInput) (*mcp.CallToolResult, mcpapi.KernelInfo, error) {
	info, err := mcpapi.GetKernelInfo()
	if err != nil {
		return nil, mcpapi.KernelInfo{}, err
	}
	return nil, info, nil
}

func init() {
	mcp.AddTool(server, &mcp.Tool{
		Name:  "kernel_info",
		Title: "Inspect kernel tracing capabilities",
		Description: "Return the running kernel identity and the tracing capabilities available to bpfsnoop. " +
			"Call this first when an investigation depends on a particular BPF attachment or capture feature.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint: true,
		},
	}, kernelInfo)
}
