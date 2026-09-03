// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"context"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	mcpapi "github.com/bpfsnoop/bpfsnoop/internal/mcp"
)

type readInput struct {
	Expressions []string `json:"expressions"`
}

func readInputSchema() *jsonschema.Schema {
	minimumItems := 1
	minimumLength := 1
	return &jsonschema.Schema{
		Type:     "object",
		Required: []string{"expressions"},
		Properties: map[string]*jsonschema.Schema{
			"expressions": {
				Type:        "array",
				Description: "one or more kernel-memory C expressions to evaluate",
				MinItems:    &minimumItems,
				Items: &jsonschema.Schema{
					Type:      "string",
					MinLength: &minimumLength,
				},
			},
		},
	}
}

func read(ctx context.Context, _ *mcp.CallToolRequest, input readInput) (*mcp.CallToolResult, mcpapi.ReadOutput, error) {
	output, err := mcpapi.Read(ctx, input.Expressions)
	return nil, output, err
}

func init() {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "read",
		Title:       "Read kernel memory",
		InputSchema: readInputSchema(),
		Description: "Evaluate one or more bpfsnoop C expressions against kernel memory and return structured results. " +
			"Values use native JSON containers and scalar types; integers outside JSON's exact range are decimal strings. " +
			"Expressions must include the address and type needed for the read, for example *(int *)0xffffffffdeadbeef. " +
			"Use this only for focused inspection after identifying the relevant kernel object.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint: true,
		},
	}, read)
}
