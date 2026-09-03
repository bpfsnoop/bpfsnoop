// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"context"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	mcpapi "github.com/bpfsnoop/bpfsnoop/internal/mcp"
)

func findInputSchema() *jsonschema.Schema {
	minimum := 1.0
	maximum := float64(mcpapi.MaxFindLimit)
	return &jsonschema.Schema{
		Type:     "object",
		Required: []string{"pattern"},
		Properties: map[string]*jsonschema.Schema{
			"pattern": {
				Type:        "string",
				Description: "kernel object name or glob pattern to search for; * matches any sequence of characters",
				MinLength:   intPtr(1),
			},
			"kind": {
				Type:        "string",
				Description: "optional object kind; omit to search all kinds",
				Enum: []any{
					mcpapi.FindKindFunction,
					mcpapi.FindKindTracepoint,
					mcpapi.FindKindBPFProgram,
					mcpapi.FindKindBTFType,
				},
			},
			"limit": {
				Type:        "integer",
				Description: "maximum number of matches to return; defaults to 50 and cannot exceed 200",
				Minimum:     &minimum,
				Maximum:     &maximum,
				Default:     []byte("50"),
			},
			"include_xlated_insns": {
				Type:        "boolean",
				Description: "include structured kernel-translated eBPF instructions; requires kind bpf_program",
				Default:     []byte("false"),
			},
			"include_jited_insns": {
				Type:        "boolean",
				Description: "include hexadecimal JITed native instruction bytes grouped by function; requires kind bpf_program",
				Default:     []byte("false"),
			},
		},
	}
}

func find(ctx context.Context, _ *mcp.CallToolRequest, input mcpapi.FindOptions) (*mcp.CallToolResult, mcpapi.FindOutput, error) {
	output, err := mcpapi.Find(ctx, input)
	return nil, output, err
}

func init() {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "find",
		Title:       "Find kernel and BPF objects",
		InputSchema: findInputSchema(),
		Description: "Discover kernel functions, tracepoints, loaded BPF programs, or BTF types by exact name or glob pattern. " +
			"Set kind to limit the search to one object class; omit it to search all classes. " +
			"Every function match reports fentry/fexit and kprobe.multi traceability plus BTF and kallsyms metadata; untraceable functions are retained. " +
			"Results are stable and bounded; BTF matches include type-specific structural details. " +
			"BPF program matches include available ProgramInfo metadata; set include_xlated_insns or include_jited_insns with kind bpf_program to request instruction payloads explicitly. " +
			"Matches include the exact names or program IDs needed by trace. " +
			"Use this before trace when the target name or loaded BPF program ID is uncertain.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint: true,
		},
	}, find)
}
