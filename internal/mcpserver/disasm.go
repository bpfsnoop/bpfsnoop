// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"context"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	mcpapi "github.com/bpfsnoop/bpfsnoop/internal/mcp"
)

type disasmTargetInput struct {
	Kind string `json:"kind" jsonschema:"target kind: function or bpf_program"`
	Name string `json:"name,omitempty" jsonschema:"exact kernel function name, hexadecimal kernel address, or optional BPF subprogram name"`
	ID   uint32 `json:"id,omitempty" jsonschema:"loaded BPF program ID; required for bpf_program"`
}

type disasmInput struct {
	Target          disasmTargetInput `json:"target" jsonschema:"kernel function or loaded BPF program to disassemble"`
	Bytes           uint32            `json:"bytes,omitempty" jsonschema:"kernel bytes to read; omit to infer the function size, maximum 4096"`
	MaxInstructions int               `json:"max_instructions,omitempty" jsonschema:"maximum instructions to return across all functions; defaults to 256, maximum 2048"`
	Syntax          string            `json:"syntax,omitempty" jsonschema:"assembly syntax: att or intel; defaults to att, and intel is amd64-only"`
}

func disasmInputSchema() *jsonschema.Schema {
	minimum := 1.0
	maxBytes := float64(mcpapi.MaxDisasmBytes)
	maxInstructions := float64(mcpapi.MaxDisasmInstructions)
	return &jsonschema.Schema{
		Type:     "object",
		Required: []string{"target"},
		Properties: map[string]*jsonschema.Schema{
			"target": {
				Type:     "object",
				Required: []string{"kind"},
				Properties: map[string]*jsonschema.Schema{
					"kind": {
						Type:        "string",
						Description: "target kind",
						Enum:        []any{mcpapi.DisasmKindFunction, mcpapi.DisasmKindBPFProgram},
					},
					"name": {
						Type:        "string",
						Description: "exact kernel function name, hexadecimal address, or optional BPF subprogram name",
						MinLength:   findIntPtr(1),
					},
					"id": {
						Type:        "integer",
						Description: "loaded BPF program ID; required for bpf_program",
						Minimum:     &minimum,
					},
				},
			},
			"bytes": {
				Type:        "integer",
				Description: "kernel bytes to read; omit to infer the function size",
				Minimum:     &minimum,
				Maximum:     &maxBytes,
			},
			"max_instructions": {
				Type:        "integer",
				Description: "maximum instructions to return across all functions",
				Minimum:     &minimum,
				Maximum:     &maxInstructions,
				Default:     []byte("256"),
			},
			"syntax": {
				Type:        "string",
				Description: "assembly operand syntax; intel is amd64-only",
				Enum:        []any{"att", "intel"},
				Default:     []byte(`"att"`),
			},
		},
	}
}

func disasm(ctx context.Context, _ *mcp.CallToolRequest, input disasmInput) (*mcp.CallToolResult, mcpapi.DisasmOutput, error) {
	output, err := mcpapi.Disasm(ctx, mcpapi.DisasmOptions{
		Kind:            input.Target.Kind,
		Name:            input.Target.Name,
		ProgramID:       input.Target.ID,
		Bytes:           input.Bytes,
		MaxInstructions: input.MaxInstructions,
		Syntax:          input.Syntax,
	})
	if err != nil {
		return nil, mcpapi.DisasmOutput{}, err
	}
	return nil, output, nil
}

func init() {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "disasm",
		Title:       "Disassemble kernel or BPF code",
		InputSchema: disasmInputSchema(),
		Description: "Disassemble one exact kernel function/address or loaded BPF program into bounded structured native instructions. " +
			"For BPF programs, provide the ID from find and optionally an exact subprogram name; omitting the name selects all functions. " +
			"Use bytes only for kernel functions and max_instructions to control response size. " +
			"Addresses are exact hexadecimal strings; source lines and direct branch targets, including target source lines, are included when debug metadata is available.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint: true,
		},
	}, disasm)
}
