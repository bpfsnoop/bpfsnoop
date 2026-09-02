// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package mcp

import "context"

type disasmSourceOutput struct {
	File   string `json:"file,omitempty" jsonschema:"source file path from BPF or kernel debug metadata"`
	Line   uint32 `json:"line,omitempty" jsonschema:"one-based source line number"`
	Column uint32 `json:"column,omitempty" jsonschema:"one-based source column number"`
	Text   string `json:"text,omitempty" jsonschema:"source line text when available"`
	Inline bool   `json:"inline,omitempty" jsonschema:"true when debug metadata identifies an inlined call site"`
}

type disasmLocationOutput struct {
	Name        string              `json:"name,omitempty" jsonschema:"function or symbol containing the address"`
	Address     string              `json:"address" jsonschema:"exact hexadecimal target address"`
	OffsetBytes uint64              `json:"offset_bytes" jsonschema:"offset from the containing function or symbol"`
	Module      string              `json:"module,omitempty" jsonschema:"kernel module containing the target"`
	BPF         bool                `json:"bpf,omitempty" jsonschema:"true when the target is a JITed BPF function"`
	Source      *disasmSourceOutput `json:"source,omitempty" jsonschema:"source line at the branch target when available"`
}

type disasmInstructionOutput struct {
	Address      string                `json:"address" jsonschema:"exact hexadecimal instruction address"`
	OffsetBytes  uint64                `json:"offset_bytes" jsonschema:"instruction offset from the function start"`
	Bytes        string                `json:"bytes" jsonschema:"machine instruction bytes as a hexadecimal string"`
	Mnemonic     string                `json:"mnemonic" jsonschema:"instruction mnemonic"`
	Operands     string                `json:"operands,omitempty" jsonschema:"architecture-specific instruction operands"`
	Source       *disasmSourceOutput   `json:"source,omitempty" jsonschema:"source line active at this instruction"`
	BranchTarget *disasmLocationOutput `json:"branch_target,omitempty" jsonschema:"resolved direct branch or call target"`
}

type disasmFunctionOutput struct {
	Name              string                    `json:"name" jsonschema:"function name"`
	Prototype         string                    `json:"prototype,omitempty" jsonschema:"BTF function prototype when available"`
	Address           string                    `json:"address" jsonschema:"exact hexadecimal function start address"`
	SizeBytes         uint64                    `json:"size_bytes" jsonschema:"number of machine-code bytes in the selected function range"`
	BytesDisassembled uint64                    `json:"bytes_disassembled" jsonschema:"number of bytes represented by returned instructions"`
	Instructions      []disasmInstructionOutput `json:"instructions" jsonschema:"ordered native machine instructions"`
	Truncated         bool                      `json:"truncated" jsonschema:"true when the instruction limit or undecodable trailing bytes shortened this function"`
}

// DisasmOutput contains bounded, structured native disassembly for an MCP
// request.
type DisasmOutput struct {
	Kind         string                 `json:"kind" jsonschema:"disassembled target kind"`
	Name         string                 `json:"name" jsonschema:"resolved target name"`
	ProgramID    uint32                 `json:"program_id,omitempty" jsonschema:"loaded BPF program ID"`
	ProgramName  string                 `json:"program_name,omitempty" jsonschema:"kernel-visible BPF program name"`
	ProgramType  string                 `json:"program_type,omitempty" jsonschema:"loaded BPF program type"`
	Architecture string                 `json:"architecture" jsonschema:"native instruction architecture"`
	Syntax       string                 `json:"syntax" jsonschema:"assembly operand syntax"`
	Functions    []disasmFunctionOutput `json:"functions" jsonschema:"ordered disassembled functions"`
	Truncated    bool                   `json:"truncated" jsonschema:"true when the global instruction limit shortened the result"`
}

func makeDisasmSourceOutput(source *DisasmSource) *disasmSourceOutput {
	if source == nil {
		return nil
	}
	return &disasmSourceOutput{
		File:   source.File,
		Line:   source.Line,
		Column: source.Column,
		Text:   source.Text,
		Inline: source.Inline,
	}
}

func makeDisasmLocationOutput(location *DisasmLocation) *disasmLocationOutput {
	if location == nil {
		return nil
	}
	return &disasmLocationOutput{
		Name:        location.Name,
		Address:     location.Address,
		OffsetBytes: location.OffsetBytes,
		Module:      location.Module,
		BPF:         location.BPF,
		Source:      makeDisasmSourceOutput(location.Source),
	}
}

// Disasm validates, disassembles, and converts a native code target into the
// MCP result model.
func Disasm(ctx context.Context, options DisasmOptions) (DisasmOutput, error) {
	result, err := disassemble(ctx, options)
	if err != nil {
		return DisasmOutput{}, err
	}

	output := DisasmOutput{
		Kind:         result.Kind,
		Name:         result.Name,
		ProgramID:    result.ProgramID,
		ProgramName:  result.ProgramName,
		ProgramType:  result.ProgramType,
		Architecture: result.Architecture,
		Syntax:       result.Syntax,
		Functions:    make([]disasmFunctionOutput, 0, len(result.Functions)),
		Truncated:    result.Truncated,
	}
	for _, function := range result.Functions {
		functionOutput := disasmFunctionOutput{
			Name:              function.Name,
			Prototype:         function.Prototype,
			Address:           function.Address,
			SizeBytes:         function.SizeBytes,
			BytesDisassembled: function.BytesDisassembled,
			Instructions:      make([]disasmInstructionOutput, 0, len(function.Instructions)),
			Truncated:         function.Truncated,
		}
		for _, instruction := range function.Instructions {
			functionOutput.Instructions = append(functionOutput.Instructions, disasmInstructionOutput{
				Address:      instruction.Address,
				OffsetBytes:  instruction.OffsetBytes,
				Bytes:        instruction.Bytes,
				Mnemonic:     instruction.Mnemonic,
				Operands:     instruction.Operands,
				Source:       makeDisasmSourceOutput(instruction.Source),
				BranchTarget: makeDisasmLocationOutput(instruction.BranchTarget),
			})
		}
		output.Functions = append(output.Functions, functionOutput)
	}
	return output, nil
}
