// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
)

type findKernelFunctionSymbolOutput struct {
	Address   string `json:"address" jsonschema:"exact hexadecimal kallsyms address"`
	SizeBytes uint64 `json:"size_bytes,omitempty" jsonschema:"distance in bytes to the next kernel text symbol when known"`
	Module    string `json:"module" jsonschema:"kernel module providing this symbol address, or vmlinux"`
}

type findKernelFunctionTraceabilityOutput struct {
	Fentry           bool `json:"fentry" jsonschema:"whether bpfsnoop can attach through fentry"`
	Fexit            bool `json:"fexit" jsonschema:"whether bpfsnoop can attach through fexit"`
	KprobeMultiEntry bool `json:"kprobe_multi_entry" jsonschema:"whether bpfsnoop can attach an entry probe through kprobe.multi"`
	KprobeMultiExit  bool `json:"kprobe_multi_exit" jsonschema:"whether bpfsnoop can attach a return probe through kprobe.multi"`
}

type findBPFJitedFunctionOutput struct {
	Name    string `json:"name" jsonschema:"BPF function name"`
	Address string `json:"address,omitempty" jsonschema:"exact hexadecimal JITed function address when available"`
	Bytes   string `json:"bytes" jsonschema:"complete JITed native instruction bytes as hexadecimal"`
}

type findMatchOutput struct {
	Kind           string                                `json:"kind" jsonschema:"matched object kind: function, tracepoint, bpf_program, or btf_type"`
	Name           string                                `json:"name" jsonschema:"matched object name; use this exact name as a trace target when applicable"`
	Module         string                                `json:"module,omitempty" jsonschema:"kernel module providing the object, or vmlinux for built-in objects"`
	Prototype      string                                `json:"prototype,omitempty" jsonschema:"function, tracepoint, or BTF function prototype when available"`
	ID             uint32                                `json:"id,omitempty" jsonschema:"loaded BPF program ID"`
	ProgramName    string                                `json:"program_name,omitempty" jsonschema:"name assigned to a loaded BPF program"`
	ProgramType    string                                `json:"program_type,omitempty" jsonschema:"loaded BPF program type"`
	Tag            string                                `json:"tag,omitempty" jsonschema:"loaded BPF program instruction tag"`
	BTF            *bool                                 `json:"btf,omitempty" jsonschema:"whether the loaded BPF program has BTF metadata"`
	CreatedByUID   *uint32                               `json:"created_by_uid,omitempty" jsonschema:"UID that loaded the BPF program"`
	BTFID          *uint32                               `json:"btf_id,omitempty" jsonschema:"BTF type ID for a kernel function or BTF object ID associated with a BPF program"`
	LoadedAt       string                                `json:"loaded_at,omitempty" jsonschema:"estimated RFC 3339 wall-clock load time"`
	LoadTimeNS     string                                `json:"load_time_ns,omitempty" jsonschema:"exact kernel load timestamp in nanoseconds since boot"`
	XlatedBytes    *uint32                               `json:"xlated_bytes,omitempty" jsonschema:"size of translated BPF instructions without returning the instructions"`
	JitedBytes     *uint32                               `json:"jited_bytes,omitempty" jsonschema:"size of JITed native instructions without returning the instructions"`
	MemlockBytes   string                                `json:"memlock_bytes,omitempty" jsonschema:"exact approximate locked-memory usage in bytes"`
	VerifiedInsns  *uint32                               `json:"verified_instructions,omitempty" jsonschema:"number of instructions processed by the verifier"`
	MapIDs         *[]uint32                             `json:"map_ids,omitempty" jsonschema:"ordered IDs of maps referenced by the BPF program"`
	JitedKsyms     *[]string                             `json:"jited_ksym_addresses,omitempty" jsonschema:"ordered exact hexadecimal JITed function addresses"`
	JitedFuncLens  *[]uint32                             `json:"jited_function_lengths,omitempty" jsonschema:"ordered JITed function lengths in bytes"`
	JitedLineAddrs *[]string                             `json:"jited_line_addresses,omitempty" jsonschema:"ordered exact hexadecimal native addresses corresponding to line_info"`
	FunctionInfo   *[]FindBPFProgramFunction             `json:"function_info,omitempty" jsonschema:"ordered BTF function records excluding instruction payloads"`
	LineInfo       *[]FindBPFProgramLine                 `json:"line_info,omitempty" jsonschema:"ordered BTF source-line records excluding instruction payloads"`
	XlatedInsns    *[]FindBPFInstruction                 `json:"xlated_insns,omitempty" jsonschema:"ordered structured kernel-translated eBPF instructions when explicitly requested"`
	JitedInsns     *[]findBPFJitedFunctionOutput         `json:"jited_insns,omitempty" jsonschema:"JITed native instruction bytes grouped by function when explicitly requested"`
	Traceable      *bool                                 `json:"traceable,omitempty" jsonschema:"whether bpfsnoop can trace this kernel function through fentry or fexit"`
	Symbols        *[]findKernelFunctionSymbolOutput     `json:"symbols,omitempty" jsonschema:"ordered kallsyms locations for a kernel function; multiple entries identify an ambiguous symbol name"`
	Traceability   *findKernelFunctionTraceabilityOutput `json:"traceability,omitempty" jsonschema:"attachment-mode-specific kernel function traceability"`
	BTFKind        string                                `json:"btf_kind,omitempty" jsonschema:"BTF type kind when kind is btf_type"`
	SizeBytes      *uint32                               `json:"size_bytes,omitempty" jsonschema:"size of the BTF type in bytes when defined"`
	Members        *[]FindBTFMember                      `json:"members,omitempty" jsonschema:"ordered immediate members of a BTF struct or union"`
	Args           *[]FindBTFArgument                    `json:"args,omitempty" jsonschema:"ordered arguments of a BTF function or function prototype"`
	Retval         string                                `json:"retval,omitempty" jsonschema:"return type of a BTF function or function prototype"`
	TargetType     string                                `json:"target_type,omitempty" jsonschema:"target type of a BTF pointer, typedef, qualifier, or variable"`
	ElementType    string                                `json:"element_type,omitempty" jsonschema:"BTF array element type"`
	IndexType      string                                `json:"index_type,omitempty" jsonschema:"BTF array index type"`
	ElementCount   *uint32                               `json:"element_count,omitempty" jsonschema:"number of elements in a BTF array"`
	Encoding       string                                `json:"encoding,omitempty" jsonschema:"BTF integer encoding"`
	Signed         *bool                                 `json:"signed,omitempty" jsonschema:"whether BTF enum values are signed"`
	Values         *[]FindBTFEnumValue                   `json:"values,omitempty" jsonschema:"ordered values of a BTF enum"`
	Linkage        string                                `json:"linkage,omitempty" jsonschema:"BTF function or variable linkage"`
	Variables      *[]FindBTFVariable                    `json:"variables,omitempty" jsonschema:"ordered entries in a BTF data section"`
	ForwardKind    string                                `json:"forward_kind,omitempty" jsonschema:"struct or union kind named by a BTF forward declaration"`
	Tags           []string                              `json:"tags,omitempty" jsonschema:"BTF declaration tags attached to the matched type"`
}

// FindOutput contains structured, bounded MCP discovery results.
type FindOutput struct {
	Matches   []findMatchOutput `json:"matches" jsonschema:"stable, lexicographically ordered matches, bounded by limit"`
	Total     int               `json:"total" jsonschema:"number of matching objects discovered before applying limit"`
	Truncated bool              `json:"truncated" jsonschema:"true when more matches exist than were returned"`
}

// Find discovers kernel and BPF objects and converts them into the MCP result
// model.
func Find(ctx context.Context, input FindOptions) (FindOutput, error) {
	result, err := findObjects(ctx, input)
	if err != nil {
		return FindOutput{}, err
	}

	output := FindOutput{
		Matches:   make([]findMatchOutput, 0, len(result.Matches)),
		Total:     result.Total,
		Truncated: result.Truncated,
	}
	for i := range result.Matches {
		match := &result.Matches[i]
		matchOutput := findMatchOutput{
			Kind:         match.Kind,
			Name:         match.Name,
			Module:       match.Module,
			Prototype:    match.Prototype,
			ID:           match.ID,
			ProgramName:  match.ProgramName,
			ProgramType:  match.ProgramType,
			Tag:          match.Tag,
			BTFKind:      match.BTFKind,
			SizeBytes:    match.BTFSize,
			Retval:       match.BTFReturnType,
			TargetType:   match.BTFTargetType,
			ElementType:  match.BTFElementType,
			IndexType:    match.BTFIndexType,
			ElementCount: match.BTFElementCount,
			Encoding:     match.BTFEncoding,
			Signed:       match.BTFEnumSigned,
			Linkage:      match.BTFLinkage,
			ForwardKind:  match.BTFFwdKind,
			Tags:         match.BTFTags,
		}
		if match.Kind == FindKindBPFProgram {
			matchOutput.BTF = &match.BTF
			matchOutput.CreatedByUID = match.ProgramUID
			matchOutput.BTFID = match.ProgramBTFID
			matchOutput.LoadedAt = match.ProgramLoadedAt
			matchOutput.LoadTimeNS = match.ProgramLoadNS
			matchOutput.XlatedBytes = match.ProgramXlated
			matchOutput.JitedBytes = match.ProgramJited
			matchOutput.VerifiedInsns = match.ProgramVerified
			if match.ProgramMemlock != nil {
				matchOutput.MemlockBytes = strconv.FormatUint(*match.ProgramMemlock, 10)
			}
			if match.ProgramMapIDs != nil {
				matchOutput.MapIDs = &match.ProgramMapIDs
			}
			if match.ProgramKsyms != nil {
				addresses := make([]string, len(match.ProgramKsyms))
				for i, address := range match.ProgramKsyms {
					addresses[i] = fmt.Sprintf("%#x", address)
				}
				matchOutput.JitedKsyms = &addresses
			}
			if match.ProgramJitedLens != nil {
				matchOutput.JitedFuncLens = &match.ProgramJitedLens
			}
			if match.ProgramJitedLines != nil {
				addresses := make([]string, len(match.ProgramJitedLines))
				for i, address := range match.ProgramJitedLines {
					addresses[i] = fmt.Sprintf("%#x", address)
				}
				matchOutput.JitedLineAddrs = &addresses
			}
			if match.ProgramFunctions != nil {
				matchOutput.FunctionInfo = &match.ProgramFunctions
			}
			if match.ProgramLines != nil {
				matchOutput.LineInfo = &match.ProgramLines
			}
			if match.ProgramXlatedInsns != nil {
				matchOutput.XlatedInsns = &match.ProgramXlatedInsns
			}
			if match.ProgramJitedInsns != nil {
				functions := make([]findBPFJitedFunctionOutput, 0, len(match.ProgramJitedInsns))
				for _, function := range match.ProgramJitedInsns {
					output := findBPFJitedFunctionOutput{
						Name:  function.Name,
						Bytes: hex.EncodeToString(function.Bytes),
					}
					if function.Address != 0 {
						output.Address = fmt.Sprintf("%#x", function.Address)
					}
					functions = append(functions, output)
				}
				matchOutput.JitedInsns = &functions
			}
		}
		if match.Kind == FindKindFunction {
			matchOutput.Traceable = &match.Traceable
			matchOutput.BTFID = match.FunctionBTFID
			matchOutput.Traceability = &findKernelFunctionTraceabilityOutput{
				Fentry:           match.FunctionFentry,
				Fexit:            match.FunctionFexit,
				KprobeMultiEntry: match.FunctionKprobeMultiEntry,
				KprobeMultiExit:  match.FunctionKprobeMultiExit,
			}
			if match.FunctionSymbols != nil {
				symbols := make([]findKernelFunctionSymbolOutput, 0, len(match.FunctionSymbols))
				for _, symbol := range match.FunctionSymbols {
					symbols = append(symbols, findKernelFunctionSymbolOutput{
						Address:   fmt.Sprintf("%#x", symbol.Address),
						SizeBytes: symbol.SizeBytes,
						Module:    symbol.Module,
					})
				}
				matchOutput.Symbols = &symbols
			}
		}
		if match.BTFMembers != nil {
			matchOutput.Members = &match.BTFMembers
		}
		if match.BTFArguments != nil {
			matchOutput.Args = &match.BTFArguments
		}
		if match.BTFEnumValues != nil {
			matchOutput.Values = &match.BTFEnumValues
		}
		if match.BTFVariables != nil {
			matchOutput.Variables = &match.BTFVariables
		}
		output.Matches = append(output.Matches, matchOutput)
	}

	return output, nil
}
