// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"

	"github.com/bpfsnoop/bpfsnoop/internal/bpfsnoop"
)

const (
	DisasmKindFunction   = "function"
	DisasmKindBPFProgram = "bpf_program"

	DefaultDisasmMaxInstructions = 256
	MaxDisasmInstructions        = 2048
	MaxDisasmBytes               = 4096
)

// DisasmOptions selects one kernel function or loaded BPF program to
// disassemble.
type DisasmOptions struct {
	Kind            string
	Name            string
	ProgramID       uint32
	Bytes           uint32
	MaxInstructions int
	Syntax          string
}

// DisasmSource identifies the source line associated with an instruction.
type DisasmSource struct {
	File   string `json:"file,omitempty" jsonschema:"source file path from BPF or kernel debug metadata"`
	Line   uint32 `json:"line,omitempty" jsonschema:"one-based source line number"`
	Column uint32 `json:"column,omitempty" jsonschema:"one-based source column number"`
	Text   string `json:"text,omitempty" jsonschema:"source line text when available"`
	Inline bool   `json:"inline,omitempty" jsonschema:"true when debug metadata identifies an inlined call site"`
}

// DisasmLocation identifies the symbol containing an instruction or branch
// target.
type DisasmLocation struct {
	Name        string        `json:"name,omitempty" jsonschema:"function or symbol containing the address"`
	Address     string        `json:"address" jsonschema:"exact hexadecimal target address"`
	OffsetBytes uint64        `json:"offset_bytes" jsonschema:"offset from the containing function or symbol"`
	Module      string        `json:"module,omitempty" jsonschema:"kernel module containing the target"`
	BPF         bool          `json:"bpf,omitempty" jsonschema:"true when the target is a JITed BPF function"`
	Source      *DisasmSource `json:"source,omitempty" jsonschema:"source line at the branch target when available"`
}

// DisasmInstruction is one native machine instruction.
type DisasmInstruction struct {
	Address      string          `json:"address" jsonschema:"exact hexadecimal instruction address"`
	OffsetBytes  uint64          `json:"offset_bytes" jsonschema:"instruction offset from the function start"`
	Bytes        string          `json:"bytes" jsonschema:"machine instruction bytes as a hexadecimal string"`
	Mnemonic     string          `json:"mnemonic" jsonschema:"instruction mnemonic"`
	Operands     string          `json:"operands,omitempty" jsonschema:"architecture-specific instruction operands"`
	Source       *DisasmSource   `json:"source,omitempty" jsonschema:"source line active at this instruction"`
	BranchTarget *DisasmLocation `json:"branch_target,omitempty" jsonschema:"resolved direct branch or call target"`
}

// DisasmFunction contains the bounded instruction stream of one function.
type DisasmFunction struct {
	Name              string              `json:"name" jsonschema:"function name"`
	Prototype         string              `json:"prototype,omitempty" jsonschema:"BTF function prototype when available"`
	Address           string              `json:"address" jsonschema:"exact hexadecimal function start address"`
	SizeBytes         uint64              `json:"size_bytes" jsonschema:"number of machine-code bytes in the selected function range"`
	BytesDisassembled uint64              `json:"bytes_disassembled" jsonschema:"number of bytes represented by returned instructions"`
	Instructions      []DisasmInstruction `json:"instructions" jsonschema:"ordered native machine instructions"`
	Truncated         bool                `json:"truncated" jsonschema:"true when the instruction limit or undecodable trailing bytes shortened this function"`
}

// DisasmOutput contains bounded, structured native disassembly for an MCP
// request.
type DisasmOutput struct {
	Kind         string           `json:"kind" jsonschema:"disassembled target kind"`
	Name         string           `json:"name" jsonschema:"resolved target name"`
	ProgramID    uint32           `json:"program_id,omitempty" jsonschema:"loaded BPF program ID"`
	ProgramName  string           `json:"program_name,omitempty" jsonschema:"kernel-visible BPF program name"`
	ProgramType  string           `json:"program_type,omitempty" jsonschema:"loaded BPF program type"`
	Architecture string           `json:"architecture" jsonschema:"native instruction architecture"`
	Syntax       string           `json:"syntax" jsonschema:"assembly operand syntax"`
	Functions    []DisasmFunction `json:"functions" jsonschema:"ordered disassembled functions"`
	Truncated    bool             `json:"truncated" jsonschema:"true when the global instruction limit shortened the result"`
}

type disasmFunctionRange struct {
	name    string
	address uint64
	size    uint64
	module  string
	bpf     bool
}

func validateDisasmOptions(options *DisasmOptions) error {
	if options.MaxInstructions == 0 {
		options.MaxInstructions = DefaultDisasmMaxInstructions
	}
	if options.MaxInstructions < 1 || options.MaxInstructions > MaxDisasmInstructions {
		return fmt.Errorf("max instructions %d must be between 1 and %d",
			options.MaxInstructions, MaxDisasmInstructions)
	}
	if options.Bytes > MaxDisasmBytes {
		return fmt.Errorf("disassembly byte count %d exceeds maximum %d",
			options.Bytes, MaxDisasmBytes)
	}
	if options.Syntax == "" {
		options.Syntax = "att"
	}
	if options.Syntax != "att" && options.Syntax != "intel" {
		return fmt.Errorf("unsupported disassembly syntax %q", options.Syntax)
	}
	if options.Syntax == "intel" && runtime.GOARCH != "amd64" {
		return errors.New("Intel syntax is only supported on amd64")
	}

	switch options.Kind {
	case DisasmKindFunction:
		if strings.TrimSpace(options.Name) == "" {
			return errors.New("function disassembly requires a target name or address")
		}
		if options.ProgramID != 0 {
			return errors.New("function disassembly does not accept a BPF program ID")
		}
	case DisasmKindBPFProgram:
		if options.ProgramID == 0 {
			return errors.New("BPF program disassembly requires a program ID")
		}
		if options.Bytes != 0 {
			return errors.New("byte count is only supported for kernel functions")
		}
	default:
		return fmt.Errorf("unsupported disassembly target kind %q", options.Kind)
	}
	return nil
}

// Disasm returns bounded native disassembly for one kernel function or loaded
// BPF program.
func Disasm(ctx context.Context, options DisasmOptions) (DisasmOutput, error) {
	if err := ctx.Err(); err != nil {
		return DisasmOutput{}, err
	}
	if err := validateDisasmOptions(&options); err != nil {
		return DisasmOutput{}, err
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return DisasmOutput{}, fmt.Errorf("unsupported architecture %s", runtime.GOARCH)
	}

	disassembler, err := bpfsnoop.NewDisassembler(ctx, options.Syntax)
	if err != nil {
		return DisasmOutput{}, err
	}
	defer disassembler.Close()
	if err := ctx.Err(); err != nil {
		return DisasmOutput{}, err
	}

	result := DisasmOutput{
		Kind:         options.Kind,
		Architecture: runtime.GOARCH,
		Syntax:       options.Syntax,
		Functions:    make([]DisasmFunction, 0, 1),
	}
	switch options.Kind {
	case DisasmKindFunction:
		return disassembleKernelFunction(ctx, options, disassembler, result)
	case DisasmKindBPFProgram:
		return disassembleBPFProgram(ctx, options, disassembler, result)
	default:
		panic("validated disassembly kind is unreachable")
	}
}

func disassembleKernelFunction(ctx context.Context, options DisasmOptions,
	disassembler *bpfsnoop.Disassembler,
	result DisasmOutput,
) (DisasmOutput, error) {
	target, err := disassembler.KernelFunction(options.Name, options.Bytes, MaxDisasmBytes)
	if err != nil {
		return DisasmOutput{}, err
	}

	ranges := []disasmFunctionRange{{
		name:    target.Name,
		address: target.Address,
		size:    uint64(len(target.Bytes)),
		module:  target.Module,
	}}
	remaining := options.MaxInstructions
	function, err := disassembleFunctionBytes(ctx, disassembler, target.Bytes, ranges[0],
		target.Prototype, nil, ranges, &remaining)
	if err != nil {
		return DisasmOutput{}, err
	}

	result.Name = target.Name
	result.Functions = append(result.Functions, function)
	result.Truncated = function.Truncated
	return result, nil
}

func disassembleBPFProgram(ctx context.Context, options DisasmOptions,
	disassembler *bpfsnoop.Disassembler,
	result DisasmOutput,
) (DisasmOutput, error) {
	program, err := ebpf.NewProgramFromID(ebpf.ProgramID(options.ProgramID))
	if err != nil {
		return DisasmOutput{}, fmt.Errorf("failed to open BPF program %d: %w", options.ProgramID, err)
	}
	defer program.Close()

	info, err := program.Info()
	if err != nil {
		return DisasmOutput{}, fmt.Errorf("failed to inspect BPF program %d: %w", options.ProgramID, err)
	}
	jitedInsns, ok := info.JitedInsns()
	if !ok || len(jitedInsns) == 0 {
		return DisasmOutput{}, fmt.Errorf("BPF program %d has no JITed instructions", options.ProgramID)
	}
	jitedAddresses, ok := info.JitedKsymAddrs()
	if !ok {
		return DisasmOutput{}, fmt.Errorf("BPF program %d has no JITed function addresses", options.ProgramID)
	}
	jitedLengths, ok := info.JitedFuncLens()
	if !ok {
		return DisasmOutput{}, fmt.Errorf("BPF program %d has no JITed function lengths", options.ProgramID)
	}
	funcInfos, err := info.FuncInfos()
	if err != nil {
		return DisasmOutput{}, fmt.Errorf("BPF program %d has no function metadata: %w",
			options.ProgramID, err)
	}
	if len(funcInfos) != len(jitedAddresses) || len(funcInfos) != len(jitedLengths) {
		return DisasmOutput{}, fmt.Errorf(
			"BPF program %d metadata mismatch: funcs=%d addresses=%d lengths=%d",
			options.ProgramID, len(funcInfos), len(jitedAddresses), len(jitedLengths),
		)
	}

	lines, lineErr := info.LineInfos()
	jitedLineAddresses, lineAddressOK := info.JitedLineInfos()
	sources := make(map[uint64]DisasmSource)
	if lineErr == nil && lineAddressOK && len(lines) == len(jitedLineAddresses) {
		for i, address := range jitedLineAddresses {
			file := lines[i].Line.FileName()
			if strings.HasPrefix(file, "./") {
				file = strings.TrimLeft(file, "./")
			}
			sources[address] = DisasmSource{
				File:   file,
				Line:   lines[i].Line.LineNumber(),
				Column: lines[i].Line.LineColumn(),
				Text:   strings.TrimSpace(lines[i].Line.Line()),
			}
		}
	}

	ranges := make([]disasmFunctionRange, len(funcInfos))
	for i, function := range funcInfos {
		ranges[i] = disasmFunctionRange{
			name:    function.Func.Name,
			address: uint64(jitedAddresses[i]),
			size:    uint64(jitedLengths[i]),
			bpf:     true,
		}
	}

	result.Name = info.Name
	if options.Name != "" {
		result.Name = options.Name
	}
	result.ProgramID = options.ProgramID
	result.ProgramName = info.Name
	result.ProgramType = info.Type.String()
	result.Functions = make([]DisasmFunction, 0, len(funcInfos))
	remaining := options.MaxInstructions
	insnOffset := 0
	matched := false
	for i, function := range funcInfos {
		if err := ctx.Err(); err != nil {
			return DisasmOutput{}, err
		}
		length := int(jitedLengths[i])
		if length < 0 || insnOffset+length > len(jitedInsns) {
			return DisasmOutput{}, fmt.Errorf("BPF program %d function %s is out of instruction bounds",
				options.ProgramID, function.Func.Name)
		}
		functionData := jitedInsns[insnOffset : insnOffset+length]
		insnOffset += length
		if options.Name != "" && function.Func.Name != options.Name {
			continue
		}
		matched = true
		if remaining == 0 {
			result.Truncated = true
			break
		}

		disassembled, err := disassembleFunctionBytes(ctx, disassembler, functionData,
			ranges[i], formatFuncPrototype(function.Func), sources, ranges, &remaining)
		if err != nil {
			return DisasmOutput{}, fmt.Errorf("failed to disassemble BPF function %s: %w",
				function.Func.Name, err)
		}
		result.Functions = append(result.Functions, disassembled)
		result.Truncated = result.Truncated || disassembled.Truncated
	}
	if options.Name != "" && !matched {
		return DisasmOutput{}, fmt.Errorf("BPF program %d has no function %q",
			options.ProgramID, options.Name)
	}
	if insnOffset < len(jitedInsns) && options.Name == "" {
		result.Truncated = true
	}
	return result, nil
}

func disassembleFunctionBytes(ctx context.Context, disassembler *bpfsnoop.Disassembler, data []byte,
	function disasmFunctionRange, prototype string, sources map[uint64]DisasmSource,
	ranges []disasmFunctionRange, remaining *int,
) (DisasmFunction, error) {
	result := DisasmFunction{
		Name:         function.name,
		Prototype:    prototype,
		Address:      fmt.Sprintf("%#x", function.address),
		SizeBytes:    uint64(len(data)),
		Instructions: make([]DisasmInstruction, 0, min(len(data), *remaining)),
	}
	bytesRemaining := data
	pc := function.address
	var currentSource *DisasmSource
	for len(bytesRemaining) != 0 {
		if err := ctx.Err(); err != nil {
			return DisasmFunction{}, err
		}
		if *remaining == 0 {
			result.Truncated = true
			break
		}
		if source, ok := sources[pc]; ok {
			copy := source
			currentSource = &copy
		}
		if !function.bpf {
			currentSource = makeDisasmSource(disassembler.KernelSource(pc))
		}
		instruction, err := disassembler.DecodeOne(bytesRemaining, pc)
		if err != nil {
			if runtime.GOARCH == "amd64" && bytesRemaining[0] == 0x82 {
				result.Instructions = append(result.Instructions, DisasmInstruction{
					Address:     fmt.Sprintf("%#x", pc),
					OffsetBytes: pc - function.address,
					Bytes:       "82",
					Mnemonic:    "(bad)",
					Source:      currentSource,
				})
				pc++
				bytesRemaining = bytesRemaining[1:]
				result.BytesDisassembled++
				*remaining--
				continue
			}
			if len(bytesRemaining) <= 10 {
				result.Truncated = true
				break
			}
			return DisasmFunction{}, fmt.Errorf("failed at address %#x: %w", pc, err)
		}

		size := uint64(instruction.Size)
		if size == 0 || size > uint64(len(bytesRemaining)) {
			return DisasmFunction{}, fmt.Errorf("invalid instruction size %d at address %#x", size, pc)
		}
		output := DisasmInstruction{
			Address:     fmt.Sprintf("%#x", pc),
			OffsetBytes: pc - function.address,
			Bytes:       hex.EncodeToString(instruction.Bytes),
			Mnemonic:    instruction.Mnemonic,
			Operands:    instruction.Operands,
			Source:      currentSource,
		}
		if target, ok := disasmBranchAddress(instruction.Operands); ok {
			output.BranchTarget = resolveDisasmLocation(target, ranges, sources,
				disassembler)
		}
		result.Instructions = append(result.Instructions, output)
		pc += size
		bytesRemaining = bytesRemaining[size:]
		result.BytesDisassembled += size
		*remaining--
	}
	return result, nil
}

func bpfDisasmSource(address uint64, function disasmFunctionRange,
	sources map[uint64]DisasmSource,
) *DisasmSource {
	var nearestAddress uint64
	var nearest DisasmSource
	found := false
	for sourceAddress, source := range sources {
		if sourceAddress < function.address || sourceAddress > address ||
			sourceAddress >= function.address+function.size {
			continue
		}
		if !found || sourceAddress > nearestAddress {
			nearestAddress = sourceAddress
			nearest = source
			found = true
		}
	}
	if !found {
		return nil
	}
	return &nearest
}

func disasmBranchAddress(operands string) (uint64, bool) {
	value := strings.TrimPrefix(strings.TrimSpace(operands), "#")
	if !strings.HasPrefix(value, "0x") {
		return 0, false
	}
	address, err := strconv.ParseUint(value, 0, 64)
	return address, err == nil
}

func resolveDisasmLocation(address uint64, ranges []disasmFunctionRange,
	sources map[uint64]DisasmSource, disassembler *bpfsnoop.Disassembler,
) *DisasmLocation {
	for _, function := range ranges {
		if function.address <= address && address < function.address+function.size {
			var source *DisasmSource
			if function.bpf {
				source = bpfDisasmSource(address, function, sources)
			} else {
				source = makeDisasmSource(disassembler.KernelSource(address))
			}
			return &DisasmLocation{
				Name:        function.name,
				Address:     fmt.Sprintf("%#x", address),
				OffsetBytes: address - function.address,
				Module:      function.module,
				BPF:         function.bpf,
				Source:      source,
			}
		}
	}
	location := disassembler.KernelLocation(address)
	return &DisasmLocation{
		Name:        location.Name,
		Address:     fmt.Sprintf("%#x", location.Address),
		OffsetBytes: location.OffsetBytes,
		Module:      location.Module,
		Source:      makeDisasmSource(location.Source),
	}
}

func makeDisasmSource(source *bpfsnoop.DisasmSource) *DisasmSource {
	if source == nil {
		return nil
	}
	return &DisasmSource{
		File:   source.File,
		Line:   source.Line,
		Inline: source.Inline,
	}
}
