// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/gobwas/glob"
	"golang.org/x/sys/unix"

	"github.com/bpfsnoop/bpfsnoop/internal/bpfsnoop"
	"github.com/bpfsnoop/bpfsnoop/internal/btfx"
)

const kernelBTFPath = "/sys/kernel/btf"

const (
	FindKindFunction   = "function"
	FindKindTracepoint = "tracepoint"
	FindKindBPFProgram = "bpf_program"
	FindKindBTFType    = "btf_type"

	DefaultFindLimit = 50
	MaxFindLimit     = 200
)

// FindOptions controls kernel object discovery.
type FindOptions struct {
	Pattern            string `json:"pattern"`
	Kind               string `json:"kind,omitempty"`
	Limit              int    `json:"limit,omitempty"`
	IncludeXlatedInsns bool   `json:"include_xlated_insns,omitempty"`
	IncludeJitedInsns  bool   `json:"include_jited_insns,omitempty"`
}

// FindBTFMember describes one immediate member of a BTF struct or union.
type FindBTFMember struct {
	Name         string `json:"name" jsonschema:"BTF member name; empty for an anonymous member"`
	Type         string `json:"type" jsonschema:"BTF member type"`
	OffsetBits   uint32 `json:"offset_bits" jsonschema:"member offset from the containing type in bits"`
	BitfieldSize uint32 `json:"bitfield_size,omitempty" jsonschema:"bitfield width in bits; omitted for non-bitfield members"`
}

// FindBTFArgument describes one argument of a BTF function or function
// prototype.
type FindBTFArgument struct {
	Name string `json:"name" jsonschema:"BTF function argument name; empty when unnamed"`
	Type string `json:"type" jsonschema:"BTF function argument type"`
}

// FindBTFEnumValue describes one named BTF enum value.
type FindBTFEnumValue struct {
	Name  string `json:"name" jsonschema:"BTF enum value name"`
	Value string `json:"value" jsonschema:"BTF enum value as an exact decimal integer"`
}

// FindBTFVariable describes one entry in a BTF data section.
type FindBTFVariable struct {
	Kind        string `json:"kind" jsonschema:"BTF data-section entry kind"`
	Name        string `json:"name" jsonschema:"BTF variable or function name"`
	Type        string `json:"type" jsonschema:"BTF variable type or function prototype"`
	OffsetBytes uint32 `json:"offset_bytes" jsonschema:"offset in the BTF data section in bytes"`
	SizeBytes   uint32 `json:"size_bytes" jsonschema:"size in the BTF data section in bytes"`
}

// FindBPFProgramFunction describes one BTF function record associated with a
// loaded BPF program.
type FindBPFProgramFunction struct {
	InstructionOffset uint64 `json:"instruction_offset" jsonschema:"raw BPF instruction offset of the function record"`
	Name              string `json:"name" jsonschema:"BPF function name"`
	Prototype         string `json:"prototype" jsonschema:"BTF function prototype"`
}

// FindBPFProgramLine describes one BTF line record associated with a loaded
// BPF program.
type FindBPFProgramLine struct {
	InstructionOffset uint64 `json:"instruction_offset" jsonschema:"raw BPF instruction offset where the source line becomes active"`
	File              string `json:"file,omitempty" jsonschema:"source file path"`
	Line              uint32 `json:"line,omitempty" jsonschema:"one-based source line number"`
	Column            uint32 `json:"column,omitempty" jsonschema:"one-based source column number"`
	Text              string `json:"text,omitempty" jsonschema:"source line text when available"`
}

// FindBPFInstruction describes one kernel-translated eBPF instruction.
type FindBPFInstruction struct {
	InstructionOffset uint64              `json:"instruction_offset" jsonschema:"raw eBPF instruction offset accounting for double-wide instructions"`
	Width             uint32              `json:"width" jsonschema:"instruction width in raw eBPF instruction slots"`
	OpCode            string              `json:"opcode" jsonschema:"decoded eBPF opcode"`
	Dst               string              `json:"dst" jsonschema:"raw destination register"`
	Src               string              `json:"src" jsonschema:"raw source register"`
	Offset            int16               `json:"offset" jsonschema:"raw signed instruction offset field"`
	Constant          string              `json:"constant" jsonschema:"raw signed instruction constant as an exact decimal integer"`
	Symbol            string              `json:"symbol,omitempty" jsonschema:"BPF symbol beginning at this instruction"`
	Reference         string              `json:"reference,omitempty" jsonschema:"BPF symbol or map referenced by this instruction"`
	Text              string              `json:"text" jsonschema:"human-readable decoded eBPF instruction"`
	Function          string              `json:"function,omitempty" jsonschema:"BTF function beginning at this instruction"`
	Prototype         string              `json:"prototype,omitempty" jsonschema:"BTF function prototype when a function begins here"`
	Source            *FindBPFProgramLine `json:"source,omitempty" jsonschema:"BTF source line active at this instruction"`
}

// findBPFJitedFunction contains the native instruction bytes for one JITed
// BPF function.
type findBPFJitedFunction struct {
	Name    string
	Address uint64
	Bytes   []byte
}

// findKernelFunctionSymbol describes one kallsyms address associated with a
// kernel function. A name can have more than one address across the kernel and
// its modules.
type findKernelFunctionSymbol struct {
	Address   uint64
	SizeBytes uint64
	Module    string
}

// findMatch describes one kernel object found by findObjects.
type findMatch struct {
	Kind                     string
	Name                     string
	Module                   string
	Prototype                string
	ID                       uint32
	ProgramName              string
	ProgramType              string
	Tag                      string
	BTF                      bool
	ProgramUID               *uint32
	ProgramBTFID             *uint32
	ProgramLoadedAt          string
	ProgramLoadNS            string
	ProgramXlated            *uint32
	ProgramJited             *uint32
	ProgramMemlock           *uint64
	ProgramVerified          *uint32
	ProgramMapIDs            []uint32
	ProgramKsyms             []uint64
	ProgramJitedLens         []uint32
	ProgramJitedLines        []uint64
	ProgramFunctions         []FindBPFProgramFunction
	ProgramLines             []FindBPFProgramLine
	ProgramXlatedInsns       []FindBPFInstruction
	ProgramJitedInsns        []findBPFJitedFunction
	Traceable                bool
	FunctionBTFID            *uint32
	FunctionSymbols          []findKernelFunctionSymbol
	FunctionFentry           bool
	FunctionFexit            bool
	FunctionKprobeMultiEntry bool
	FunctionKprobeMultiExit  bool
	BTFKind                  string
	BTFSize                  *uint32
	BTFMembers               []FindBTFMember
	BTFArguments             []FindBTFArgument
	BTFReturnType            string
	BTFTargetType            string
	BTFElementType           string
	BTFIndexType             string
	BTFElementCount          *uint32
	BTFEncoding              string
	BTFEnumSigned            *bool
	BTFEnumValues            []FindBTFEnumValue
	BTFLinkage               string
	BTFVariables             []FindBTFVariable
	BTFFwdKind               string
	BTFTags                  []string

	function *btf.Func
}

// findResult contains bounded, deterministically ordered discovery results.
type findResult struct {
	Matches   []findMatch
	Total     int
	Truncated bool
}

type findCollector struct {
	limit   int
	total   int
	seen    map[string]struct{}
	matches []findMatch
}

func newFindCollector(limit int) *findCollector {
	return &findCollector{
		limit:   limit,
		seen:    make(map[string]struct{}),
		matches: make([]findMatch, 0, limit),
	}
}

func findKindRank(kind string) int {
	switch kind {
	case FindKindFunction:
		return 0
	case FindKindTracepoint:
		return 1
	case FindKindBPFProgram:
		return 2
	case FindKindBTFType:
		return 3
	default:
		return 4
	}
}

func compareFindMatch(a, b findMatch) int {
	if cmp := findKindRank(a.Kind) - findKindRank(b.Kind); cmp != 0 {
		return cmp
	}
	if cmp := strings.Compare(a.Name, b.Name); cmp != 0 {
		return cmp
	}
	if cmp := strings.Compare(a.Module, b.Module); cmp != 0 {
		return cmp
	}
	if a.ID < b.ID {
		return -1
	}
	if a.ID > b.ID {
		return 1
	}
	if cmp := strings.Compare(a.ProgramName, b.ProgramName); cmp != 0 {
		return cmp
	}
	return strings.Compare(a.BTFKind, b.BTFKind)
}

func (c *findCollector) add(match findMatch) {
	key := fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%s\x00%s",
		match.Kind, match.Name, match.Module, match.ID, match.ProgramName, match.BTFKind)
	if _, ok := c.seen[key]; ok {
		return
	}
	c.seen[key] = struct{}{}
	c.total++

	idx := sort.Search(len(c.matches), func(i int) bool {
		return compareFindMatch(c.matches[i], match) >= 0
	})
	if len(c.matches) < c.limit {
		c.matches = append(c.matches, findMatch{})
		copy(c.matches[idx+1:], c.matches[idx:])
		c.matches[idx] = match
		return
	}
	if idx >= c.limit {
		return
	}

	c.matches = append(c.matches, findMatch{})
	copy(c.matches[idx+1:], c.matches[idx:c.limit])
	c.matches[idx] = match
	c.matches = c.matches[:c.limit]
}

func (c *findCollector) result() findResult {
	return findResult{
		Matches:   c.matches,
		Total:     c.total,
		Truncated: c.total > len(c.matches),
	}
}

func validateFindOptions(options *FindOptions) error {
	if options.Pattern == "" {
		return errors.New("find pattern must not be empty")
	}

	switch options.Kind {
	case "", FindKindFunction, FindKindTracepoint, FindKindBPFProgram, FindKindBTFType:
	default:
		return fmt.Errorf("unsupported find kind %q", options.Kind)
	}

	if options.Limit < 0 {
		return errors.New("find limit must not be negative")
	}
	if options.Limit == 0 {
		options.Limit = DefaultFindLimit
	}
	if options.Limit > MaxFindLimit {
		return fmt.Errorf("find limit %d exceeds maximum %d", options.Limit, MaxFindLimit)
	}
	if (options.IncludeXlatedInsns || options.IncludeJitedInsns) && options.Kind != FindKindBPFProgram {
		return errors.New("BPF instruction payloads require kind bpf_program")
	}
	return nil
}

func wantsFindKind(requested, kind string) bool {
	return requested == "" || requested == kind
}

func formatFuncPrototype(fn *btf.Func) string {
	proto := fn.Type.(*btf.FuncProto)
	var output strings.Builder

	returnType := btfx.Repr(proto.Return)
	output.WriteString(returnType)
	if !strings.HasSuffix(returnType, "*") {
		output.WriteByte(' ')
	}
	output.WriteString(fn.Name)
	output.WriteByte('(')
	for i, param := range proto.Params {
		if i != 0 {
			output.WriteString(", ")
		}
		paramType := btfx.Repr(param.Type)
		output.WriteString(paramType)
		if param.Name != "" {
			if !strings.HasSuffix(paramType, "*") {
				output.WriteByte(' ')
			}
			output.WriteString(param.Name)
		}
	}
	output.WriteByte(')')

	return output.String()
}

func btfTypeKind(typ btf.Type) string {
	switch typ.(type) {
	case *btf.Void:
		return "void"
	case *btf.Int:
		return "int"
	case *btf.Pointer:
		return "pointer"
	case *btf.Array:
		return "array"
	case *btf.Struct:
		return "struct"
	case *btf.Union:
		return "union"
	case *btf.Enum:
		return "enum"
	case *btf.Fwd:
		return "forward"
	case *btf.Typedef:
		return "typedef"
	case *btf.Volatile:
		return "volatile"
	case *btf.Const:
		return "const"
	case *btf.Restrict:
		return "restrict"
	case *btf.Var:
		return "variable"
	case *btf.Datasec:
		return "data_section"
	case *btf.Float:
		return "float"
	case *btf.Func:
		return "func"
	case *btf.FuncProto:
		return "func_proto"
	case *btf.TypeTag:
		return "type_tag"
	default:
		return "other"
	}
}

func btfDetailType(typ btf.Type) btf.Type {
	for {
		switch value := typ.(type) {
		case *btf.Func:
			typ = value.Type
		case *btf.Typedef:
			typ = value.Type
		case *btf.Volatile:
			typ = value.Type
		case *btf.Const:
			typ = value.Type
		case *btf.Restrict:
			typ = value.Type
		case *btf.TypeTag:
			typ = value.Type
		case *btf.Pointer:
			target := btfDetailType(value.Target)
			if _, ok := target.(*btf.FuncProto); ok {
				return target
			}
			return typ
		default:
			return typ
		}
	}
}

func populateBTFDetails(match *findMatch, typ btf.Type) {
	switch value := typ.(type) {
	case *btf.Typedef:
		match.BTFTargetType = btfx.Repr(value.Type)
		match.BTFTags = slices.Clone(value.Tags)
	case *btf.Struct:
		match.BTFTags = slices.Clone(value.Tags)
	case *btf.Union:
		match.BTFTags = slices.Clone(value.Tags)
	case *btf.Func:
		match.BTFLinkage = value.Linkage.String()
		match.BTFTags = slices.Clone(value.Tags)
	case *btf.Var:
		match.BTFTargetType = btfx.Repr(value.Type)
		match.BTFLinkage = value.Linkage.String()
		match.BTFTags = slices.Clone(value.Tags)
	}

	detail := btfDetailType(typ)
	switch value := detail.(type) {
	case *btf.Int:
		size := value.Size
		match.BTFSize = &size
		match.BTFEncoding = value.Encoding.String()

	case *btf.Pointer:
		size := uint32(8)
		match.BTFSize = &size
		match.BTFTargetType = btfx.Repr(value.Target)

	case *btf.Array:
		match.BTFElementType = btfx.Repr(value.Type)
		match.BTFIndexType = btfx.Repr(value.Index)
		count := value.Nelems
		match.BTFElementCount = &count
		if size, err := btf.Sizeof(value); err == nil {
			size := uint32(size)
			match.BTFSize = &size
		}

	case *btf.Struct:
		size := value.Size
		match.BTFSize = &size
		match.BTFMembers = make([]FindBTFMember, 0, len(value.Members))
		for _, member := range value.Members {
			match.BTFMembers = append(match.BTFMembers, FindBTFMember{
				Name:         member.Name,
				Type:         btfx.Repr(member.Type),
				OffsetBits:   uint32(member.Offset),
				BitfieldSize: uint32(member.BitfieldSize),
			})
		}

	case *btf.Union:
		size := value.Size
		match.BTFSize = &size
		match.BTFMembers = make([]FindBTFMember, 0, len(value.Members))
		for _, member := range value.Members {
			match.BTFMembers = append(match.BTFMembers, FindBTFMember{
				Name:         member.Name,
				Type:         btfx.Repr(member.Type),
				OffsetBits:   uint32(member.Offset),
				BitfieldSize: uint32(member.BitfieldSize),
			})
		}

	case *btf.FuncProto:
		match.BTFArguments = make([]FindBTFArgument, 0, len(value.Params))
		for _, argument := range value.Params {
			match.BTFArguments = append(match.BTFArguments, FindBTFArgument{
				Name: argument.Name,
				Type: btfx.Repr(argument.Type),
			})
		}
		match.BTFReturnType = btfx.Repr(value.Return)

	case *btf.Enum:
		size := value.Size
		match.BTFSize = &size
		signed := value.Signed
		match.BTFEnumSigned = &signed
		match.BTFEnumValues = make([]FindBTFEnumValue, 0, len(value.Values))
		for _, enumValue := range value.Values {
			var valueText string
			if value.Signed {
				shift := 64 - min(value.Size*8, 64)
				valueText = strconv.FormatInt(int64(enumValue.Value<<shift)>>shift, 10)
			} else {
				valueText = strconv.FormatUint(enumValue.Value, 10)
			}
			match.BTFEnumValues = append(match.BTFEnumValues, FindBTFEnumValue{
				Name:  enumValue.Name,
				Value: valueText,
			})
		}

	case *btf.Fwd:
		match.BTFFwdKind = value.Kind.String()

	case *btf.Var:
		match.BTFTargetType = btfx.Repr(value.Type)
		match.BTFLinkage = value.Linkage.String()

	case *btf.Datasec:
		size := value.Size
		match.BTFSize = &size
		match.BTFVariables = make([]FindBTFVariable, 0, len(value.Vars))
		for _, variable := range value.Vars {
			variableInfo := FindBTFVariable{
				Kind:        btfTypeKind(variable.Type),
				Name:        variable.Type.TypeName(),
				Type:        btfx.Repr(variable.Type),
				OffsetBytes: variable.Offset,
				SizeBytes:   variable.Size,
			}
			switch typedVariable := variable.Type.(type) {
			case *btf.Var:
				variableInfo.Type = btfx.Repr(typedVariable.Type)
			case *btf.Func:
				variableInfo.Type = formatFuncPrototype(typedVariable)
			}
			match.BTFVariables = append(match.BTFVariables, variableInfo)
		}

	case *btf.Float:
		size := value.Size
		match.BTFSize = &size
	}
}

func newBTFTypeMatch(name, module string, typ btf.Type) findMatch {
	match := findMatch{
		Kind:    FindKindBTFType,
		Name:    name,
		Module:  module,
		BTFKind: btfTypeKind(typ),
	}
	if fn, ok := typ.(*btf.Func); ok {
		match.Prototype = formatFuncPrototype(fn)
	}
	populateBTFDetails(&match, typ)
	return match
}

func walkKernelBTFs(ctx context.Context, visit func(string, *btf.Spec) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	kernelBTF, err := bpfsnoop.FindKernelBTF("vmlinux")
	if err != nil {
		return fmt.Errorf("failed to load kernel BTF: %w", err)
	}
	if err := visit("vmlinux", kernelBTF); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	entries, err := os.ReadDir(kernelBTFPath)
	if err != nil {
		return fmt.Errorf("failed to read kernel BTF directory: %w", err)
	}
	modules := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && entry.Name() != "vmlinux" {
			modules = append(modules, entry.Name())
		}
	}
	slices.Sort(modules)

	for _, module := range modules {
		if err := ctx.Err(); err != nil {
			return err
		}
		spec, err := bpfsnoop.FindKernelBTF(module)
		if err != nil {
			return fmt.Errorf("failed to load kernel module BTF %s: %w", module, err)
		}
		if err := visit(module, spec); err != nil {
			return err
		}
	}
	return nil
}

func addKernelFunctionMatch(module string, spec *btf.Spec, fn *btf.Func, ksyms *bpfsnoop.Kallsyms, collector *findCollector) {
	info := bpfsnoop.FindKernelFunction(fn, ksyms)
	functionModule := module
	if len(info.Symbols) != 0 {
		functionModule = info.Symbols[0].Module
	}
	match := findMatch{
		Kind:      FindKindFunction,
		Name:      fn.Name,
		Module:    functionModule,
		Prototype: formatFuncPrototype(fn),
		Traceable: info.Traceable,
		function:  fn,
	}
	if id, err := spec.TypeID(fn); err == nil {
		value := uint32(id)
		match.FunctionBTFID = &value
	}
	populateBTFDetails(&match, fn)
	collector.add(match)
}

func findExactKernelFunction(ctx context.Context, name string, ksyms *bpfsnoop.Kallsyms, collector *findCollector) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	visit := func(module string, spec *btf.Spec) error {
		types, err := spec.AnyTypesByName(name)
		if errors.Is(err, btf.ErrNotFound) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to find %q in %s BTF: %w", name, module, err)
		}
		for _, typ := range types {
			if fn, ok := typ.(*btf.Func); ok {
				addKernelFunctionMatch(module, spec, fn, ksyms, collector)
			}
		}
		return nil
	}

	modules := bpfsnoop.FindKernelFunctionModules(name, ksyms)
	if len(modules) == 0 {
		return walkKernelBTFs(ctx, visit)
	}
	for _, module := range modules {
		if err := ctx.Err(); err != nil {
			return err
		}
		if module == "vmlinux" {
			spec, err := bpfsnoop.FindKernelBTF(module)
			if err != nil {
				return fmt.Errorf("failed to load kernel BTF: %w", err)
			}
			if err := visit(module, spec); err != nil {
				return err
			}
			continue
		}
		spec, err := bpfsnoop.FindKernelBTF(module)
		if err != nil {
			return fmt.Errorf("failed to load kernel module BTF %s: %w", module, err)
		}
		if err := visit(module, spec); err != nil {
			return err
		}
	}
	return nil
}

func findKernelBTFObjects(ctx context.Context, matcher glob.Glob, findFunctions, findTypes bool, ksyms *bpfsnoop.Kallsyms, collector *findCollector) error {
	return walkKernelBTFs(ctx, func(module string, spec *btf.Spec) error {
		for typ, err := range spec.All() {
			if err != nil {
				return fmt.Errorf("failed to iterate %s BTF: %w", module, err)
			}
			if err := ctx.Err(); err != nil {
				return err
			}

			if fn, ok := typ.(*btf.Func); ok {
				if !matcher.Match(fn.Name) {
					continue
				}
				if findFunctions {
					addKernelFunctionMatch(module, spec, fn, ksyms, collector)
				}
				if findTypes {
					collector.add(newBTFTypeMatch(fn.Name, module, fn))
				}
				continue
			}

			if !findTypes {
				continue
			}
			name := typ.TypeName()
			if name == "" || !matcher.Match(name) {
				continue
			}
			collector.add(newBTFTypeMatch(name, module, typ))
		}
		return nil
	})
}

func populateKernelFunctionMetadata(ctx context.Context, result *findResult, ksyms *bpfsnoop.Kallsyms) error {
	hasFunction := false
	for i := range result.Matches {
		if result.Matches[i].Kind == FindKindFunction {
			hasFunction = true
			break
		}
	}
	if !hasFunction {
		return nil
	}

	features, err := bpfsnoop.GetBPFFeatures()
	if err != nil {
		return fmt.Errorf("failed to inspect kernel tracing capabilities: %w", err)
	}

	var availableFilterFunctions []string
	if features.HasKprobeMulti {
		availableFilterFunctions, err = bpfsnoop.FindKprobeMultiFunctions()
		if err != nil {
			return fmt.Errorf("failed to inspect kprobe.multi functions: %w", err)
		}
	}

	addressMatches := make(map[uintptr][]int)
	fexitCandidates := make(map[int]bool)
	for i := range result.Matches {
		match := &result.Matches[i]
		if match.Kind != FindKindFunction {
			continue
		}

		if match.function == nil {
			continue
		}
		info := bpfsnoop.FindKernelFunction(match.function, ksyms)
		match.FunctionSymbols = make([]findKernelFunctionSymbol, len(info.Symbols))
		for i, symbol := range info.Symbols {
			match.FunctionSymbols[i] = findKernelFunctionSymbol(symbol)
		}
		match.Traceable = false
		if !info.Traceable {
			continue
		}

		if features.HasKprobeMulti && info.KprobeMultiEntry {
			_, match.FunctionKprobeMultiEntry = slices.BinarySearch(availableFilterFunctions, match.Name)
			match.FunctionKprobeMultiExit = match.FunctionKprobeMultiEntry && info.KprobeMultiExit
		}

		if info.FentryCandidate {
			addressMatches[info.Address] = append(addressMatches[info.Address], i)
			fexitCandidates[i] = info.FexitCandidate
		}
	}

	if len(addressMatches) != 0 {
		addresses := slices.Sorted(maps.Keys(addressMatches))
		for len(addresses) != 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
			count := min(len(addresses), bpfsnoop.AddrCap)
			batch := addresses[:count]
			traceable, err := bpfsnoop.FindKernelFunctionTraceability(batch)
			if err != nil {
				return fmt.Errorf("failed to detect function traceability: %w", err)
			}
			for i, address := range batch {
				for _, matchIndex := range addressMatches[address] {
					match := &result.Matches[matchIndex]
					match.FunctionFentry = traceable[i]
					match.FunctionFexit = traceable[i] && fexitCandidates[matchIndex]
				}
			}
			addresses = addresses[count:]
		}
	}

	for i := range result.Matches {
		match := &result.Matches[i]
		if match.Kind == FindKindFunction {
			// Traceable retains its original fentry/fexit meaning. kprobe.multi
			// availability is reported independently.
			match.Traceable = match.FunctionFentry || match.FunctionFexit
		}
	}
	return nil
}

func findTracepoints(ctx context.Context, pattern string, ksyms *bpfsnoop.Kallsyms, collector *findCollector) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	tracepoints, err := bpfsnoop.FindTracepoints(pattern, ksyms)
	if err != nil {
		return fmt.Errorf("failed to discover kernel tracepoints: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for name, tracepoint := range tracepoints {
		collector.add(findMatch{
			Kind:      FindKindTracepoint,
			Name:      name,
			Prototype: formatFuncPrototype(tracepoint.Func),
		})
	}
	return nil
}

func findValuePtr[T any](value T) *T {
	return &value
}

func bpfProgramLoadedAt(loadTime time.Duration) string {
	var bootTime unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &bootTime); err != nil {
		return ""
	}
	loadedAt := time.Now().Add(loadTime - time.Duration(bootTime.Nano()))
	return loadedAt.Format(time.RFC3339Nano)
}

func populateBPFProgramMetadata(match *findMatch, info *ebpf.ProgramInfo, options FindOptions) error {
	if uid, ok := info.CreatedByUID(); ok {
		match.ProgramUID = findValuePtr(uid)
	}
	if btfID, ok := info.BTFID(); ok {
		value := uint32(btfID)
		match.ProgramBTFID = &value
	}
	if loadTime, ok := info.LoadTime(); ok {
		match.ProgramLoadNS = strconv.FormatInt(int64(loadTime), 10)
		match.ProgramLoadedAt = bpfProgramLoadedAt(loadTime)
	}
	if size, err := info.TranslatedSize(); err == nil {
		value := uint32(size)
		match.ProgramXlated = &value
	}
	if size, err := info.JitedSize(); err == nil {
		match.ProgramJited = &size
	}
	if memlock, ok := info.Memlock(); ok {
		match.ProgramMemlock = &memlock
	}
	if verified, ok := info.VerifiedInstructions(); ok {
		match.ProgramVerified = &verified
	}
	if mapIDs, ok := info.MapIDs(); ok {
		match.ProgramMapIDs = make([]uint32, len(mapIDs))
		for i, id := range mapIDs {
			match.ProgramMapIDs[i] = uint32(id)
		}
	}
	if addresses, ok := info.JitedKsymAddrs(); ok {
		match.ProgramKsyms = make([]uint64, len(addresses))
		for i, address := range addresses {
			match.ProgramKsyms[i] = uint64(address)
		}
	}
	if lengths, ok := info.JitedFuncLens(); ok {
		match.ProgramJitedLens = slices.Clone(lengths)
	}
	if addresses, ok := info.JitedLineInfos(); ok {
		match.ProgramJitedLines = slices.Clone(addresses)
	}
	if functions, err := info.FuncInfos(); err == nil {
		match.ProgramFunctions = make([]FindBPFProgramFunction, 0, len(functions))
		for _, function := range functions {
			match.ProgramFunctions = append(match.ProgramFunctions, FindBPFProgramFunction{
				InstructionOffset: uint64(function.Offset),
				Name:              function.Func.Name,
				Prototype:         formatFuncPrototype(function.Func),
			})
		}
	}
	if lines, err := info.LineInfos(); err == nil {
		match.ProgramLines = make([]FindBPFProgramLine, 0, len(lines))
		for _, line := range lines {
			match.ProgramLines = append(match.ProgramLines, FindBPFProgramLine{
				InstructionOffset: uint64(line.Offset),
				File:              line.Line.FileName(),
				Line:              line.Line.LineNumber(),
				Column:            line.Line.LineColumn(),
				Text:              strings.TrimSpace(line.Line.Line()),
			})
		}
	}

	if options.IncludeXlatedInsns {
		match.ProgramXlatedInsns = make([]FindBPFInstruction, 0)
		instructions, err := info.Instructions()
		if err != nil {
			return fmt.Errorf("failed to read translated instructions for BPF program %d: %w", match.ID, err)
		}
		iterator := instructions.Iterate()
		for iterator.Next() {
			instruction := iterator.Ins
			output := FindBPFInstruction{
				InstructionOffset: uint64(iterator.Offset),
				Width:             uint32(instruction.Width()),
				OpCode:            instruction.OpCode.String(),
				Dst:               instruction.Dst.String(),
				Src:               instruction.Src.String(),
				Offset:            instruction.Offset,
				Constant:          strconv.FormatInt(instruction.Constant, 10),
				Symbol:            instruction.Symbol(),
				Reference:         instruction.Reference(),
				Text:              fmt.Sprintf("%v", instruction),
			}
			if fn := btf.FuncMetadata(instruction); fn != nil {
				output.Function = fn.Name
				output.Prototype = formatFuncPrototype(fn)
			}
			if line, ok := instruction.Source().(*btf.Line); ok {
				output.Source = &FindBPFProgramLine{
					InstructionOffset: uint64(iterator.Offset),
					File:              line.FileName(),
					Line:              line.LineNumber(),
					Column:            line.LineColumn(),
					Text:              strings.TrimSpace(line.Line()),
				}
			}
			match.ProgramXlatedInsns = append(match.ProgramXlatedInsns, output)
		}
	}

	if options.IncludeJitedInsns {
		match.ProgramJitedInsns = make([]findBPFJitedFunction, 0)
		instructions, ok := info.JitedInsns()
		if !ok {
			return fmt.Errorf("BPF program %d has no JITed instructions", match.ID)
		}
		if len(match.ProgramJitedLens) == len(match.ProgramFunctions) && len(match.ProgramJitedLens) != 0 {
			offset := 0
			for i, length := range match.ProgramJitedLens {
				end := offset + int(length)
				if end > len(instructions) {
					return fmt.Errorf("BPF program %d JITed function lengths exceed instruction payload", match.ID)
				}
				function := findBPFJitedFunction{
					Name:  match.ProgramFunctions[i].Name,
					Bytes: slices.Clone(instructions[offset:end]),
				}
				if i < len(match.ProgramKsyms) {
					function.Address = match.ProgramKsyms[i]
				}
				match.ProgramJitedInsns = append(match.ProgramJitedInsns, function)
				offset = end
			}
			if offset != len(instructions) {
				return fmt.Errorf("BPF program %d JITed function lengths do not cover instruction payload", match.ID)
			}
		} else {
			address := uint64(0)
			if len(match.ProgramKsyms) != 0 {
				address = match.ProgramKsyms[0]
			}
			match.ProgramJitedInsns = append(match.ProgramJitedInsns, findBPFJitedFunction{
				Name:    match.Name,
				Address: address,
				Bytes:   slices.Clone(instructions),
			})
		}
	}

	return nil
}

func findBPFPrograms(ctx context.Context, matcher glob.Glob, options FindOptions, collector *findCollector) error {
	for id, err := ebpf.ProgramGetNextID(0); ; id, err = ebpf.ProgramGetNextID(id) {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to enumerate loaded BPF programs: %w", err)
		}
		program, err := ebpf.NewProgramFromID(id)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("failed to open BPF program %d: %w", id, err)
		}
		info, err := func() (*ebpf.ProgramInfo, error) {
			defer program.Close()
			return program.Info()
		}()
		if err != nil {
			return fmt.Errorf("failed to inspect BPF program %d: %w", id, err)
		}

		entryName := ""
		_, hasBTF := info.BTFID()
		if hasBTF {
			entryName, _ = bpfsnoop.FindBPFProgramEntryName(info)
		}
		idText := strconv.FormatUint(uint64(id), 10)
		if !matcher.Match(info.Name) && !matcher.Match(entryName) &&
			!matcher.Match(info.Tag) && !matcher.Match(idText) {
			continue
		}

		name := entryName
		if name == "" {
			name = info.Name
		}
		if name == "" {
			name = idText
		}
		match := findMatch{
			Kind:        FindKindBPFProgram,
			Name:        name,
			ID:          uint32(id),
			ProgramName: info.Name,
			ProgramType: info.Type.String(),
			Tag:         info.Tag,
			BTF:         hasBTF,
		}
		if err := populateBPFProgramMetadata(&match, info, options); err != nil {
			return err
		}
		collector.add(match)
	}
}

// findObjects discovers kernel and BPF objects matching a name or glob.
func findObjects(ctx context.Context, options FindOptions) (findResult, error) {
	if err := ctx.Err(); err != nil {
		return findResult{}, err
	}
	if err := validateFindOptions(&options); err != nil {
		return findResult{}, err
	}
	matcher, err := glob.Compile(options.Pattern)
	if err != nil {
		return findResult{}, fmt.Errorf("invalid find pattern %q: %w", options.Pattern, err)
	}

	findFunctions := wantsFindKind(options.Kind, FindKindFunction)
	findTracepoint := wantsFindKind(options.Kind, FindKindTracepoint)
	findPrograms := wantsFindKind(options.Kind, FindKindBPFProgram)
	findTypes := wantsFindKind(options.Kind, FindKindBTFType)
	var ksyms *bpfsnoop.Kallsyms
	if findFunctions || findTracepoint {
		ksyms, err = bpfsnoop.NewKallsyms()
		if err != nil {
			return findResult{}, err
		}
	}

	collector := newFindCollector(options.Limit)
	if findFunctions || findTypes {
		var err error
		if options.Kind == FindKindFunction && glob.QuoteMeta(options.Pattern) == options.Pattern {
			err = findExactKernelFunction(ctx, options.Pattern, ksyms, collector)
		} else {
			err = findKernelBTFObjects(ctx, matcher, findFunctions, findTypes, ksyms, collector)
		}
		if err != nil {
			return findResult{}, err
		}
	}
	if findTracepoint {
		if err := findTracepoints(ctx, options.Pattern, ksyms, collector); err != nil {
			return findResult{}, err
		}
	}
	if findPrograms {
		if err := findBPFPrograms(ctx, matcher, options, collector); err != nil {
			return findResult{}, err
		}
	}

	result := collector.result()
	if findFunctions {
		if err := populateKernelFunctionMetadata(ctx, &result, ksyms); err != nil {
			return findResult{}, err
		}
	}
	return result, nil
}
