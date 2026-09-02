// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"context"
	"errors"
	"fmt"

	"github.com/bpfsnoop/bpfsnoop/internal/assert"
	"github.com/bpfsnoop/gapstone"
)

// KernelFunction contains the bytes and metadata for one kernel function
// selected for disassembly.
type KernelFunction struct {
	Name      string
	Address   uint64
	Module    string
	Prototype string
	Bytes     []byte
}

// Instruction contains the neutral information needed by the disassembly
// API for one native instruction.
type Instruction struct {
	Size     uint64
	Bytes    []byte
	Mnemonic string
	Operands string
}

// DisasmSource identifies a kernel source line.
type DisasmSource struct {
	File   string
	Line   uint32
	Inline bool
}

// DisasmLocation identifies the kernel symbol containing an address.
type DisasmLocation struct {
	Name        string
	Address     uint64
	OffsetBytes uint64
	Module      string
	Source      *DisasmSource
}

// Disassembler owns the resources needed to inspect and disassemble native
// kernel code. Its implementation details remain private to this package.
type Disassembler struct {
	disasmAddr2LineSetup
	engine   *gapstone.Engine
	kallsyms *Kallsyms
}

var errDisassemblerClosed = errors.New("disassembler is closed")

// NewDisassembler creates a disassembler for the requested assembly syntax.
// Kernel symbol and debug metadata are prepared as part of construction.
func NewDisassembler(ctx context.Context, syntax string) (*Disassembler, error) {
	if ctx == nil {
		return nil, errors.New("disassembler context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	engine, err := createGapstoneEngineWithSyntax(syntax)
	if err != nil {
		return nil, err
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = engine.Close()
		}
	}()

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	kallsyms, err := NewKallsyms()
	if err != nil {
		return nil, fmt.Errorf("failed to read kallsyms: %w", err)
	}

	debugSetup, err := prepareDisasmAddr2Line(ctx)
	if err != nil {
		return nil, err
	}
	disassembler := &Disassembler{
		engine:               engine,
		kallsyms:             kallsyms,
		disasmAddr2LineSetup: debugSetup,
	}

	closeOnError = false
	return disassembler, nil
}

// Close releases resources owned by the disassembler. It is safe to call
// Close more than once.
func (d *Disassembler) Close() error {
	if d == nil || d.engine == nil {
		return nil
	}

	engine := d.engine
	d.engine = nil
	d.kallsyms = nil
	d.disasmAddr2LineSetup = disasmAddr2LineSetup{}
	if err := engine.Close(); err != nil && err != gapstone.ErrOK {
		return err
	}
	return nil
}

// KernelFunction reads one exact kernel function or address, bounded by
// maxBytes. A zero byte count lets the symbol table determine the range.
func (d *Disassembler) KernelFunction(name string, bytes, maxBytes uint32) (KernelFunction, error) {
	if d == nil || d.engine == nil || d.kallsyms == nil {
		return KernelFunction{}, errDisassemblerClosed
	}

	entry, err := resolveKernelTarget(name, d.kallsyms)
	if err != nil {
		return KernelFunction{}, err
	}
	function, err := d.readKernelFunction(entry.name, entry.addr, entry.mod, bytes, maxBytes)
	if err != nil {
		return KernelFunction{}, err
	}
	function.Prototype = kernelFunctionPrototype(entry.name, entry.mod)
	return function, nil
}

func (d *Disassembler) readKernelFunction(name string, address uint64, module string,
	bytes, maxBytes uint32,
) (KernelFunction, error) {
	if d == nil || d.engine == nil || d.kallsyms == nil {
		return KernelFunction{}, errDisassemblerClosed
	}

	byteCount := guessBytes(uintptr(address), d.kallsyms, uint(bytes))
	if byteCount > uint(maxBytes) {
		return KernelFunction{}, fmt.Errorf("disassembly byte count %d exceeds maximum %d",
			byteCount, maxBytes)
	}
	defer FlushReadObjs()
	data, err := readKernel(address, uint32(byteCount))
	if err != nil {
		return KernelFunction{}, fmt.Errorf("failed to read %d bytes from kernel function %s: %w",
			byteCount, name, err)
	}
	data = trimTailingInsns(data)
	return KernelFunction{
		Name:    name,
		Address: address,
		Module:  module,
		Bytes:   data,
	}, nil
}

// DecodeOne decodes the first native instruction in code at pc.
func (d *Disassembler) DecodeOne(code []byte, pc uint64) (Instruction, error) {
	if d == nil || d.engine == nil {
		return Instruction{}, errDisassemblerClosed
	}
	if len(code) == 0 {
		return Instruction{}, errors.New("no instruction bytes")
	}

	instructions, err := d.engine.Disasm(code, pc, 1)
	if err != nil || len(instructions) == 0 {
		if err == nil {
			err = gapstone.ErrOK
		}
		return Instruction{}, err
	}

	instruction := instructions[0]
	return Instruction{
		Size:     uint64(instruction.Size),
		Bytes:    append([]byte(nil), instruction.Bytes...),
		Mnemonic: instruction.Mnemonic,
		Operands: instruction.OpStr,
	}, nil
}

// KernelSource resolves source information for a kernel address when debug
// metadata is available.
func (d *Disassembler) KernelSource(address uint64) *DisasmSource {
	if d == nil || d.engine == nil || d.kallsyms == nil {
		return nil
	}
	return kernelSource(address, d.kallsyms, d.addr2line)
}

// KernelLocation resolves the kernel symbol and source for an address.
func (d *Disassembler) KernelLocation(address uint64) DisasmLocation {
	location := DisasmLocation{Address: address}
	if d == nil || d.engine == nil || d.kallsyms == nil {
		return location
	}

	entry, ok := d.kallsyms.find(uintptr(address))
	if !ok {
		return location
	}
	location.Name = entry.name
	location.OffsetBytes = address - entry.addr
	location.Module = entry.mod
	location.Source = d.KernelSource(address)
	return location
}

func (d *Disassembler) verboseLog() {
	if d.vmlinux != "" {
		VerboseLog("Found vmlinux: %s", d.vmlinux)
		VerboseLog("Creating addr2line from vmlinux ..")
	}

	if d.err == nil {
		return
	}

	err := errors.Unwrap(d.err)
	switch d.stage {
	case disasmDebugSetupFindVmlinux:
		if errors.Is(err, ErrNotFound) {
			VerboseLog("Dbgsym vmlinux not found")
		} else {
			assert.NoErr(err, "Failed to find vmlinux: %v")
		}
	case disasmDebugSetupReadText:
		assert.NoErr(err, "Failed to read .text address from vmlinux: %v")
	case disasmDebugSetupCreateAddr2Line:
		assert.NoErr(err, "Failed to create addr2line: %v")
	default:
		assert.NoErr(d.err, "Failed to prepare addr2line: %v")
	}
}
