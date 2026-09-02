// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/btf"

	"github.com/bpfsnoop/bpfsnoop/internal/atomix"
	"github.com/bpfsnoop/bpfsnoop/internal/btfx"
)

type disasmDebugSetupStage uint8

const (
	disasmDebugSetupNone disasmDebugSetupStage = iota
	disasmDebugSetupFindVmlinux
	disasmDebugSetupReadText
	disasmDebugSetupCreateAddr2Line
)

type disasmAddr2LineSetup struct {
	addr2line *Addr2Line
	vmlinux   string
	stage     disasmDebugSetupStage
	err       error
}

var disasmAddr2LineOnce = atomix.NewOnce(loadDisasmAddr2Line)

type disasmAddr2LineResult struct {
	setup disasmAddr2LineSetup
	err   error
}

func prepareDisasmAddr2Line(ctx context.Context) (disasmAddr2LineSetup, error) {
	resultCh := make(chan disasmAddr2LineResult, 1)
	go func() {
		setup, err := disasmAddr2LineOnce.Do()
		resultCh <- disasmAddr2LineResult{setup: setup, err: err}
	}()
	select {
	case <-ctx.Done():
		return disasmAddr2LineSetup{}, ctx.Err()
	case result := <-resultCh:
		return result.setup, result.err
	}
}

func loadDisasmAddr2Line() (disasmAddr2LineSetup, error) {
	kallsyms, err := NewKallsyms()
	if err != nil {
		return disasmAddr2LineSetup{
			err: fmt.Errorf("read kallsyms for addr2line: %w", err),
		}, nil
	}

	vmlinux, err := FindVmlinux()
	if err != nil {
		return disasmAddr2LineSetup{
			stage: disasmDebugSetupFindVmlinux,
			err:   fmt.Errorf("find vmlinux: %w", err),
		}, nil
	}
	textAddress, err := ReadTextAddrFromVmlinux(vmlinux)
	if err != nil {
		return disasmAddr2LineSetup{
			vmlinux: vmlinux,
			stage:   disasmDebugSetupReadText,
			err:     fmt.Errorf("read .text address: %w", err),
		}, nil
	}
	addr2line, err := NewAddr2Line(vmlinux,
		NewKaslr(kallsyms.Stext(), textAddress), kallsyms.SysBPF(), kallsyms.Stext())
	if err != nil {
		return disasmAddr2LineSetup{
			vmlinux: vmlinux,
			stage:   disasmDebugSetupCreateAddr2Line,
			err:     fmt.Errorf("create addr2line: %w", err),
		}, nil
	}
	return disasmAddr2LineSetup{
		addr2line: addr2line,
		vmlinux:   vmlinux,
	}, nil
}

func resolveKernelTarget(name string, kallsyms *Kallsyms) (*KsymEntry, error) {
	if strings.HasPrefix(name, "0x") {
		address, err := strconv.ParseUint(name, 0, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid kernel address %q: %w", name, err)
		}
		entry, ok := kallsyms.find(uintptr(address))
		if !ok {
			return nil, fmt.Errorf("kernel address %s is not in kallsyms", name)
		}
		copy := *entry
		copy.addr = address
		return &copy, nil
	}

	entry, ok := kallsyms.findBySymbol(name)
	if !ok {
		return nil, fmt.Errorf("kernel function %q was not found", name)
	}
	return entry, nil
}

func kernelFunctionPrototype(name, module string) string {
	if err := PrepareKernelBTF(); err != nil {
		return ""
	}
	spec := getKernelBTF()
	if module != "" {
		if moduleSpec, err := btfCache.Module(module); err == nil {
			spec = moduleSpec
		}
	}
	if spec == nil {
		return ""
	}
	types, err := spec.AnyTypesByName(name)
	if err != nil {
		return ""
	}
	for _, typ := range types {
		if fn, ok := typ.(*btf.Func); ok {
			return formatKernelFuncPrototype(fn)
		}
	}
	return ""
}

func formatKernelFuncPrototype(fn *btf.Func) string {
	proto, ok := fn.Type.(*btf.FuncProto)
	if !ok {
		return ""
	}

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

func kernelSource(address uint64, kallsyms *Kallsyms, addr2line *Addr2Line) *DisasmSource {
	if addr2line == nil {
		return nil
	}
	entry, ok := kallsyms.find(uintptr(address))
	if !ok {
		return nil
	}
	line, err := addr2line.get(uintptr(address), entry)
	if err != nil {
		return nil
	}
	file := line.File
	if strings.HasPrefix(file, addr2line.buildDir) {
		file = file[len(addr2line.buildDir):]
	}
	if file == "" && line.Line == 0 {
		return nil
	}
	return &DisasmSource{
		File:   file,
		Line:   uint32(line.Line),
		Inline: line.Inline,
	}
}
