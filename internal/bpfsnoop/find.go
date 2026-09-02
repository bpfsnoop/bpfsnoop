// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"errors"
	"maps"
	"slices"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"

	"github.com/bpfsnoop/bpfsnoop/internal/bpf"
)

// FindKernelFunctionSymbol describes one address associated with a kernel
// function name.
type FindKernelFunctionSymbol struct {
	Address   uint64
	SizeBytes uint64
	Module    string
}

// FindKernelFunctionInfo contains the low-level facts needed to describe a
// kernel function and determine its supported attachment modes.
type FindKernelFunctionInfo struct {
	Address          uintptr
	Symbols          []FindKernelFunctionSymbol
	Traceable        bool
	FentryCandidate  bool
	FexitCandidate   bool
	KprobeMultiEntry bool
	KprobeMultiExit  bool
}

// FindKernelBTF returns the BTF specification for vmlinux or a kernel module.
func FindKernelBTF(module string) (*btf.Spec, error) {
	if err := PrepareKernelBTF(); err != nil {
		return nil, err
	}
	if module == "" || module == "vmlinux" {
		spec := getKernelBTF()
		if spec == nil {
			return nil, errors.New("kernel BTF is unavailable")
		}
		return spec, nil
	}
	return btfCache.Module(module)
}

// FindKernelFunction returns kallsyms and attachment facts for fn.
func FindKernelFunction(fn *btf.Func, ksyms *Kallsyms) FindKernelFunctionInfo {
	var info FindKernelFunctionInfo
	ksym := ksyms.n2s[fn.Name]
	if ksym == nil {
		return info
	}

	addresses := append([]uint64{ksym.addr}, ksym.extra...)
	slices.Sort(addresses)
	addresses = slices.Compact(addresses)
	info.Symbols = make([]FindKernelFunctionSymbol, 0, len(addresses))
	for _, address := range addresses {
		entry := ksyms.a2s[address]
		module := "vmlinux"
		if entry != nil && entry.mod != "" {
			module = entry.mod
		}
		var size uint64
		if next, ok := ksyms.next(uintptr(address)); ok {
			size = next.addr - address
		}
		info.Symbols = append(info.Symbols, FindKernelFunctionSymbol{
			Address:   address,
			SizeBytes: size,
			Module:    module,
		})
	}

	_, info.Traceable = checkKfuncTraceable(fn, ksyms, true, true)
	if !info.Traceable {
		return info
	}
	info.KprobeMultiEntry = !skipKprobeMultiSymbol(fn.Name)
	info.KprobeMultiExit = info.KprobeMultiEntry && !slices.Contains(noreturnFuncs, fn.Name)
	if slices.Contains(tracingDenyFuncs, fn.Name) {
		return info
	}
	entry, eligible := checkKfuncTraceable(fn, ksyms, false, true)
	if eligible {
		info.Address = uintptr(entry.addr)
		info.FentryCandidate = true
		info.FexitCandidate = !slices.Contains(noreturnFuncs, fn.Name)
	}
	return info
}

// FindKernelFunctionModules returns the modules containing a symbol name.
func FindKernelFunctionModules(name string, ksyms *Kallsyms) []string {
	ksym := ksyms.n2s[name]
	if ksym == nil {
		return nil
	}
	modules := make(map[string]struct{})
	for _, address := range append([]uint64{ksym.addr}, ksym.extra...) {
		module := "vmlinux"
		if entry := ksyms.a2s[address]; entry != nil && entry.mod != "" {
			module = entry.mod
		}
		modules[module] = struct{}{}
	}
	return slices.Sorted(maps.Keys(modules))
}

// FindKernelFunctionTraceability probes fentry/fexit support for addresses.
func FindKernelFunctionTraceability(addresses []uintptr) ([]bool, error) {
	spec, err := bpf.LoadTraceable()
	if err != nil {
		return nil, err
	}
	traceable, _, err := detectTraceable(spec, addresses)
	return traceable, err
}

// FindKprobeMultiFunctions returns the cached kprobe.multi function names.
func FindKprobeMultiFunctions() ([]string, error) {
	return loadAvailableFilterFunctions()
}

// FindTracepoints discovers tracepoints matching pattern.
func FindTracepoints(pattern string, ksyms *Kallsyms) (Tracepoints, error) {
	if err := PrepareKernelBTF(); err != nil {
		return nil, err
	}
	return probeKernelTracepoints([]string{pattern}, ksyms, true)
}

// FindBPFProgramEntryName returns the BTF entry function name for a BPF
// program.
func FindBPFProgramEntryName(info *ebpf.ProgramInfo) (string, error) {
	return getProgEntryFuncName(info)
}
