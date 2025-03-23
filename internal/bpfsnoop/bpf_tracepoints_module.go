// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"errors"
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/bpfsnoop/bpfsnoop/internal/strx"
)

const (
	tpModuleMax    = 256
	tpModuleMaxTps = 65536
)

type tracepointModuleInfo struct {
	module string
	tps    map[string]tracepointInfo
}

type TpModuleInfo struct {
	Name           [56]byte
	NrBpfRawEvents uint64
	BpfRawEvent    uint64
}

func probeTracepointModuleInfos(spec, tpSpec *ebpf.CollectionSpec, head, start uint64, ksyms *Kallsyms) (map[string]tracepointModuleInfo, error) {
	spec = spec.Copy()

	if err := spec.Variables["__head"].Set(head); err != nil {
		return nil, fmt.Errorf("failed to set __head: %w", err)
	}
	if err := spec.Variables["__start"].Set(start); err != nil {
		return nil, fmt.Errorf("failed to set __start: %w", err)
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogDisabled: true,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create bpf collection: %w", err)
	}
	defer coll.Close()

	prog := coll.Programs["probe"]
	l, err := link.AttachTracing(link.TracingOptions{
		Program:    prog,
		AttachType: ebpf.AttachTraceFEntry,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to attach tracing: %w", err)
	}
	defer l.Close()

	nanosleep()

	var run bool
	if err := coll.Variables["run"].Get(&run); err != nil {
		return nil, fmt.Errorf("failed to get run: %w", err)
	}
	if !run {
		return nil, errors.New("probing tracepoint infos was not triggered")
	}

	var isEnd bool
	err = coll.Variables["end"].Get(&isEnd)
	if err != nil {
		return nil, fmt.Errorf("failed to get end: %w", err)
	}
	if !isEnd {
		return nil, errors.New("there are too many modules (should be fixed in the future)")
	}

	// Read the number of modules
	var nrModules uint32
	err = coll.Variables["nr_modules"].Get(&nrModules)
	if err != nil {
		return nil, fmt.Errorf("failed to get nr_tps: %w", err)
	}

	var moduleInfos [tpModuleMax]TpModuleInfo
	err = coll.Variables["modules"].Get(ptr2bytes(unsafe.Pointer(&moduleInfos), int(unsafe.Sizeof(TpModuleInfo{}))*tpModuleMax))
	if err != nil {
		return nil, fmt.Errorf("failed to get modules: %w", err)
	}

	kernelSpec, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, fmt.Errorf("failed to load kernel btf spec: %w", err)
	}
	bpfRawTp, err := kernelSpec.AnyTypeByName("bpf_raw_event_map")
	if err != nil {
		return nil, fmt.Errorf("failed to find bpf_raw_event_map btf: %w", err)
	}
	size, err := btf.Sizeof(bpfRawTp)
	if err != nil {
		return nil, fmt.Errorf("failed to get size of struct bpf_raw_event_map: %w", err)
	}
	if size == 0 {
		return nil, errors.New("size of struct bpf_raw_event_map must not be 0")
	}

	modules := make(map[string]tracepointModuleInfo, nrModules)
	for _, moduleInfo := range moduleInfos[:nrModules] {
		if moduleInfo.NrBpfRawEvents == 0 || moduleInfo.NrBpfRawEvents > tpModuleMaxTps /* skip internal anonymous one */ {
			continue
		}

		modName := strx.NullTerminated(moduleInfo.Name[:])
		modSpec, err := btf.LoadKernelModuleSpec(modName)
		if errors.Is(err, unix.ENOENT) {
			// Skip if the module does not have BTF file under /sys/kernel/btf/.
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("failed to load kernel module btf spec for %s: %w", modName, err)
		}

		tps, err := probeTracepoints(tpSpec, ksyms, modSpec, size, moduleInfo.BpfRawEvent, moduleInfo.NrBpfRawEvents)
		if err != nil {
			return nil, fmt.Errorf("failed to probe tracepoint infos for kernel module %s: %w", modName, err)
		}

		modules[modName] = tracepointModuleInfo{
			module: modName,
			tps:    tps,
		}
	}

	return modules, nil
}

func ProbeTracepointModuleInfos(spec, tpSpec *ebpf.CollectionSpec, ksyms *Kallsyms) (map[string]tracepointModuleInfo, error) {
	if ksyms.bpfTraceModules == 0 {
		return nil, errors.New("bpf_trace_modules is not found in /proc/kallsyms")
	}

	return probeTracepointModuleInfos(spec, tpSpec, ksyms.bpfTraceModules, 0, ksyms)
}
