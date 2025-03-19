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

	"github.com/bpfsnoop/bpfsnoop/internal/strx"
)

const tpMax = 256

type tracepointInfo struct {
	name   string
	sym    uint64
	nrArgs uint32

	fn *btf.Func
}

type TpInfo struct {
	Name   [64]byte
	Sym    uint64
	NrArgs uint32
}

func probeTracepointInfos(spec *ebpf.CollectionSpec, start uint64, cnt uint32) (map[string]tracepointInfo, error) {
	spec = spec.Copy()

	if err := spec.Variables["__start"].Set(start); err != nil {
		return nil, fmt.Errorf("failed to set __start: %w", err)
	}
	if err := spec.Variables["nr_tps"].Set(cnt); err != nil {
		return nil, fmt.Errorf("failed to set nr_tps: %w", err)
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
	defer l.Close()

	nanosleep()

	var run bool
	if err := coll.Variables["run"].Get(&run); err != nil {
		return nil, fmt.Errorf("failed to get run: %w", err)
	}
	if !run {
		return nil, errors.New("probing tracepoint infos was not triggered")
	}

	var tps [tpMax]TpInfo
	if err := coll.Variables["tps"].Get(ptr2bytes(unsafe.Pointer(&tps), (64+8+8)*tpMax)); err != nil {
		return nil, fmt.Errorf("failed to get tps: %w", err)
	}

	infos := make(map[string]tracepointInfo, cnt)
	for _, tp := range tps[:] {
		if tp.Sym == 0 {
			continue
		}

		infos[strx.NullTerminated(tp.Name[:])] = tracepointInfo{
			sym:    tp.Sym,
			nrArgs: tp.NrArgs,
		}
	}

	return infos, nil
}

func ProbeTracepoints(spec *ebpf.CollectionSpec, ksyms *Kallsyms) (map[string]tracepointInfo, error) {
	if ksyms.bpfRawTpStart == 0 || ksyms.bpfRawTpStop == 0 || ksyms.bpfRawTpStart >= ksyms.bpfRawTpStop {
		return nil, fmt.Errorf("invalid %s(%d) and %s(%d)", bpfRawTpStart, ksyms.bpfRawTpStart, bpfRawTpStop, ksyms.bpfRawTpStop)
	}

	kernelSpec, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, fmt.Errorf("failed to load kernel btf: %w", err)
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

	start := ksyms.bpfRawTpStart
	total := (ksyms.bpfRawTpStop - ksyms.bpfRawTpStart) / uint64(size)

	tps := make(map[string]tracepointInfo)
	for total > 0 {
		cnt := min(total, tpMax)

		infos, err := probeTracepointInfos(spec, start, uint32(cnt))
		if err != nil {
			return nil, fmt.Errorf("failed to probe tracepoint infos: %w", err)
		}

		for name, info := range infos {
			i := info
			i.name = name

			ksym, ok := ksyms.a2s[info.sym]
			if !ok {
				return nil, fmt.Errorf("%d is not found in kallsyms", info.sym)
			}

			t, err := kernelSpec.AnyTypeByName(ksym.name)
			if err != nil {
				return nil, fmt.Errorf("%s is not found in kernel btf", ksym.name)
			}

			fn, ok := t.(*btf.Func)
			if !ok {
				return nil, fmt.Errorf("%s is not a func in kernel btf", ksym.name)
			}

			i.fn = fn

			tps[name] = i
		}

		total -= cnt
		start += uint64(size) * cnt
	}

	return tps, nil
}
