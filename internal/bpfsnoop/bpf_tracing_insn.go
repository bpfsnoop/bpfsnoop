// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"errors"
	"fmt"

	"github.com/bpfsnoop/bpfsnoop/internal/bpf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

func (t *bpfTracing) traceInsn(spec *ebpf.CollectionSpec, reusedMaps map[string]*ebpf.Map, insn FuncInsn) error {
	spec = spec.Copy()

	if err := spec.Variables["INSN_IP"].Set(insn.IP); err != nil {
		return fmt.Errorf("failed to set INSN_IP: %w", err)
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			".data.ready":       reusedMaps[".data.ready"],
			"bpfsnoop_events":   reusedMaps["bpfsnoop_events"],
			"bpfsnoop_sessions": reusedMaps["bpfsnoop_sessions"],
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create bpf collection for tracing insn '%s': %w", insn.Desc, err)
	}
	defer coll.Close()

	prog := coll.Programs["bpfsnoop_insn"]
	delete(coll.Programs, "bpfsnoop_insn")
	l, err := link.Kprobe(insn.Func, prog, &link.KprobeOptions{
		Offset: insn.Off,
	})
	if err != nil {
		_ = prog.Close()
		DebugLog("Failed to attach kprobe %s insn '%s': %v", insn.Func, insn.Desc, err)
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EADDRNOTAVAIL) {
			return nil
		}
		return fmt.Errorf("failed to attach kprobe %s insn '%s': %w", insn.Func, insn.Desc, err)
	}

	VerboseLog("Tracing func %s insn '%s'", insn.Func, insn.Desc)

	t.llock.Lock()
	t.progs = append(t.progs, prog)
	t.ilnks = append(t.ilnks, l)
	t.llock.Unlock()

	return nil
}

func (t *bpfTracing) traceInsns(errg *errgroup.Group, reusedMaps map[string]*ebpf.Map, insns FuncInsns) error {
	if len(insns) == 0 {
		return nil
	}

	insnSpec, err := bpf.LoadInsn()
	if err != nil {
		return fmt.Errorf("failed to load insn bpf spec: %w", err)
	}

	for _, insn := range insns {
		insn := insn
		errg.Go(func() error {
			return t.traceInsn(insnSpec, reusedMaps, insn)
		})
	}

	return nil
}
