// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sync/errgroup"
)

type tracingProg struct {
	l link.Link
	p *ebpf.Program
}

func (t *tracingProg) Close() {
	_ = t.l.Close()
	_ = t.p.Close()
}

func (t *bpfTracing) traceProg(spec *ebpf.CollectionSpec, reusedMaps map[string]*ebpf.Map, info *bpfTracingInfo, bprogs *bpfProgs, bothEntryExit, fexit, stack bool) error {
	krnl := getKernelBTF()

	spec = spec.Copy()

	traceeName := info.fn.Name
	tracingFuncName := TracingProgName()
	progSpec := spec.Programs[tracingFuncName]
	params := info.fn.Type.(*btf.FuncProto).Params
	bprog := bprogs.funcs[info.funcIP]
	bprog.pktOutput = t.injectPktOutput(info.flag.pkt, progSpec, params, traceeName)
	if err := t.injectPktFilter(progSpec, params, traceeName); err != nil {
		return err
	}
	if err := t.injectArgFilter(progSpec, params, krnl, traceeName); err != nil {
		return err
	}
	args, argDataSize, err := t.injectArgOutput(progSpec, params, krnl, true, traceeName)
	if err != nil {
		return err
	}
	bprog.funcArgs = args
	bprog.argDataSz = argDataSize
	fnArgsBufSize, err := injectOutputFuncArgs(progSpec, info.params, info.ret, fexit)
	if err != nil {
		return fmt.Errorf("failed to inject output func args: %w", err)
	}
	if fexit {
		bprog.argExitSz = fnArgsBufSize
	} else {
		bprog.argEntrySz = fnArgsBufSize
	}

	if err := setBpfsnoopConfig(spec, uint64(info.funcIP), len(info.params),
		fnArgsBufSize, argDataSize, info.flag.lbr, stack,
		bprog.pktOutput, bothEntryExit, fexit); err != nil {
		return fmt.Errorf("failed to set bpfsnoop config: %w", err)
	}

	attachType := ebpf.AttachTraceFExit
	if !fexit {
		attachType = ebpf.AttachTraceFEntry
	}

	progSpec.AttachTarget = info.prog
	progSpec.AttachTo = info.funcName
	progSpec.AttachType = attachType

	progSpec.Name = tracingFuncName + "_entry"
	if fexit {
		progSpec.Name = tracingFuncName + "_exit"
	}
	progSpec.Instructions[0] = progSpec.Instructions[0].WithSymbol(progSpec.Name)
	delete(spec.Programs, tracingFuncName)
	spec.Programs[progSpec.Name] = progSpec
	tracingFuncName = progSpec.Name

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: reusedMaps,
	})
	if err != nil {
		return fmt.Errorf("failed to create bpf collection for tracing prog %s: %w", traceeName, err)
	}
	defer coll.Close()

	prog := coll.Programs[tracingFuncName]
	l, err := link.AttachTracing(link.TracingOptions{
		Program:    prog,
		AttachType: attachType,
	})
	if err != nil {
		if strings.Contains(err.Error(), "Cannot recursively attach") {
			VerboseLog("Skipped tracing a tracing prog %s", traceeName)
			return nil
		}
		return fmt.Errorf("failed to attach tracing prog %s: %w", traceeName, err)
	}

	VerboseLog("Tracing %s of prog %v", info.funcName, info.prog)

	delete(coll.Programs, tracingFuncName)
	t.llock.Lock()
	t.progs = append(t.progs, prog)
	t.bprgs = append(t.bprgs, tracingProg{
		l: l,
		p: prog,
	})
	t.llock.Unlock()

	return nil
}

func (t *bpfTracing) traceProgs(errg *errgroup.Group, spec *ebpf.CollectionSpec, reusedMaps map[string]*ebpf.Map, bprogs *bpfProgs) {
	if len(bprogs.tracings) == 0 {
		return
	}

	for _, info := range bprogs.tracings {
		bothEntryExit := info.flag.graph || info.flag.both
		info := info

		if bothEntryExit {
			errg.Go(func() error {
				return t.traceProg(spec, reusedMaps, info, bprogs, true, false, false)
			})

			errg.Go(func() error {
				return t.traceProg(spec, reusedMaps, info, bprogs, true, true, info.flag.stack)
			})
		} else {
			errg.Go(func() error {
				return t.traceProg(spec, reusedMaps, info, bprogs, false, hasModeExit(), info.flag.stack)
			})
		}
	}
}
