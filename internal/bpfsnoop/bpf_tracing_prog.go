// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"
	"slices"
	"strings"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sync/errgroup"

	"github.com/bpfsnoop/bpfsnoop/internal/btfx"
)

type tracingProg struct {
	l link.Link
	p *ebpf.Program
}

func (t *tracingProg) Close() {
	_ = t.l.Close()
	_ = t.p.Close()
}

func correctArgType(t btf.Type) (btf.Type, error) {
	ptr, ok := mybtf.UnderlyingType(t).(*btf.Pointer)
	if !ok {
		return t, nil
	}

	stt, ok := ptr.Target.(*btf.Struct)
	if !ok {
		return t, nil
	}

	var err error
	switch stt.Name {
	case "__sk_buff":
		t, err = btfx.GetStructBtfPointer("sk_buff", getKernelBTF())
		if err != nil {
			return nil, fmt.Errorf("failed to get sk_buff btf pointer: %w", err)
		}

	case "xdp_md":
		t, err = btfx.GetStructBtfPointer("xdp_buff", getKernelBTF())
		if err != nil {
			return nil, fmt.Errorf("failed to get xdp_buff btf pointer: %w", err)
		}
	}

	return t, nil
}

func correctArgTypeInParams(params []btf.FuncParam) ([]btf.FuncParam, error) {
	params = slices.Clone(params)
	for i, p := range params {
		t, err := correctArgType(p.Type)
		if err != nil {
			return nil, fmt.Errorf("failed to correct arg type: %w", err)
		}

		params[i].Type = t
	}

	return params, nil
}

func (t *bpfTracing) traceProg(spec *ebpf.CollectionSpec, reusedMaps map[string]*ebpf.Map, info *bpfTracingInfo, bprogs *bpfProgs, bothEntryExit, fexit, stack bool) error {
	krnl := getKernelBTF()

	params := info.fn.Type.(*btf.FuncProto).Params
	params, err := correctArgTypeInParams(params)
	if err != nil {
		return fmt.Errorf("failed to correct arg types in params of %s: %w", info.fn.Name, err)
	}

	spec = spec.Copy()

	traceeName := info.fn.Name
	tracingFuncName := TracingProgName()
	progSpec := spec.Programs[tracingFuncName]
	bprog := bprogs.funcs[info.funcIP]
	bprog.pktOutput = t.injectPktOutput(info.flag.pkt, progSpec, params, traceeName)
	if err := t.injectPktFilter(progSpec, params, traceeName); err != nil {
		return err
	}
	if err := t.injectArgFilter(progSpec, params, krnl, traceeName); err != nil {
		return err
	}
	args, argDataSize, err := t.injectArgOutput(progSpec, params, krnl, traceeName)
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
