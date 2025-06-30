// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

func ignoreFuncTraceErr(err error, fnName string) bool {
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, ebpf.ErrNotSupported) {
		return true
	}
	if errors.Is(err, unix.EBUSY) /* Because no nop5 at the function entry, especially non-traceable funcs */ {
		VerboseLog("Cannot trace kfunc %s", fnName)
		return true
	}
	return false
}

func ignoreFuncTraceVerifierErr(err error, fnName string) bool {
	// e.g. pwru::'filter_pcap_ebpf_tunnel_l2': program bpfsnoop_fgraph: attach
	// Tracing/TraceFExit: load target BTF: file descriptor in bad state
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EBADFD) {
		return true
	}

	s := err.Error()

	// STRUCT arg is unsupported since
	// commit fec56f5890 ("bpf: Introduce BPF trampoline") kernel 5.5.
	// STRUCT arg is supported if size <= 16 since
	// commit 720e6a4351 ("bpf: Allow struct argument in trampoline based programs")
	// kernel 6.1.
	if strings.Contains(s, "type STRUCT is unsupported") {
		VerboseLog("Cannot trace kfunc %s: %s", fnName, s)
		return true
	}

	return false
}

func (t *bpfTracing) traceFunc(spec *ebpf.CollectionSpec, reusedMaps map[string]*ebpf.Map, fn *KFunc, bothEntryExit, isExit bool) error {
	spec = spec.Copy()

	isTracepoint := fn.IsTp
	tracingFuncName := TracingProgName()

	traceeName := fn.Func.Name
	progSpec := spec.Programs[tracingFuncName]
	funcProto := fn.Func.Type.(*btf.FuncProto)
	params := funcProto.Params
	fn.Pkt = t.injectPktOutput(progSpec, params, traceeName)
	if err := t.injectPktFilter(progSpec, params, traceeName); err != nil {
		return err
	}
	if err := t.injectArgFilter(progSpec, params, fn.Btf, traceeName); err != nil {
		return err
	}
	args, argDataSize, err := t.injectArgOutput(progSpec, params, fn.Btf, false, traceeName)
	if err != nil {
		return err
	}
	fn.Args = args
	fn.Data = argDataSize

	withRet := !isTracepoint && isExit
	fnArgsBufSize, err := injectOutputFuncArgs(progSpec, fn.Prms, fn.Ret, withRet)
	if err != nil {
		return fmt.Errorf("failed to inject output func args: %w", err)
	}
	if isExit {
		fn.Exit = fnArgsBufSize
	} else {
		fn.Ent = fnArgsBufSize
	}

	if err := setBpfsnoopConfig(spec, fn.Ksym.addr, len(fn.Prms), fnArgsBufSize, argDataSize, bothEntryExit, withRet); err != nil {
		return fmt.Errorf("failed to set bpfsnoop config: %w", err)
	}

	attachType := ebpf.AttachTraceFEntry
	if isExit {
		attachType = ebpf.AttachTraceFExit
	}
	if isTracepoint {
		attachType = ebpf.AttachTraceRawTp
	}

	fnName := fn.Func.Name
	progSpec.AttachTo = fnName
	progSpec.AttachType = attachType

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: reusedMaps,
	})
	if err != nil {
		if ignoreFuncTraceVerifierErr(err, fnName) {
			return nil
		}
		return fmt.Errorf("failed to create bpf collection for tracing %s: %w", traceeName, err)
	}
	defer coll.Close()

	prog := coll.Programs[tracingFuncName]
	delete(coll.Programs, tracingFuncName)
	l, err := link.AttachTracing(link.TracingOptions{
		Program:    prog,
		AttachType: attachType,
	})
	if err != nil {
		_ = prog.Close()
		if ignoreFuncTraceErr(err, fnName) {
			return nil
		}
		return fmt.Errorf("failed to attach tracing: %w", err)
	}

	verboseLogIf(!isTracepoint && isExit, "Tracing(fexit) kernel function %s", fnName)
	verboseLogIf(!isTracepoint && !isExit, "Tracing(fentry) kernel function %s", fnName)
	verboseLogIf(isTracepoint, "Tracing kernel tracepoint %s", fnName)

	t.llock.Lock()
	t.progs = append(t.progs, prog)
	t.klnks = append(t.klnks, l)
	t.llock.Unlock()

	return nil
}

func (t *bpfTracing) traceFuncs(errg *errgroup.Group, spec *ebpf.CollectionSpec, reusedMaps map[string]*ebpf.Map, kfuncs KFuncs) {
	if len(kfuncs) == 0 {
		return
	}

	for _, fn := range kfuncs {
		bothEntryExit := fn.Insn || fn.Grph || (hasModeEntry() && hasModeExit())
		fn := fn

		if fn.IsTp {
			errg.Go(func() error {
				return t.traceFunc(spec, reusedMaps, fn, bothEntryExit, false)
			})
			continue
		}

		errg.Go(func() error {
			return t.traceFunc(spec, reusedMaps, fn, bothEntryExit, hasModeExit())
		})

		if bothEntryExit {
			errg.Go(func() error {
				return t.traceFunc(spec, reusedMaps, fn, bothEntryExit, !hasModeExit())
			})
		}
	}
}
