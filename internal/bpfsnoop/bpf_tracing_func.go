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

type tracingFunc struct {
	l link.Link
	p *ebpf.Program
}

func (t *tracingFunc) Close() {
	_ = t.l.Close()
	_ = t.p.Close()
}

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
	if errors.Is(err, unix.ENOENT) {
		return true
	}

	s := err.Error()

	// STRUCT arg is unsupported since
	// commit fec56f5890 ("bpf: Introduce BPF trampoline") kernel 5.5.
	// STRUCT arg is supported if size <= 16 since
	// commit 720e6a4351 ("bpf: Allow struct argument in trampoline based programs")
	// kernel 6.1.
	if strings.Contains(s, "type STRUCT is unsupported") {
		VerboseLog("Cannot trace STRUCT-arg kfunc %s: %s", fnName, s)
		return true
	}

	// UNION arg is unsupported since
	// commit ??? ("bpf: Support fentry/fexit for functions with union args")
	if strings.Contains(s, "type UNION is unsupported") {
		VerboseLog("Cannot trace UNION-arg kfunc %s: %s", fnName, s)
		return true
	}

	return false
}

func (t *bpfTracing) traceFunc(spec *ebpf.CollectionSpec, reusedMaps map[string]*ebpf.Map, fn *KFunc, bothEntryExit, isExit, fsession, stack bool) error {
	spec = spec.Copy()

	isTracepoint := fn.IsTp
	tracingFuncName := TracingProgName()

	traceeName := fn.Func.Name
	progSpec := spec.Programs[tracingFuncName]
	funcProto := fn.Func.Type.(*btf.FuncProto)
	params := funcProto.Params
	fn.Pkt = t.injectPktOutput(fn.Flag.pkt, progSpec, params, traceeName)
	if err := t.injectPktFilter(progSpec, params, traceeName); err != nil {
		return err
	}
	if err := t.injectArgFilter(progSpec, params, fn.Btf, traceeName); err != nil {
		return err
	}
	args, argDataSize, err := t.injectArgOutput(progSpec, params, fn.Btf, traceeName)
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

	argEntrySize, argExitSize := 0, 0
	if bothEntryExit {
		argEntrySize = fnArgsBufSize
		argExitSize = fnArgsBufSize
	} else if withRet {
		argExitSize = fnArgsBufSize
	} else {
		argEntrySize = fnArgsBufSize
	}
	if err := setBpfsnoopConfig(spec, traceeConfig{
		funcIP:        fn.Ksym.addr,
		fnArgsNr:      len(fn.Prms),
		fnArgsBufSz:   fnArgsBufSize,
		argEntrySz:    argEntrySize,
		argExitSz:     argExitSize,
		argDataSz:     argDataSize,
		outputLbr:     fn.Flag.lbr,
		outputStack:   stack,
		outputPkt:     fn.Pkt,
		insnMode:      fn.Insn,
		graphMode:     fn.Flag.graph,
		bothEntryExit: bothEntryExit,
		isTp:          fn.IsTp,
		isProg:        false,
		kmultiMode:    false,
		withRet:       withRet,
		session:       fsession,
	}); err != nil {
		return fmt.Errorf("failed to set bpfsnoop config: %w", err)
	}

	attachType := ebpf.AttachTraceFEntry
	if isExit {
		attachType = ebpf.AttachTraceFExit
	}
	if bothEntryExit && fsession {
		attachType = ebpf.AttachTraceFSession
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

	verboseLogIf(attachType == ebpf.AttachTraceFExit, "Tracing(fexit) kernel function %s", fnName)
	verboseLogIf(attachType == ebpf.AttachTraceFEntry, "Tracing(fentry) kernel function %s", fnName)
	verboseLogIf(attachType == ebpf.AttachTraceFSession, "Tracing(fsession) kernel function %s", fnName)
	verboseLogIf(attachType == ebpf.AttachTraceRawTp, "Tracing kernel tracepoint %s", fnName)

	t.llock.Lock()
	t.progs = append(t.progs, prog)
	t.kfns = append(t.kfns, tracingFunc{
		l: l,
		p: prog,
	})
	t.llock.Unlock()

	return nil
}

func (t *bpfTracing) traceFuncs(errg *errgroup.Group, spec *ebpf.CollectionSpec, reusedMaps map[string]*ebpf.Map, kfuncs KFuncs) error {
	if len(kfuncs) == 0 {
		return nil
	}

	for _, fn := range kfuncs {
		bothEntryExit := fn.Insn || fn.Flag.graph || fn.Flag.both
		fn := fn

		if fn.IsTp {
			errg.Go(func() error {
				return t.traceFunc(spec, reusedMaps, fn, false, false, false, fn.Flag.stack)
			})
			continue
		}

		if bothEntryExit {
			if hasFsession {
				errg.Go(func() error {
					return t.traceFunc(spec, reusedMaps, fn, true, true, true, fn.Flag.stack)
				})
				continue
			}

			errg.Go(func() error {
				return t.traceFunc(spec, reusedMaps, fn, true, false, false, false)
			})

			errg.Go(func() error {
				return t.traceFunc(spec, reusedMaps, fn, true, true, false, fn.Flag.stack)
			})
		} else {
			errg.Go(func() error {
				return t.traceFunc(spec, reusedMaps, fn, false, hasModeExit(), false, fn.Flag.stack)
			})
		}
	}

	return nil
}
