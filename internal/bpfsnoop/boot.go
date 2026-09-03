// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"

	"github.com/bpfsnoop/bpfsnoop/internal/bpf"
	"github.com/bpfsnoop/bpfsnoop/internal/mathx"
)

// Boot initializes bpfsnoop and runs the operation selected by flags. Tracing
// operations run until their event limit is reached or ctx is cancelled.
func Boot(ctx context.Context, flags *Flags, output io.Writer) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock limit: %w", err)
	}
	if err := PrepareKernelBTF(); err != nil {
		return fmt.Errorf("failed to prepare kernel BTF: %w", err)
	}
	if err := DetectBPFFeatures(); err != nil {
		return fmt.Errorf("failed to detect BPF features: %w", err)
	}

	if flags.Disasm() {
		Disasm(flags)
		return nil
	}
	if flags.ShowFuncProto() {
		ShowFuncProto(flags)
		return nil
	}
	if flags.ShowFgraphProto() {
		ShowFuncGraphProto(flags)
		return nil
	}

	return bootTracing(ctx, flags, output)
}

func bootTracing(ctx context.Context, flags *Flags, output io.Writer) error {
	var r syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &r); err != nil {
		return fmt.Errorf("failed to get nofile rlimit: %w", err)
	}
	VerboseLog("Current nofile rlimit: curr=%d max=%d", r.Cur, r.Max)

	VerboseLog("Reading /proc/kallsyms ..")
	kallsyms, err := NewKallsyms()
	if err != nil {
		return fmt.Errorf("failed to read /proc/kallsyms: %w", err)
	}

	progs, err := flags.ParseProgs()
	if err != nil {
		return fmt.Errorf("failed to parse BPF program info: %w", err)
	}

	var lbrPerfEvents *LbrPerfEvent
	if flags.OutputLbr() {
		lbrPerfEvents, err = OpenLbrPerfEvent(flags.BranchTypes())
		if err != nil {
			if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EOPNOTSUPP) {
				return errors.New("LBR is not supported on the current system")
			}
			return fmt.Errorf("failed to open LBR perf event: %w", err)
		}
		defer lbrPerfEvents.Close()

		if err := ReadLbrNr(kallsyms); err != nil {
			return fmt.Errorf("failed to read LBR depth: %w", err)
		}
	}

	bpfSpec, err := bpf.LoadBpfsnoop()
	if err != nil {
		return fmt.Errorf("failed to load BPF spec: %w", err)
	}
	if err := PatchBPFSessionInsns(bpfSpec); err != nil {
		return fmt.Errorf("failed to patch BPF session instructions: %w", err)
	}

	numCPU, err := ebpf.PossibleCPU()
	if err != nil {
		return fmt.Errorf("failed to get possible CPU count: %w", err)
	}
	if err := bpfSpec.Variables["CPU_MASK"].Set(uint32(mathx.Mask(numCPU))); err != nil {
		return fmt.Errorf("failed to set CPU mask: %w", err)
	}
	if err := ProbeTailcallIssue(bpfSpec); err != nil {
		return fmt.Errorf("failed to probe tail-call support: %w", err)
	}

	defer FlushReadObjs()

	if err := bpfSpec.Variables["PID"].Set(uint32(os.Getpid())); err != nil {
		return fmt.Errorf("failed to set bpfsnoop PID: %w", err)
	}

	maxArg, err := DetectSupportedMaxArg(bpfSpec, kallsyms)
	if err != nil {
		return fmt.Errorf("failed to detect supported function argument count: %w", err)
	}
	VerboseLog("Max arg count limits to %d", maxArg)

	kfuncs, err := FindKernelFuncs(flags.Kfuncs(), kallsyms, maxArg)
	if err != nil {
		return fmt.Errorf("failed to find kernel functions: %w", err)
	}
	VerboseLog("Detect %d kernel functions traceable ..", len(kfuncs))
	kfuncs, err = DetectTraceable(kfuncs)
	if err != nil {
		return fmt.Errorf("failed to detect traceable kernel functions: %w", err)
	}

	kfuncsMulti, err := FindKernelFuncsMulti(flags.KfuncsMulti(), kallsyms)
	if err != nil {
		return fmt.Errorf("failed to find kernel functions for multi-mode: %w", err)
	}

	tpStarted := time.Now()
	ktps, err := FindKernelTracepoints(flags.Ktps(), kallsyms)
	if err != nil {
		return fmt.Errorf("failed to detect tracepoints: %w", err)
	}
	DebugLog("Detected %d tracepoints cost %s", len(ktps), time.Since(tpStarted))
	MergeTracepointsToKfuncs(ktps, kfuncs)

	var addr2line *Addr2Line
	vmlinux, err := FindVmlinux()
	if err != nil && !errors.Is(err, ErrNotFound) {
		return fmt.Errorf("failed to find vmlinux: %w", err)
	}
	if errors.Is(err, ErrNotFound) {
		VerboseLog("Dbgsym vmlinux not found")
	}
	if err == nil && flags.Vmlinux() {
		VerboseLog("Found vmlinux: %s", vmlinux)

		textAddr, err := ReadTextAddrFromVmlinux(vmlinux)
		if err != nil {
			return fmt.Errorf("failed to read .text address from vmlinux: %w", err)
		}
		VerboseLog("Creating addr2line from vmlinux ..")
		kaslr := NewKaslr(kallsyms.Stext(), textAddr)
		addr2line, err = NewAddr2Line(vmlinux, kaslr, kallsyms.SysBPF(), kallsyms.Stext())
		if err != nil {
			return fmt.Errorf("failed to create addr2line from vmlinux: %w", err)
		}
	}

	insns, err := NewFuncInsns(kfuncs, kallsyms)
	if err != nil {
		return fmt.Errorf("failed to create function instructions: %w", err)
	}

	VerboseLog("Disassembling bpf progs ..")
	bpfProgs, err := NewBPFProgs(progs, false, false)
	if err != nil {
		return fmt.Errorf("failed to get BPF programs: %w", err)
	}
	defer bpfProgs.Close()

	graphStarted := time.Now()
	graphs, err := FindGraphFuncs(ctx, flags, kfuncs, bpfProgs, kallsyms, maxArg)
	if err != nil {
		return fmt.Errorf("failed to find graph functions: %w", err)
	}
	defer graphs.Close()
	DebugLog("Found %d graph functions/progs cost %s", len(graphs), time.Since(graphStarted))

	if err := ctx.Err(); err != nil {
		log.Print("bpfsnoop is exiting early ..")
		return nil
	}

	WarnLogIf(len(graphs) != 0, "funcgraph is possible to crash your kernel, please use it with caution!")
	tracingTargets := bpfProgs.Tracings()
	if len(tracingTargets)+len(kfuncs)+len(insns)+len(graphs)+len(kfuncsMulti) == 0 {
		return errors.New("no tracing target")
	}

	VerboseLog("Tracing bpf progs or kernel functions/tracepoints ..")
	TrimSpec(bpfSpec)
	reusedMaps := PrepareBPFMaps(bpfSpec)
	defer CloseBPFMaps(reusedMaps)

	LogIf(len(kfuncs) > 20, "bpfsnoop is tracing %d kernel functions/tracepoints, this may take a while", len(kfuncs))
	LogIf(len(graphs) > 20, "bpfsnoop is tracing %d graph functions/progs, this may take a while", len(graphs))

	tracingStarted := time.Now()
	tracings, err := NewBPFTracing(bpfSpec, reusedMaps, bpfProgs, kfuncs, insns, graphs, kfuncsMulti)
	if err != nil {
		return fmt.Errorf("failed to trace targets: %w", err)
	}
	DebugLog("Tracing %d tracees costs %s", len(tracings.Progs()), time.Since(tracingStarted))
	defer func() {
		started := time.Now()
		tracings.Close()
		DebugLog("Untracing %d tracees costs %s", len(tracings.Progs()), time.Since(started))
	}()
	if !tracings.HaveTracing() {
		return errors.New("no traceable target")
	}
	if err := bpfProgs.AddProgs(tracings.Progs(), true); err != nil {
		return fmt.Errorf("failed to add bpfsnoop BPF programs: %w", err)
	}

	kallsyms, err = NewKallsyms()
	if err != nil {
		return fmt.Errorf("failed to reread /proc/kallsyms: %w", err)
	}
	FlushReadObjs()

	reader, err := ringbuf.NewReader(reusedMaps["bpfsnoop_events"])
	if err != nil {
		return fmt.Errorf("failed to create ring-buffer reader: %w", err)
	}
	defer reader.Close()

	if flags.OutputFile() != "" {
		file, err := os.OpenFile(flags.OutputFile(), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer file.Close()
		output = file
	}

	helpers := &Helpers{
		Flags:     flags,
		Progs:     bpfProgs,
		Addr2line: addr2line,
		Ksyms:     kallsyms,
		Kfuncs:    kfuncs,
		Insns:     insns,
		Graphs:    graphs,
		KfnsMulti: kfuncsMulti,
	}
	readyData := reusedMaps[".data.ready"]
	if err := readyData.Put(uint32(0), uint32(1)); err != nil {
		return fmt.Errorf("failed to mark bpfsnoop ready: %w", err)
	}
	defer readyData.Put(uint32(0), uint32(0))
	DebugLog("bpfsnoop pid is %d", os.Getpid())
	log.Print("bpfsnoop is running..")
	defer log.Print("bpfsnoop is exiting..")

	errgroup, runCtx := errgroup.WithContext(ctx)
	errgroup.Go(func() error {
		<-runCtx.Done()
		_ = reader.Close()
		return nil
	})

	errgroup.Go(func() error { return Run(reader, reusedMaps, output, helpers) })

	if err := errgroup.Wait(); err != nil && !errors.Is(err, ErrFinished) {
		return fmt.Errorf("bpfsnoop run failed: %w", err)
	}
	return nil
}
