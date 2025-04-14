// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"

	"github.com/bpfsnoop/bpfsnoop/internal/assert"
	"github.com/bpfsnoop/bpfsnoop/internal/bpfsnoop"
	"github.com/bpfsnoop/bpfsnoop/internal/mathx"
)

func main() {
	flags, err := bpfsnoop.ParseFlags()
	assert.NoErr(err, "Failed to parse flags: %v")

	readSpec, err := loadRead()
	assert.NoErr(err, "Failed to load read bpf spec: %v")

	if flags.Disasm() {
		bpfsnoop.Disasm(flags, readSpec)
		return
	}

	tpSpec, err := loadTracepoint()
	assert.NoErr(err, "Failed to load tracepoint bpf spec: %v")

	tpModSpec, err := loadTracepoint_module()
	assert.NoErr(err, "Failed to load tracepoint_module bpf spec: %v")

	if flags.ShowFuncProto() {
		bpfsnoop.ShowFuncProto(flags, tpSpec, tpModSpec)
		return
	}

	mode := flags.Mode()
	assert.True(slices.Contains([]string{bpfsnoop.TracingModeEntry, bpfsnoop.TracingModeExit}, mode),
		fmt.Sprintf("Mode (%s) must be exit or entry", mode))

	progs, err := flags.ParseProgs()
	assert.NoErr(err, "Failed to parse bpf prog infos: %v")

	featBPFSpec, err := loadFeat()
	assert.NoErr(err, "Failed to load feat bpf spec: %v")

	err = bpfsnoop.DetectBPFFeatures(featBPFSpec)
	assert.NoVerifierErr(err, "Failed to detect bpf features: %v")

	if flags.OutputLbr() {
		lbrPerfEvents, err := bpfsnoop.OpenLbrPerfEvent()
		if err != nil &&
			(errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EOPNOTSUPP)) {
			log.Fatalln("LBR is not supported on current system")
		}
		assert.NoErr(err, "Failed to open LBR perf event: %v")
		defer lbrPerfEvents.Close()
	}

	bpfsnoop.VerboseLog("Reading /proc/kallsyms ..")
	kallsyms, err := bpfsnoop.NewKallsyms()
	assert.NoErr(err, "Failed to read /proc/kallsyms: %v")

	traceableBPFSpec, err := loadTraceable()
	assert.NoErr(err, "Failed to load traceable bpf spec: %v")

	bpfSpec, err := loadBpfsnoop()
	assert.NoErr(err, "Failed to load bpf spec: %v")

	numCPU, err := ebpf.PossibleCPU()
	assert.NoErr(err, "Failed to get possible cpu count: %v")

	err = bpfSpec.Variables["CPU_MASK"].Set(uint32(mathx.Mask(numCPU)))
	assert.NoErr(err, "Failed to set CPU_MASK: %v")

	tailcallSpec, err := loadTailcall()
	assert.NoErr(err, "Failed to load tailcall bpf spec: %v")

	err = bpfsnoop.ProbeTailcallIssue(bpfSpec, tailcallSpec, readSpec)
	assert.NoVerifierErr(err, "Failed to probe tailcall info: %v")

	err = bpfSpec.Variables["PID"].Set(uint32(os.Getpid()))
	assert.NoErr(err, "Failed to set PID: %v")

	maxArg, err := bpfsnoop.DetectSupportedMaxArg(traceableBPFSpec, bpfSpec, kallsyms)
	assert.NoErr(err, "Failed to detect supported func max arg: %v")
	bpfsnoop.VerboseLog("Max arg count limits to %d", maxArg)

	kfuncs, err := bpfsnoop.FindKernelFuncs(flags.Kfuncs(), kallsyms, maxArg)
	assert.NoErr(err, "Failed to find kernel functions: %v")

	bpfsnoop.VerboseLog("Detect %d kernel functions traceable ..", len(kfuncs))
	kfuncs, err = bpfsnoop.DetectTraceable(traceableBPFSpec, kfuncs)
	assert.NoVerifierErr(err, "Failed to detect traceable for kfuncs: %v")

	tpTs := time.Now()
	ktps, err := bpfsnoop.FindKernelTracepoints(flags.Ktps(), tpSpec, tpModSpec, kallsyms)
	assert.NoVerifierErr(err, "Failed to detect tracepoints: %v")
	bpfsnoop.DebugLog("Detected %d tracepoints cost %s", len(ktps), time.Since(tpTs))

	bpfsnoop.MergeTracepointsToKfuncs(ktps, kfuncs)

	var addr2line *bpfsnoop.Addr2Line

	vmlinux, err := bpfsnoop.FindVmlinux()
	if err != nil {
		if errors.Is(err, bpfsnoop.ErrNotFound) {
			bpfsnoop.VerboseLog("Dbgsym vmlinux not found")
		} else {
			assert.NoErr(err, "Failed to find vmlinux: %v")
		}
	}
	if err == nil {
		bpfsnoop.VerboseLog("Found vmlinux: %s", vmlinux)

		textAddr, err := bpfsnoop.ReadTextAddrFromVmlinux(vmlinux)
		assert.NoErr(err, "Failed to read .text address from vmlinux: %v")

		bpfsnoop.VerboseLog("Creating addr2line from vmlinux ..")
		kaslr := bpfsnoop.NewKaslr(kallsyms.Stext(), textAddr)
		addr2line, err = bpfsnoop.NewAddr2Line(vmlinux, kaslr, kallsyms.SysBPF(), kallsyms.Stext())
		assert.NoErr(err, "Failed to create addr2line: %v")
	}

	insnSpec, err := loadInsn()
	assert.NoErr(err, "Failed to load insn bpf spec: %v")

	bpfsnoop.VerboseLog("Disassembling bpf progs ..")
	bpfProgs, err := bpfsnoop.NewBPFProgs(progs, false, false)
	assert.NoErr(err, "Failed to get bpf progs: %v")
	defer bpfProgs.Close()

	tracingTargets := bpfProgs.Tracings()
	insns, err := bpfsnoop.NewFuncInsns(kfuncs, bpfProgs.Tracings(), kallsyms, readSpec)
	assert.NoErr(err, "Failed to create func insns: %v")

	assert.True(len(tracingTargets)+len(kfuncs)+len(insns.Insns) != 0, "No tracing target")

	bpfsnoop.VerboseLog("Tracing bpf progs or kernel functions/tracepoints ..")

	bpfsnoop.TrimSpec(bpfSpec)

	reusedMaps := bpfsnoop.PrepareBPFMaps(bpfSpec)
	defer bpfsnoop.CloseBPFMaps(reusedMaps)

	if len(kfuncs) > 20 {
		log.Printf("bpfsnoop is tracing %d kernel functions/tracepoints, this may take a while", len(kfuncs))
	}

	tstarted := time.Now()
	tracings, err := bpfsnoop.NewBPFTracing(bpfSpec, insnSpec, reusedMaps, bpfProgs, kfuncs, insns)
	assert.NoVerifierErr(err, "Failed to trace: %v")
	bpfsnoop.DebugLog("Tracing %d tracees cost %s", len(tracings.Progs()), time.Since(tstarted))
	var tended time.Time
	defer func() { bpfsnoop.DebugLog("Untracing %d tracees cost %s", len(tracings.Progs()), time.Since(tended)) }()
	defer tracings.Close()
	defer func() { tended = time.Now() }()
	assert.True(tracings.HaveTracing(), "No tracing target")

	err = bpfProgs.AddProgs(tracings.Progs(), true)
	assert.NoErr(err, "Failed to add bpf progs: %v")

	kallsyms, err = bpfsnoop.NewKallsyms()
	assert.NoErr(err, "Failed to reread /proc/kallsyms: %v")

	reader, err := ringbuf.NewReader(reusedMaps["bpfsnoop_events"])
	assert.NoErr(err, "Failed to create ringbuf reader: %v")
	defer reader.Close()

	w := os.Stdout
	if flags.OutputFile() != "" {
		f, err := os.OpenFile(flags.OutputFile(), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		assert.NoErr(err, "Failed to create output file: %v")
		defer f.Close()
		w = f
	}

	readyData := reusedMaps[".data.ready"]
	err = readyData.Put(uint32(0), uint32(1))
	assert.NoErr(err, "Failed to update ready data map: %v")
	defer readyData.Put(uint32(0), uint32(0))

	bpfsnoop.DebugLog("bpfsnoop pid is %d", os.Getpid())
	log.Print("bpfsnoop is running..")
	defer log.Print("bpfsnoop is exiting..")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errg, ctx := errgroup.WithContext(ctx)

	errg.Go(func() error {
		<-ctx.Done()
		_ = reader.Close()
		return nil
	})

	errg.Go(func() error {
		helpers := bpfsnoop.Helpers{
			Progs:     bpfProgs,
			Addr2line: addr2line,
			Ksyms:     kallsyms,
			Kfuncs:    kfuncs,
			Insns:     insns,
		}
		return bpfsnoop.Run(reader, &helpers, reusedMaps, w)
	})

	err = errg.Wait()
	if err == bpfsnoop.ErrFinished {
		return
	}
	assert.NoErr(err, "Failed: %v")
}
