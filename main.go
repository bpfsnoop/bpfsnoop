// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"

	"github.com/bpfsnoop/bpfsnoop/internal/assert"
	"github.com/bpfsnoop/bpfsnoop/internal/bpf"
	"github.com/bpfsnoop/bpfsnoop/internal/bpfsnoop"
	"github.com/bpfsnoop/bpfsnoop/internal/mathx"
)

func main() {
	flags, err := bpfsnoop.ParseFlags()
	assert.NoErr(err, "Failed to parse flags: %v")

	err = rlimit.RemoveMemlock()
	assert.NoErr(err, "Failed to remove memlock limit: %v")

	err = bpfsnoop.PrepareKernelBTF()
	assert.NoErr(err, "Failed to prepare kernel btf: %v")

	err = bpfsnoop.DetectBPFFeatures()
	assert.NoVerifierErr(err, "Failed to detect bpf features: %v")

	if flags.Disasm() {
		bpfsnoop.Disasm(flags)
		return
	}

	if flags.ShowFuncProto() {
		bpfsnoop.ShowFuncProto(flags)
		return
	}

	if flags.ShowFgraphProto() {
		bpfsnoop.ShowFuncGraphProto(flags)
		return
	}

	var r syscall.Rlimit
	err = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &r)
	assert.NoErr(err, "Failed to get rlimit: %v", err)
	bpfsnoop.VerboseLog("Current nofile rlimit: curr=%d max=%d", r.Cur, r.Max)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer stop()

	bpfsnoop.VerboseLog("Reading /proc/kallsyms ..")
	kallsyms, err := bpfsnoop.NewKallsyms()
	assert.NoErr(err, "Failed to read /proc/kallsyms: %v")

	progs, err := flags.ParseProgs()
	assert.NoErr(err, "Failed to parse bpf prog infos: %v")

	if flags.OutputLbr() {
		lbrPerfEvents, err := bpfsnoop.OpenLbrPerfEvent(flags.BranchTypes())
		if err != nil &&
			(errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EOPNOTSUPP)) {
			log.Fatalln("LBR is not supported on current system")
		}
		assert.NoErr(err, "Failed to open LBR perf event: %v")
		defer lbrPerfEvents.Close()

		err = bpfsnoop.ReadLbrNr(kallsyms)
		assert.NoErr(err, "Failed to read LBR depth: %v")
	}

	bpfSpec, err := bpf.LoadBpfsnoop()
	assert.NoErr(err, "Failed to load bpf spec: %v")

	numCPU, err := ebpf.PossibleCPU()
	assert.NoErr(err, "Failed to get possible cpu count: %v")

	err = bpfSpec.Variables["CPU_MASK"].Set(uint32(mathx.Mask(numCPU)))
	assert.NoErr(err, "Failed to set CPU_MASK: %v")

	err = bpfsnoop.ProbeTailcallIssue(bpfSpec)
	assert.NoVerifierErr(err, "Failed to probe tailcall info: %v")

	err = bpfSpec.Variables["PID"].Set(uint32(os.Getpid()))
	assert.NoErr(err, "Failed to set PID: %v")

	maxArg, err := bpfsnoop.DetectSupportedMaxArg(bpfSpec, kallsyms)
	assert.NoErr(err, "Failed to detect supported func max arg: %v")
	bpfsnoop.VerboseLog("Max arg count limits to %d", maxArg)

	kfuncs, err := bpfsnoop.FindKernelFuncs(flags.Kfuncs(), kallsyms, maxArg)
	assert.NoErr(err, "Failed to find kernel functions: %v")

	bpfsnoop.VerboseLog("Detect %d kernel functions traceable ..", len(kfuncs))
	kfuncs, err = bpfsnoop.DetectTraceable(kfuncs)
	assert.NoVerifierErr(err, "Failed to detect traceable for kfuncs: %v")

	kfuncsMulti, err := bpfsnoop.FindKernelFuncsMulti(flags.KfuncsMulti(), kallsyms)
	assert.NoErr(err, "Failed to find kernel functions for multi-mode: %v")

	tpTs := time.Now()
	ktps, err := bpfsnoop.FindKernelTracepoints(flags.Ktps(), kallsyms)
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
	if err == nil && flags.Vmlinux() {
		bpfsnoop.VerboseLog("Found vmlinux: %s", vmlinux)

		textAddr, err := bpfsnoop.ReadTextAddrFromVmlinux(vmlinux)
		assert.NoErr(err, "Failed to read .text address from vmlinux: %v")

		bpfsnoop.VerboseLog("Creating addr2line from vmlinux ..")
		kaslr := bpfsnoop.NewKaslr(kallsyms.Stext(), textAddr)
		addr2line, err = bpfsnoop.NewAddr2Line(vmlinux, kaslr, kallsyms.SysBPF(), kallsyms.Stext())
		assert.NoErr(err, "Failed to create addr2line: %v")
	}

	insns, err := bpfsnoop.NewFuncInsns(kfuncs, kallsyms)
	assert.NoErr(err, "Failed to create func insns: %v")

	bpfsnoop.VerboseLog("Disassembling bpf progs ..")
	bpfProgs, err := bpfsnoop.NewBPFProgs(progs, false, false)
	assert.NoErr(err, "Failed to get bpf progs: %v")
	defer bpfProgs.Close()

	fgTs := time.Now()
	graphs, err := bpfsnoop.FindGraphFuncs(ctx, flags, kfuncs, bpfProgs, kallsyms, maxArg)
	assert.NoErr(err, "Failed to find graph functions: %v")
	defer graphs.Close()
	bpfsnoop.DebugLog("Found %d graph functions/progs cost %s", len(graphs), time.Since(fgTs))
	assert.False(bpfsnoop.FgraphExceedMaxDepth(flags, graphs),
		"Current kernel does not support too large --fgraph-max-depth %d, limit 10", flags.FgraphMaxDepth())

	select {
	case <-ctx.Done():
		log.Println("bpfsnoop is exiting early ..")
		return
	default:
	}

	bpfsnoop.WarnLogIf(len(graphs) != 0, "funcgraph is possible to crash your kernel, please use it with caution!")

	tracingTargets := bpfProgs.Tracings()
	assert.True(len(tracingTargets)+len(kfuncs)+len(insns)+len(graphs)+len(kfuncsMulti) != 0, "No tracing target")

	bpfsnoop.VerboseLog("Tracing bpf progs or kernel functions/tracepoints ..")

	bpfsnoop.TrimSpec(bpfSpec)

	reusedMaps := bpfsnoop.PrepareBPFMaps(bpfSpec)
	defer bpfsnoop.CloseBPFMaps(reusedMaps)

	bpfsnoop.LogIf(len(kfuncs) > 20, "bpfsnoop is tracing %d kernel functions/tracepoints, this may take a while", len(kfuncs))
	bpfsnoop.LogIf(len(graphs) > 20, "bpfsnoop is tracing %d graph functions/progs, this may take a while", len(graphs))

	tstarted := time.Now()
	tracings, err := bpfsnoop.NewBPFTracing(bpfSpec, reusedMaps, bpfProgs, kfuncs, insns, graphs, kfuncsMulti)
	assert.NoVerifierErr(err, "Failed to trace: %v")
	bpfsnoop.DebugLog("Tracing %d tracees costs %s", len(tracings.Progs()), time.Since(tstarted))
	var tended time.Time
	defer func() { bpfsnoop.DebugLog("Untracing %d tracees costs %s", len(tracings.Progs()), time.Since(tended)) }()
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

	errg, ctx := errgroup.WithContext(ctx)

	errg.Go(func() error {
		<-ctx.Done()
		_ = reader.Close()
		return nil
	})

	errg.Go(func() error {
		return bpfsnoop.Run(reader, reusedMaps, w, &bpfsnoop.Helpers{
			Flags:     flags,
			Progs:     bpfProgs,
			Addr2line: addr2line,
			Ksyms:     kallsyms,
			Kfuncs:    kfuncs,
			Insns:     insns,
			Graphs:    graphs,
			KfnsMulti: kfuncsMulti,
		})
	})

	err = errg.Wait()
	if err == bpfsnoop.ErrFinished {
		return
	}
	assert.NoErr(err, "Failed: %v")
}
