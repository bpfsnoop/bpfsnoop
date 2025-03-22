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

	"github.com/cilium/ebpf/ringbuf"
	"github.com/knightsc/gapstone"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"

	"github.com/bpfsnoop/bpfsnoop/internal/assert"
	"github.com/bpfsnoop/bpfsnoop/internal/bpfsnoop"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpfsnoop ./bpf/bpfsnoop.c -- -g -D__TARGET_ARCH_x86 -I./bpf -I./bpf/headers -I./lib/libbpf/src -Wall
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang feat ./bpf/feature.c -- -g -D__TARGET_ARCH_x86 -I./bpf/headers -I./lib/libbpf/src -Wall
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang traceable ./bpf/traceable.c -- -g -D__TARGET_ARCH_x86 -I./bpf/headers -I./lib/libbpf/src -Wall

func main() {
	flags, err := bpfsnoop.ParseFlags()
	assert.NoErr(err, "Failed to parse flags: %v")

	if flags.Disasm() {
		bpfsnoop.Disasm(flags)
		return
	}

	if flags.ShowFuncProto() {
		bpfsnoop.ShowFuncProto(flags)
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
	delete(bpfSpec.Programs, bpfsnoop.TracingProgName(flags.OtherMode()))

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

	engine, err := gapstone.New(int(gapstone.CS_ARCH_X86), int(gapstone.CS_MODE_64))
	assert.NoErr(err, "Failed to create capstone engine: %v")
	defer engine.Close()

	bpfsnoop.VerboseLog("Disassembling bpf progs ..")
	bpfProgs, err := bpfsnoop.NewBPFProgs(progs, false, false)
	assert.NoErr(err, "Failed to get bpf progs: %v")
	defer bpfProgs.Close()

	tracingTargets := bpfProgs.Tracings()
	assert.True(len(tracingTargets)+len(kfuncs) != 0, "No tracing target")

	bpfsnoop.VerboseLog("Tracing bpf progs or kernel functions ..")

	bpfsnoop.TrimSpec(bpfSpec)

	reusedMaps := bpfsnoop.PrepareBPFMaps(bpfSpec)
	defer bpfsnoop.CloseBPFMaps(reusedMaps)

	if len(kfuncs) > 20 {
		log.Printf("bpfsnoop is tracing %d kernel functions, this may take a while", len(kfuncs))
	}

	tstarted := time.Now()
	tracings, err := bpfsnoop.NewBPFTracing(bpfSpec, reusedMaps, bpfProgs, kfuncs)
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
		return bpfsnoop.Run(reader, bpfProgs, addr2line, kallsyms, kfuncs, reusedMaps, w)
	})

	err = errg.Wait()
	if err == bpfsnoop.ErrFinished {
		return
	}
	assert.NoErr(err, "Failed: %v")
}
