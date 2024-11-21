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
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/knightsc/gapstone"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"

	"github.com/Asphaltt/bpflbr/internal/assert"
	"github.com/Asphaltt/bpflbr/internal/bpflbr"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang lbr ./bpf/lbr.c -- -g -D__TARGET_ARCH_x86 -I./bpf/headers -Wall
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang feat ./bpf/feature.c -- -g -D__TARGET_ARCH_x86 -I./bpf/headers -Wall

func main() {
	flags, err := bpflbr.ParseFlags()
	assert.NoErr(err, "Failed to parse flags: %v")

	if flags.Disasm() {
		bpflbr.Disasm(flags)
		return
	}

	progs, err := flags.ParseProgs()
	assert.NoErr(err, "Failed to parse bpf prog infos: %v")

	featBPFSpec, err := loadFeat()
	assert.NoErr(err, "Failed to load feat bpf spec: %v")

	err = bpflbr.DetectBPFFeatures(featBPFSpec)
	assert.NoErr(err, "Failed to detect bpf features: %v")

	lbrPerfEvents, err := bpflbr.OpenLbrPerfEvent()
	if err != nil && errors.Is(err, unix.ENOENT) {
		log.Fatalln("LBR is not supported on current system")
	}
	assert.NoErr(err, "Failed to open LBR perf event: %v")
	defer lbrPerfEvents.Close()

	kallsyms, err := bpflbr.NewKallsyms()
	assert.NoErr(err, "Failed to read /proc/kallsyms: %v")

	vmlinux, err := bpflbr.FindVmlinux()
	assert.NoErr(err, "Failed to find vmlinux: %v")

	textAddr, err := bpflbr.ReadTextAddrFromVmlinux(vmlinux)
	assert.NoErr(err, "Failed to read .text address from vmlinux: %v")

	kaslrOffset := textAddr - kallsyms.Stext()
	addr2line, err := bpflbr.NewAddr2Line(vmlinux, kaslrOffset, kallsyms.SysBPF())
	assert.NoErr(err, "Failed to create addr2line: %v")

	engine, err := gapstone.New(int(gapstone.CS_ARCH_X86), int(gapstone.CS_MODE_64))
	assert.NoErr(err, "Failed to create capstone engine: %v")
	defer engine.Close()

	bpfProgs, err := bpflbr.NewBPFProgs(engine, progs, false)
	assert.NoErr(err, "Failed to get bpf progs: %v")
	defer bpfProgs.Close()

	tracingTargets := bpfProgs.Tracings()
	assert.True(len(tracingTargets)+len(flags.Kfuncs()) != 0, "No tracing target")

	bpfSpec, err := loadLbr()
	assert.NoErr(err, "Failed to load bpf spec: %v")

	numCPU, err := ebpf.PossibleCPU()
	assert.NoErr(err, "Failed to get possible cpu: %v")

	lbrsMapSpec := bpfSpec.Maps[".data.lbrs"]
	lbrsMapSpec.ValueSize = uint32(unsafe.Sizeof(bpflbr.Event{})) * uint32(numCPU)
	lbrsMapSpec.Contents[0].Value = make([]byte, lbrsMapSpec.ValueSize)
	lbrs, err := ebpf.NewMap(lbrsMapSpec)
	assert.NoErr(err, "Failed to create lbrs map: %v")

	events, err := ebpf.NewMap(bpfSpec.Maps["events"])
	assert.NoErr(err, "Failed to create events map: %v")
	defer events.Close()

	reusedMaps := map[string]*ebpf.Map{
		"events":     events,
		".data.lbrs": lbrs,
	}

	kfuncs := flags.Kfuncs()
	if len(kfuncs) != 0 && len(progs) == 0 {
		tracingTargets = tracingTargets[:0]
	}

	tracings, err := bpflbr.NewBPFTracing(bpfSpec, reusedMaps, tracingTargets, kfuncs)
	assert.NoVerifierErr(err, "Failed to trace: %v")
	defer tracings.Close()

	err = bpfProgs.AddProgs(tracings.Progs(), engine, true)
	assert.NoErr(err, "Failed to add bpf progs: %v")

	kallsyms, err = bpflbr.NewKallsyms()
	assert.NoErr(err, "Failed to reread /proc/kallsyms: %v")

	reader, err := ringbuf.NewReader(events)
	assert.NoErr(err, "Failed to create ringbuf reader: %v")
	defer reader.Close()

	w := os.Stdout
	if flags.OutputFile() != "" {
		f, err := os.OpenFile(flags.OutputFile(), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		assert.NoErr(err, "Failed to create output file: %v")
		defer f.Close()
		w = f
	}

	log.Print("bpflbr is running..")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errg, ctx := errgroup.WithContext(ctx)

	errg.Go(func() error {
		<-ctx.Done()
		_ = reader.Close()
		return nil
	})

	errg.Go(func() error {
		return bpflbr.Run(reader, bpfProgs, addr2line, kallsyms, w)
	})

	err = errg.Wait()
	assert.NoErr(err, "Failed: %v")
}
