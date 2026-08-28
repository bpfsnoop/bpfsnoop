// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/fatih/color"
	"golang.org/x/sys/unix"

	"github.com/bpfsnoop/bpfsnoop/internal/assert"
	"github.com/bpfsnoop/bpfsnoop/internal/bpf"
	"github.com/bpfsnoop/bpfsnoop/internal/cc"
)

const (
	stubReadData = "read_stub"
)

func readKernelData(expr string, helpers *Helpers) error {
	var arg funcArgumentOutput
	arg.expr = expr

	err := PrepareKernelBTF()
	assert.NoErr(err, "Failed to prepare kernel BTF: %v", err)
	krnl := getKernelBTF()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	readSize, err := arg.compile(nil, nil, krnl, krnl, 0, int(cc.MemoryReadFlagForce), "__read_data_fail")
	if err != nil {
		return fmt.Errorf("Failed to compile expression %q: %w", expr, err)
	}

	var insns asm.Instructions
	insns = append(
		insns,
		asm.Mov.Reg(outputArgRegBuff, asm.R1), // buff = R1
	)
	insns = append(insns, arg.insn...)
	insns = append(
		insns,
		asm.Return(),
	)

	spec, err := bpf.LoadRead()
	if err != nil {
		return fmt.Errorf("failed to load read bpf spec: %w", err)
	}
	delete(spec.Programs, "read") // not used here

	pidTgid := uint64(os.Getpid())<<32 | uint64(unix.Gettid())
	if err := spec.Variables["target_pid_tgid"].Set(pidTgid); err != nil {
		return fmt.Errorf("failed to update target_pid_tgid: %w", err)
	}

	progSpec := spec.Programs["read_data"]
	injectInsns(progSpec, stubReadData, insns)

	progSpec.AttachTo = bpfFentryTest1
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("failed to create collection: %w", err)
	}
	defer coll.Close()

	prog := coll.Programs["read_data"]
	l, err := link.AttachTracing(link.TracingOptions{
		Program:    prog,
		AttachType: ebpf.AttachTraceFEntry,
	})
	if err != nil {
		return fmt.Errorf("failed to fentry %s: %w", bpfFentryTest1, err)
	}
	defer l.Close()

	_, err = prog.Run(nil)
	if err != nil {
		return fmt.Errorf("failed to run read_data program: %w", err)
	}

	var run bool
	if err := coll.Variables["run"].Get(&run); err != nil {
		return fmt.Errorf("failed to get run: %w", err)
	}
	if !run {
		return errors.New("reading kernel was not triggered")
	}

	buff := cloneVar(coll.Variables["buff"], int(readSize))

	hist := newHistogram(helpers.Flags.histExpr)
	defer hist.render(os.Stdout)

	tdigest := newTDigest(helpers.Flags.tdigestExpr)
	defer tdigest.render(os.Stdout)

	var sb strings.Builder
	f := findSymbolHelper(0, helpers)
	err = __outputFuncArgAttrs(&sb, []funcArgumentOutput{arg}, buff, true, hist, tdigest, f)
	if err != nil {
		return fmt.Errorf("failed to output function arg attrs: %w", err)
	}

	fmt.Print("Expr: ")
	if colorfulOutput {
		color.New(color.FgGreen).Printf("%s\n", expr)
	} else {
		fmt.Printf("%s\n", expr)
	}
	fmt.Printf("Out: %s\n", sb.String())

	return nil
}

func readKernelDatum(exprs []string, flags *Flags) {
	ksyms, err := NewKallsyms()
	assert.NoErr(err, "Failed to read kallsyms: %v")

	progs, err := NewBPFProgs([]ProgFlag{{all: true}}, false, false)
	assert.NoErr(err, "Failed to prepare BPF programs: %v")

	defer FlushReadObjs()

	var helpers Helpers
	helpers.Ksyms = ksyms
	helpers.Progs = progs
	helpers.Flags = flags

	for i, expr := range exprs {
		if i != 0 {
			fmt.Printf("\n---\n")
		}

		err := readKernelData(expr, &helpers)
		assert.NoVerifierErr(err, "Failed to read kernel data for expr %q: %v", expr)
	}
}
