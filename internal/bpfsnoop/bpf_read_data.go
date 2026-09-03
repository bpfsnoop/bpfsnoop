// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/fatih/color"
	"golang.org/x/sys/unix"

	"github.com/bpfsnoop/bpfsnoop/internal/assert"
	"github.com/bpfsnoop/bpfsnoop/internal/bpf"
	"github.com/bpfsnoop/bpfsnoop/internal/btfx"
	"github.com/bpfsnoop/bpfsnoop/internal/cc"
)

const (
	stubReadData = "read_stub"
)

// ReadKernelResult contains the raw value and type metadata for one
// kernel-memory expression.
type ReadKernelResult struct {
	Expression     string
	Type           string
	BTFType        btf.Type
	Buffer         []byte
	Size           int
	DataSize       int
	String         bool
	BufferValue    bool
	Slice          bool
	Hex            bool
	IntegerType    string
	AddressType    string
	PortType       string
	Packet         bool
	PacketType     string
	NumericPointer bool
}

type kernelReadOutput struct {
	result    ReadKernelResult
	formatted string
}

func readKernelData(expr string, helpers *Helpers) (kernelReadOutput, error) {
	var arg funcArgumentOutput
	arg.expr = expr

	err := PrepareKernelBTF()
	if err != nil {
		return kernelReadOutput{}, fmt.Errorf("failed to prepare kernel BTF: %w", err)
	}
	krnl := getKernelBTF()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	readSize, err := arg.compile(nil, krnl, krnl, 0, int(cc.MemoryReadFlagForce), "__read_data_fail")
	if err != nil {
		return kernelReadOutput{}, fmt.Errorf("failed to compile expression %q: %w", expr, err)
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
		return kernelReadOutput{}, fmt.Errorf("failed to load read bpf spec: %w", err)
	}
	delete(spec.Programs, "read") // not used here

	pidTgid := uint64(os.Getpid())<<32 | uint64(unix.Gettid())
	if err := spec.Variables["target_pid_tgid"].Set(pidTgid); err != nil {
		return kernelReadOutput{}, fmt.Errorf("failed to update target_pid_tgid: %w", err)
	}

	progSpec := spec.Programs["read_data"]
	injectInsns(progSpec, stubReadData, insns)

	progSpec.AttachTo = bpfFentryTest1
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return kernelReadOutput{}, fmt.Errorf("failed to create collection: %w", err)
	}
	defer coll.Close()

	prog := coll.Programs["read_data"]
	l, err := link.AttachTracing(link.TracingOptions{
		Program:    prog,
		AttachType: ebpf.AttachTraceFEntry,
	})
	if err != nil {
		return kernelReadOutput{}, fmt.Errorf("failed to fentry %s: %w", bpfFentryTest1, err)
	}
	defer l.Close()

	_, err = prog.Run(nil)
	if err != nil {
		return kernelReadOutput{}, fmt.Errorf("failed to run read_data program: %w", err)
	}

	var run bool
	if err := coll.Variables["run"].Get(&run); err != nil {
		return kernelReadOutput{}, fmt.Errorf("failed to get run: %w", err)
	}
	if !run {
		return kernelReadOutput{}, errors.New("reading kernel was not triggered")
	}

	buff := cloneVar(coll.Variables["buff"], int(readSize))

	hist := newHistogram(helpers.Flags.histExpr)
	tdigest := newTDigest(helpers.Flags.tdigestExpr)

	var sb strings.Builder
	f := findSymbolHelper(0, helpers)
	err = __outputFuncArgAttrs(&sb, []funcArgumentOutput{arg}, buff, hist, tdigest, f)
	if err != nil {
		return kernelReadOutput{}, fmt.Errorf("failed to output function arg attrs: %w", err)
	}

	tdigest.render(&sb)
	hist.render(&sb)

	typeName := btfx.Repr(arg.t)
	formatted := sb.String()
	return kernelReadOutput{
		result: ReadKernelResult{
			Expression:     expr,
			Type:           typeName,
			BTFType:        arg.t,
			Buffer:         buff,
			Size:           arg.size,
			DataSize:       arg.trueDataSize,
			String:         arg.isString,
			BufferValue:    arg.isBuf,
			Slice:          arg.isSlice,
			Hex:            arg.isHex,
			IntegerType:    arg.intType,
			AddressType:    arg.addrType,
			PortType:       arg.portType,
			Packet:         arg.isPkt,
			PacketType:     arg.pktType,
			NumericPointer: arg.isNumPtr,
		},
		formatted: formatted,
	}, nil
}

func newKernelReadHelpers(flags *Flags) (*Helpers, error) {
	ksyms, err := NewKallsyms()
	if err != nil {
		return nil, fmt.Errorf("failed to read kallsyms: %w", err)
	}

	progs, err := NewBPFProgs([]ProgFlag{{all: true}}, false, false)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare BPF programs: %w", err)
	}
	if err := progs.wait(); err != nil {
		progs.Close()
		return nil, fmt.Errorf("failed to parse BPF programs: %w", err)
	}

	return &Helpers{
		Flags: flags,
		Progs: progs,
		Ksyms: ksyms,
	}, nil
}

// ReadKernelData evaluates kernel-memory C expressions and returns their
// structured values. It stops at the first invalid expression or read failure.
func ReadKernelData(ctx context.Context, exprs []string) ([]ReadKernelResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	helpers, err := newKernelReadHelpers(&Flags{})
	if err != nil {
		return nil, err
	}
	defer helpers.Progs.Close()
	defer FlushReadObjs()

	results := make([]ReadKernelResult, 0, len(exprs))
	for _, expr := range exprs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		output, err := readKernelData(expr, helpers)
		if err != nil {
			return nil, fmt.Errorf("failed to read kernel data for expression %q: %w", expr, err)
		}
		results = append(results, output.result)
	}

	return results, nil
}

func printKernelReadResult(expr, output string) {
	fmt.Print("Expr: ")
	if colorfulOutput {
		color.New(color.FgGreen).Printf("%s\n", expr)
	} else {
		fmt.Printf("%s\n", expr)
	}
	fmt.Printf("Out: %s\n", output)
}

func readKernelDatum(exprs []string, flags *Flags) {
	helpers, err := newKernelReadHelpers(flags)
	assert.NoErr(err, "Failed to prepare kernel read helpers: %v")
	defer helpers.Progs.Close()
	defer FlushReadObjs()

	for i, expr := range exprs {
		if i != 0 {
			fmt.Printf("\n---\n")
		}

		output, err := readKernelData(expr, helpers)
		assert.NoVerifierErr(err, "Failed to read kernel data for expr %q: %v", expr)
		printKernelReadResult(expr, output.formatted)
	}
}
