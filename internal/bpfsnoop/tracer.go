// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"context"
	"errors"
	"io"
	"slices"
	"strconv"
	"sync/atomic"

	"github.com/cilium/ebpf"
)

// TraceTargetKind identifies the backend target class.
type TraceTargetKind uint8

const (
	TraceTargetFunction TraceTargetKind = iota
	TraceTargetBPFProgram
	TraceTargetTracepoint
)

// TraceAttachMode selects the kernel-function attachment mechanism.
type TraceAttachMode uint8

const (
	TraceAttachFentry TraceAttachMode = iota
	TraceAttachKprobeMulti
)

// TraceTarget selects one backend tracing target.
type TraceTarget struct {
	Kind        TraceTargetKind
	Name        string
	ID          uint32
	ProgramName string
	Attach      TraceAttachMode
}

// TraceCapture selects the data decoded from trace events.
type TraceCapture struct {
	Arguments           bool
	Retval              bool
	Duration            bool
	KernelStack         bool
	ArgumentExpressions []string
	Packet              bool
	FlameGraph          bool
	FunctionGraph       bool
	Instructions        bool
}

// TraceOptions configures one backend trace run. Callers are responsible for
// bounding the context and event count.
type TraceOptions struct {
	Targets            []TraceTarget
	PID                uint32
	Comm               string
	FilterExpression   string
	PacketFilter       string
	Capture            TraceCapture
	FunctionGraphDepth int
	MaxEvents          uint
	MaxKernelFunctions int
	Ready              func()
	Event              func(TraceEvent) error
}

func prepareTraceFlags(options TraceOptions) (*Flags, error) {
	flags := &Flags{fgraphDepth: uint(options.FunctionGraphDepth)}
	for _, target := range options.Targets {
		switch target.Kind {
		case TraceTargetFunction:
			name := target.Name
			if target.Attach == TraceAttachKprobeMulti {
				name = "(m)" + name
			}
			flags.kfuncs = append(flags.kfuncs, name)

		case TraceTargetBPFProgram:
			program := strconv.FormatUint(uint64(target.ID), 10)
			if target.ProgramName != "" {
				program = "n:" + target.ProgramName
			}
			if target.Name != "" {
				program += ":" + target.Name
			}
			flags.progs = append(flags.progs, program)

		case TraceTargetTracepoint:
			flags.ktps = append(flags.ktps, target.Name)

		default:
			return nil, errors.New("unsupported trace target kind")
		}
	}

	modes = []string{TracingModeEntry}
	if options.Capture.Retval {
		modes = []string{TracingModeExit}
	}
	if options.Capture.Duration {
		modes = []string{TracingModeEntry, TracingModeExit}
	}
	filterPid = options.PID
	filterComm = options.Comm
	filterArg = nil
	if options.FilterExpression != "" {
		filterArg = []string{options.FilterExpression}
	}
	var err error
	argFilter, err = prepareFuncArgumentsE(filterArg)
	if err != nil {
		return nil, err
	}
	filterPkt = options.PacketFilter
	pktFilter = preparePacketFilter(filterPkt)
	outputArg = slices.Clone(options.Capture.ArgumentExpressions)
	argOutput, err = prepareFuncArgOutputE(outputArg)
	if err != nil {
		return nil, err
	}
	outputPkt = options.Capture.Packet
	outputLbr = false
	requiredLbr = false
	outputFuncStack = options.Capture.KernelStack || options.Capture.FlameGraph
	outputFlameGraph = ""
	outputFuncInsns = options.Capture.Instructions
	outputFuncGraph = options.Capture.FunctionGraph
	debugTraceInsnCnt = 64
	runDurationThreshold = 0
	flags.requiredVmlinux = outputFuncStack
	return flags, nil
}

var traceRunning atomic.Bool

// Trace runs one native structured trace. Only one trace can run at a time
// because bpfsnoop's tracing configuration is process-global.
func Trace(ctx context.Context, options TraceOptions) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if options.Event == nil {
		return errors.New("trace event callback is nil")
	}
	if !traceRunning.CompareAndSwap(false, true) {
		return errors.New("another trace is already running")
	}
	defer traceRunning.Store(false)

	flags, err := prepareTraceFlags(options)
	if err != nil {
		return err
	}
	capture := traceStreamCapture{
		arguments:         options.Capture.Arguments,
		retval:            options.Capture.Retval,
		duration:          options.Capture.Duration,
		kernelStack:       options.Capture.KernelStack,
		selectedArguments: len(options.Capture.ArgumentExpressions) != 0,
		packet:            options.Capture.Packet,
		flameGraph:        options.Capture.FlameGraph,
		functionGraph:     options.Capture.FunctionGraph,
		instructions:      options.Capture.Instructions,
	}
	factory := func(maps map[string]*ebpf.Map, _ io.Writer, helpers *Helpers) (EventHandler, func(), error) {
		return NewTraceEventHandler(maps, helpers, capture, options.Event), nil, nil
	}
	return Boot(ctx, flags, BootConfig{
		NewEventHandler: factory,
		MaxEvents:       options.MaxEvents,
		MaxKernelFuncs:  options.MaxKernelFunctions,
		Ready:           options.Ready,
		isEventStream:   true,
	})
}
