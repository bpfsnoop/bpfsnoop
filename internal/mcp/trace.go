// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/bpfsnoop/bpfsnoop/internal/bpfsnoop"
)

const (
	TraceKindFunction   = "function"
	TraceKindBPFProgram = "bpf_program"
	TraceKindTracepoint = "tracepoint"
	TraceAttachFentry   = "fentry"
	TraceAttachKprobe   = "kprobe_multi"

	DefaultTraceDuration    = 3 * time.Second
	MinTraceDuration        = 100 * time.Millisecond
	MaxTraceDuration        = 30 * time.Second
	DefaultTraceEvents      = 100
	MaxTraceEvents          = 1000
	MaxTraceFentryFunctions = 200
	MaxTraceFunctionDepth   = 20
	MaxTraceCommLength      = 15

	traceSetupTimeout = 30 * time.Second
)

// TraceTarget selects one kernel function, tracepoint, or loaded BPF program.
type TraceTarget struct {
	Kind        string `json:"kind"`
	Name        string `json:"name,omitempty"`
	ID          uint32 `json:"id,omitempty"`
	ProgramName string `json:"program_name,omitempty"`
	Attach      string `json:"attach,omitempty"`
}

// TraceCapture selects the data returned for each event.
type TraceCapture struct {
	Arguments           bool     `json:"arguments,omitempty"`
	Retval              bool     `json:"retval,omitempty"`
	Duration            bool     `json:"duration,omitempty"`
	KernelStack         bool     `json:"kernel_stack,omitempty"`
	ArgumentExpressions []string `json:"argument_expressions,omitempty"`
	Packet              bool     `json:"packet,omitempty"`
	FlameGraph          bool     `json:"flame_graph,omitempty"`
	FunctionGraph       bool     `json:"function_graph,omitempty"`
	Instructions        bool     `json:"instructions,omitempty"`
}

// TraceOptions controls one bounded trace request.
type TraceOptions struct {
	Targets            []TraceTarget
	PID                uint32
	Comm               string
	Expr               string
	PacketExpr         string
	Capture            TraceCapture
	FunctionGraphDepth int
	Duration           time.Duration
	MaxEvents          int
}

func normalizeTraceOptions(options TraceOptions) (TraceOptions, error) {
	if len(options.Targets) == 0 {
		return options, errors.New("at least one trace target is required")
	}
	for i, target := range options.Targets {
		switch target.Kind {
		case TraceKindFunction:
			if strings.TrimSpace(target.Name) == "" {
				return options, fmt.Errorf("function target %d has an empty name", i)
			}
			if target.ID != 0 || target.ProgramName != "" {
				return options, fmt.Errorf("function target %d only accepts name and attach", i)
			}
			if target.Attach == "" {
				options.Targets[i].Attach = TraceAttachFentry
			} else if target.Attach != TraceAttachFentry && target.Attach != TraceAttachKprobe {
				return options, fmt.Errorf("function target %d has unsupported attach mode %q", i, target.Attach)
			}
			if target.Attach == TraceAttachKprobe && options.Expr != "" {
				return options, fmt.Errorf("function target %d uses kprobe_multi, which does not support expr without a common typed argument", i)
			}

		case TraceKindBPFProgram:
			if target.ID == 0 && strings.TrimSpace(target.ProgramName) == "" {
				return options, fmt.Errorf("BPF program target %d requires id or program_name", i)
			}
			if target.ID != 0 && target.ProgramName != "" {
				return options, fmt.Errorf("BPF program target %d must select by either id or program_name", i)
			}
			if target.Attach != "" {
				return options, fmt.Errorf("BPF program target %d must not specify attach", i)
			}

		case TraceKindTracepoint:
			if strings.TrimSpace(target.Name) == "" {
				return options, fmt.Errorf("tracepoint target %d has an empty name", i)
			}
			if target.ID != 0 || target.ProgramName != "" || target.Attach != "" {
				return options, fmt.Errorf("tracepoint target %d only accepts name", i)
			}

		default:
			return options, fmt.Errorf("target %d has unsupported kind %q", i, target.Kind)
		}
	}
	if len(options.Comm) > MaxTraceCommLength {
		return options, fmt.Errorf("comm filter is too long: maximum is %d bytes", MaxTraceCommLength)
	}
	if options.Duration == 0 {
		options.Duration = DefaultTraceDuration
	}
	if options.Duration < MinTraceDuration || options.Duration > MaxTraceDuration {
		return options, fmt.Errorf("duration must be between %s and %s", MinTraceDuration, MaxTraceDuration)
	}
	if options.MaxEvents == 0 {
		options.MaxEvents = DefaultTraceEvents
	}
	if options.MaxEvents < 1 || options.MaxEvents > MaxTraceEvents {
		return options, fmt.Errorf("max_events must be between 1 and %d", MaxTraceEvents)
	}
	if options.Capture.Duration {
		options.Capture.Retval = true
	}
	if options.Capture.FunctionGraph && options.Capture.Instructions {
		return options, errors.New("function_graph and instructions cannot be captured together")
	}
	if options.Capture.Instructions {
		for i, target := range options.Targets {
			if target.Kind != TraceKindFunction || target.Attach == TraceAttachKprobe {
				return options, fmt.Errorf("instructions require an fentry kernel function target, got target %d", i)
			}
		}
	}
	if options.FunctionGraphDepth == 0 {
		options.FunctionGraphDepth = 3
	}
	if options.FunctionGraphDepth < 1 || options.FunctionGraphDepth > MaxTraceFunctionDepth {
		return options, fmt.Errorf("function_graph_depth must be between 1 and %d", MaxTraceFunctionDepth)
	}
	return options, nil
}

func backendTraceTargets(targets []TraceTarget) []bpfsnoop.TraceTarget {
	result := make([]bpfsnoop.TraceTarget, 0, len(targets))
	for _, target := range targets {
		backend := bpfsnoop.TraceTarget{
			Name:        target.Name,
			ID:          target.ID,
			ProgramName: target.ProgramName,
		}
		switch target.Kind {
		case TraceKindFunction:
			backend.Kind = bpfsnoop.TraceTargetFunction
			if target.Attach == TraceAttachKprobe {
				backend.Attach = bpfsnoop.TraceAttachKprobeMulti
			}
		case TraceKindBPFProgram:
			backend.Kind = bpfsnoop.TraceTargetBPFProgram
		case TraceKindTracepoint:
			backend.Kind = bpfsnoop.TraceTargetTracepoint
		}
		result = append(result, backend)
	}
	return result
}

func handleTraceFlameGraph(event *bpfsnoop.TraceEvent, flameGraph map[string]*traceFlameGraphEntryOutput, keepStack bool) {
	if len(event.KernelStack) == 0 {
		return
	}

	stack := make([]string, 0, len(event.KernelStack))
	for _, frame := range event.KernelStack {
		name := frame.Function
		if name == "" {
			name = frame.Address
		}
		stack = append(stack, name)
	}
	slices.Reverse(stack)

	key := strings.Join(stack, "\x00")
	entry := flameGraph[key]
	if entry == nil {
		entry = &traceFlameGraphEntryOutput{Stack: stack}
		flameGraph[key] = entry
	}
	entry.Count++
	if !keepStack {
		event.KernelStack = nil
	}
}

// Trace validates and runs one bounded tracing experiment.
func Trace(ctx context.Context, options TraceOptions) (TraceOutput, error) {
	options, err := normalizeTraceOptions(options)
	if err != nil {
		return TraceOutput{}, err
	}
	if err := ctx.Err(); err != nil {
		return TraceOutput{}, err
	}

	output := TraceOutput{
		Status: "completed",
		Events: make([]traceEventOutput, 0, options.MaxEvents),
	}
	flameGraph := make(map[string]*traceFlameGraphEntryOutput)
	runCtx, session, err := beginTrace(ctx)
	if err != nil {
		return TraceOutput{}, err
	}

	var setupExpired atomic.Bool
	setupTimer := time.AfterFunc(traceSetupTimeout, func() {
		setupExpired.Store(true)
		session.cancel()
	})
	defer setupTimer.Stop()

	var durationExpired atomic.Bool
	var durationTimer *time.Timer
	var started time.Time
	ready := func() {
		if !setupTimer.Stop() {
			return
		}
		started = time.Now()
		durationTimer = time.AfterFunc(options.Duration, func() {
			durationExpired.Store(true)
			session.cancel()
		})
	}
	event := func(event bpfsnoop.TraceEvent) error {
		if options.Capture.FlameGraph {
			handleTraceFlameGraph(&event, flameGraph, options.Capture.KernelStack)
		}
		output.Events = append(output.Events, makeTraceEventOutput(event))
		return nil
	}

	err = bpfsnoop.Trace(runCtx, bpfsnoop.TraceOptions{
		Targets:          backendTraceTargets(options.Targets),
		PID:              options.PID,
		Comm:             options.Comm,
		FilterExpression: options.Expr,
		PacketFilter:     options.PacketExpr,
		Capture: bpfsnoop.TraceCapture{
			Arguments:           options.Capture.Arguments,
			Retval:              options.Capture.Retval,
			Duration:            options.Capture.Duration,
			KernelStack:         options.Capture.KernelStack,
			ArgumentExpressions: options.Capture.ArgumentExpressions,
			Packet:              options.Capture.Packet,
			FlameGraph:          options.Capture.FlameGraph,
			FunctionGraph:       options.Capture.FunctionGraph,
			Instructions:        options.Capture.Instructions,
		},
		FunctionGraphDepth: options.FunctionGraphDepth,
		MaxEvents:          uint(options.MaxEvents),
		MaxKernelFunctions: MaxTraceFentryFunctions,
		Ready:              ready,
		Event:              event,
	})
	if durationTimer != nil {
		durationTimer.Stop()
	}
	aborted := finishTrace(session)
	if ctx.Err() != nil {
		return TraceOutput{}, ctx.Err()
	}
	if setupExpired.Load() {
		return TraceOutput{}, fmt.Errorf("trace did not become ready within %s", traceSetupTimeout)
	}
	if err != nil && !aborted {
		return TraceOutput{}, err
	}
	if started.IsZero() && !aborted {
		return TraceOutput{}, errors.New("trace exited before becoming ready")
	}
	for _, entry := range flameGraph {
		output.FlameGraph = append(output.FlameGraph, *entry)
	}
	slices.SortFunc(output.FlameGraph, func(a, b traceFlameGraphEntryOutput) int {
		return strings.Compare(strings.Join(a.Stack, "\x00"), strings.Join(b.Stack, "\x00"))
	})

	output.Stats.Returned = len(output.Events)
	if !started.IsZero() {
		output.Stats.DurationMS = time.Since(started).Milliseconds()
	}
	if aborted {
		output.Status = "aborted"
		output.StoppedBy = "abort"
		return output, nil
	}
	if durationExpired.Load() {
		output.StoppedBy = "duration"
		return output, nil
	}
	if len(output.Events) == options.MaxEvents {
		output.StoppedBy = "max_events"
		output.Truncated = true
		return output, nil
	}
	return TraceOutput{}, errors.New("trace exited before reaching a trace limit")
}
