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
	Kind        string
	Name        string
	ID          uint32
	ProgramName string
	Attach      string
}

// TraceCapture selects the data returned for each event.
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

type traceStats struct {
	returned   int
	durationMS int64
}

type traceFlameGraphEntry struct {
	stack []string
	count int
}

type traceResult struct {
	status     string
	stoppedBy  string
	stats      traceStats
	events     []bpfsnoop.TraceEvent
	flameGraph []traceFlameGraphEntry
	truncated  bool
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

func handleTraceFlameGraph(event *bpfsnoop.TraceEvent, flameGraph map[string]*traceFlameGraphEntry, keepStack bool) {
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
		entry = &traceFlameGraphEntry{stack: stack}
		flameGraph[key] = entry
	}
	entry.count++
	if !keepStack {
		event.KernelStack = nil
	}
}

func runTrace(ctx context.Context, options TraceOptions) (traceResult, error) {
	options, err := normalizeTraceOptions(options)
	if err != nil {
		return traceResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return traceResult{}, err
	}

	result := traceResult{
		status: "completed",
		events: make([]bpfsnoop.TraceEvent, 0, options.MaxEvents),
	}
	flameGraph := make(map[string]*traceFlameGraphEntry)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var setupExpired atomic.Bool
	setupTimer := time.AfterFunc(traceSetupTimeout, func() {
		setupExpired.Store(true)
		cancel()
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
			cancel()
		})
	}
	event := func(event bpfsnoop.TraceEvent) error {
		if options.Capture.FlameGraph {
			handleTraceFlameGraph(&event, flameGraph, options.Capture.KernelStack)
		}
		result.events = append(result.events, event)
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
	if ctx.Err() != nil {
		return traceResult{}, ctx.Err()
	}
	if setupExpired.Load() {
		return traceResult{}, fmt.Errorf("trace did not become ready within %s", traceSetupTimeout)
	}
	if err != nil {
		return traceResult{}, err
	}
	if started.IsZero() {
		return traceResult{}, errors.New("trace exited before becoming ready")
	}
	for _, entry := range flameGraph {
		result.flameGraph = append(result.flameGraph, *entry)
	}
	slices.SortFunc(result.flameGraph, func(a, b traceFlameGraphEntry) int {
		return strings.Compare(strings.Join(a.stack, "\x00"), strings.Join(b.stack, "\x00"))
	})

	result.stats.returned = len(result.events)
	result.stats.durationMS = time.Since(started).Milliseconds()
	if durationExpired.Load() {
		result.stoppedBy = "duration"
		return result, nil
	}
	if len(result.events) == options.MaxEvents {
		result.stoppedBy = "max_events"
		result.truncated = true
		return result, nil
	}
	return traceResult{}, errors.New("trace exited before reaching a trace limit")
}
