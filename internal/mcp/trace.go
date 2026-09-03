// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bpfsnoop/bpfsnoop/internal/bpfsnoop"
	"github.com/bpfsnoop/bpfsnoop/internal/cc"
)

const (
	TraceKindFunction         = "function"
	TraceKindBPFProgram       = "bpf_program"
	TraceKindTracepoint       = "tracepoint"
	TraceAttachFentry         = "fentry"
	TraceAttachKprobe         = "kprobe_multi"
	TracePacketSourceArgument = "argument"
	TracePacketSourceRetval   = "retval"

	DefaultTraceDuration    = 3 * time.Second
	MinTraceDuration        = 100 * time.Millisecond
	MaxTraceDuration        = 30 * time.Second
	DefaultTraceEvents      = 100
	MaxTraceEvents          = 1000
	MaxTraceFentryFunctions = 200
	MaxTraceFunctionDepth   = 20
	MaxTraceCommLength      = 15

	traceSetupTimeout = 30 * time.Second

	TraceActionStart = "start"
	TraceActionWait  = "wait"
	TraceActionAbort = "abort"
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
	PacketSource        string   `json:"packet_source,omitempty"`
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
	PacketSource       string
	Capture            TraceCapture
	FunctionGraphDepth int
	Duration           time.Duration
	MaxEvents          int
}

type traceSession struct {
	cancel    context.CancelFunc
	ready     chan struct{}
	done      chan struct{}
	startedAt time.Time
	readyAt   time.Time
	deadline  time.Time
	aborted   bool
	events    int
	options   TraceOptions
	warnings  []string
	output    TraceOutput
	err       error
}

var traces struct {
	sync.Mutex
	session *traceSession
}

func destroyTraceSession(session *traceSession) {
	traces.Lock()
	if traces.session != session {
		traces.Unlock()
		return
	}
	session.aborted = true
	session.cancel()
	traces.Unlock()

	<-session.done

	traces.Lock()
	if traces.session == session {
		traces.session = nil
	}
	traces.Unlock()
}

type TraceStartOutput struct {
	State    string   `json:"state" jsonschema:"ready once bpfsnoop is attached"`
	ReadyAt  string   `json:"ready_at" jsonschema:"UTC time when tracing became ready"`
	Deadline string   `json:"deadline" jsonschema:"UTC time when tracing will stop by duration"`
	Warnings []string `json:"warnings,omitempty" jsonschema:"warnings emitted while preparing the trace"`
}

type TraceAbortOutput struct {
	Aborted bool `json:"aborted" jsonschema:"true when the active trace was cancelled"`
}

func normalizePacketSource(source, field string) (string, error) {
	if source == "" {
		return TracePacketSourceArgument, nil
	}
	if source != TracePacketSourceArgument && source != TracePacketSourceRetval {
		return "", fmt.Errorf("%s must be %q or %q", field, TracePacketSourceArgument, TracePacketSourceRetval)
	}
	return source, nil
}

func traceExpressionUsesRetval(field, expr string) (bool, error) {
	if expr == "" {
		return false, nil
	}
	vars, err := cc.ExtractVarNames(expr)
	if err != nil {
		return false, fmt.Errorf("invalid %s: %w", field, err)
	}
	return slices.Contains(vars, cc.RetvalName), nil
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
	options.PacketExpr = strings.TrimSpace(options.PacketExpr)
	if packetExpr, ok := strings.CutPrefix(options.PacketExpr, "(r)"); ok {
		if options.PacketSource != "" && options.PacketSource != TracePacketSourceRetval {
			return options, errors.New("filter.packet uses the (r) return selector but filter.packet_source selects an argument")
		}
		options.PacketSource = TracePacketSourceRetval
		options.PacketExpr = strings.TrimSpace(packetExpr)
	}
	if options.PacketExpr == "" {
		if options.PacketSource != "" {
			return options, errors.New("filter.packet_source requires filter.packet")
		}
	} else {
		var err error
		options.PacketSource, err = normalizePacketSource(options.PacketSource, "filter.packet_source")
		if err != nil {
			return options, err
		}
	}
	if !options.Capture.Packet {
		if options.Capture.PacketSource != "" {
			return options, errors.New("capture.packet_source requires capture.packet")
		}
	} else {
		var err error
		options.Capture.PacketSource, err = normalizePacketSource(options.Capture.PacketSource, "capture.packet_source")
		if err != nil {
			return options, err
		}
	}
	if _, err := traceExpressionUsesRetval("filter.expr", options.Expr); err != nil {
		return options, err
	}
	selectedUsesRetval := false
	for i, expr := range options.Capture.ArgumentExpressions {
		usesRetval, err := traceExpressionUsesRetval(fmt.Sprintf("capture.argument_expressions[%d]", i), expr)
		if err != nil {
			return options, err
		}
		selectedUsesRetval = selectedUsesRetval || usesRetval
	}
	for i, target := range options.Targets {
		if target.Kind != TraceKindFunction || target.Attach != TraceAttachKprobe {
			continue
		}
		if options.Expr != "" {
			return options, fmt.Errorf("function target %d uses kprobe_multi, which does not support expr without a common typed argument", i)
		}
		if selectedUsesRetval {
			return options, fmt.Errorf("function target %d uses kprobe_multi, which does not support %s in argument_expressions", i, cc.RetvalName)
		}
		if options.PacketSource == TracePacketSourceRetval {
			return options, fmt.Errorf("function target %d uses kprobe_multi, which does not support a packet filter from %s", i, cc.RetvalName)
		}
		if options.Capture.PacketSource == TracePacketSourceRetval {
			return options, fmt.Errorf("function target %d uses kprobe_multi, which does not support packet capture from %s", i, cc.RetvalName)
		}
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
	if options.Capture.FunctionGraph {
		options.Capture.Arguments = true
		options.Capture.Duration = true
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

func runTrace(ctx context.Context, options TraceOptions, readyNotify func(), warningNotify func(string), eventNotify func(), isAborted func() bool) (TraceOutput, error) {
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
	warnings := make([]string, 0)
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
		if readyNotify != nil {
			readyNotify()
		}
		durationTimer = time.AfterFunc(options.Duration, func() {
			durationExpired.Store(true)
			cancel()
		})
	}
	event := func(event bpfsnoop.TraceEvent) error {
		if options.Capture.FlameGraph {
			handleTraceFlameGraph(&event, flameGraph, options.Capture.KernelStack)
		}
		converted, err := makeTraceEventOutput(event)
		if err != nil {
			return err
		}
		output.Events = append(output.Events, converted)
		if eventNotify != nil {
			eventNotify()
		}
		return nil
	}

	err = bpfsnoop.Trace(runCtx, bpfsnoop.TraceOptions{
		Targets:            backendTraceTargets(options.Targets),
		PID:                options.PID,
		Comm:               options.Comm,
		FilterExpression:   options.Expr,
		PacketFilter:       options.PacketExpr,
		PacketFilterRetval: options.PacketSource == TracePacketSourceRetval,
		Capture: bpfsnoop.TraceCapture{
			Arguments:           options.Capture.Arguments,
			Retval:              options.Capture.Retval,
			Duration:            options.Capture.Duration,
			KernelStack:         options.Capture.KernelStack,
			ArgumentExpressions: options.Capture.ArgumentExpressions,
			Packet:              options.Capture.Packet,
			PacketRetval:        options.Capture.PacketSource == TracePacketSourceRetval,
			FlameGraph:          options.Capture.FlameGraph,
			FunctionGraph:       options.Capture.FunctionGraph,
			Instructions:        options.Capture.Instructions,
		},
		FunctionGraphDepth: options.FunctionGraphDepth,
		MaxEvents:          uint(options.MaxEvents),
		MaxKernelFunctions: MaxTraceFentryFunctions,
		Ready:              ready,
		Warning: func(warning string) {
			warnings = append(warnings, warning)
			if warningNotify != nil {
				warningNotify(warning)
			}
		},
		Event: event,
	})
	if durationTimer != nil {
		durationTimer.Stop()
	}
	aborted := isAborted != nil && isAborted()
	if ctx.Err() != nil && !aborted {
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
	output.Warnings = warnings
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

// Trace validates and runs one bounded tracing experiment synchronously.
func Trace(ctx context.Context, options TraceOptions) (TraceOutput, error) {
	return runTrace(ctx, options, nil, nil, nil, nil)
}

// StartTrace returns only after the sole trace session is attached and ready.
func StartTrace(ctx context.Context, options TraceOptions) (TraceStartOutput, error) {
	options, err := normalizeTraceOptions(options)
	if err != nil {
		return TraceStartOutput{}, err
	}

	traces.Lock()
	if traces.session != nil {
		select {
		case <-traces.session.done:
			if traces.session.err == nil {
				traces.Unlock()
				return TraceStartOutput{}, errors.New("the previous trace result has not been collected; call trace with action wait")
			}
			traces.session = nil
		default:
			traces.Unlock()
			return TraceStartOutput{}, errors.New("another trace is already running")
		}
	}
	runCtx, cancel := context.WithCancel(context.Background())
	session := &traceSession{cancel: cancel, ready: make(chan struct{}), done: make(chan struct{}), startedAt: time.Now(), options: options}
	traces.session = session
	traces.Unlock()

	go func() {
		output, err := runTrace(runCtx, options, func() {
			traces.Lock()
			session.readyAt = time.Now()
			session.deadline = session.readyAt.Add(options.Duration)
			close(session.ready)
			traces.Unlock()
		}, func(warning string) {
			traces.Lock()
			session.warnings = append(session.warnings, warning)
			traces.Unlock()
		}, func() {
			traces.Lock()
			session.events++
			traces.Unlock()
		}, func() bool {
			traces.Lock()
			defer traces.Unlock()
			return session.aborted
		})
		traces.Lock()
		session.output, session.err = output, err
		close(session.done)
		traces.Unlock()
	}()

	select {
	case <-session.ready:
		traces.Lock()
		output := TraceStartOutput{State: "ready", ReadyAt: session.readyAt.UTC().Format(time.RFC3339Nano), Deadline: session.deadline.UTC().Format(time.RFC3339Nano), Warnings: slices.Clone(session.warnings)}
		traces.Unlock()
		return output, nil
	case <-session.done:
		traces.Lock()
		err := session.err
		if traces.session == session {
			traces.session = nil
		}
		traces.Unlock()
		if err != nil {
			return TraceStartOutput{}, err
		}
		return TraceStartOutput{}, errors.New("trace exited before becoming ready")
	case <-ctx.Done():
		destroyTraceSession(session)
		return TraceStartOutput{}, ctx.Err()
	}
}

// WaitTrace returns the completed result for the sole trace session.
func WaitTrace(ctx context.Context) (TraceOutput, error) {
	traces.Lock()
	session := traces.session
	traces.Unlock()
	if session == nil {
		return TraceOutput{}, errors.New("no trace has been started")
	}
	select {
	case <-session.done:
		traces.Lock()
		defer traces.Unlock()
		if traces.session != session {
			return TraceOutput{}, errors.New("trace session changed while waiting")
		}
		traces.session = nil
		if session.err != nil {
			return TraceOutput{}, session.err
		}
		return session.output, nil
	case <-ctx.Done():
		destroyTraceSession(session)
		return TraceOutput{}, ctx.Err()
	}
}

// AbortTrace cancels the sole active trace. Its result remains available
// through WaitTrace.
func AbortTrace(ctx context.Context) (TraceAbortOutput, error) {
	traces.Lock()
	session := traces.session
	if session == nil {
		traces.Unlock()
		return TraceAbortOutput{}, nil
	}
	select {
	case <-session.done:
		traces.Unlock()
		return TraceAbortOutput{}, nil
	default:
		session.aborted = true
		session.cancel()
	}
	traces.Unlock()
	select {
	case <-session.done:
		return TraceAbortOutput{Aborted: true}, nil
	case <-ctx.Done():
		return TraceAbortOutput{}, ctx.Err()
	}
}
