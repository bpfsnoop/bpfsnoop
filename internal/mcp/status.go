// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package mcp

import "time"

const (
	StatusIdle   = "idle"
	StatusActive = "active"

	SessionSettingUp = "setting_up"
	SessionRunning   = "running"
	SessionAborting  = "aborting"
)

// StatusTraceFilter describes the filters of an active trace session.
type StatusTraceFilter struct {
	PID    uint32 `json:"pid,omitempty" jsonschema:"process ID selected by the trace"`
	Comm   string `json:"comm,omitempty" jsonschema:"process command name selected by the trace"`
	Expr   string `json:"expr,omitempty" jsonschema:"typed C expression used to filter function events"`
	Packet string `json:"packet,omitempty" jsonschema:"packet expression used to filter events"`
}

// StatusTraceLimits describes the bounds of an active trace session.
type StatusTraceLimits struct {
	DurationMS int64 `json:"duration_ms" jsonschema:"maximum running time after attachment in milliseconds"`
	MaxEvents  int   `json:"max_events" jsonschema:"maximum number of events returned by the trace"`
}

// ActiveSessionInfo describes the operation currently running in the MCP
// daemon.
type ActiveSessionInfo struct {
	Tool               string             `json:"tool" jsonschema:"MCP tool currently running"`
	State              string             `json:"state" jsonschema:"current operation state: setting_up, running, or aborting"`
	StartedAt          string             `json:"started_at" jsonschema:"UTC time when the operation started"`
	ElapsedMS          int64              `json:"elapsed_ms" jsonschema:"milliseconds since the operation started"`
	EventsCollected    int                `json:"events_collected" jsonschema:"number of trace events collected so far"`
	Targets            []TraceTarget      `json:"targets" jsonschema:"normalized targets attached by the trace"`
	Filter             *StatusTraceFilter `json:"filter,omitempty" jsonschema:"filters applied by the trace"`
	Capture            TraceCapture       `json:"capture" jsonschema:"data selected for capture by the trace"`
	Limits             StatusTraceLimits  `json:"limits" jsonschema:"bounds applied to the trace"`
	FunctionGraphDepth int                `json:"function_graph_depth,omitempty" jsonschema:"maximum function graph depth when graph capture is enabled"`
}

// StatusOutput reports whether the MCP daemon has an active operation.
type StatusOutput struct {
	Status        string             `json:"status" jsonschema:"daemon state: idle or active"`
	ActiveSession *ActiveSessionInfo `json:"active_session,omitempty" jsonschema:"details of the operation running in the daemon"`
}

func makeStatusTraceFilter(options TraceOptions) *StatusTraceFilter {
	if options.PID == 0 && options.Comm == "" && options.Expr == "" && options.PacketExpr == "" {
		return nil
	}
	return &StatusTraceFilter{
		PID:    options.PID,
		Comm:   options.Comm,
		Expr:   options.Expr,
		Packet: options.PacketExpr,
	}
}

// Status returns a snapshot of the current MCP daemon operation.
func Status() StatusOutput {
	activeTrace.Lock()
	defer activeTrace.Unlock()

	session := activeTrace.session
	if session == nil {
		return StatusOutput{Status: StatusIdle}
	}

	state := SessionSettingUp
	if !session.readyAt.IsZero() {
		state = SessionRunning
	}
	if session.aborted {
		state = SessionAborting
	}

	options := session.options
	functionGraphDepth := 0
	if options.Capture.FunctionGraph {
		functionGraphDepth = options.FunctionGraphDepth
	}
	return StatusOutput{
		Status: StatusActive,
		ActiveSession: &ActiveSessionInfo{
			Tool:            "trace",
			State:           state,
			StartedAt:       session.startedAt.UTC().Format(time.RFC3339Nano),
			ElapsedMS:       time.Since(session.startedAt).Milliseconds(),
			EventsCollected: session.events,
			Targets:         options.Targets,
			Filter:          makeStatusTraceFilter(options),
			Capture:         options.Capture,
			Limits: StatusTraceLimits{
				DurationMS: options.Duration.Milliseconds(),
				MaxEvents:  options.MaxEvents,
			},
			FunctionGraphDepth: functionGraphDepth,
		},
	}
}
