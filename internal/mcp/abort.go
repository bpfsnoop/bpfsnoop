// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"sync"
)

type activeTraceSession struct {
	cancel  context.CancelFunc
	aborted bool
	done    chan struct{}
}

var activeTrace struct {
	sync.Mutex
	session *activeTraceSession
}

func beginTrace(ctx context.Context) (context.Context, *activeTraceSession, error) {
	activeTrace.Lock()
	defer activeTrace.Unlock()
	if activeTrace.session != nil {
		return nil, nil, errors.New("another trace is already running")
	}

	runCtx, cancel := context.WithCancel(ctx)
	session := &activeTraceSession{cancel: cancel, done: make(chan struct{})}
	activeTrace.session = session
	return runCtx, session, nil
}

func finishTrace(session *activeTraceSession) bool {
	session.cancel()

	activeTrace.Lock()
	defer activeTrace.Unlock()
	if activeTrace.session == session {
		activeTrace.session = nil
	}
	close(session.done)
	return session.aborted
}

// AbortOutput reports whether an active trace was aborted.
type AbortOutput struct {
	Aborted bool `json:"aborted" jsonschema:"true when an active MCP trace was cancelled and released"`
}

// Abort cancels the active MCP trace and waits for its resources to be
// released.
func Abort(ctx context.Context) (AbortOutput, error) {
	activeTrace.Lock()
	session := activeTrace.session
	if session == nil {
		activeTrace.Unlock()
		return AbortOutput{}, nil
	}
	session.aborted = true
	session.cancel()
	done := session.done
	activeTrace.Unlock()

	select {
	case <-done:
		return AbortOutput{Aborted: true}, nil
	case <-ctx.Done():
		return AbortOutput{}, ctx.Err()
	}
}
