// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

// Package cliworker defines a persistent CLI subprocess protocol. Requests use
// stdin, output and completion records use stdout, and logs use stderr.
package cliworker

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

type Request struct {
	Args   []string `json:"args,omitempty"`
	Cancel bool     `json:"cancel,omitempty"`
}

type Event struct {
	Type  string `json:"type"`
	Data  string `json:"data,omitempty"`
	Error string `json:"error,omitempty"`
}

// CanForward leaves commands that exit during flag parsing in their own process.
func CanForward(args []string) bool {
	for _, arg := range args {
		name, _, _ := strings.Cut(arg, "=")
		switch name {
		case "--mcp", "--mcp-daemon", "--cli-worker", "--read", "--show-type-proto", "--find-vmlinux", "--detect-features", "--help", "-h":
			return false
		}
		if strings.HasPrefix(arg, "-C") {
			return false
		}
	}
	return true
}

// Serve runs one request at a time while retaining process-wide backend caches.
// A cancel request or EOF stops the current trace and waits for its cleanup.
func Serve(ctx context.Context, run func(context.Context, []string, func()) error) error {
	ctx, stop := context.WithCancel(ctx)
	defer stop()

	encoder := json.NewEncoder(os.Stdout)
	var outputMu sync.Mutex

	send := func(event Event) {
		outputMu.Lock()
		defer outputMu.Unlock()
		if err := encoder.Encode(event); err != nil {
			stop()
		}
	}

	requests := make(chan Request)
	go func() {
		defer stop()
		decoder := json.NewDecoder(os.Stdin)
		for {
			var request Request
			if err := decoder.Decode(&request); err != nil {
				return
			}
			select {
			case requests <- request:
			case <-ctx.Done():
				return
			}
		}
	}()

	send(Event{Type: "worker-ready"})

	var done chan error
	var cancel context.CancelFunc

	for {
		select {
		case <-ctx.Done():
			if cancel != nil {
				cancel()
				<-done
			}
			return nil

		case request := <-requests:
			if request.Cancel {
				if cancel != nil {
					cancel()
				}
				continue
			}

			if done != nil || !CanForward(request.Args) {
				send(Event{Type: "done", Error: "unsupported or concurrent CLI worker request"})
				continue
			}

			var runCtx context.Context
			runCtx, cancel = context.WithCancel(ctx)
			done = make(chan error, 1)
			go func() {
				done <- captureOutput(runCtx, request.Args, run, send)
			}()

		case err := <-done:
			cancel()
			cancel, done = nil, nil
			event := Event{Type: "done"}
			if err != nil {
				event.Error = fmt.Sprintf("%+v", err)
			}
			send(event)
		}
	}
}

func captureOutput(ctx context.Context, args []string, run func(context.Context, []string, func()) error, send func(Event)) error {
	reader, writer, err := os.Pipe()
	if err != nil {
		return err
	}

	defer reader.Close()
	done := make(chan error, 1)

	go func() {
		lines := bufio.NewReader(reader)
		for {
			line, err := lines.ReadString('\n')
			if line != "" {
				send(Event{Type: "output", Data: line})
			}
			if err != nil {
				if err == io.EOF {
					err = nil
				}
				done <- err
				return
			}
		}
	}()

	stdout := os.Stdout
	os.Stdout = writer
	err = run(ctx, args, func() { send(Event{Type: "ready"}) })

	os.Stdout = stdout
	_ = writer.Close()
	readErr := <-done
	if err != nil {
		return err
	}
	return readErr
}
