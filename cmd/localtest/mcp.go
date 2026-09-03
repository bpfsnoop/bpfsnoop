// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type mcpCallOutcome struct {
	result *mcp.CallToolResult
	err    error
}

func testMCP(w io.Writer, t testCase) bool {
	started := time.Now()

	var arguments map[string]any
	if err := json.Unmarshal([]byte(t.arguments), &arguments); err != nil {
		prErr(w, red, "Test FAILED in %s (invalid MCP arguments: %v)\n", time.Since(started), err)
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), t.timeout)
	defer cancel()

	cmd := exec.Command("./bpfsnoop-mcp")
	cmd.Stderr = w
	client := mcp.NewClient(&mcp.Implementation{
		Name:    "bpfsnoop-localtest",
		Version: "dev",
	}, nil)
	session, err := client.Connect(ctx, &mcp.CommandTransport{
		Command:           cmd,
		TerminateDuration: time.Second,
	}, nil)
	if err != nil {
		prErr(w, red, "Test FAILED in %s (failed to connect to MCP server: %v)\n", time.Since(started), err)
		return false
	}
	defer session.Close()

	if t.triggerProcess != "" {
		prInfo(w, yellow, "Triggering: %s\n", t.triggerProcess)
		trigger := exec.Command("bash", "-c", "sleep 0.5; "+t.triggerProcess)
		trigger.Stdout = w
		trigger.Stderr = w
		if err := trigger.Start(); err != nil {
			prErr(w, red, "Test FAILED in %s (failed to start trigger: %v)\n", time.Since(started), err)
			return false
		}
		defer killCmd(trigger)
	}

	var abortDone chan mcpCallOutcome
	if t.abortAfter > 0 {
		abortDone = make(chan mcpCallOutcome, 1)
		go func() {
			timer := time.NewTimer(t.abortAfter)
			defer timer.Stop()
			select {
			case <-timer.C:
				result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "abort", Arguments: map[string]any{}})
				abortDone <- mcpCallOutcome{result: result, err: err}
			case <-ctx.Done():
				abortDone <- mcpCallOutcome{err: ctx.Err()}
			}
		}()
	}

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      t.tool,
		Arguments: arguments,
	})
	if err != nil {
		prErr(w, red, "Test FAILED in %s (MCP call failed: %v)\n", time.Since(started), err)
		return false
	}
	if abortDone != nil {
		outcome := <-abortDone
		if outcome.err != nil {
			prErr(w, red, "Test FAILED in %s (MCP abort failed: %v)\n", time.Since(started), outcome.err)
			return false
		}
		if outcome.result.IsError {
			prErr(w, red, "Test FAILED in %s (MCP abort returned an error)\n", time.Since(started))
			return false
		}
		output, _ := json.Marshal(outcome.result.StructuredContent)
		fmt.Fprintln(w, string(output))
		if !strings.Contains(string(output), `"aborted":true`) {
			prErr(w, red, "Test FAILED in %s (MCP abort found no active trace)\n", time.Since(started))
			return false
		}
	}

	if result.IsError {
		output, _ := json.Marshal(result.Content)
		fmt.Fprintln(w, string(output))
		if t.expectError && strings.Contains(string(output), t.match) {
			prInfo(w, green, "Test PASSED in %s\n", time.Since(started))
			return true
		}
		prErr(w, red, "Test FAILED in %s (MCP tool returned an error)\n", time.Since(started))
		return false
	}
	if t.expectError {
		prErr(w, red, "Test FAILED in %s (MCP tool did not return an error)\n", time.Since(started))
		return false
	}

	output, err := json.Marshal(result.StructuredContent)
	if err != nil {
		prErr(w, red, "Test FAILED in %s (failed to encode MCP result: %v)\n", time.Since(started), err)
		return false
	}
	fmt.Fprintln(w, string(output))

	if !strings.Contains(string(output), t.match) {
		prErr(w, red, "Test FAILED in %s (not match)\n", time.Since(started))
		return false
	}

	prInfo(w, green, "Test PASSED in %s\n", time.Since(started))
	return true
}
