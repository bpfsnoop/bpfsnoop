// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
)

type testCase struct {
	name            string
	tag             string
	test            string
	tool            string
	arguments       string
	match           string
	expectError     bool
	timeout         time.Duration
	abortAfter      time.Duration
	requiredProcess string
	triggerProcess  string
}

func (t *testCase) reset() {
	t.arguments = "{}"
	t.timeout = 5 * time.Second
}

func (t *testCase) valid() bool {
	target := t.test
	if mcpMode {
		target = t.tool
	}
	return t.tag != "" && target != "" && t.match != "" && t.timeout > 0
}

func test(w io.Writer, t testCase) bool {
	if !t.valid() {
		prErr(w, red, "Invalid test case: %+v\n", t)
		return false
	}

	if t.requiredProcess != "" {
		prInfo(w, yellow, "Required process: %s\n", t.requiredProcess)
		defer killCmd(runCmd(w, t.requiredProcess, 200*time.Millisecond))
	}

	prInfo(w, yellow, "Name: %s\n", t.name)
	prInfo(w, yellow, "Tags: %s\n", t.tag)
	if mcpMode {
		prInfo(w, yellow, "Calling MCP tool: %s (arguments: %s, match: %s, timeout: %s)\n",
			t.tool, t.arguments, t.match, t.timeout)
		return testMCP(w, t)
	}

	prInfo(w, yellow, "Running: %s (match: %s, timeout: %s)\n",
		t.test, t.match, t.timeout)
	return testCLI(w, t)
}

func testCLI(w io.Writer, t testCase) bool {
	started := time.Now()

	cmd := exec.Command("bash", "-c", t.test)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		prErr(w, red, "Failed to get stdout pipe for %s: %v\n", t.test, err)
		return false
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		prErr(w, red, "Failed to get stderr pipe for %s: %v\n", t.test, err)
		return false
	}

	err = cmd.Start()
	if err != nil {
		prErr(w, red, "Test FAILED in %s (failed to start %s: %v)\n", time.Since(started), t.test, err)
		return false
	}

	fmt.Fprintln(w, "Starting bpfsnoop...")

	matched := make(chan struct{}, 10)
	ready := make(chan struct{})

	var errg errgroup.Group

	errCh := make(chan error, 1)

	errg.Go(func() error {
		defer close(errCh)
		errCh <- cmd.Wait()
		return nil
	})

	errg.Go(func() error {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			fmt.Fprintln(w, line)

			if strings.Contains(line, t.match) {
				matched <- struct{}{}
			}
		}

		return nil
	})

	errg.Go(func() error {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			fmt.Fprintln(w, line)

			if strings.Contains(line, t.match) {
				matched <- struct{}{}
			}
			if strings.Contains(line, "bpfsnoop is running..") {
				close(ready)
			}
		}

		return nil
	})

	select {
	case err := <-errCh:
		if err != nil {
			prErr(w, red, "Test FAILED in %s (failed to start bpfsnoop)\n", time.Since(started))
			return false
		}

	case <-ready:
		prInfo(w, yellow, "bpfsnoop is ready\n")
		break

	case <-time.After(t.timeout):
		prErr(w, red, "Timeout after %s waiting for bpfsnoop to start\n", t.timeout)
		prErr(w, red, "Test FAILED in %s (timeout of %s exceeded)\n",
			time.Since(started), t.timeout)
		killCmd(cmd)
		return false
	}

	if t.triggerProcess != "" {
		prInfo(w, yellow, "Triggering: %s\n", t.triggerProcess)
		defer killCmd(runCmd(w, t.triggerProcess, 500*time.Millisecond))
	}

	var passed bool

	select {
	case <-matched:
		prInfo(w, green, "Test PASSED in %s\n", time.Since(started))
		passed = true

	case <-time.After(t.timeout):
		prErr(w, red, "Test FAILED in %s (not match)\n", time.Since(started))
	}

	killCmd(cmd)

	_ = errg.Wait()

	return passed
}
