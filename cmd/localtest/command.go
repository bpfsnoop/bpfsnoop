// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

type runningCmd struct {
	cmd  *exec.Cmd
	done chan struct{}
	err  error // published by closing done
}

func runCmd(w io.Writer, command string) (*runningCmd, error) {
	cmd := exec.Command("bash", "-c", command)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout = w
	cmd.Stderr = w
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	process := &runningCmd{cmd: cmd, done: make(chan struct{})}
	go func() {
		process.err = cmd.Wait()
		close(process.done)
	}()
	return process, nil
}

func killCmd(process *runningCmd, signals ...os.Signal) {
	select {
	case <-process.done:
		return
	default:
	}
	sig := os.Kill
	if len(signals) != 0 {
		sig = signals[0]
	}

	// Kill the whole group, including children of shell loops and pipelines.
	_ = syscall.Kill(-process.cmd.Process.Pid, sig.(syscall.Signal))
	select {
	case <-process.done:
	case <-time.After(30 * time.Second):
		_ = syscall.Kill(-process.cmd.Process.Pid, syscall.SIGKILL)
		<-process.done
	}
}

type readinessWriter struct {
	w     io.Writer
	match string
	ready chan struct{}
	mu    sync.Mutex
	tail  string
	seen  bool
}

func (w *readinessWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.w.Write(p)
	if !w.seen {
		text := w.tail + string(p[:n])
		if strings.Contains(text, w.match) {
			w.seen = true
			close(w.ready)
		} else {
			// Preserve matches split across writes without retaining all output.
			w.tail = text[max(0, len(text)-len(w.match)+1):]
		}
	}
	return n, err
}

func runPrerequisite(w io.Writer, command, match string, timeout time.Duration) (*runningCmd, error) {
	if match == "" {
		return nil, fmt.Errorf("prerequisite requires a readiness match")
	}
	output := &readinessWriter{w: w, match: match, ready: make(chan struct{})}
	process, err := runCmd(output, command)
	if err != nil {
		return nil, err
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-output.ready:
		return process, nil
	case <-process.done:
		err = fmt.Errorf("prerequisite exited before readiness: %v", process.err)
	case <-timer.C:
		err = fmt.Errorf("timeout after %s waiting for prerequisite readiness %q", timeout, match)
	}
	killCmd(process)
	return nil, err
}
