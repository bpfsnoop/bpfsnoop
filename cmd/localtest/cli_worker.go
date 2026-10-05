// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/bpfsnoop/bpfsnoop/internal/cliworker"
)

type cliProcess struct {
	process *runningCmd
	stdin   io.WriteCloser
	encoder *json.Encoder
	events  chan cliworker.Event
	group   errgroup.Group
}

var cliBackend *cliProcess

func startCLIWorker(w io.Writer) (*cliProcess, error) {
	cmd := exec.Command("./bpfsnoop", "--cli-worker")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return nil, err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		stdin.Close()
		stdout.Close()
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		stdin.Close()
		stdout.Close()
		stderr.Close()
		return nil, err
	}

	p := &cliProcess{
		process: &runningCmd{cmd: cmd, done: make(chan struct{})},
		stdin:   stdin, encoder: json.NewEncoder(stdin), events: make(chan cliworker.Event, 64),
	}

	var readers errgroup.Group
	readers.Go(func() error {
		defer stdout.Close()
		decoder := json.NewDecoder(stdout)

		for {
			var event cliworker.Event
			if err := decoder.Decode(&event); err != nil {
				if err == io.EOF {
					return nil
				}
				_ = p.stdin.Close()
				return fmt.Errorf("CLI worker protocol error: %w", err)
			}
			p.events <- event
		}
	})

	readers.Go(func() error {
		defer stderr.Close()
		lines := bufio.NewReader(stderr)

		for {
			line, err := lines.ReadString('\n')
			if line != "" {
				p.events <- cliworker.Event{Type: "output", Data: line}
			}
			if err != nil {
				if err == io.EOF {
					return nil
				}
				_ = p.stdin.Close()
				return fmt.Errorf("CLI worker stderr error: %w", err)
			}
		}
	})

	p.group.Go(func() error {
		readErr := readers.Wait()
		close(p.events)
		p.process.err = errors.Join(readErr, cmd.Wait())
		close(p.process.done)
		return p.process.err
	})

	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()

	for {
		select {
		case event, ok := <-p.events:
			if !ok {
				p.Close(w)
				return nil, fmt.Errorf("CLI worker exited before readiness")
			}
			if event.Type == "worker-ready" {
				return p, nil
			}
			fmt.Fprint(w, event.Data)

		case <-timer.C:
			p.Close(w)
			return nil, fmt.Errorf("CLI worker readiness timeout")
		}
	}
}

func (p *cliProcess) Close(w io.Writer) {
	_ = p.stdin.Close()
	// Drain output while EOF cancels the worker's final request and cleans up.
	var drain errgroup.Group
	drain.Go(func() error {
		var writeErr error
		for event := range p.events {
			if _, err := fmt.Fprint(w, event.Data); err != nil && writeErr == nil {
				writeErr = err
			}
		}
		return writeErr
	})

	killCmd(p.process, syscall.SIGTERM)
	if err := errors.Join(drain.Wait(), p.group.Wait()); err != nil {
		prErr(w, red, "CLI worker shutdown failed: %v\n", err)
	}
}

// Let bash perform the same quoting and command substitutions as the original
// test command, then transfer its expanded arguments without reparsing them.
func expandCLIArgs(command string) ([]string, error) {
	command, ok := strings.CutPrefix(command, "./bpfsnoop ")
	if !ok {
		return nil, nil
	}

	cmd := exec.Command("bash", "-c", "set -- "+command+"\nprintf '%s\\0' \"$@\"")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to expand CLI arguments: %w: %s", err, stderr.String())
	}

	args := strings.Split(strings.TrimSuffix(string(output), "\x00"), "\x00")
	return append([]string{"bpfsnoop"}, args...), nil
}

func (p *cliProcess) Test(w io.Writer, t testCase, args []string) bool {
	started := time.Now()
	if err := p.encoder.Encode(cliworker.Request{Args: args}); err != nil {
		prErr(w, red, "Failed to send CLI request: %v\n", err)
		return false
	}

	var trigger *runningCmd
	defer func() {
		if trigger != nil {
			killCmd(trigger)
		}
	}()

	timer := time.NewTimer(t.timeout)
	defer timer.Stop()

	matched, cancelled, failed := false, false, false
	cancel := func() {
		if !cancelled {
			cancelled = true
			_ = p.encoder.Encode(cliworker.Request{Cancel: true})
			timer.Reset(30 * time.Second) // Allow attachment cleanup before reuse.
		}
	}

	for {
		select {
		case event, ok := <-p.events:
			if !ok {
				prErr(w, red, "CLI worker exited during test\n")
				return false
			}

			switch event.Type {
			case "output":
				fmt.Fprint(w, event.Data)
				if strings.Contains(event.Data, t.match) {
					matched = true
					cancel()
				}

			case "ready":
				prInfo(w, yellow, "bpfsnoop is ready\n")
				if !cancelled {
					timer.Reset(t.timeout)
				}
				if t.triggerProcess != "" && !cancelled {
					prInfo(w, yellow, "Triggering: %s\n", t.triggerProcess)
					var err error
					trigger, err = runCmd(w, t.triggerProcess)
					if err != nil {
						prErr(w, red, "Failed to start trigger: %v\n", err)
						failed = true
						cancel()
					}
				}

			case "done":
				if event.Error != "" {
					prErr(w, red, "CLI request failed: %s\n", event.Error)
					return false
				}
				passed := matched && !failed
				if passed {
					prInfo(w, green, "Test PASSED in %s\n", time.Since(started))
				} else {
					prErr(w, red, "Test FAILED in %s (not match)\n", time.Since(started))
				}
				return passed
			}

		case <-timer.C:
			prErr(w, red, "CLI test timeout after %s\n", time.Since(started))
			if cancelled {
				p.Close(w)
				return false
			}

			failed = true
			cancel()
		}
	}
}
