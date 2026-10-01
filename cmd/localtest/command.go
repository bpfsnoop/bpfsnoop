// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"os"
	"os/exec"
	"time"
)

func runCmd(w io.Writer, command string, wait time.Duration) *exec.Cmd {
	cmd := exec.Command("bash", "-c", command)
	cmd.Stdout = w
	cmd.Stderr = w

	go func() {
		if wait > 0 {
			time.Sleep(wait)
		}

		_ = cmd.Start()
	}()

	return cmd
}

func killCmd(cmd *exec.Cmd, signals ...os.Signal) {
	sig := os.Kill
	if len(signals) != 0 {
		sig = signals[0]
	}

	if cmd.Process != nil {
		_ = cmd.Process.Signal(sig)
		_ = cmd.Wait()
	}
}
