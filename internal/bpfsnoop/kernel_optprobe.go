// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

const kprobeOptimizationPath = "/proc/sys/debug/kprobes-optimization"

// disableKprobeOptimization keeps instruction probes from overlapping optimized
// jumps on kernels with the optprobe overlap bug. The caller must remove all
// instruction probes before invoking the returned restore function.
func disableKprobeOptimization(path string) (func() error, error) {
	noop := func() error { return nil }
	value, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		// CONFIG_OPTPROBES or CONFIG_SYSCTL is unavailable.
		return noop, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read kprobe optimization setting: %w", err)
	}
	switch strings.TrimSpace(string(value)) {
	case "0":
		return noop, nil
	case "1":
	default:
		return nil, fmt.Errorf("unexpected kprobe optimization setting %q", strings.TrimSpace(string(value)))
	}
	if err := os.WriteFile(path, []byte("0\n"), 0); err != nil {
		return nil, fmt.Errorf("failed to disable kprobe optimization for fninsn: %w", err)
	}
	WarnLog("Disabled kprobes-optimization for fninsn.")
	return func() error {
		if err := os.WriteFile(path, value, 0); err != nil {
			return fmt.Errorf("failed to restore kprobe optimization setting: %w", err)
		}
		DebugLog("Restored kprobes-optimization.")
		return nil
	}, nil
}
