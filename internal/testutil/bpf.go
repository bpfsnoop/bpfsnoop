// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

// Package testutil provides helpers for e2e test fixtures.
package testutil

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf"
)

func WaitMapGone(id ebpf.MapID, timeout time.Duration) error {
	return waitIDGone("map", id, ebpf.MapGetNextID, timeout)
}

func WaitProgramGone(id ebpf.ProgramID, timeout time.Duration) error {
	return waitIDGone("program", id, ebpf.ProgramGetNextID, timeout)
}

// Closing the last userspace handle may leave references held by asynchronous
// kernel teardown. Enumerate IDs without opening a new reference while waiting.
func waitIDGone[T ~uint32](kind string, id T, nextID func(T) (T, error), timeout time.Duration) error {
	if id == 0 {
		return fmt.Errorf("invalid %s ID 0", kind)
	}
	deadline := time.Now().Add(timeout)
	for {
		next, err := nextID(id - 1)
		if errors.Is(err, os.ErrNotExist) || (err == nil && next != id) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("enumerate %s %d: %w", kind, id, err)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s %d still exists after %s", kind, id, timeout)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
