// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"fmt"

	"github.com/cilium/ebpf/rlimit"

	"github.com/bpfsnoop/bpfsnoop/internal/atomix"
)

var startOnce = atomix.NewOnce(func() (struct{}, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return struct{}{}, fmt.Errorf("failed to remove memlock limit: %w", err)
	}
	return struct{}{}, nil
})

// Start prepares process-wide state required by MCP tools.
func Start() error {
	_, err := startOnce.Do()
	return err
}
