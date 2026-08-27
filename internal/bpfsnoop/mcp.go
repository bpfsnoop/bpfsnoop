// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

var runMCP func() error

// RegisterMCPRunner installs the handler for the hidden MCP execution mode.
func RegisterMCPRunner(run func() error) {
	runMCP = run
}
