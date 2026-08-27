// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

var runMCP func(daemon bool) error

// RegisterMCPRunner installs the handler for the hidden MCP execution modes.
func RegisterMCPRunner(run func(daemon bool) error) {
	runMCP = run
}
