// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

// Package mcpserver implements the MCP adapter for bpfsnoop.
package mcpserver

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bpfsnoop/bpfsnoop/internal/bpfsnoop"
	mcpapi "github.com/bpfsnoop/bpfsnoop/internal/mcp"
)

const serverInstructions = `bpfsnoop provides Linux kernel and eBPF tracing tools.

The server must be launched with root privileges. Start an investigation with
kernel_info, use find when a target name is uncertain, and use trace only for a
bounded tracing experiment. Refine an investigation by issuing another trace;
the server does not keep hidden tracing sessions.`

var errNotImplemented = errors.New("this bpfsnoop MCP tool is not implemented yet")

var server = mcp.NewServer(&mcp.Implementation{
	Name:    "bpfsnoop",
	Version: "dev",
}, &mcp.ServerOptions{
	Instructions: serverInstructions,
})

func notImplemented[In any](context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, any, error) {
	return nil, nil, errNotImplemented
}

// Run serves the registered bpfsnoop tools over stdin/stdout.
func Run(ctx context.Context) error {
	if err := mcpapi.Start(); err != nil {
		return err
	}
	return server.Run(ctx, &mcp.StdioTransport{})
}

func runMode() error {
	if os.Geteuid() != 0 {
		return errors.New("root privileges are required; run bpfsnoop-mcp as root")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer stop()

	err := Run(ctx)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func init() {
	bpfsnoop.RegisterMCPRunner(runMode)
}
