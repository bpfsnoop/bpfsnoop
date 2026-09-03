// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

// Package mcpserver implements the MCP adapter for bpfsnoop.
package mcpserver

import (
	"context"
	"errors"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bpfsnoop/bpfsnoop/internal/bpfsnoop"
	mcpapi "github.com/bpfsnoop/bpfsnoop/internal/mcp"
)

const serverInstructions = `bpfsnoop provides Linux kernel and eBPF tracing tools.

Start an investigation with kernel_info, use find when a target name is
uncertain, use read for focused kernel-memory inspection, use disasm for
bounded native-code inspection, and use trace only for a bounded tracing
experiment. Refine an investigation by issuing another trace; the server does
not keep hidden tracing sessions. Use status to inspect an active trace and
abort when its event cannot be triggered.`

var server = mcp.NewServer(&mcp.Implementation{
	Name:    "bpfsnoop",
	Version: "dev",
}, &mcp.ServerOptions{
	Instructions: serverInstructions,
})

func intPtr(value int) *int {
	return &value
}

type closeOnceReadWriteCloser struct {
	io.ReadWriteCloser
	once sync.Once
	err  error
}

func (c *closeOnceReadWriteCloser) Close() error {
	c.once.Do(func() {
		c.err = c.ReadWriteCloser.Close()
	})
	return c.err
}

// RunConn serves one MCP session over a connected byte stream.
func RunConn(ctx context.Context, conn io.ReadWriteCloser) error {
	rwc := &closeOnceReadWriteCloser{ReadWriteCloser: conn}
	return server.Run(ctx, &mcp.IOTransport{Reader: rwc, Writer: rwc})
}

// Run serves MCP directly on stdio when privileged and otherwise proxies the
// session to the privileged daemon.
func Run(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return runProxy(ctx)
	}
	if err := mcpapi.Start(); err != nil {
		return err
	}

	err := server.Run(ctx, &mcp.StdioTransport{})
	if normalSessionClose(err) {
		return nil
	}
	return err
}

func runMode(daemon bool) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer stop()

	var err error
	if daemon {
		err = RunDaemon(ctx)
	} else {
		err = Run(ctx)
	}
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func init() {
	bpfsnoop.RegisterMCPRunner(runMode)
}
