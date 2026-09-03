// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"context"
	"errors"
	"io"
	"net"
	"os"

	"github.com/bpfsnoop/bpfsnoop/internal/mcpsocket"
)

var (
	errDaemonUnavailable = errors.New("bpfsnoop MCP daemon is not running; ask the user to run bpfsnoop-mcp-daemon as root, then retry")
	errDaemonBusy        = errors.New("bpfsnoop MCP daemon already has an active session; retry after it finishes")
)

func copyToDaemon(conn net.Conn) <-chan error {
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(conn, os.Stdin)
		if err == nil {
			if unixConn, ok := conn.(*net.UnixConn); ok {
				err = unixConn.CloseWrite()
			}
		}
		done <- err
	}()
	return done
}

func copyFromDaemon(conn net.Conn) <-chan error {
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(os.Stdout, conn)
		done <- err
	}()
	return done
}

func proxy(ctx context.Context, conn net.Conn) error {
	inputDone := copyToDaemon(conn)
	outputDone := copyFromDaemon(conn)

	for inputDone != nil || outputDone != nil {
		select {
		case err := <-inputDone:
			inputDone = nil
			if err != nil && !errors.Is(err, net.ErrClosed) {
				return errors.New("failed to send an MCP message to the bpfsnoop daemon")
			}
		case err := <-outputDone:
			outputDone = nil
			if err != nil && !errors.Is(err, net.ErrClosed) {
				return errors.New("failed to receive an MCP message from the bpfsnoop daemon")
			}
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

func runProxy(ctx context.Context) error {
	conn, err := mcpsocket.Dial(ctx)
	if err != nil {
		if errors.Is(err, mcpsocket.ErrSessionBusy) {
			return errDaemonBusy
		}
		return errDaemonUnavailable
	}
	defer conn.Close()

	return proxy(ctx, conn)
}
