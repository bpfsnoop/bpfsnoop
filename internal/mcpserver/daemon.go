// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"

	mcpapi "github.com/bpfsnoop/bpfsnoop/internal/mcp"
	"github.com/bpfsnoop/bpfsnoop/internal/mcpsocket"
)

func socketOwner() (int, int) {
	uid, uidErr := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, gidErr := strconv.Atoi(os.Getenv("SUDO_GID"))
	if uidErr == nil && gidErr == nil && uid >= 0 && gid >= 0 {
		return uid, gid
	}
	return 0, 0
}

func normalSessionClose(err error) bool {
	return err == nil || errors.Is(err, io.EOF) || err.Error() == "server is closing: EOF"
}

func serveDaemon(ctx context.Context, listener *net.UnixListener) error {
	ctx, cancel := context.WithCancel(ctx)
	var sessions sync.WaitGroup
	active := make(chan struct{}, 1)
	defer sessions.Wait()
	defer cancel()

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("failed to accept MCP connection: %w", err)
		}

		select {
		case active <- struct{}{}:
			if err := mcpsocket.AcceptSession(conn); err != nil {
				conn.Close()
				<-active
				continue
			}
		default:
			mcpsocket.RejectSession(conn)
			conn.Close()
			continue
		}

		sessions.Add(1)
		go func() {
			defer sessions.Done()
			defer func() { <-active }()
			if err := RunConn(ctx, conn); ctx.Err() == nil && !normalSessionClose(err) {
				fmt.Fprintf(os.Stderr, "bpfsnoop-mcp-daemon: MCP session failed: %v\n", err)
			}
		}()
	}
}

// RunDaemon serves one MCP session at a time over the private local socket.
func RunDaemon(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return errors.New("root privileges are required; run bpfsnoop-mcp-daemon with sudo")
	}
	if err := mcpapi.Start(); err != nil {
		return err
	}

	uid, gid := socketOwner()
	listener, err := mcpsocket.Listen(uid, gid)
	if err != nil {
		return err
	}
	defer mcpsocket.Close(listener)

	fmt.Fprintln(os.Stderr, "bpfsnoop-mcp-daemon: ready; leave this process running")
	return serveDaemon(ctx, listener)
}
