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

	"golang.org/x/sys/unix"

	mcpapi "github.com/bpfsnoop/bpfsnoop/internal/mcp"
	"github.com/bpfsnoop/bpfsnoop/internal/mcpsocket"
)

const daemonLockPath = "/run/bpfsnoop-mcp.lock"

func lockDaemon(path string) (*os.File, error) {
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("failed to open daemon lock: %w", err)
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errors.New("another bpfsnoop MCP daemon is already running")
		}
		return nil, fmt.Errorf("failed to lock daemon instance: %w", err)
	}
	return lock, nil
}

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

		if err := mcpsocket.AcceptSession(conn); err != nil {
			conn.Close()
			continue
		}

		sessions.Go(func() {
			if err := RunConn(ctx, conn); ctx.Err() == nil && !normalSessionClose(err) {
				fmt.Fprintf(os.Stderr, "bpfsnoop-mcp-daemon: MCP session failed: %v\n", err)
			}
		})
	}
}

// RunDaemon serves MCP sessions over the private local socket. Trace itself
// still permits only one active tracing experiment.
func RunDaemon(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return errors.New("root privileges are required; run bpfsnoop-mcp-daemon with sudo")
	}
	lock, err := lockDaemon(daemonLockPath)
	if err != nil {
		return err
	}
	defer lock.Close()

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
