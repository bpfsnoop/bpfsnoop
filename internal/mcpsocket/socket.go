// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

// Package mcpsocket contains the private transport between the bpfsnoop MCP
// frontend and its privileged daemon.
package mcpsocket

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"time"
)

const path = "/run/bpfsnoop-mcp.sock"

const (
	sessionAccepted = byte(1)
	sessionBusy     = byte(2)
)

// ErrSessionBusy indicates that the daemon is already serving an MCP client.
var ErrSessionBusy = errors.New("bpfsnoop MCP daemon already has an active session")

// Dial connects the MCP frontend to the local daemon.
func Dial(ctx context.Context) (net.Conn, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}

	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		conn.Close()
		return nil, err
	}
	var status [1]byte
	_, err = io.ReadFull(conn, status[:])
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		conn.Close()
		return nil, err
	}

	switch status[0] {
	case sessionAccepted:
		return conn, nil
	case sessionBusy:
		conn.Close()
		return nil, ErrSessionBusy
	default:
		conn.Close()
		return nil, errors.New("invalid response from bpfsnoop MCP daemon")
	}
}

// AcceptSession tells a frontend that its MCP session may start.
func AcceptSession(conn net.Conn) error {
	_, err := conn.Write([]byte{sessionAccepted})
	return err
}

// RejectSession tells a frontend that another MCP session is active.
func RejectSession(conn net.Conn) error {
	_, err := conn.Write([]byte{sessionBusy})
	return err
}

func removeStaleSocket() error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to inspect daemon socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return errors.New("daemon socket path is occupied by a non-socket file")
	}

	conn, err := net.DialTimeout("unix", path, 250*time.Millisecond)
	if err == nil {
		conn.Close()
		return errors.New("another bpfsnoop MCP daemon is already running")
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("failed to check existing daemon socket: %w", err)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("failed to remove stale daemon socket: %w", err)
	}
	return nil
}

// Listen creates the daemon listener and restricts access to uid and gid.
func Listen(uid, gid int) (*net.UnixListener, error) {
	if err := removeStaleSocket(); err != nil {
		return nil, err
	}

	oldUmask := syscall.Umask(0o077)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	syscall.Umask(oldUmask)
	if err != nil {
		return nil, fmt.Errorf("failed to listen for MCP clients: %w", err)
	}

	if err := os.Chown(path, uid, gid); err != nil {
		listener.Close()
		os.Remove(path)
		return nil, fmt.Errorf("failed to set daemon socket owner: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		listener.Close()
		os.Remove(path)
		return nil, fmt.Errorf("failed to set daemon socket permissions: %w", err)
	}

	return listener, nil
}

// Close closes the listener and removes its runtime endpoint.
func Close(listener *net.UnixListener) error {
	return errors.Join(listener.Close(), os.Remove(path))
}
