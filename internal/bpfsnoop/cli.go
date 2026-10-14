// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"

	"github.com/bpfsnoop/bpfsnoop/internal/cliworker"
)

func runCLI() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer stop()

	err := initEnv()
	if err != nil {
		return fmt.Errorf("failed to init env: %w", err)
	}

	events, readers, err := newEventRingbufReaders()
	if err != nil {
		return err
	}
	defer readers.close()
	defer events.Close()

	return cliworker.Serve(ctx, func(ctx context.Context, args []string, ready func()) error {
		flags, err := ParseFlagsArgs(args)
		if err != nil {
			return err
		}

		err = boot(ctx, flags, BootConfig{
			Output:        os.Stdout,
			Ready:         ready,
			reusedObjects: true,
		}, events, readers)
		if verr, ok := errors.AsType[*ebpf.VerifierError](err); ok {
			return fmt.Errorf("%w\nVerifier log:\n%+v", err, verr)
		}
		return err
	})
}
