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

	return cliworker.Serve(ctx, func(ctx context.Context, args []string, ready func()) error {
		flags, err := ParseFlagsArgs(args)
		if err != nil {
			return err
		}

		err = Boot(ctx, flags, BootConfig{Output: os.Stdout, Ready: ready})
		if verr, ok := errors.AsType[*ebpf.VerifierError](err); ok {
			return fmt.Errorf("%w\nVerifier log:\n%+v", err, verr)
		}
		return err
	})
}
