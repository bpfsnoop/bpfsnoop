// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/bpfsnoop/bpfsnoop/internal/assert"
	"github.com/bpfsnoop/bpfsnoop/internal/bpfsnoop"
	_ "github.com/bpfsnoop/bpfsnoop/internal/mcpserver"
)

func main() {
	flags, err := bpfsnoop.ParseFlags()
	assert.NoErr(err, "Failed to parse flags: %v")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer stop()

	err = bpfsnoop.Boot(ctx, flags, os.Stdout)
	assert.NoVerifierErr(err, "Failed to boot bpfsnoop: %v")
}
