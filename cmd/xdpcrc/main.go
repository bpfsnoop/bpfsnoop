// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/bpfsnoop/bpfsnoop/internal/assert"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	flag "github.com/spf13/pflag"
)

func main() {
	var device string
	flag.StringVarP(&device, "device", "d", "lo", "device to attach XDP program")
	flag.Parse()

	ifi, err := net.InterfaceByName(device)
	assert.NoErr(err, "Failed to get link by name %s: %v", device)

	assert.NoErr(rlimit.RemoveMemlock(), "Failed to remove rlimit memlock: %v")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var obj xdpObjects
	assert.NoVerifierErr(loadXdpObjects(&obj, nil), "Failed to load xdp objects: %v")
	defer obj.Close()

	assert.NoErr(obj.CcLookup.Put(uint32(ifi.Index), [3]uint32{42, 84, 7}),
		"Failed to populate map lookup fixture: %v")

	xdp, err := link.AttachXDP(link.XDPOptions{
		Program:   obj.Crc,
		Interface: ifi.Index,
	})
	assert.NoErr(err, "Failed to attach xdp program: %v")
	defer xdp.Close()

	log.Printf("Attached xdp to %s", device)

	<-ctx.Done()
}
