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
	"time"

	"github.com/bpfsnoop/bpfsnoop/internal/assert"
	"github.com/bpfsnoop/bpfsnoop/internal/testutil"
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
	mapInfo, err := obj.CcLookup.Info()
	assert.NoErr(err, "Failed to get fixture map info: %v")
	mapID, ok := mapInfo.ID()
	assert.True(ok, "Fixture map ID unavailable")
	progInfo, err := obj.Crc.Info()
	assert.NoErr(err, "Failed to get fixture program info: %v")
	progID, ok := progInfo.ID()
	assert.True(ok, "Fixture program ID unavailable")

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

	assert.NoErr(xdp.Close(), "Failed to detach XDP fixture: %v")
	assert.NoErr(obj.Close(), "Failed to close XDP fixture: %v")
	assert.NoErr(testutil.WaitProgramGone(progID, 10*time.Second), "Failed to wait for XDP program cleanup: %v")
	assert.NoErr(testutil.WaitMapGone(mapID, 10*time.Second), "Failed to wait for fixture map cleanup: %v")
}
