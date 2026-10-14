// Copyright 2026 Liang Tang.
// SPDX-License-Identifier: Apache-2.0

// Command arenaprobe keeps data in a BPF arena, for the arena tests.
package main

import (
	"context"
	"encoding/binary"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/bpfsnoop/bpfsnoop/internal/assert"
	"github.com/bpfsnoop/bpfsnoop/internal/testutil"
)

// A list node in the arena:
//
//	struct arena_node {
//	    int val;
//	    char name[12];
//	    struct arena_node __arena *next;
//	};
const (
	nodeSize    = 24
	nodeNameLen = 12
)

func putNode(b []byte, val int32, name string, next uint64) {
	binary.NativeEndian.PutUint32(b[0:], uint32(val))
	copy(b[4:4+nodeNameLen], name)
	binary.NativeEndian.PutUint64(b[16:], next)
}

func main() {
	assert.NoErr(rlimit.RemoveMemlock(), "Failed to remove rlimit memlock: %v")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// A BPF arena is memory shared by bpf progs and user space, allocated
	// in pages. Unlike other maps, it has no keys or values.
	arena, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "arenaprobe",
		Type:       ebpf.Arena,
		Flags:      unix.BPF_F_MMAPABLE,
		MaxEntries: 1, // pages
	})
	assert.NoErr(err, "Failed to create arena: %v")
	defer arena.Close()
	info, err := arena.Info()
	assert.NoErr(err, "Failed to get arena info: %v")
	id, ok := info.ID()
	if !ok {
		log.Fatal("Arena map ID unavailable")
	}

	// The first mmap of an arena fixes its user address range. Faulting a
	// page in from user space allocates it for both sides. A pointer in the
	// arena holds the user address of its target.
	mem, err := unix.Mmap(arena.FD(), 0, os.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	assert.NoErr(err, "Failed to mmap arena: %v")
	defer func() {
		if mem != nil {
			_ = unix.Munmap(mem)
		}
	}()

	base := uint64(uintptr(unsafe.Pointer(&mem[0])))
	putNode(mem[0:], 1, "first", base+nodeSize)
	putNode(mem[nodeSize:], 2, "second", 0)

	log.Printf("Mapped arenaprobe at %#x", base)

	<-ctx.Done()

	// Program teardown can retain a map reference after bpfsnoop exits.
	// Release our own references, then wait until the old name cannot collide
	// with the next test's arena. Do not open the map while waiting: that would
	// acquire another reference and could prolong its lifetime.
	assert.NoErr(unix.Munmap(mem), "Failed to unmap arena: %v")
	mem = nil
	assert.NoErr(arena.Close(), "Failed to close arena: %v")
	assert.NoErr(testutil.WaitMapGone(id, 10*time.Second), "Failed to wait for arena cleanup: %v")
}
