// Copyright 2026 Liang Tang.
// SPDX-License-Identifier: Apache-2.0

// Command arenaprobe keeps data in a BPF arena, and runs a bpf prog passing
// pointers into it to funcs, for the arena tests.
package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
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
//
// After the two nodes, a kernel pointer, struct arena_task in arena.c.
const (
	nodeSize    = 24
	nodeNameLen = 12
	taskOff     = 2 * nodeSize
)

func putNode(b []byte, val int32, name string, next uint64) {
	binary.NativeEndian.PutUint32(b[0:], uint32(val))
	copy(b[4:4+nodeNameLen], name)
	binary.NativeEndian.PutUint64(b[16:], next)
}

// kallsyms returns the address of a kernel symbol, or 0.
func kallsyms(name string) uint64 {
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return 0
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 3 && fields[2] == name {
			addr, _ := strconv.ParseUint(fields[0], 16, 64)
			return addr
		}
	}
	return 0
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
	binary.NativeEndian.PutUint64(mem[taskOff:], kallsyms("init_task"))

	spec, err := loadArena()
	assert.NoErr(err, "Failed to load arena spec: %v")
	assert.NoErr(spec.Variables["head"].Set(base), "Failed to set head: %v")
	assert.NoErr(spec.Variables["task_off"].Set(uint64(taskOff)), "Failed to set task_off: %v")

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{"arenaprobe": arena},
	})
	assert.NoVerifierErr(err, "Failed to load arena collection: %v")

	log.Printf("Mapped arenaprobe at %#x", base)

	// Keep calling the funcs for bpfsnoop to trace them.
	data := make([]byte, 64)
	ticker := time.NewTicker(100 * time.Millisecond)
	for running := true; running; {
		select {
		case <-ctx.Done():
			running = false
		case <-ticker.C:
			_, err := coll.Programs["arena_main"].Run(&ebpf.RunOptions{Data: data})
			assert.NoErr(err, "Failed to run arena_main: %v")
		}
	}
	ticker.Stop()
	coll.Close()

	// Program teardown can retain a map reference after bpfsnoop exits.
	// Release our own references, then wait until the old name cannot collide
	// with the next test's arena. Do not open the map while waiting: that would
	// acquire another reference and could prolong its lifetime.
	assert.NoErr(unix.Munmap(mem), "Failed to unmap arena: %v")
	mem = nil
	assert.NoErr(arena.Close(), "Failed to close arena: %v")
	assert.NoErr(testutil.WaitMapGone(id, 10*time.Second), "Failed to wait for arena cleanup: %v")
}
