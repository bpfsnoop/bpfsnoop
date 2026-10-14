// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/bpfsnoop/bpfsnoop/internal/bpf"
)

const (
	readLimit = 65536
)

var (
	readMu   sync.Mutex
	readColl *ebpf.Collection
	readLink link.Link
)

func initReadKernel() error {
	spec, err := bpf.LoadRead()
	if err != nil {
		return fmt.Errorf("failed to load read bpf spec: %w", err)
	}
	delete(spec.Programs, "read_data") // not used here

	spec.Programs["read"].AttachTo = bpfFentryTest1

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("failed to create read collection: %w", err)
	}

	link, err := link.AttachTracing(link.TracingOptions{
		Program:    coll.Programs["read"],
		AttachType: ebpf.AttachTraceFEntry,
	})
	if err != nil {
		coll.Close()
		return fmt.Errorf("failed to fentry %s: %w", bpfFentryTest1, err)
	}

	readColl = coll
	readLink = link

	return nil
}

func FlushReadObjs(reused bool) {
	readMu.Lock()
	defer readMu.Unlock()

	if reused {
		return
	}

	if readLink != nil {
		readLink.Close()
		readLink = nil
	}
	if readColl != nil {
		readColl.Close()
		readColl = nil
	}
}

func readKernel(addr uint64, size uint32) ([]byte, error) {
	readMu.Lock()
	defer readMu.Unlock()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if readColl == nil {
		if err := initReadKernel(); err != nil {
			return nil, err
		}
	}

	readSize := (size + 7) & (^uint32(7)) // round up to 8-times bytes
	if readSize > readLimit {
		return nil, fmt.Errorf("read size %d is too large", readSize)
	}

	pidTgid := uint64(os.Getpid())<<32 | uint64(unix.Gettid())
	if err := readColl.Variables["target_pid_tgid"].Set(pidTgid); err != nil {
		return nil, fmt.Errorf("failed to update target_pid_tgid: %w", err)
	}
	if err := readColl.Variables["target_addr"].Set(addr); err != nil {
		return nil, fmt.Errorf("failed to update target_addr: %w", err)
	}
	if err := readColl.Variables["target_size"].Set(readSize); err != nil {
		return nil, fmt.Errorf("failed to update target_size: %w", err)
	}
	if err := readColl.Variables["run"].Set(uint8(0)); err != nil {
		return nil, fmt.Errorf("failed to reset run: %w", err)
	}

	if _, err := readColl.Programs["read"].Run(nil); err != nil {
		return nil, fmt.Errorf("failed to run read program: %w", err)
	}

	var run bool
	if err := readColl.Variables["run"].Get(&run); err != nil {
		return nil, fmt.Errorf("failed to get run flag: %w", err)
	}
	if !run {
		return nil, errors.New("reading kernel was not triggered")
	}

	return cloneVar(readColl.Variables["buff"], int(size)), nil
}

type Memory struct {
	b    []byte
	ro   bool
	heap bool

	cleanup runtime.Cleanup
}

type Variable struct {
	name   string
	offset uint32
	size   uint32
	t      *btf.Var

	mm *Memory
}

func (v *Variable) clone(n int) []byte {
	return slices.Clone(v.mm.b[v.offset : v.offset+uint32(n)])
}

func cloneVar(v *ebpf.Variable, n int) []byte {
	return (*Variable)(unsafe.Pointer(v)).clone(n)
}
