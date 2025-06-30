// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/bpfsnoop/bpfsnoop/internal/bpf"
)

const (
	readLimit = 65536
)

func readKernel(addr uint64, size uint32) ([]byte, error) {
	readSize := (size + 7) & (^uint32(7)) // round up to 8-times bytes
	if readSize > readLimit {
		return nil, fmt.Errorf("read size %d is too large", readSize)
	}

	spec, err := bpf.LoadRead()
	if err != nil {
		return nil, fmt.Errorf("failed to load read bpf spec: %w", err)
	}

	buff := make([]byte, readSize)
	spec.Maps[".data.buff"].ValueSize = readSize
	spec.Maps[".data.buff"].Contents[0].Value = buff

	if err := spec.Variables["__addr"].Set(addr); err != nil {
		return nil, fmt.Errorf("failed to set __addr: %w", err)
	}
	if err := spec.Variables["__size"].Set(size); err != nil {
		return nil, fmt.Errorf("failed to set __size: %w", err)
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogDisabled: true,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create collection: %w", err)
	}
	defer coll.Close()

	var l link.Link
	prog := coll.Programs["read"]
	for {
		l, err = link.AttachTracing(link.TracingOptions{
			Program:    prog,
			AttachType: ebpf.AttachTraceFEntry,
		})
		if err == nil {
			break
		}
		if errors.Is(err, unix.E2BIG) {
			// BPF_MAX_TRAMP_PROGS 38
			time.Sleep(time.Duration(rand.Int32N(100) * int32(time.Millisecond)))
			continue
		}
		return nil, fmt.Errorf("failed to fentry nanosleep: %w", err)
	}
	defer l.Close()

	nanosleep()

	var run bool
	if err := coll.Variables["run"].Get(&run); err != nil {
		return nil, fmt.Errorf("failed to get run: %w", err)
	}
	if !run {
		return nil, errors.New("reading kernel was not triggered")
	}

	if err := coll.Maps[".data.buff"].Lookup(uint32(0), buff); err != nil {
		return nil, fmt.Errorf("failed to lookup .data.buff: %w", err)
	}

	return buff[:size], nil
}
