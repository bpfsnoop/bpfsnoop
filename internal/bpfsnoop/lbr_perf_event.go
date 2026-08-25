// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

type LbrPerfEvent struct {
	fds []int
}

func OpenLbrPerfEvent(branchTypes []string) (*LbrPerfEvent, error) {
	var p LbrPerfEvent
	var err error

	defer func() {
		if err != nil {
			p.Close()
		}
	}()

	numCPU, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, fmt.Errorf("failed to get number of CPUs: %w", err)
	}

	p.fds = make([]int, 0, numCPU)
	for i := range numCPU {
		fd, err := openLbrPerfEvent(i, branchTypes)
		if err != nil {
			return nil, fmt.Errorf("failed to open LBR perf event: %w", err)
		}

		p.fds = append(p.fds, fd)
	}

	return &p, nil
}

func (p *LbrPerfEvent) Close() {
	for _, fd := range p.fds {
		_ = unix.Close(fd)
	}
}
