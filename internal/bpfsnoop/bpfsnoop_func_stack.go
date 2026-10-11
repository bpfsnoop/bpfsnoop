// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/fatih/color"
)

type fnStack struct {
	ips   []uint64
	stack []string
}

func newFnStack() *fnStack {
	return &fnStack{
		ips:   make([]uint64, kernelPerfEventMaxStack),
		stack: make([]string, 0, kernelPerfEventMaxStack),
	}
}

func (s *fnStack) reset() {
	s.stack = s.stack[:0]
}

func (s *fnStack) get(event *Event, helpers *Helpers, stacks *ebpf.Map, symbolOnly bool) error {
	id := uint32(event.StackID)

	if len(s.stack) > 0 {
		clear(s.ips[:len(s.stack)])
	}
	err := stacks.Lookup(id, &s.ips)
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf("failed to lookup func stack map: %w", err)
	}
	// FIXME: delete the stack entry.
	// Other queued events, including on other CPUs, may share this stack ID.
	// The trace owns the map and releases its entries when it closes.

	ips := s.ips[:]
	skipEntries := true
	for _, ip := range ips {
		if ip == 0 {
			continue
		}

		li := getLineInfo(uintptr(ip), helpers.Progs, helpers.Addr2line, helpers.Ksyms)

		if skipEntries && !verbose {
			if strings.HasPrefix(li.funcName, "bpf_trampoline_") /* tracing */ ||
				strings.HasPrefix(li.funcName, "bpf_trace_run") /* tracepoint */ {
				skipEntries = false
			}
			continue
		}

		if symbolOnly {
			s.stack = append(s.stack, li.funcName)
			continue
		}

		var sb strings.Builder
		fmt.Fprint(&sb, "  ")
		if noColorOutput {
			if verbose {
				fmt.Fprintf(&sb, "0x%x:", ip)
			}
			fmt.Fprintf(&sb, "%-50s", fmt.Sprintf("%s+%#x", li.funcName, li.offset))
			if li.fileName != "" {
				fmt.Fprintf(&sb, "\t; %s:%d", li.fileName, li.fileLine)
			}
		} else {
			if verbose {
				color.New(color.FgBlue).Fprintf(&sb, "%#x", ip)
				fmt.Fprint(&sb, ":")
			}

			offset := fmt.Sprintf("+%#x", li.offset)
			color.RGB(0xE1, 0xD5, 0x77 /* light yellow */).Fprint(&sb, li.funcName)
			fmt.Fprintf(&sb, "%-*s", 50-len(li.funcName), offset)
			if li.fileName != "" {
				color.RGB(0x88, 0x88, 0x88 /* gray */).Fprintf(&sb, "\t; %s:%d", li.fileName, li.fileLine)
			}
		}

		fmt.Fprintln(&sb)

		s.stack = append(s.stack, sb.String())
	}

	return nil
}

func (s *fnStack) output(sb *strings.Builder, helpers *Helpers, stacks *ebpf.Map, fg *FlameGraph, event *Event) error {
	err := s.get(event, helpers, stacks, outputFlameGraph != "")
	if err != nil {
		return fmt.Errorf("failed to get function stack: %w", err)
	}
	if len(s.stack) == 0 {
		return nil
	}

	if outputFlameGraph == "" {
		fmt.Fprintln(sb, "Func stack:")
		for _, line := range s.stack {
			fmt.Fprint(sb, line)
		}
	} else {
		slices.Reverse(s.stack)
		fg.AddStack(s.stack, 1)
	}

	return nil
}
