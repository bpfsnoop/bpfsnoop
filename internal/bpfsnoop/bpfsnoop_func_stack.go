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

type FuncStack struct {
	IPs [MAX_STACK_DEPTH]uint64
}

type fnStack struct {
	stack []string
}

func newFnStack() *fnStack {
	return &fnStack{
		stack: make([]string, 0, MAX_STACK_DEPTH),
	}
}

func (s *fnStack) reset() {
	s.stack = s.stack[:0]
}

func (s *fnStack) get(event *Event, helpers *Helpers, stacks *ebpf.Map, symbolOnly bool) error {
	id := uint32(event.StackID)

	var data FuncStack
	err := stacks.Lookup(id, &data)
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf("failed to lookup func stack map: %w", err)
	}
	_ = stacks.Delete(id)

	ips := data.IPs[:]
	if !verbose {
		ips = ips[3:] // Skip the first 3 entries as they are entries for fentry/fexit and its trampoline.
	}
	for _, ip := range ips {
		if ip == 0 {
			continue
		}

		li := getLineInfo(uintptr(ip), helpers.Progs, helpers.Addr2line, helpers.Ksyms)

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
	if !outputFuncStack || event.StackID <= 0 {
		return nil
	}

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
