// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"
	"slices"
	"strings"
	"unsafe"

	"github.com/fatih/color"
)

type fnStack struct {
	stack []string
}

func newFnStack() *fnStack {
	return &fnStack{
		stack: make([]string, 0, kernelPerfEventMaxStack),
	}
}

func (s *fnStack) trim(stacks []uint64, helpers *Helpers) []uint64 {
	if verbose {
		return stacks
	}

	// bpf_get_stack may already omit tracing frames. Only trim when the
	// trampoline is present, otherwise retain the captured caller stack.
	for i, ip := range stacks {
		symbol, ok := helpers.Ksyms.find(uintptr(ip))
		if ok && (strings.HasPrefix(symbol.name, "bpf_trampoline_") ||
			strings.HasPrefix(symbol.name, "bpf_trace_run")) {
			return stacks[i+1:]
		}
	}

	return stacks
}

func (s *fnStack) get(event *Event, helpers *Helpers, stacks []uint64, symbolOnly bool) error {
	ips := s.trim(stacks, helpers)
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

func buf2stackPointers(buf []byte, size int) []uint64 {
	ptr := (*uint64)(unsafe.Pointer(unsafe.SliceData(buf)))
	return unsafe.Slice(ptr, size/8)
}

func (s *fnStack) output(sb *strings.Builder, helpers *Helpers, buf []byte, size int, fg *FlameGraph, event *Event) error {
	ips := buf2stackPointers(buf, size)
	err := s.get(event, helpers, ips, outputFlameGraph != "")
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
