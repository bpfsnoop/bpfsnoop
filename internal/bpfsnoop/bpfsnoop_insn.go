// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
)

type InsnEvent struct {
	Type   uint16
	Length uint16
	KernNs uint32
	SessID uint64
	InsnIP uint64
	CPU    uint32
}

func outputInsnEvent(sb *strings.Builder, sess *Sessions, insns *FuncInsns, event *InsnEvent) bool {
	insn, ok := insns.Insns[event.InsnIP]
	if !ok {
		return false
	}

	var duration time.Duration
	if s, ok := sess.Get(event.SessID); ok {
		duration = time.Duration(event.KernNs - s.started)
	}

	if !noColorOutput {
		color.New(color.FgYellow).Fprint(sb, insn.Func)
		color.New(color.FgCyan).Fprintf(sb, " cpu=%-2d", event.CPU)
		color.RGB(0xFF, 0x00, 0x7F /* rose red */).Fprintf(sb, " duration=%-12s", duration)
	} else {
		fmt.Fprintf(sb, "%s cpu=%-2d duration=%-12s", insn.Func, event.CPU, duration)
	}
	fmt.Fprintf(sb, " insn=%s", insn.Desc)

	return true
}
