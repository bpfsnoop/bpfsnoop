// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"
	"strings"
	"time"
	"unsafe"

	"github.com/fatih/color"
)

type GraphEvent struct {
	Type   uint16
	Length uint16
	KernNs uint32
	SessID uint64
	FuncIP uint64
	CPU    uint32
	Depth  uint32
}

const (
	sizeOfGraphEvent = int(unsafe.Sizeof(GraphEvent{}))
)

func outputGraphEvent(sb *strings.Builder, sessions *Sessions, graphs FuncGraphs, event *GraphEvent, fnInfo string) {
	sess, ok := sessions.Get(event.SessID)
	if !ok {
		return
	}

	duration := time.Duration(event.KernNs - sess.started)
	if colorfulOutput {
		color.RGB(58, 64, 94 /* lighter gray */).Fprint(sb, strings.Repeat("..", int(event.Depth)))
		fmt.Fprint(sb, fnInfo)
		color.New(color.FgCyan).Fprintf(sb, " cpu=%d depth=%d", event.CPU, event.Depth)
		color.RGB(0xFF, 0x00, 0x7F /* rose red */).Fprintf(sb, " duration=%s", duration)
	} else {
		fmt.Fprintf(sb, "%s%s cpu=%d depth=%d duration=%s", strings.Repeat("  ", int(event.Depth)), fnInfo, event.CPU, event.Depth, duration)
	}
	fmt.Fprintln(sb)

	sess.outputs = append(sess.outputs, sb.String())
}
