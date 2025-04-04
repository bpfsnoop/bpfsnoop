// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
)

type LbrEntry struct {
	From  uintptr
	To    uintptr
	Flags uint64
}

type LbrData struct {
	Entries [32]LbrEntry
	NrBytes int64
}

func (s *lbrStack) get(funcIP uintptr, lbrData *LbrData, helpers *Helpers) bool {
	progs, addr2line, ksyms := helpers.Progs, helpers.Addr2line, helpers.Ksyms
	progInfo, isProg := progs.funcs[funcIP]

	nrEntries := lbrData.NrBytes / int64(8*3)
	entries := lbrData.Entries[:nrEntries]
	if !verbose {
		if !isProg {
			for i := range entries {
				if ksym, ok := ksyms.find(entries[i].From); ok && ksym.addr == uint64(funcIP) {
					entries = entries[i:]
					break
				}
			}
		} else if mode == TracingModeExit {
			for i := range entries {
				if progInfo.contains(entries[i].From) || progInfo.contains(entries[i].To) {
					entries = entries[i:]
					break
				}
			}

			for i := len(entries) - 1; i >= 0; i-- {
				if progInfo.contains(entries[i].From) || progInfo.contains(entries[i].To) {
					entries = entries[:i+1]
					break
				}
			}
		} else {
			for i := range entries {
				if progInfo.contains(entries[i].From) {
					entries = entries[i:]
					break
				}
			}
		}

		if len(entries) == 0 {
			return false
		}
	}

	lbrEntries := make([]branchEntry, 0, len(entries))
	for _, entry := range entries {
		from := getLineInfo(entry.From, progs, addr2line, ksyms)
		to := getLineInfo(entry.To, progs, addr2line, ksyms)
		lbrEntries = append(lbrEntries, branchEntry{from, to})
	}

	last := len(lbrEntries) - 1
	s.pushFirstEntry(lbrEntries[last])
	for i := last - 1; i >= 0; i-- {
		s.pushEntry(lbrEntries[i])
	}

	return true
}

func (s *lbrStack) outputStack(sb *strings.Builder, helpers *Helpers, lbrData *LbrData, lbrs *ebpf.Map, ev *Event) error {
	if !outputLbr {
		return nil
	}

	b := ptr2bytes(unsafe.Pointer(lbrData), int(unsafe.Sizeof(*lbrData)))
	err := lbrs.LookupAndDelete(ev.SessID, b)
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf("failed to lookup lbr data: %w", err)
	}

	hasLbrEntries := lbrData.NrBytes > 0 && lbrData.Entries[0] != (LbrEntry{})
	hasLbrEntries = hasLbrEntries && s.get(ev.FuncIP, lbrData, helpers)
	if !hasLbrEntries {
		return nil
	}

	fmt.Fprintln(sb, "LBR stack:")
	s.output(sb)

	return nil
}
