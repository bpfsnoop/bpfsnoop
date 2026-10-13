// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"
	"io"

	"github.com/fatih/color"
)

type branchEndpoint struct {
	addr uintptr

	funcName     string
	offset       uintptr
	endpointName string // ${funcName}+${offset}

	fileName    string
	fileLine    uint32
	lineInfo    string // (${fileName}:${fileLine})[inline]
	isInline    bool
	isProg      bool
	fromVmlinux bool
}

func (b *branchEndpoint) updateInfo() {
	if verbose {
		b.endpointName = fmt.Sprintf("%#x:%s+%#x", b.addr, b.funcName, b.offset)
	} else {
		b.endpointName = fmt.Sprintf("%s+%#x", b.funcName, b.offset)
	}
	if b.fileName != "" {
		if b.isInline {
			b.lineInfo = fmt.Sprintf("(%s:%d)[inline]", b.fileName, b.fileLine)
		} else {
			b.lineInfo = fmt.Sprintf("(%s:%d)", b.fileName, b.fileLine)
		}
	}
}

func (b *branchEndpoint) format(w io.Writer, nameLen, infoLen int) {
	if noColorOutput {
		sfmt := fmt.Sprintf("%%-%ds %%-%ds", nameLen, infoLen)
		fmt.Fprintf(w, sfmt, b.endpointName, b.lineInfo)
		return
	}

	if verbose {
		color.New(color.FgBlue).Fprintf(w, "%#x", b.addr)
		fmt.Fprint(w, ":")
	}
	color.RGB(0xE1, 0xD5, 0x77 /* light yellow */).Fprint(w, b.funcName)
	fmt.Fprintf(w, "+%#x", b.offset)
	if nameLen > len(b.endpointName) {
		fmt.Fprintf(w, "%-*s", nameLen-len(b.endpointName), "")
	}

	fmt.Fprint(w, " ")

	if b.fileName != "" {
		fmt.Fprint(w, "(")
		color.RGB(0x88, 0x88, 0x88 /* gray */).Fprintf(w, "%s:%d", b.fileName, b.fileLine)
		fmt.Fprint(w, ")")
		if b.isInline {
			fmt.Fprint(w, "[inline]")
		}
		if infoLen > len(b.lineInfo) {
			fmt.Fprintf(w, "%-*s", infoLen-len(b.lineInfo), "")
		}
	} else {
		fmt.Fprintf(w, "%-*s", infoLen, "")
	}
}

type branchEntry struct {
	from, to *branchEndpoint
}

func (e *branchEntry) format(w io.Writer, lNameLen, lInfoLen, rNameLen, rInfoLen int) {
	e.from.format(w, lNameLen, lInfoLen)
	fmt.Fprint(w, " -> ")
	e.to.format(w, rNameLen, rInfoLen)
}

type branchRecord struct {
	entries []branchEntry
	last    int

	maxFromNameLen, maxFromLinfoLen int
	maxToNameLen, maxToLinfoLen     int
}

func newBranchRecord(entry branchEntry) *branchRecord {
	r := &branchRecord{
		entries: make([]branchEntry, 0, lbrNr),
		last:    -1,
	}
	r.addEntry(entry)
	return r
}

func (r *branchRecord) addEntry(entry branchEntry) {
	r.entries = append(r.entries, entry)
	r.last++

	r.maxFromNameLen = max(r.maxFromNameLen, len(entry.from.endpointName))
	r.maxFromLinfoLen = max(r.maxFromLinfoLen, len(entry.from.lineInfo))
	r.maxToNameLen = max(r.maxToNameLen, len(entry.to.endpointName))
	r.maxToLinfoLen = max(r.maxToLinfoLen, len(entry.to.lineInfo))
}

func (r *branchRecord) appendRecord(record *branchRecord) {
	r.entries = append(r.entries, record.entries...)
	r.last += len(record.entries)

	r.maxFromNameLen = max(r.maxFromNameLen, record.maxFromNameLen)
	r.maxFromLinfoLen = max(r.maxFromLinfoLen, record.maxFromLinfoLen)
	r.maxToNameLen = max(r.maxToNameLen, record.maxToNameLen)
	r.maxToLinfoLen = max(r.maxToLinfoLen, record.maxToLinfoLen)
}

type lbrStack struct {
	last  int
	stack []*branchRecord
}

func newLBRStack() *lbrStack {
	return &lbrStack{
		stack: make([]*branchRecord, 0, lbrNr),
	}
}

func (s *lbrStack) addRecord(record *branchRecord) {
	s.stack = append(s.stack, record)
	s.last++
}

func (s *lbrStack) pushFirstEntry(entry branchEntry) {
	s.stack = append(s.stack, newBranchRecord(entry))
}

func (s *lbrStack) pushEntry(entry branchEntry) {
	lastRecord := s.stack[s.last]
	lastEntry := lastRecord.entries[lastRecord.last]
	sameCallStack := lastEntry.to.funcName == entry.from.funcName

	if sameCallStack {
		lastRecord.addEntry(entry)
	} else {
		s.addRecord(newBranchRecord(entry))
	}
}

func (s *lbrStack) outputRecord(w io.Writer, r *branchRecord, idx int, lNameLen, lInfoLen, rNameLen, rInfoLen int) {
	fmt.Fprintf(w, "[#%02d] ", idx)
	r.entries[0].format(w, lNameLen, lInfoLen, rNameLen, rInfoLen)
	fmt.Fprintln(w)

	i := 1
	for ; i < len(r.entries); i++ {
		entry := r.entries[i]
		fmt.Fprintf(w, "      ")
		entry.format(w, lNameLen, lInfoLen, rNameLen, rInfoLen)
		fmt.Fprintln(w)
	}
}

func (s *lbrStack) getLeftFmt() (int, int) {
	var maxFromNameLen, maxFromLinfoLen int
	for _, r := range s.stack {
		maxFromNameLen = max(maxFromNameLen, r.maxFromNameLen)
		maxFromLinfoLen = max(maxFromLinfoLen, r.maxFromLinfoLen)
	}

	return maxFromNameLen, maxFromLinfoLen
}

func (s *lbrStack) getRightFmt() (int, int) {
	var maxToNameLen, maxToLinfoLen int
	for _, r := range s.stack {
		maxToNameLen = max(maxToNameLen, r.maxToNameLen)
		maxToLinfoLen = max(maxToLinfoLen, r.maxToLinfoLen)
	}

	return maxToNameLen, maxToLinfoLen
}

func (s *lbrStack) output(w io.Writer) {
	idx := int(lbrNr - 1)
	ln, li := s.getLeftFmt()
	rn, ri := s.getRightFmt()

	for _, r := range s.stack {
		s.outputRecord(w, r, idx, ln, li, rn, ri)
		idx--
	}
}
