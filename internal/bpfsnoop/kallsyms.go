// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"bufio"
	"fmt"
	"io"
	"iter"
	"log"
	"maps"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
)

const kallsymsFilepath = "/proc/kallsyms"

const (
	kmodBuiltinPfx = "__builtin"
	kmodBpf        = "bpf"

	bpfFentryTest1 = "bpf_fentry_test1"

	bpfRawTpStart = "__start__bpf_raw_tp"
	bpfRawTpStop  = "__stop__bpf_raw_tp"

	bpfTraceModules = "bpf_trace_modules"
	x86PMU          = "x86_pmu"

	btfIDDeny = "btf_id_deny"

	onAmd64 = runtime.GOARCH == archAMD64
	onArm64 = runtime.GOARCH == archARM64
)

var sysBPFSymbol = "__x64_sys_bpf"

func init() {
	switch runtime.GOARCH {
	case archAMD64:
		break

	case archARM64:
		sysBPFSymbol = "__arm64_sys_bpf"

	default:
		log.Fatalf("unsupported architecture %s", runtime.GOARCH)
	}
}

func isKernelBuiltinMod(mod string) bool {
	return mod == "" || strings.HasPrefix(mod, kmodBuiltinPfx) || mod == kmodBpf
}

// KsymEntry represents a symbol entry in /proc/kallsyms.
type KsymEntry struct {
	addr  uint64
	typ   byte
	name  string
	mod   string
	extra []uint64
	duped bool
}

// Addr returns the address of the symbol.
func (ke *KsymEntry) Addr() uint64 {
	return ke.addr
}

// Type returns the symbol type from /proc/kallsyms.
func (ke *KsymEntry) Type() byte {
	return ke.typ
}

// Name returns the name of the symbol.
func (ke *KsymEntry) Name() string {
	return ke.name
}

// Module returns the kernel module providing the symbol, or an empty string
// for built-in symbols.
func (ke *KsymEntry) Module() string {
	return ke.mod
}

func (ke *KsymEntry) String() string {
	if ke.mod == "" {
		return fmt.Sprintf("%#x@%s", ke.addr, ke.name)
	}
	return fmt.Sprintf("%#x@%s[%s]", ke.addr, ke.name, ke.mod)
}

// Kallsyms represents the symbols in /proc/kallsyms. The address and name
// indexes contain only t/T symbols so existing text-address lookups cannot
// resolve to data symbols.
type Kallsyms struct {
	syms []*KsymEntry // all symbols in /proc/kallsyms order

	a2s   map[uint64]*KsymEntry // addr => symbol
	n2s   map[string]*KsymEntry // name => symbol
	addrs []uint64              // sorted for binary search

	stext  uint64
	sysBPF uint64

	mods []string // kernel modules, sorted by name

	bpfRawTpStart uint64
	bpfRawTpStop  uint64

	bpfTraceModules uint64

	btfIDDeny uint64 // address of btf_id_deny, if exists
	x86PMU    uint64 // address of x86_pmu, if exists
}

// NewKallsyms reads /proc/kallsyms and returns a Kallsyms instance.
func NewKallsyms() (*Kallsyms, error) {
	fd, err := os.Open(kallsymsFilepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", kallsymsFilepath, err)
	}
	defer fd.Close()

	ks, err := newKallsyms(fd)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", kallsymsFilepath, err)
	}
	return ks, nil
}

func newKallsyms(r io.Reader) (*Kallsyms, error) {
	var ks Kallsyms
	ks.a2s = make(map[uint64]*KsymEntry)
	ks.n2s = make(map[string]*KsymEntry)

	kmods := make(map[string]struct{})

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if len(fields[1]) != 1 {
			continue
		}

		entry := &KsymEntry{
			typ:  fields[1][0],
			name: fields[2],
		}
		var err error
		entry.addr, err = strconv.ParseUint(fields[0], 16, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse addr %s: %w", fields[0], err)
		}
		if len(fields) >= 4 {
			entry.mod = strings.Trim(fields[3], "[]")
		}
		ks.syms = append(ks.syms, entry)

		// When CONFIG_KEXEC_CORE=y, .data becomes executable after Linux v6.14
		// due to commit cb33ff9e063c ("x86/kexec: Move relocate_kernel to kernel
		// .data section"). Hence, we must accept both [Tt] and [Dd] symbols.
		matchData := func() {
			switch entry.name {
			case bpfRawTpStart:
				ks.bpfRawTpStart = entry.addr

			case bpfRawTpStop:
				ks.bpfRawTpStop = entry.addr

			case bpfTraceModules:
				ks.bpfTraceModules = entry.addr

			case x86PMU:
				ks.x86PMU = entry.addr
			}
		}

		switch entry.typ {
		case 't', 'T':
			if sym, ok := ks.n2s[entry.name]; ok {
				sym.extra = append(sym.extra, entry.addr)
				sym.duped = true
				entry.duped = true
			} else {
				ks.n2s[entry.name] = entry
			}
			ks.a2s[entry.addr] = entry

			switch entry.name {
			case "_stext":
				ks.stext = entry.addr

			case sysBPFSymbol:
				ks.sysBPF = entry.addr

			default:
				matchData()
			}

			if _, exists := kmods[entry.mod]; !exists && !isKernelBuiltinMod(entry.mod) {
				kmods[entry.mod] = struct{}{}
				ks.mods = append(ks.mods, entry.mod)
			}

		case 'D', 'd':
			matchData()

		case 'R', 'r':
			switch entry.name {
			case btfIDDeny:
				ks.btfIDDeny = entry.addr
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan kallsyms: %w", err)
	}

	ks.addrs = slices.Sorted(maps.Keys(ks.a2s))

	// Sort modules by name
	slices.Sort(ks.mods)

	return &ks, nil
}

// Symbols iterates all entries read from /proc/kallsyms in file order.
func (ks *Kallsyms) Symbols() iter.Seq[*KsymEntry] {
	return slices.Values(ks.syms)
}

// Stext returns the address of _stext.
func (ks *Kallsyms) Stext() uint64 {
	return ks.stext
}

// SysBPF returns the address of __x64_sys_bpf.
func (ks *Kallsyms) SysBPF() uint64 {
	return ks.sysBPF
}

func (ks *Kallsyms) index(kaddr uintptr) (int, bool) {
	addr := uint64(kaddr)
	if addr < ks.addrs[0] || addr > ks.addrs[len(ks.addrs)-1] {
		return 0, false
	}

	total := len(ks.addrs)
	i, j := 0, total
	for i < j {
		h := int(uint(i+j) >> 1)
		if ks.addrs[h] <= addr {
			if h+1 < total && ks.addrs[h+1] > addr {
				return h, true
			}
			i = h + 1
		} else {
			j = h
		}
	}

	return i - 1, true
}

// find returns the symbol entry of the given address.
func (ks *Kallsyms) find(kaddr uintptr) (*KsymEntry, bool) {
	idx, ok := ks.index(kaddr)
	if !ok {
		return nil, false
	}

	return ks.a2s[ks.addrs[idx]], true
}

func (ks *Kallsyms) next(kaddr uintptr) (*KsymEntry, bool) {
	idx, ok := ks.index(kaddr)
	if !ok {
		return nil, false
	}

	idx++
	if idx >= len(ks.addrs) {
		return nil, false
	}

	return ks.a2s[ks.addrs[idx]], true
}

func (ks *Kallsyms) findBySymbol(symbol string) (*KsymEntry, bool) {
	entry, ok := ks.n2s[symbol]
	if ok {
		return entry, true
	}

	suffixs := []string{
		".constprop.0",
		".isra.0",
		".isra.0.cold",
		".cold",
		".part.0",
	}
	for _, suffix := range suffixs {
		if entry, ok = ks.n2s[symbol+suffix]; ok {
			return entry, true
		}
	}

	nameLLVM := symbol + ".llvm." // llvm symbols
	for name, entry := range ks.n2s {
		if strings.HasPrefix(name, nameLLVM) {
			return entry, true
		}
	}

	return nil, false
}

func (ks *Kallsyms) findSymbol(addr uint64) string {
	e, ok := ks.a2s[addr]
	if ok {
		return e.name
	}
	return ""
}
