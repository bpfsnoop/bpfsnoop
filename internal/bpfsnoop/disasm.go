// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"context"
	"errors"
	"fmt"
	"log"
	"maps"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/Asphaltt/addr2line"
	"github.com/bpfsnoop/gapstone"
	"github.com/fatih/color"

	"github.com/bpfsnoop/bpfsnoop/internal/assert"
)

const (
	kcorePath = "/proc/kcore"
)

func Disasm(f *Flags) {
	assert.False(len(f.progs) != 0 && len(f.kfuncs) != 0, "progs %v or kfuncs %v to be disassembled?", f.progs, f.kfuncs)

	if len(f.progs) != 0 {
		progs, err := f.ParseProgs()
		assert.NoErr(err, "Failed to parse bpf prog infos: %v")

		assert.SliceLen(progs, 1, "Only one --prog is allowed for --disasm")
		DumpProg(progs)
		return
	}

	if len(f.kfuncs) != 0 {
		assert.SliceLen(f.kfuncs, 1, "Only one --kfunc is allowed for --disasm")

		dumpKfunc(f.kfuncs[0], kfuncKmods, f.disasmBytes)
		return
	}
}

func guessBytes(kaddr uintptr, ks *Kallsyms, bytes uint) uint {
	if bytes != 0 {
		return bytes
	}

	nxt, ok := ks.next(kaddr)
	if !ok {
		return 4096 // limit to 4KiB
	}

	return min(uint(nxt.addr)-uint(kaddr), 4096)
}

func trimTailingInsns(b []byte) []byte {
	if runtime.GOARCH != archAMD64 {
		return b
	}

	skipInsns := map[byte]struct{}{
		0xcc: {}, // int3
		0x90: {}, // nop
	}

	i := len(b) - 1
	for ; i >= 0; i-- {
		if _, ok := skipInsns[b[i]]; !ok {
			break
		}
	}
	return b[:i+1]
}

func findDisasmKfuncInKmods(kfunc string, kaddr uint64, kmods []string, a2l *Addr2Line) (uint64, bool) {
	if a2l == nil {
		return 0, false
	}

	VerboseLog("Symbol %s not found in /proc/kallsyms", kfunc)

	for _, kmodName := range kmods {
		err := a2l.addKmod(kmodName)
		assert.NoErr(err, "Failed to parse addr2line of kmod %s: %v", kmodName)

		kmod := a2l.kmods[kmodName]
		var entry *addr2line.Addr2LineEntry
		if kaddr != 0 {
			entry, err = kmod.Addr2Line.Get(kaddr, true)
		} else {
			entry, err = kmod.Addr2Line.FindBySymbol(kfunc)
		}
		if err == nil {
			return kmod.kaslr.revertAddr(entry.Address), true
		}
	}

	return 0, false
}

func parseDisasmKfunc(kfunc string, kmods []string, ksyms *Kallsyms, a2l *Addr2Line) (uint64, string) {
	var err error
	var kaddr uint64
	if !strings.HasPrefix(kfunc, "0x") {
		kaddr, err = strconv.ParseUint("0x"+kfunc, 0, 64)
	} else {
		kaddr, err = strconv.ParseUint(kfunc, 0, 64)
	}
	if err == nil {
		entry, ok := ksyms.find(uintptr(kaddr))
		if ok {
			return kaddr, entry.name
		}

		kaddr, ok = findDisasmKfuncInKmods(kfunc, kaddr, kmods, a2l)
		assert.True(ok, "Symbol %s not found", kfunc)
		return kaddr, kfunc
	}

	// kfunc may be a symbol name
	entry, ok := ksyms.findBySymbol(kfunc)
	if ok {
		return entry.addr, entry.name
	}

	if ksym, ok := ksyms.findBySymbol(kfunc); ok && ksym.mod != "" {
		kmods = []string{ksym.mod}
	} else {
		kmods, err = inferenceKfuncKmods([]string{kfunc}, kfuncKmods, ksyms)
		assert.NoErr(err, "Failed to inference kernel modules for kfunc %s: %v", kfunc)
	}

	// kfunc may be a glob filter
	kfuncs, _ := findKernelFuncs([]string{kfunc}, kmods, ksyms, 0xFF, false, true)
	if len(kfuncs) != 0 {
		// grab the very first one sorted by name
		values := slices.SortedFunc(maps.Values(kfuncs), func(a, b *KFunc) int {
			return strings.Compare(a.Ksym.name, b.Ksym.name)
		})
		return values[0].Ksym.addr, values[0].Ksym.name
	}

	kaddr, ok = findDisasmKfuncInKmods(kfunc, 0, kmods, a2l)
	assert.True(ok, "Symbol %s not found", kfunc)
	return kaddr, kfunc
}

func dumpKfunc(kfunc string, kmods []string, bytes uint) {
	supportedArchs := []string{archAMD64, archARM64}
	assert.True(slices.Contains(supportedArchs, runtime.GOARCH), "Unsupported arch %s", runtime.GOARCH)

	VerboseLog("Reading /proc/kallsyms ..")
	syntax := "att"
	if disasmIntelSyntax {
		syntax = "intel"
	}
	dis, err := NewDisassembler(context.Background(), syntax)
	assert.NoErr(err, "Failed to create disassembler: %v")
	defer dis.Close()
	dis.verboseLog()

	kallsyms, addr2line := dis.kallsyms, dis.addr2line
	kaddr, kfunc := parseDisasmKfunc(kfunc, kmods, kallsyms, addr2line)
	assert.False(bytes > readLimit, "Disasm bytes %d is larger than limit %d", bytes, readLimit)
	target, err := dis.readKernelFunction(kfunc, kaddr, "", uint32(bytes), readLimit)
	assert.NoErr(err, "Failed to read kernel memory: %v")
	data := target.Bytes
	log.Printf("Disassembling %s at %s (%d bytes) ..",
		color.New(color.FgYellow, color.Bold).Sprint(kfunc),
		color.New(color.FgBlue).Sprintf("%#x", kaddr), len(data))

	VerboseLog("Disassembling bpf progs ..")
	bpfProgs, err := NewBPFProgs([]ProgFlag{{all: true}}, false, true)
	assert.NoErr(err, "Failed to get bpf progs: %v")
	defer bpfProgs.Close()

	<-bpfProgs.done
	assert.NoErr(bpfProgs.err, "Failed to parse bpf progs: %v")

	var sb strings.Builder

	printLineInfo := func(li *branchEndpoint) {
		gray := color.RGB(0x88, 0x88, 0x88)
		gray.Fprintf(&sb, "; %s+%#x", li.funcName, li.offset)
		if li.fileName != "" {
			gray.Fprintf(&sb, " %s:%d", li.fileName, li.fileLine)
		}
		if li.isInline {
			gray.Fprint(&sb, " [inline]")
		}
		if li.isProg {
			gray.Fprint(&sb, " [bpf]")
		}
		fmt.Fprintln(&sb)
	}

	li := getLineInfo(uintptr(kaddr), bpfProgs, addr2line, kallsyms)
	printLineInfo(li)

	prev := li

	b, pc := data[:], uint64(kaddr)
	for len(b) != 0 {
		inst, err := dis.DecodeOne(b, pc)
		if err != nil && len(b) <= 10 {
			break
		}
		if err != nil {
			if runtime.GOARCH == archAMD64 && b[0] == 0x82 {
				fmt.Fprint(&sb, printInsnInfo(pc, pc-kaddr, b[:1], "(bad)", ""))

				pc++
				b = b[1:]
				continue
			}

			fmt.Print(sb.String())
			if errors.Is(err, gapstone.ErrOK) {
				log.Printf("Finish disassembling early, %d bytes left", len(b))
				log.Fatalf(`Please try: gdb -q -c /proc/kcore -ex 'disas/r %#v,+%d' -ex 'quit'`, pc, len(b))
			}
			assert.NoErr(err, "Failed to disasm: %v")
		}

		li := getLineInfo(uintptr(pc), bpfProgs, addr2line, kallsyms)
		if (li.fromVmlinux || li.isProg) && (prev.fileName != li.fileName || prev.fileLine != li.fileLine) {
			printLineInfo(li)

			prev = li
		}

		opstr := inst.Operands
		fmt.Fprint(&sb, printInsnInfo(pc, pc-kaddr, inst.Bytes, inst.Mnemonic, opstr))

		var endpoint *branchEndpoint
		if strings.HasPrefix(opstr, "0x") || strings.HasPrefix(opstr, "#0x") {
			// On amd64, the target address is encoded as a hex number with a
			// leading "0x".
			// On arm64, the target address is encoded as a hex number with a
			// leading "#0x".
			s := strings.TrimPrefix(opstr, "#")
			n, err := strconv.ParseUint(s, 0, 64)
			if err == nil {
				endpoint = getLineInfo(uintptr(n), bpfProgs, addr2line, kallsyms)
			}
		}
		if endpoint != nil {
			fmt.Fprint(&sb, "\t")
			printLineInfo(endpoint)
		} else {
			fmt.Fprintln(&sb)
		}

		if bytes == 0 && len(inst.Bytes) == 1 &&
			(inst.Bytes[0] == 0xc3 /* retq */ ||
				inst.Bytes[0] == 0xcc /* int3 */) {
			break
		}

		insnSize := uint64(inst.Size)
		pc += insnSize
		b = b[insnSize:]
	}

	fmt.Print(sb.String())
}
