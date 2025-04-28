// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"errors"
	"fmt"
	"log"
	"runtime"
	"strconv"
	"strings"

	"github.com/bpfsnoop/gapstone"
	"github.com/cilium/ebpf"
	"github.com/fatih/color"

	"github.com/bpfsnoop/bpfsnoop/internal/assert"
)

const (
	kcorePath = "/proc/kcore"
)

func Disasm(f *Flags, readSpec *ebpf.CollectionSpec) {
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

		dumpKfunc(f.kfuncs[0], kfuncKmods, f.disasmBytes, readSpec)
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

	return uint(nxt.addr) - uint(kaddr)
}

func trimTailingInsns(b []byte) []byte {
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

func dumpKfunc(kfunc string, kmods []string, bytes uint, readSpec *ebpf.CollectionSpec) {
	assert.True(runtime.GOARCH == "amd64", "Only support amd64 arch")

	VerboseLog("Reading /proc/kallsyms ..")
	kallsyms, err := NewKallsyms()
	assert.NoErr(err, "Failed to read /proc/kallsyms: %v")

	var addr2line *Addr2Line

	vmlinux, err := FindVmlinux()
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			VerboseLog("Dbgsym vmlinux not found")
		} else {
			assert.NoErr(err, "Failed to find vmlinux: %v")
		}
	}
	if err == nil {
		VerboseLog("Found vmlinux: %s", vmlinux)

		textAddr, err := ReadTextAddrFromVmlinux(vmlinux)
		assert.NoErr(err, "Failed to read .text address from vmlinux: %v")

		VerboseLog("Creating addr2line from vmlinux ..")
		kaslr := NewKaslr(kallsyms.Stext(), textAddr)
		addr2line, err = NewAddr2Line(vmlinux, kaslr, kallsyms.SysBPF(), kallsyms.Stext())
		assert.NoErr(err, "Failed to create addr2line: %v")
	}

	var kaddr uint64
	if !strings.HasPrefix(kfunc, "0x") {
		kaddr, err = strconv.ParseUint("0x"+kfunc, 0, 64)
	} else {
		kaddr, err = strconv.ParseUint(kfunc, 0, 64)
	}
	if err != nil {
		// kfunc may be a symbol name
		entry, ok := kallsyms.findBySymbol(kfunc)
		if !ok {
			VerboseLog("Symbol %s not found in /proc/kallsyms", kfunc)

			if addr2line == nil {
				log.Fatal("Dbgsym is required to disasm %s", kfunc)
			}

			for _, kmodName := range kmods {
				err := addr2line.addKmod(kmodName)
				assert.NoErr(err, "Failed to parse addr2line of kmod %s: %w", kmodName, err)

				kmod := addr2line.kmods[kmodName]
				entry, err := kmod.Addr2Line.FindBySymbol(kfunc)
				if err == nil {
					kaddr = kmod.kaslr.revertAddr(entry.Address)
					break
				}
			}

			assert.False(kaddr == 0, "Symbol %s not found", kfunc)
		} else {
			kaddr = entry.addr
			kfunc = entry.name
		}
	} else {
		entry, ok := kallsyms.find(uintptr(kaddr))
		if !ok {
			VerboseLog("Address %#x not found in /proc/kallsyms", kaddr)

			if addr2line == nil {
				log.Fatal("Dbgsym is required to disasm %s", kfunc)
			}

			for _, kmodName := range kmods {
				err := addr2line.addKmod(kmodName)
				assert.NoErr(err, "Failed to parse addr2line of kmod %s: %w", kmodName, err)

				kmod := addr2line.kmods[kmodName]
				entry, err := kmod.Addr2Line.Get(kaddr, true)
				if err == nil {
					kaddr = kmod.kaslr.revertAddr(entry.Address)
					break
				}
			}

			assert.False(kaddr == 0, "Symbol %s not found", kfunc)
		} else {
			kfunc = entry.name
		}
	}

	bytes = guessBytes(uintptr(kaddr), kallsyms, bytes)
	assert.False(bytes > readLimit, "Disasm bytes %d is larger than limit %d", bytes, readLimit)
	data, err := readKernel(readSpec, kaddr, uint32(bytes))
	assert.NoErr(err, "Failed to read kernel memory: %v", err)

	data = trimTailingInsns(data)
	log.Printf("Disassembling %s at %s (%d bytes) ..",
		color.New(color.FgYellow, color.Bold).Sprint(kfunc),
		color.New(color.FgBlue).Sprintf("%#x", kaddr), len(data))

	engine, err := createGapstoneEngine()
	assert.NoErr(err, "Failed to create gapstone engine: %v", err)
	defer engine.Close()

	VerboseLog("Disassembling bpf progs ..")
	bpfProgs, err := NewBPFProgs([]ProgFlag{{all: true}}, false, true)
	assert.NoErr(err, "Failed to get bpf progs: %v")
	defer bpfProgs.Close()

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

	printInsnInfo := func(pc uint64, opcode string, mnemonic string, opstr string) {
		offset := pc - uint64(kaddr)
		fmt.Fprintf(&sb, "%s %-14s %-19s\t%s\t%s",
			color.New(color.FgBlue).Sprintf("%#x", pc),
			fmt.Sprintf("<+%d/%#x>:", offset, offset),
			opcode,
			color.GreenString(mnemonic), color.RedString(opstr))
	}

	li := getLineInfo(uintptr(kaddr), bpfProgs, addr2line, kallsyms)
	printLineInfo(li)

	prev := li

	b, pc := data[:], uint64(kaddr)
	for len(b) != 0 {
		insts, err := engine.Disasm(b, pc, 1)
		if err != nil && len(b) <= 10 {
			break
		}
		if err != nil {
			if b[0] == 0x82 {
				printInsnInfo(pc, "82", "(bad)", "")

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

		inst := insts[0]

		var opcodes []string
		for _, insn := range inst.Bytes {
			opcodes = append(opcodes, fmt.Sprintf("%02x", insn))
		}
		opcode := strings.Join(opcodes, " ")
		opstr := inst.OpStr
		printInsnInfo(pc, opcode, inst.Mnemonic, opstr)

		var endpoint *branchEndpoint
		if strings.HasPrefix(opstr, "0x") {
			n, err := strconv.ParseUint(opstr, 0, 64)
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
