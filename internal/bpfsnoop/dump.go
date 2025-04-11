// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/bpfsnoop/gapstone"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/fatih/color"

	"github.com/bpfsnoop/bpfsnoop/internal/assert"
)

func printInsnInfo(pc uint64, insn gapstone.Instruction) string {
	var opcodes []string
	for _, insn := range insn.Bytes {
		opcodes = append(opcodes, fmt.Sprintf("%02x", insn))
	}
	opcode := strings.Join(opcodes, " ")
	opstr := insn.OpStr
	mnemonic := insn.Mnemonic

	if noColorOutput {
		return fmt.Sprintf("%#x: %-19s\t%s\t%s",
			pc, opcode, mnemonic, opstr)
	}
	return fmt.Sprintf("%s: %-19s\t%s\t%s",
		color.New(color.FgBlue).Sprintf("%#x", pc), opcode,
		color.GreenString(mnemonic), color.RedString(opstr))
}

func DumpProg(pf []ProgFlag) {
	progs, err := NewBPFProgs(pf, true, true)
	assert.NoErr(err, "Failed to get bpf progs: %v")
	defer progs.Close()

	var prog *ebpf.Program
	for _, p := range progs.progs {
		prog = p
		break
	}

	if prog == nil {
		log.Fatalf("No prog found")
	}

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

	engine, err := createGapstoneEngine()
	assert.NoErr(err, "Failed to create engine: %v")
	defer engine.Close()

	VerboseLog("Disassembling bpf progs ..")
	bpfProgs, err := NewBPFProgs([]ProgFlag{{all: true}}, false, true)
	assert.NoErr(err, "Failed to get bpf progs: %v")
	defer bpfProgs.Close()

	info, err := prog.Info()
	assert.NoErr(err, "Failed to get prog info: %v")

	jitedInsns, _ := info.JitedInsns()
	jitedKsyms, _ := info.JitedKsymAddrs()
	jitedFuncLens, _ := info.JitedFuncLens()
	jitedLineInfos, _ := info.JitedLineInfos()
	assert.SliceNotEmpty(jitedInsns, "No jited insns")
	assert.Equal(len(jitedFuncLens), len(jitedKsyms), "Func len number %d != ksym number %d", len(jitedFuncLens), len(jitedKsyms))

	// jitedFuncLens are the insns length of each function.
	// Then, jitedInsns can be split into len(jitedFuncLens) functions with each function having jitedFuncLens[i] insns.

	lines, err := info.LineInfos()
	assert.NoErr(err, "Failed to get line infos: %v")
	assert.Equal(len(lines), len(jitedLineInfos), "Line info mismatch: %d != %d (jited)", len(lines), len(jitedLineInfos))

	// Each jitedLineInfo is corresponding to a lineInfo.

	// jitedLineInfos are kernel addresses.
	// jitedKsyms are ksyms for funcs.
	//
	// ksym addr + insn offset = jited line info addr.
	// jited line info addr => line info.

	jited2LineInfos := make(map[uint64]btf.LineOffset, len(jitedLineInfos))
	for i, kaddr := range jitedLineInfos {
		jited2LineInfos[kaddr] = lines[i]
	}

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

	insns := jitedInsns
	for i, funcLen := range jitedFuncLens {
		ksym := uint64(jitedKsyms[i])
		fnInsns := insns[:funcLen]
		pc := uint64(0)

		for len(fnInsns) > 0 {
			kaddr := ksym + pc
			if li, ok := jited2LineInfos[kaddr]; ok {
				fileName := li.Line.FileName()
				if fileName != "" && fileName[0] == '.' {
					fileName = strings.TrimLeft(fileName, "./")
				}
				color.RGB(0x88, 0x88, 0x88).Fprintf(&sb, "; %s:%d:%d %s\n",
					fileName, li.Line.LineNumber(), li.Line.LineColumn(),
					strings.TrimSpace(li.Line.Line()))
			}

			inst, err := engine.Disasm(fnInsns, kaddr, 1)
			assert.NoErr(err, "Failed to disasm instruction: %v")

			fmt.Fprint(&sb, printInsnInfo(kaddr, inst[0]))

			opstr := inst[0].OpStr
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

			insnSize := uint64(inst[0].Size)
			pc += insnSize
			fnInsns = fnInsns[insnSize:]
		}

		fmt.Fprintln(&sb)

		insns = insns[funcLen:]
	}

	fmt.Print(sb.String())
}
