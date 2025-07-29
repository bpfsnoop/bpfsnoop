// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"

	"github.com/cilium/ebpf/btf"
	"github.com/fatih/color"
	"golang.org/x/exp/maps"

	"github.com/bpfsnoop/bpfsnoop/internal/assert"
	"github.com/bpfsnoop/bpfsnoop/internal/btfx"
)

func showFuncProto(w io.Writer, fn *btf.Func, clr *color.Color, listParams bool) {
	// func return
	retDesc := btfx.Repr(fn.Type.(*btf.FuncProto).Return)
	if retDesc[len(retDesc)-1] == '*' {
		clr.Fprintf(w, "%s", retDesc)
	} else {
		clr.Fprintf(w, "%s ", retDesc)
	}

	// func name
	clr.Fprint(w, fn.Name)

	// func params
	clr.Fprint(w, "(")
	params := fn.Type.(*btf.FuncProto).Params
	for i, p := range params {
		if i != 0 {
			clr.Fprint(w, ", ")
		}
		if listParams {
			clr.Fprintf(w, "\n%d:\t", i)
		}
		typeDesc := btfx.Repr(p.Type)
		if p.Name != "" {
			if typeDesc[len(typeDesc)-1] == '*' {
				clr.Fprintf(w, "%s%s", typeDesc, p.Name)
			} else {
				clr.Fprintf(w, "%s %s", typeDesc, p.Name)
			}
		} else {
			clr.Fprintf(w, "%s", btfx.Repr(p.Type))
		}
	}
	if listParams && len(params) > 0 {
		clr.Fprint(w, "\n")
	}
	clr.Fprint(w, ")")
}

func printFuncProto(w io.Writer, fn *btf.Func, color *color.Color, listParams bool) {
	showFuncProto(w, fn, color, listParams)
	color.Fprintln(w, ";")
}

func printKfuncProto(w io.Writer, fn *btf.Func, clr *color.Color, listParams, traceable bool, a2l *Addr2Line, bprogs *bpfProgs, ksyms *Kallsyms) {
	if a2l != nil {
		ksym, ok := ksyms.n2s[fn.Name]
		assert.True(ok, "Failed to find ksym for %s", fn.Name)

		li := getLineInfo(uintptr(ksym.addr), bprogs, a2l, ksyms)

		gray := color.RGB(0x88, 0x88, 0x88)
		gray.Fprintf(w, "; %s+%#x", li.funcName, li.offset)
		if li.fileName != "" {
			gray.Fprintf(w, " %s:%d", li.fileName, li.fileLine)
		}
		if li.isInline {
			gray.Fprint(w, " [inline]")
		}
		fmt.Fprintln(w)
	}

	showFuncProto(w, fn, clr, listParams)
	clr.Fprint(w, ";")
	if traceable {
		clr.Fprint(w, " [traceable]")
	}
	clr.Fprintln(w)
}

func ShowFuncProto(f *Flags) {
	yellow := color.New(color.FgYellow)
	var sb strings.Builder

	printNewline := false
	if len(f.progs) != 0 {
		pflags, err := f.ParseProgs()
		assert.NoErr(err, "Failed to parse bpf prog flags: %v")

		progs, err := NewBPFProgs(pflags, true, true)
		if len(progs.tracings) != 0 {
			fmt.Fprint(&sb, "BPF functions:")
			color.New(color.FgGreen).Fprintf(&sb, " (total %d)\n", len(progs.tracings))

			keys := maps.Keys(progs.tracings)
			sort.Strings(keys)

			for _, k := range keys {
				printFuncProto(&sb, progs.tracings[k].fn, yellow, f.listFuncParams)
			}

			printNewline = true
		}
	}

	if len(f.kfuncs) != 0 {
		kallsyms, err := NewKallsyms()
		assert.NoErr(err, "Failed to read /proc/kallsyms: %v")

		if printNewline {
			fmt.Fprintln(&sb)
		}

		var kmods []string
		if ksym, ok := kallsyms.findBySymbol(f.kfuncs[0]); ok && ksym.mod != "" {
			kmods = []string{ksym.mod}
		} else {
			kmods, err = inferenceKfuncKmods(f.kfuncs, kfuncKmods, kallsyms)
			assert.NoErr(err, "Failed to inference kernel module names for kernel functions: %v")
		}

		kmods = sortCompact(append([]string{"vmlinux"}, kmods...))
		kfuncs, err := findKernelFuncs(f.kfuncs, kmods, kallsyms, MAX_BPF_FUNC_ARGS, false, true)
		assert.NoErr(err, "Failed to find kernel functions: %v")

		fmt.Fprint(&sb, "Kernel functions:")
		color.New(color.FgGreen).Fprintf(&sb, " (total %d)\n", len(kfuncs))

		fns := make([]*btf.Func, 0, len(kfuncs))
		for _, kf := range kfuncs {
			fns = append(fns, kf.Func)
		}
		slices.SortFunc(fns, func(a, b *btf.Func) int {
			return strings.Compare(a.Name, b.Name)
		})

		var addr2line *Addr2Line
		var bprogs *bpfProgs
		if f.listFuncParams {
			vmlinux, err := FindVmlinux()
			if errors.Is(err, ErrNotFound) {
				VerboseLog("Dbgsym vmlinux not found")
			} else {
				assert.NoErr(err, "Failed to find vmlinux: %v")
			}

			if vmlinux != "" && f.funcProtoVmlinux {
				LogIf(true, "Found vmlinux: %s", vmlinux)

				textAddr, err := ReadTextAddrFromVmlinux(vmlinux)
				assert.NoErr(err, "Failed to read .text address from vmlinux: %v", err)

				kaslr := NewKaslr(kallsyms.Stext(), textAddr)
				addr2line, err = NewAddr2Line(vmlinux, kaslr, kallsyms.SysBPF(), kallsyms.Stext())
				assert.NoErr(err, "Failed to create addr2line: %v", err)

				bprogs, err = NewBPFProgs([]ProgFlag{{all: false}}, true, false)
				assert.NoErr(err, "Failed to prepare bpf progs: %v", err)
			}
		}

		for _, fn := range fns {
			traceable, err := detectKfuncTraceable(fn.Name, kallsyms, !hasModeEntry(), false)
			assert.NoErr(err, "Failed to detect traceable for %s: %v", fn.Name)
			printKfuncProto(&sb, fn, yellow, f.listFuncParams, traceable, addr2line, bprogs, kallsyms)
		}

		printNewline = true
	}

	if len(f.ktps) != 0 {
		kallsyms, err := NewKallsyms()
		assert.NoErr(err, "Failed to read /proc/kallsyms: %v")

		if printNewline {
			fmt.Fprintln(&sb)
		}

		ktps, err := probeKernelTracepoints(f.ktps, kallsyms, true)
		assert.NoErr(err, "Failed to find kernel tracepoints: %v")

		fmt.Fprint(&sb, "Kernel tracepoints:")
		color.New(color.FgGreen).Fprintf(&sb, " (total %d)\n", len(ktps))

		keys := maps.Keys(ktps)
		slices.Sort(keys)

		for _, k := range keys {
			printFuncProto(&sb, ktps[k].Func, yellow, f.listFuncParams)
		}
	}

	fmt.Print(sb.String())
}
