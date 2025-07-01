// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
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
	if listParams {
		clr.Fprint(w, "\n")
	}
	clr.Fprint(w, ")")
}

func printFuncProto(w io.Writer, fn *btf.Func, color *color.Color, listParams bool) {
	showFuncProto(w, fn, color, listParams)
	color.Fprint(w, ";\n")
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

		kfuncs, err := findKernelFuncs(f.kfuncs, kmods, kallsyms, MAX_BPF_FUNC_ARGS, false, true)
		assert.NoErr(err, "Failed to find kernel functions: %v")

		fmt.Fprint(&sb, "Kernel functions:")
		color.New(color.FgGreen).Fprintf(&sb, " (total %d)\n", len(kfuncs))

		keys := maps.Keys(kfuncs)
		slices.Sort(keys)

		for _, k := range keys {
			printFuncProto(&sb, kfuncs[k].Func, yellow, f.listFuncParams)
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
