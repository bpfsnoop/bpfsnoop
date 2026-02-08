// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	flag "github.com/spf13/pflag"

	"github.com/bpfsnoop/bpfsnoop/internal/assert"
)

const (
	TracingModeEntry = "entry"
	TracingModeExit  = "exit"
)

var (
	verbose           bool
	debugLog          bool
	disasmIntelSyntax bool
	modes             []string
	filterArg         []string
	filterBr          []string
	filterPkt         string
	outputArg         []string
	skipTunnel        bool

	outputFlameGraph string

	outputLbr       bool
	outputFuncStack bool
	outputFuncInsns bool
	outputFuncGraph bool
	outputPkt       bool
	filterPid       uint32
	kfuncAllKmods   bool
	kfuncKmods      []string
	noColorOutput   bool
	colorfulOutput  bool
	limitEvents     uint

	runDurationThreshold time.Duration

	debugTraceInsnCnt uint

	kernelVmlinuxDir string

	forceProbeReadKernel bool
)

type Flags struct {
	progs  []string
	kfuncs []string
	ktps   []string

	fgraphInclude []string
	fgraphExclude []string
	fgraphExtra   []string
	fgraphDepth   uint
	fgraphProto   bool
	fgraphDebug   bool

	outputFile string

	disasm      bool
	disasmBytes uint

	showFuncProto  bool
	listFuncParams bool

	noVmlinux       bool
	requiredVmlinux bool

	outputHist bool
	histExpr   string

	outputTDigest bool
	tdigestExpr   string
}

func ParseFlags() (*Flags, error) {
	var findVmlinux bool
	var showTypes []string
	var readDatum []string
	var flags Flags

	f := flag.NewFlagSet("bpfsnoop", flag.ExitOnError)
	f.StringSliceVarP(&flags.progs, "prog", "p", nil, "bpf prog info for bpfsnoop in format PROG[,PROG,..], PROG: PROGID[:<prog function name>], PROGID: <prog ID> or 'i/id:<prog ID>' or 'p/pinned:<pinned file>' or 't/tag:<prog tag>' or 'n/name:<prog full name>' or 'pid:<pid>'; all bpf progs will be traced if '*' is specified")
	f.StringSliceVarP(&flags.kfuncs, "kfunc", "k", nil, "filter kernel functions, '(i)' prefix means insn tracing, '(m)' prefix means kprobe.multi tracing (requires typed arg), '<kfunc>[:<arg>][:<type>]' format")
	f.StringSliceVarP(&flags.ktps, "tracepoint", "t", nil, "filter kernel tracepoints")
	f.BoolVar(&kfuncAllKmods, "kfunc-all-kmods", false, "filter functions in all kernel modules")
	f.StringSliceVar(&kfuncKmods, "kfunc-kmods", nil, "filter functions in specified kernel modules")
	f.StringVarP(&flags.outputFile, "output", "o", "", "output file for the result, default is stdout")
	f.BoolVarP(&flags.disasm, "disasm", "d", false, "disasm bpf prog or kernel function")
	f.UintVarP(&flags.disasmBytes, "disasm-bytes", "B", 0, "disasm bytes of kernel function, 0 to guess it automatically")
	f.BoolVar(&disasmIntelSyntax, "disasm-intel-syntax", false, "use Intel asm syntax for disasm, ATT asm syntax by default")
	f.BoolVarP(&verbose, "verbose", "v", false, "output verbose log")
	f.BoolVarP(&debugLog, "debug-log", "D", false, "output many debug logs")
	f.StringSliceVarP(&modes, "mode", "m", []string{TracingModeExit}, "mode of bpfsnoop, exit and/or entry")
	f.BoolVar(&outputLbr, "output-lbr", false, "output LBR perf event")
	f.BoolVar(&outputFuncStack, "output-stack", false, "output function call stack")
	f.StringVar(&outputFlameGraph, "output-flamegraph", "", "output flamegraph fold data")
	f.BoolVar(&outputFuncInsns, "output-insns", false, "output function's insns exec path, same as '(i)' in -k, only works with -k")
	f.BoolVarP(&outputFuncGraph, "output-fgraph", "g", false, "output function call graph, works with -k,-p")
	f.UintVar(&flags.fgraphDepth, "fgraph-max-depth", 5, "maximum depth of function call graph, larger means slower to start bpfsnoop, 5 by default")
	f.StringSliceVar(&flags.fgraphInclude, "fgraph-include", nil, "limited functions in function call graph, empty means all functions, rules are same as -k, '(m)' is not supported here yet")
	f.StringSliceVar(&flags.fgraphExclude, "fgraph-exclude", nil, "exclude functions in function call graph, empty means no exclude, rules are same as -k, '(m)' is not supported here yet")
	f.StringSliceVar(&flags.fgraphExtra, "fgraph-extra", nil, "extra functions in function call graph as depth 1, rules are same as -k, '(m)' is not supported here yet")
	f.BoolVar(&flags.fgraphProto, "fgraph-proto", false, "output function prototype in function call graph, like --show-func-proto")
	f.BoolVar(&flags.fgraphDebug, "fgraph-debug", false, "debug deadlock caused by fgraph")
	f.BoolVar(&outputPkt, "output-pkt", false, "output packet's tuple info if tracee has skb/xdp argument")
	f.Uint32Var(&filterPid, "filter-pid", 0, "filter pid for tracing")
	f.StringSliceVar(&filterArg, "filter-arg", nil, "filter function's argument with C expression, e.g. 'prog->type == BPF_PROG_TYPE_TRACING'")
	f.StringArrayVar /* use StringArray to accept comma in value */ (&outputArg, "output-arg", nil, "output function's argument with C expression, e.g. 'prog->type'")
	f.StringVar(&filterPkt, "filter-pkt", "", "filter packet with pcap-filter(7) expr if function argument is skb or xdp, e.g. 'icmp and host 1.1.1.1'")
	f.StringSliceVar(&filterBr, "filter-br", []string{"any"}, "filter branch types: any, any_call, any_return, ind_call, abort_tx, in_tx, no_tx, cond, call_stack, ind_jump, call")
	f.UintVar(&limitEvents, "limit-events", 0, "limited number events to output, 0 to output all events")
	f.BoolVar(&flags.showFuncProto, "show-func-proto", false, "show function prototype of -p,-k,-t")
	f.StringSliceVarP(&showTypes, "show-type-proto", "C", nil, "show struct/union/enum prototype like `pahole -C`")
	f.UintVar(&debugTraceInsnCnt, "trace-insn-debug-cnt", 0, "trace insn count for debug")
	f.StringVar(&kernelVmlinuxDir, "kernel-vmlinux", "", "specific kernel vmlinux directory to search vmlinux and modules dbgsym files")
	f.BoolVar(&skipTunnel, "skip-tunnel", false, "skip tunnel (vxlan) header when parsing packet, applied for both --filter-pkt and --output-pkt")
	f.StringArrayVar(&readDatum, "read", nil, "read kernel memory using C expressions")

	f.BoolVarP(&flags.listFuncParams, "show-func-proto-internal", "S", false, "show function prototype of -p,-k,-t")
	f.UintVarP(&limitEvents, "limit-events-internal", "E", 0, "limited number events to output, 0 to output all events")
	f.BoolVarP(&flags.noVmlinux, "no-vmlinux", "N", false, "do not load vmlinux")
	f.DurationVar(&runDurationThreshold, "duration-threshold", 0, "threshold for run duration, e.g. 1s, 100ms, 0 to disable")
	f.BoolVarP(&forceProbeReadKernel, "force-probe-read-kernel", "P", false, "force reading kernel memory using bpf_probe_read_kernel() helper")
	f.BoolVar(&findVmlinux, "find-vmlinux", false, "find vmlinux file in standard locations and print the path")

	f.MarkHidden("debug-log")
	f.MarkHidden("output-flamegraph")
	f.MarkHidden("show-func-proto-internal")
	f.MarkHidden("limit-events-internal")
	f.MarkHidden("trace-insn-debug-cnt")
	f.MarkHidden("no-vmlinux")
	f.MarkHidden("duration-threshold")
	f.MarkHidden("fgraph-debug")
	f.MarkHidden("force-probe-read-kernel")
	f.MarkHidden("find-vmlinux")

	err := f.Parse(os.Args)

	outputFuncStack = outputFuncStack || outputFlameGraph != ""
	noColorOutput = flags.outputFile != "" || !isatty(os.Stdout.Fd())
	colorfulOutput = !noColorOutput
	argFilter = prepareFuncArguments(filterArg)
	argOutput = prepareFuncArgOutput(outputArg)
	pktFilter = preparePacketFilter(filterPkt)
	flags.showFuncProto = flags.showFuncProto || flags.listFuncParams

	if kernelVmlinuxDir != "" {
		if fileExists(kernelVmlinuxDir) {
			kernelVmlinuxDir = filepath.Dir(kernelVmlinuxDir)
		} else {
			kernelVmlinuxDir = filepath.Clean(kernelVmlinuxDir)
		}
	}

	if findVmlinux {
		vmlinuxPath, err := FindVmlinux()
		assert.NoErr(err, "Failed to find vmlinux file: %v")
		fmt.Println(vmlinuxPath)
		os.Exit(0)
	}

	if e := flags.checkMode(); e != nil {
		return nil, e
	}

	if flags.fgraphDepth == 0 {
		return nil, fmt.Errorf("--fgraph-max-depth must be greater than 0")
	}
	if flags.fgraphDepth > 500 {
		return nil, fmt.Errorf("--fgraph-max-depth is larger than limit 500")
	}

	for _, k := range flags.kfuncs {
		if strings.Contains(k, "(m)") && strings.Contains(k, "(g)") {
			return nil, fmt.Errorf("fgraph does not support '(m)' yet, got kfunc %q", k)
		}
	}
	for _, k := range flags.fgraphInclude {
		if strings.Contains(k, "(m)") {
			return nil, fmt.Errorf("--fgraph-include does not support '(m)' yet, got %q", k)
		}
	}
	for _, k := range flags.fgraphExclude {
		if strings.Contains(k, "(m)") {
			return nil, fmt.Errorf("--fgraph-exclude does not support '(m)' yet, got %q", k)
		}
	}
	for _, k := range flags.fgraphExtra {
		if strings.Contains(k, "(m)") {
			return nil, fmt.Errorf("--fgraph-extra does not support '(m)' yet, got %q", k)
		}
	}

	// check histogram
	for _, s := range outputArg {
		if !strings.HasPrefix(s, "hist(") {
			continue
		}
		if flags.outputHist {
			return nil, fmt.Errorf("only one histogram output is allowed")
		}

		flags.outputHist = true
		flags.histExpr = strings.TrimSuffix(strings.TrimPrefix(s, "hist("), ")")
	}

	// check t-digest
	for _, s := range outputArg {
		if !strings.HasPrefix(s, "tdigest(") {
			continue
		}
		if flags.outputTDigest {
			return nil, fmt.Errorf("only one t-digest output is allowed")
		}

		flags.outputTDigest = true
		flags.tdigestExpr = strings.TrimSuffix(strings.TrimPrefix(s, "tdigest("), ")")
	}

	requiredLbr = outputLbr
	for _, s := range flags.kfuncs {
		flags.requiredVmlinux = flags.requiredVmlinux || strings.Contains(s, "(s)")
		requiredLbr = requiredLbr || strings.Contains(s, "(l)")
	}
	for _, s := range flags.ktps {
		flags.requiredVmlinux = flags.requiredVmlinux || strings.Contains(s, "(s)")
	}
	for _, s := range flags.progs {
		flags.requiredVmlinux = flags.requiredVmlinux || strings.Contains(s, "(s)")
		requiredLbr = requiredLbr || strings.Contains(s, "(l)")
	}
	flags.requiredVmlinux = !flags.noVmlinux &&
		(flags.requiredVmlinux || outputFuncStack || outputLbr || requiredLbr)

	if len(showTypes) != 0 {
		showTypeProto(showTypes)
		os.Exit(0)
	}

	if len(readDatum) != 0 {
		readKernelDatum(readDatum, &flags)
		os.Exit(0)
	}

	return &flags, err
}

func (f *Flags) ParseProgs() ([]ProgFlag, error) {
	return parseProgsFlag(f.progs)
}

func (f *Flags) checkMode() error {
	switch len(modes) {
	case 1:
		if !slices.Contains([]string{TracingModeEntry, TracingModeExit}, modes[0]) {
			return fmt.Errorf("invalid mode %q, must be %q and/or %q", modes[0], TracingModeEntry, TracingModeExit)
		}

	case 2:
		for _, m := range modes {
			if !slices.Contains([]string{TracingModeEntry, TracingModeExit}, m) {
				return fmt.Errorf("invalid mode %q, must be %q and/or %q", m, TracingModeEntry, TracingModeExit)
			}
		}

	default:
		return fmt.Errorf("invalid number of modes %d, must be 1 or 2", len(modes))
	}

	return nil
}

func hasModeEntry() bool {
	return slices.Contains(modes, TracingModeEntry)
}

func hasModeExit() bool {
	return slices.Contains(modes, TracingModeExit)
}

func (f *Flags) Kfuncs() []string {
	var kfuncs []string
	for _, kf := range f.kfuncs {
		if !strings.Contains(kf, "(m)") {
			kfuncs = append(kfuncs, kf)
		}
	}
	return kfuncs
}

func (f *Flags) KfuncsMulti() []string {
	var kfuncs []string
	for _, kf := range f.kfuncs {
		if strings.Contains(kf, "(m)") {
			kfuncs = append(kfuncs, kf)
		}
	}
	return kfuncs
}

func (f *Flags) Ktps() []string {
	return f.ktps
}

func (f *Flags) OutputFile() string {
	return f.outputFile
}

func (f *Flags) DumpProg() bool {
	return f.disasm
}

func (f *Flags) Disasm() bool {
	return f.disasm
}

func (f *Flags) OutputLbr() bool {
	return requiredLbr
}

func (f *Flags) BranchTypes() []string {
	return filterBr
}

func (f *Flags) ShowFuncProto() bool {
	return f.showFuncProto
}

func (f *Flags) ShowFgraphProto() bool {
	return f.fgraphProto
}

func (f *Flags) Vmlinux() bool {
	return f.requiredVmlinux
}

func (f *Flags) FgraphMaxDepth() uint {
	return f.fgraphDepth
}
