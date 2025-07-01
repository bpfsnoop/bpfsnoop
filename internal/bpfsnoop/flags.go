// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"

	flag "github.com/spf13/pflag"
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
	filterPkt         string
	outputArg         []string

	outputFlameGraph string

	outputLbr       bool
	outputFuncStack bool
	outputFuncInsns bool
	outputPkt       bool
	filterPid       uint32
	kfuncAllKmods   bool
	kfuncKmods      []string
	noColorOutput   bool
	colorfulOutput  bool
	limitEvents     uint

	debugTraceInsnCnt uint

	kernelVmlinuxDir string
)

type Flags struct {
	progs  []string
	kfuncs []string
	ktps   []string

	outputFile string

	disasm      bool
	disasmBytes uint

	showFuncProto  bool
	listFuncParams bool

	noVmlinux bool
}

func ParseFlags() (*Flags, error) {
	var flags Flags

	f := flag.NewFlagSet("bpfsnoop", flag.ExitOnError)
	f.StringSliceVarP(&flags.progs, "prog", "p", nil, "bpf prog info for bpfsnoop in format PROG[,PROG,..], PROG: PROGID[:<prog function name>], PROGID: <prog ID> or 'i/id:<prog ID>' or 'p/pinned:<pinned file>' or 't/tag:<prog tag>' or 'n/name:<prog full name>' or 'pid:<pid>'; all bpf progs will be traced if '*' is specified")
	f.StringSliceVarP(&flags.kfuncs, "kfunc", "k", nil, "filter kernel functions, '(i)' prefix means insn tracing, '<kfunc>[:<arg>][:<type>]' format, e.g. 'tcp_v4_connect:sk:struct sock *', '*:(struct sk_buff *)skb'")
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
	f.BoolVar(&outputPkt, "output-pkt", false, "output packet's tuple info if tracee has skb/xdp argument")
	f.Uint32Var(&filterPid, "filter-pid", 0, "filter pid for tracing")
	f.StringSliceVar(&filterArg, "filter-arg", nil, "filter function's argument with C expression, e.g. 'prog->type == BPF_PROG_TYPE_TRACING'")
	f.StringArrayVar /* use StringArray to accept comma in value */ (&outputArg, "output-arg", nil, "output function's argument with C expression, e.g. 'prog->type'")
	f.StringVar(&filterPkt, "filter-pkt", "", "filter packet with pcap-filter(7) expr if function argument is skb or xdp, e.g. 'icmp and host 1.1.1.1'")
	f.UintVar(&limitEvents, "limit-events", 0, "limited number events to output, 0 to output all events")
	f.BoolVar(&flags.showFuncProto, "show-func-proto", false, "show function prototype of -p,-k,-t")
	f.UintVar(&debugTraceInsnCnt, "trace-insn-debug-cnt", 0, "trace insn count for debug")
	f.StringVar(&kernelVmlinuxDir, "kernel-vmlinux", "", "specific kernel vmlinux directory to search vmlinux and modules dbgsym files")

	f.BoolVarP(&flags.listFuncParams, "show-func-proto-internal", "S", false, "show function prototype of -p,-k,-t")
	f.UintVarP(&limitEvents, "limit-events-internal", "E", 0, "limited number events to output, 0 to output all events")
	f.BoolVarP(&flags.noVmlinux, "no-vmlinux", "N", false, "do not load vmlinux")

	f.MarkHidden("debug-log")
	f.MarkHidden("output-flamegraph")
	f.MarkHidden("show-func-proto-internal")
	f.MarkHidden("limit-events-internal")
	f.MarkHidden("trace-insn-debug-cnt")
	f.MarkHidden("no-vmlinux")

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

	if e := flags.checkMode(); e != nil {
		return nil, e
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
	return f.kfuncs
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
	return outputLbr
}

func (f *Flags) OutputFuncStack() bool {
	return outputFuncStack
}

func (f *Flags) ShowFuncProto() bool {
	return f.showFuncProto
}

func (f *Flags) Vmlinux() bool {
	return !f.noVmlinux
}
