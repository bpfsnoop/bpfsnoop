// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"slices"
	"sort"
	"strings"
	"syscall"

	"github.com/bpfsnoop/gapstone"
	"github.com/cilium/ebpf/btf"
	"github.com/fatih/color"
	"golang.org/x/exp/maps"

	"github.com/bpfsnoop/bpfsnoop/internal/assert"
	"github.com/bpfsnoop/bpfsnoop/internal/bpf"
)

type fgraphCallee struct {
	ip    uint64
	name  string
	proto string
	bytes uint
}

type fgraphProto struct {
	ksyms *Kallsyms
	progs *bpfProgs

	engine *gapstone.Engine // disassembler engine

	maxDepth uint

	traceable map[string]bool // traceable functions

	ips     map[uint64]string
	callees map[uint64][]fgraphCallee
}

func (p *fgraphProto) printDepth(depth uint) {
	color.RGB(58, 64, 94 /* lighter gray */).Fprint(os.Stdout, strings.Repeat("..", int(depth)))
}

func (p *fgraphProto) print(fn string, depth uint) {
	p.printDepth(depth)
	fmt.Print(fn)
}

func detectKfuncTraceable(fnName string, ksyms *Kallsyms, fexit, silent bool) (bool, error) {
	if fexit && slices.Contains(noreturnFuncs, fnName) {
		return false, nil // skip noreturn functions
	}
	if slices.Contains(tracingDenyFuncs, fnName) {
		return false, nil // skip tracing for deny functions
	}

	fn, err := findBtfOfKfunc(fnName)
	if err != nil {
		return false, fmt.Errorf("failed to find BTF function %q: %w", fn.Name, err)
	}
	if fn == nil {
		verboseLogIf(!silent, "BTF function %q not found", fnName)
		return false, nil
	}

	ksym, ok := checkKfuncTraceable(fn, ksyms, silent)
	if !ok {
		return false, nil
	}

	spec, err := bpf.LoadTraceable()
	if err != nil {
		return false, fmt.Errorf("failed to load traceable spec: %w", err)
	}

	nontraceables, err := detectTraceable(spec, []uintptr{uintptr(ksym.addr)})
	if err != nil {
		return false, fmt.Errorf("failed to detect traceable functions: %w", err)
	}

	return !slices.Contains(nontraceables, uintptr(ksym.addr)), nil
}

func (p *fgraphProto) checkTraceable(fnName string) bool {
	if traceable, ok := p.traceable[fnName]; ok {
		return traceable
	}

	traceable, _ := detectKfuncTraceable(fnName, p.ksyms, true, true)
	p.traceable[fnName] = traceable
	return traceable
}

func (p *fgraphProto) getFuncProto(fn *btf.Func) string {
	yellow := color.New(color.FgYellow)

	var sb strings.Builder
	showFuncProto(&sb, fn, yellow, false)
	yellow.Fprint(&sb, ";")

	if p.checkTraceable(fn.Name) {
		yellow.Fprint(&sb, " [traceable]")
	}

	fmt.Fprintln(&sb)
	return sb.String()
}

func findBtfOfKfunc(name string) (bfn *btf.Func, e error) {
	err := iterateKernelBtfs(true, nil, func(s *btf.Spec) bool {
		if bfn != nil || e != nil {
			return true
		}

		typ, err := s.AnyTypeByName(name)
		if errors.Is(err, btf.ErrNotFound) {
			return false
		}
		if err != nil {
			e = fmt.Errorf("failed to find type %q in btf spec: %w", name, err)
			return true // continue iterating
		}

		fn, ok := typ.(*btf.Func)
		if !ok {
			e = fmt.Errorf("type %q is not a function type", name)
			return true // continue iterating
		}

		bfn = fn
		return true // stop iterating
	})
	if err != nil {
		return nil, fmt.Errorf("failed to iterate kernel BTFs: %w", err)
	}

	return
}

func (p *fgraphProto) findBtfFunc(name string) *btf.Func {
	bfunc, _ := findBtfOfKfunc(name)
	return bfunc
}

func (p *fgraphProto) getCallee(ctx context.Context, ip uint64) (fgraphCallee, bool) {
	var callee fgraphCallee

	callee.ip = ip

	if prog, ok := p.progs.funcs[uintptr(ip)]; ok {
		if s, ok := p.ips[ip]; ok {
			callee.proto = s
		} else {
			s := p.getFuncProto(prog.funcProto)
			callee.proto = s
			p.ips[ip] = s
		}

		callee.name = prog.funcName
		callee.bytes = uint(prog.kaddrRange.end - prog.kaddrRange.start)
		return callee, true
	}

	if ksym, ok := p.ksyms.a2s[ip]; ok {
		callee.name = ksym.name
		callee.bytes = guessBytes(uintptr(ip), p.ksyms, 0)

		fn := p.findBtfFunc(ksym.name)
		if fn == nil {
			callee.proto = ksym.name + "\n"
			return callee, true
		}

		if s, ok := p.ips[ip]; ok {
			callee.proto = s
		} else {
			s := p.getFuncProto(fn)
			callee.proto = s
			p.ips[ip] = s
		}

		return callee, true
	}

	return callee, false
}

func (p *fgraphProto) parse(ctx context.Context, ip uint64, bytes, depth uint) {
	if depth > p.maxDepth {
		return
	}

	select {
	case <-ctx.Done():
		return
	default:
	}

	callees, ok := p.callees[ip]

	if !ok {
		insts, err := disasmKfuncAt(ip, bytes, p.ksyms, p.engine)
		assert.NoErr(err, "Failed to disassemble insns at %x: %v", ip, err)

		for _, inst := range insts {
			calleeIP, _ := getCalleeIPFromInsn(inst)
			if calleeIP == 0 {
				continue // skip if no callee IP found
			}

			callee, ok := p.getCallee(ctx, calleeIP)
			if ok {
				callees = append(callees, callee)
			}
		}

		p.callees[ip] = callees
	}

	for _, callee := range callees {
		p.print(callee.proto, depth)
		p.parse(ctx, callee.ip, callee.bytes, depth+1)
	}
}

func ShowFuncGraphProto(flags *Flags) {
	ksyms, err := NewKallsyms()
	assert.NoErr(err, "Failed to create kallsyms: %v")

	pflags, err := flags.ParseProgs()
	assert.NoErr(err, "Failed to parse bpf prog flags: %v")

	progs, err := NewBPFProgs(pflags, true, true)
	assert.NoErr(err, "Failed to find bpf progs: %v")
	bps := progs.tracings

	kfs, err := FindKernelFuncs(flags.kfuncs, ksyms, MAX_BPF_FUNC_ARGS)
	assert.NoErr(err, "Failed to find kfuncs: %v")
	if len(kfs) == 0 && len(flags.kfuncs) != 0 {
		for _, kf := range flags.kfuncs {
			kaddr, _ := parseDisasmKfunc(kf, kfuncKmods, ksyms, nil)
			ksym, ok := ksyms.findBySymbol(kf)
			assert.True(ok, "Failed to find ksym for %s", kf)

			kfs[uintptr(kaddr)] = &KFunc{
				Ksym: ksym,
			}
		}
	}

	if len(kfs) == 0 && len(bps) == 0 {
		log.Print("Not found any kfuncs/progs")
		return
	}

	bprogs, err := NewBPFProgs([]ProgFlag{{all: true}}, false, true)
	assert.NoErr(err, "Failed to prepare bpf progs: %v")
	defer bprogs.Close()

	engine, err := createGapstoneEngine()
	assert.NoErr(err, "Failed to create gapstone engine: %v")
	defer engine.Close()

	var fp fgraphProto
	fp.ksyms = ksyms
	fp.progs = bprogs
	fp.engine = engine
	fp.maxDepth = flags.fgraphDepth
	fp.traceable = make(map[string]bool, 64)
	fp.ips = make(map[uint64]string, 64)
	fp.callees = make(map[uint64][]fgraphCallee, 64)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer stop()

	printNewline := false
	if len(kfs) > 0 {
		kfuncs := maps.Values(kfs)
		sort.Slice(kfuncs, func(i, j int) bool {
			return kfuncs[i].Ksym.name < kfuncs[j].Ksym.name
		})

		for _, kf := range kfuncs {
			bfunc := fp.findBtfFunc(kf.Ksym.name)
			if bfunc != nil {
				fp.print(fp.getFuncProto(bfunc), 0)
			} else {
				fp.print(kf.Ksym.name+"\n", 0)
			}

			addr := kf.Ksym.addr
			bytes := guessBytes(uintptr(addr), ksyms, flags.disasmBytes)
			fp.parse(ctx, addr, bytes, 1)

			printNewline = true
			fmt.Println()
		}
	}

	if len(bps) > 0 {
		if printNewline {
			fmt.Println()
		}

		progs := maps.Values(bps)
		sort.Slice(progs, func(i, j int) bool {
			return progs[i].funcName < progs[j].funcName
		})

		for _, bp := range progs {
			fp.print(fp.getFuncProto(bp.fn), 0)

			addr := bp.funcIP
			bytes := bp.jitedLen
			fp.parse(ctx, uint64(addr), uint(bytes), 1)

			fmt.Println()
		}
	}
}
