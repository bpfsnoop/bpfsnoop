// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/bpfsnoop/gapstone"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sync/errgroup"
)

const (
	insnCallqPrefix = 0xe8 // callq instruction prefix for x86_64
	insnJmpqPrefix  = 0xe9 // jmpq instruction prefix for x86_64

	insnCallqSize = 5 // size of the callq instruction in bytes for x86_64
)

var ne = binary.NativeEndian // use native endianness for kernel addresses

type FuncGraphParser struct {
	ksyms *Kallsyms
	progs *bpfProgs

	engine *gapstone.Engine // disassembler engine

	includes, excludes []*kfuncMatch // function name includes/excludes

	glock  sync.RWMutex // protects the map
	graphs map[uint64]*FuncGraph
	syms   map[string]struct{}
	callee map[uint64][]uint64 // callee IPs for each caller IP

	unlock       sync.RWMutex        // protects the untraceable map
	untraceables map[uint64]struct{} // IPs that are not traceable

	maxDepth uint // max depth of the function call graph
	maxArgs  int  // max number of arguments to trace kfunc

	errg *errgroup.Group
	ctx  context.Context
}

func newFuncGraphParser(ctx context.Context, ksyms *Kallsyms, progs *bpfProgs,
	engine *gapstone.Engine, maxDepth uint, maxArgs int,
	includes, excludes []*kfuncMatch,
) *FuncGraphParser {
	errg, ctx := errgroup.WithContext(ctx)
	return &FuncGraphParser{
		ksyms:        ksyms,
		progs:        progs,
		engine:       engine,
		includes:     includes,
		excludes:     excludes,
		graphs:       make(map[uint64]*FuncGraph, 64),
		syms:         make(map[string]struct{}, 64), // to avoid duplicate symbols
		callee:       make(map[uint64][]uint64, 64), // callee IPs for each caller IP
		untraceables: make(map[uint64]struct{}, 64), // IPs that are not traceable
		maxDepth:     maxDepth,
		maxArgs:      maxArgs,
		errg:         errg,
		ctx:          ctx,
	}
}

func (p *FuncGraphParser) wait() error {
	return p.errg.Wait()
}

func getCalleeIP(kaddr uint64, offset uint32) uint64 {
	// Calculate the callee IP based on the instruction address and offset.
	// The offset is added to the instruction address to get the callee IP.
	return kaddr + insnCallqSize + uint64(offset) | 0xFFFFFFFF00000000 // ensure it's a kernel address
}

func (p *FuncGraphParser) parse(ip uint64, bytes uint, depth uint, isBPF bool, tracee string) error {
	DebugLog("Parsing graph %s at %#x %d bytes %d depth bpf:%v", tracee, ip, bytes, depth, isBPF)

	p.glock.RLock()
	callees, ok := p.callee[ip]
	p.glock.RUnlock()
	if ok {
		for _, callee := range callees {
			if err := p.add(callee, depth+1); err != nil {
				return fmt.Errorf("failed to add callee %#x: %w", callee, err)
			}
		}
		return nil // already parsed, skip further processing
	}

	data, err := readKernel(ip, uint32(bytes))
	if err != nil {
		return fmt.Errorf("failed to read %d bytes kernel memory from %#x: %w", bytes, ip, err)
	}

	data = trimTailingInsns(data)

	insts, err := p.engine.Disasm(data, ip, 0)
	if err != nil {
		return fmt.Errorf("failed to disassemble %d bytes kernel memory from %#x: %w", bytes, ip, err)
	}

	if isBPF && insts[0].Bytes[0] == insnJmpqPrefix {
		// the prog has been replaced by a freplace prog, jump to the new prog
		newIP := getCalleeIP(uint64(insts[0].Address), ne.Uint32(insts[0].Bytes[1:5]))
		DebugLog("BPF prog %s at %#x replaced by freplace prog at %#x", tracee, ip, newIP)
		return p.add(newIP, depth)
	}

	for _, inst := range insts {
		if len(inst.Bytes) != 5 || inst.Bytes[0] != insnCallqPrefix {
			// TODO: long jump instructions (0xe9)
			continue // Only handle call instructions (5 bytes, 0xe8).
		}

		callee := getCalleeIP(uint64(inst.Address), ne.Uint32(inst.Bytes[1:5]))
		if err := p.add(callee, depth+1); err != nil {
			return fmt.Errorf("failed to add callee %#x: %w", callee, err)
		}

		callees = append(callees, callee) // collect callee IPs
	}

	p.glock.Lock()
	p.callee[ip] = callees // store callee IPs for this caller
	p.glock.Unlock()

	return nil
}

func (p *FuncGraphParser) isExcludedKfunc(funcName string) (bool, error) {
	var excluded bool

	err := iterateKernelBtfs(true, nil, func(spec *btf.Spec) bool {
		if excluded {
			return true // skip if already matched
		}

		typ, err := spec.AnyTypeByName(funcName)
		if err != nil {
			return false
		}

		fn, ok := typ.(*btf.Func)
		if !ok {
			return false // skip if not a function type
		}

		_, ok = matchKernelFunc(p.excludes, fn, p.maxArgs, p.ksyms, false, false)
		if ok {
			excluded = true
			return true // stop iterating after finding a match
		}

		return false
	})
	if err != nil {
		return false, fmt.Errorf("failed to iterate kernel BTFs for excludes: %w", err)
	}

	return excluded, nil
}

func (p *FuncGraphParser) checkIncludedKfunc(funcName string) (*KFunc, error) {
	var (
		kfunc   *KFunc
		errIter error
	)

	noIncludes := len(p.includes) == 0
	err := iterateKernelBtfs(true, nil, func(spec *btf.Spec) bool {
		if kfunc != nil || errIter != nil {
			return true // stop if already found or error occurred
		}

		typ, err := spec.AnyTypeByName(funcName)
		if err != nil {
			if errors.Is(err, btf.ErrNotFound) {
				return false // continue iterating if not found
			}
			VerboseLog("Failed to find type %s in BTF spec: %v\n", funcName, err)
			return false
		}

		fn, ok := typ.(*btf.Func)
		if !ok {
			VerboseLog("Type %s is not a function in BTF spec\n", funcName)
			return false // skip if not a function type
		}

		_, traceable := checkKfuncTraceable(fn, p.ksyms, false)
		if !traceable {
			DebugLog("Function %s is not traceable\n", funcName)
			return false // skip if not traceable
		}

		if noIncludes {
			params, ret, err := getFuncParams(fn)
			if err != nil {
				errIter = err
				return true // stop on error
			}

			if len(params) <= p.maxArgs {
				kfunc = &KFunc{
					Func: fn,
					Btf:  spec,
					Prms: params,
					Ret:  ret,
				}

				return true // stop iterating after finding the function
			}
		} else {
			kfunc, ok = matchKernelFunc(p.includes, fn, p.maxArgs, p.ksyms, false, false)
			if ok {
				kfunc.Btf = spec
				return true // stop iterating after finding the function
			}
		}

		return false // continue iterating
	})
	if err != nil {
		return nil, fmt.Errorf("failed to iterate kernel BTFs for includes: %w", err)
	}

	return kfunc, errIter
}

func (p *FuncGraphParser) isUntraceable(ip uint64) bool {
	p.unlock.RLock()
	defer p.unlock.RUnlock()
	_, ok := p.untraceables[ip]
	return ok
}

func (p *FuncGraphParser) markUntraceable(ip uint64) {
	p.unlock.Lock()
	defer p.unlock.Unlock()
	p.untraceables[ip] = struct{}{}
}

func (p *FuncGraphParser) add(ip uint64, depth uint) error {
	if depth > p.maxDepth {
		return nil
	}

	p.glock.Lock()
	g, ok := p.graphs[ip]
	if !ok {
		g = &FuncGraph{}
		p.graphs[ip] = g // mark as processed to avoid cyclic parsing
	}
	p.glock.Unlock()

	if ok {
		if g.bytes != 0 {
			p.addParse(ip, g.bytes, depth, g.Bprog != nil, g.Func)
		}
		return nil
	}

	if p.isUntraceable(ip) {
		return nil
	}

	g.MaxDepth = uint(p.maxDepth)
	g.IP = ip

	if prog, ok := p.progs.funcs[uintptr(ip)]; ok {
		if !p.progs.canTrace(prog.prog, prog.progID) {
			DebugLog("Skip bpf prog %s at %#x, not traceable\n", prog.funcName, ip)
			p.markUntraceable(ip) // mark as untraceable
			return nil            // skip if bpf prog is not traceable
		}

		g.bytes = uint(prog.kaddrRange.end - prog.kaddrRange.start)
		g.Func = prog.funcName + "[bpf]"
		g.Bprog = prog

		p, err := prog.prog.Clone()
		if err != nil {
			return fmt.Errorf("failed to clone bpf prog %s at %#x: %w", prog.funcName, ip, err)
		}
		g.Bprog.prog = p
	} else if ksym, ok := p.ksyms.a2s[ip]; ok {
		if ksym.duped {
			DebugLog("Skip duplicated ksym %s at %#x\n", ksym.name, ip)
			p.markUntraceable(ip) // mark as untraceable
			return nil            // skip if ksym is duplicated
		}
		if ksym.mod == kmodBpf {
			DebugLog("Skip bpf ksym %s at %#x\n", ksym.name, ip)
			p.markUntraceable(ip) // mark as untraceable
			return nil            // skip if ksym is used for bpf
		}

		if slices.Contains(tracingDenyFuncs, ksym.name) ||
			slices.Contains(noreturnFuncs, ksym.name) {
			DebugLog("Deny ksym %s at %#x\n", ksym.name, ip)
			p.markUntraceable(ip) // mark as untraceable
			return nil            // skip if ksym is in deny list
		}

		excluded, err := p.isExcludedKfunc(ksym.name)
		if err != nil {
			return fmt.Errorf("failed to check if function %s is excluded: %w", ksym.name, err)
		}
		if excluded {
			VerboseLog("Exclude function %s at %#x\n", ksym.name, ip)
			p.markUntraceable(ip) // mark as untraceable
			return nil            // skip if excluded
		}

		kfunc, err := p.checkIncludedKfunc(ksym.name)
		if err != nil {
			return fmt.Errorf("failed to check if function %s is included: %w", ksym.name, err)
		}
		if kfunc == nil {
			DebugLog("Not found/included function %s at %#x\n", ksym.name, ip)
			p.markUntraceable(ip) // mark as untraceable
			return nil            // skip if not included
		}

		p.glock.Lock()
		_, ok := p.syms[ksym.name]
		if !ok {
			p.syms[ksym.name] = struct{}{} // mark as processed
		}
		p.glock.Unlock()
		if ok {
			DebugLog("Skip duplicated ksym %s at %#x\n", ksym.name, ip)
			p.markUntraceable(ip) // mark as untraceable
			return nil            // skip if ksym is already processed
		}

		g.bytes = guessBytes(uintptr(ksym.addr), p.ksyms, 0)
		g.Func = ksym.name
		kfunc.Ksym = ksym
		g.Kfunc = kfunc

	} else {
		// If the IP is not the entry of kfunc or bpf prog, ignore it.
		p.markUntraceable(ip) // mark as untraceable
		return nil
	}

	select {
	case <-p.ctx.Done():
		return nil

	default:
	}

	p.addParse(ip, g.bytes, depth, g.Bprog != nil, g.Func)

	return nil
}

func (p *FuncGraphParser) addParse(ip uint64, bytes uint, depth uint, isBPF bool, tracee string) {
	p.errg.Go(func() error {
		return p.parse(ip, bytes, depth, isBPF, tracee)
	})
}
