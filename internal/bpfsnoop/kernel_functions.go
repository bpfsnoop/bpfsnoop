// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"
	"slices"
	"strings"

	"github.com/Asphaltt/mybtf"
	"github.com/bpfsnoop/bpfsnoop/internal/slicex"
	"github.com/cilium/ebpf/btf"
)

const (
	MAX_BPF_FUNC_ARGS      = 12
	MAX_BPF_FUNC_ARGS_PREV = 6
)

// According to patch [bpf: Reject attaching fexit/fmod_ret to __noreturn functions](https://lore.kernel.org/bpf/20250318114447.75484-1-laoar.shao@gmail.com/),
// the following functions in noreturn_deny set cannot be traced by fexit.
var noreturnFuncs = []string{
	"__ia32_sys_exit",
	"__ia32_sys_exit_group",

	"__kunit_abort",
	"kunit_try_catch_throw",

	"__module_put_and_kthread_exit",

	"__x64_sys_exit",
	"__x64_sys_exit_group",

	"do_exit",
	"do_group_exit",
	"kthread_complete_and_exit",
	"kthread_exit",
	"make_task_dead",
}

// According to patch [bpf: Add deny list of btf ids check for tracing programs](https://lore.kernel.org/bpf/20210429114712.43783-1-jolsa@kernel.org/),
// the following functions in btf_id_deny set cannot be traced by fentry/fexit.
var tracingDenyFuncs = []string{
	"migrate_disable",
	"migrate_enable",

	"rcu_read_unlock_strict",

	"preempt_count_add",
	"preempt_count_sub",

	"__rcu_read_lock",
	"__rcu_read_unlock",

	// check func_graph.go::fgraphDenyList for more explanation.
	"bpf_dispatcher_xdp_func",
}

type ParamFlags struct {
	IsNumberPtr bool
	IsStr       bool
}

type FuncParamFlags struct {
	ParamFlags
	partOfPrevParam bool
}

type KFunc struct {
	Ksym *KsymEntry
	Func *btf.Func
	Btf  *btf.Spec
	Args []funcArgumentOutput
	Prms []FuncParamFlags
	Ret  FuncParamFlags
	Ent  int // fn args buffer size for fentry
	Exit int // fn args buffer size for fexit
	Data int // arg output data size
	Insn bool
	Flag progFlagImmInfo
	IsTp bool
	Pkt  bool
}

func (k *KFunc) Name() string {
	return k.Func.Name
}

func isValistParam(p btf.FuncParam) bool {
	_, isVoid := p.Type.(*btf.Void)
	return p.Name == "" && isVoid
}

func checkKfuncTraceable(fn *btf.Func, ksyms *Kallsyms, silent bool) (*KsymEntry, bool) {
	funcProto := fn.Type.(*btf.FuncProto)

	if isValist := len(funcProto.Params) != 0 && isValistParam(funcProto.Params[len(funcProto.Params)-1]); isValist {
		verboseLogIf(!silent, "Skip function %s with variable args", fn.Name)
		return nil, false
	}

	if _, isStruct := mybtf.UnderlyingType(funcProto.Return).(*btf.Struct); isStruct {
		verboseLogIf(!silent, "Skip function %s with struct return type", fn.Name)
		return nil, false
	}

	ksym, ok := ksyms.n2s[fn.Name]
	if !ok {
		verboseLogIf(!silent, "Failed to find ksym for %s", fn.Name)
		return nil, false
	}
	if ksym.duped {
		verboseLogIf(!silent, "Skip multiple-addrs ksym %s", fn.Name)
		return nil, false
	}

	return ksym, true
}

func matchKernelFunc(matches []*kfuncMatch, fn *btf.Func, maxArgs int, ksyms *Kallsyms, findManyArgs, silent bool) (*KFunc, bool) {
	if len(matches) == 0 {
		return nil, false
	}

	funcProto := fn.Type.(*btf.FuncProto)
	match, matched := matchKfunc(fn.Name, funcProto, matches)
	if !matched {
		return nil, false
	}

	ksym, traceable := checkKfuncTraceable(fn, ksyms, silent)
	if !traceable {
		return nil, false
	}

	params, ret, err := getFuncParams(fn)
	if err != nil {
		verboseLogIf(!silent, "Failed to get params for %s: %v", fn.Name, err)
		return nil, false
	}

	if findManyArgs {
		if MAX_BPF_FUNC_ARGS_PREV < len(funcProto.Params) && len(funcProto.Params) <= MAX_BPF_FUNC_ARGS {
			kf := KFunc{Ksym: ksym, Func: fn}
			kf.Prms = params
			kf.Insn = match.flag.insn
			kf.Flag = match.flag.progFlagImmInfo
			kf.Ret = ret
			return &kf, true
		}
		return nil, false
	}

	if len(funcProto.Params) <= maxArgs {
		kf := KFunc{Ksym: ksym, Func: fn}
		kf.Prms = params
		kf.Insn = match.flag.insn
		kf.Flag = match.flag.progFlagImmInfo
		kf.Ret = ret
		return &kf, true
	}

	verboseLogIf(!silent, "Skip function %s with %d args because of limit %d args\n",
		fn.Name, len(funcProto.Params), maxArgs)

	return nil, false
}

type KFuncs map[uintptr]*KFunc

func findKernelFuncs(funcs, kmods []string, ksyms *Kallsyms, maxArgs int, findManyArgs, silent bool) (KFuncs, error) {
	matchFuncs, err := kfuncFlags2matches(funcs)
	if err != nil {
		return KFuncs{}, err
	}

	kfuncs := make(KFuncs, len(matchFuncs))
	err = iterateKernelBtfs(kfuncAllKmods, kmods, func(spec *btf.Spec) bool {
		for val := range spec.All() {
			if fn, ok := val.(*btf.Func); ok {
				kf, ok := matchKernelFunc(matchFuncs, fn, maxArgs, ksyms, findManyArgs, silent)
				if ok {
					kf.Btf = spec
					kfuncs[uintptr(kf.Ksym.addr)] = kf
				}
			}
		}

		return false // continue iterating
	})
	if err != nil {
		return kfuncs, err
	}

	return kfuncs, nil
}

func searchKernelFuncs(funcs, kmods []string, ksyms *Kallsyms, maxArgs int) (KFuncs, error) {
	kfuncs, err := findKernelFuncs(funcs, kmods, ksyms, maxArgs, false, false)
	if err != nil {
		return nil, err
	}

	fexit := hasModeExit()
	for ptr, kf := range kfuncs {
		if (fexit || kf.Flag.both || kf.Insn || kf.Flag.graph) && slices.Contains(noreturnFuncs, kf.Name()) {
			VerboseLog("Skip fexit for noreturn function %s", kf.Name())
			delete(kfuncs, ptr)
		}
		if slices.Contains(tracingDenyFuncs, kf.Name()) {
			VerboseLog("Skip fentry/fexit for tracing deny function %s", kf.Name())
			delete(kfuncs, ptr)
		}
	}

	return kfuncs, nil
}

func inferenceKfuncKmods(kfuncs, kmods []string, ksyms *Kallsyms) ([]string, error) {
	kmods = slices.Clone(kmods)
	for _, fn := range kfuncs {
		var matchedKmod string
		for _, mod := range ksyms.mods {
			if strings.HasPrefix(fn, mod) {
				matchedKmod = mod
				break
			}
		}
		if matchedKmod != "" && !slices.Contains(kmods, matchedKmod) {
			kmods = append(kmods, matchedKmod)
		}
	}

	slices.Sort(kmods)
	return slices.Compact(kmods), nil
}

func prepareKmods(funcs []string, ksyms *Kallsyms) ([]string, error) {
	kmods, err := inferenceKfuncKmods(funcs, kfuncKmods, ksyms)
	if err != nil {
		return nil, fmt.Errorf("failed to inference kernel modules: %w", err)
	}

	for _, fn := range funcs {
		if ksym, ok := ksyms.findBySymbol(fn); ok && ksym.mod != "" &&
			!slices.Contains(kmods, ksym.mod) {
			// If the function is already a symbol, use its module directly.
			kmods = append(kmods, ksym.mod)
		}
	}

	return slicex.SortCompact(kmods), nil
}

func FindKernelFuncs(funcs []string, ksyms *Kallsyms, maxArgs int) (KFuncs, error) {
	if len(funcs) == 0 {
		return KFuncs{}, nil
	}

	kmods, err := prepareKmods(funcs, ksyms)
	if err != nil {
		return nil, err
	}

	return searchKernelFuncs(funcs, kmods, ksyms, maxArgs)
}
