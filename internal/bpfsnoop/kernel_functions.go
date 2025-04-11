// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"slices"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf/btf"
)

const (
	MAX_BPF_FUNC_ARGS      = 12
	MAX_BPF_FUNC_ARGS_PREV = 6
)

// According to patch [bpf: Reject attaching fexit/fmod_ret to __noreturn functions](https://lore.kernel.org/bpf/20250318114447.75484-1-laoar.shao@gmail.com/),
// the following functions cannot be traced by fexit.
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
	Args []funcArgumentOutput
	Prms []FuncParamFlags
	Ret  FuncParamFlags
	Insn bool
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

func matchKernelFunc(matches []*kfuncMatch, fn *btf.Func, maxArgs int, ksyms *Kallsyms, findManyArgs, silent bool) (*KFunc, bool) {
	if len(matches) == 0 {
		return nil, false
	}

	funcProto := fn.Type.(*btf.FuncProto)
	insnMode, matched := matchKfunc(fn.Name, funcProto, matches)
	if !matched {
		return nil, false
	}

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

	params, ret, err := getFuncParams(fn)
	if err != nil {
		verboseLogIf(!silent, "Failed to get params for %s: %v", fn.Name, err)
		return nil, false
	}

	if findManyArgs {
		if MAX_BPF_FUNC_ARGS_PREV < len(funcProto.Params) && len(funcProto.Params) <= MAX_BPF_FUNC_ARGS {
			kf := KFunc{Ksym: ksym, Func: fn}
			kf.Prms = params
			kf.Insn = insnMode
			kf.Ret = ret
			return &kf, true
		}
		return nil, false
	}

	if len(funcProto.Params) <= maxArgs {
		kf := KFunc{Ksym: ksym, Func: fn}
		kf.Prms = params
		kf.Insn = insnMode
		kf.Ret = ret
		return &kf, true
	}

	verboseLogIf(!silent, "Skip function %s with %d args because of limit %d args\n",
		fn.Name, len(funcProto.Params), maxArgs)

	return nil, false
}

type KFuncs map[uintptr]*KFunc

func findKernelFuncs(funcs []string, ksyms *Kallsyms, maxArgs int, findManyArgs, silent bool) (KFuncs, error) {
	matchFuncs, err := kfuncFlags2matches(funcs)
	if err != nil {
		return KFuncs{}, err
	}

	kfuncs := make(KFuncs, len(funcs))
	err = iterateKernelBtfs(func(spec *btf.Spec) {
		iter := spec.Iterate()
		for iter.Next() {
			if fn, ok := iter.Type.(*btf.Func); ok {
				kf, ok := matchKernelFunc(matchFuncs, fn, maxArgs, ksyms, findManyArgs, silent)
				if ok {
					kfuncs[uintptr(kf.Ksym.addr)] = kf
				}
			}
		}
	})
	if err != nil {
		return kfuncs, err
	}

	return kfuncs, nil
}

func FindKernelFuncs(funcs []string, ksyms *Kallsyms, maxArgs int) (KFuncs, error) {
	if len(funcs) == 0 {
		return KFuncs{}, nil
	}

	kfuncs, err := findKernelFuncs(funcs, ksyms, maxArgs, false, false)
	if err != nil {
		return nil, err
	}

	if mode != TracingModeExit {
		return kfuncs, nil
	}

	for ptr, kf := range kfuncs {
		if slices.Contains(noreturnFuncs, kf.Name()) {
			delete(kfuncs, ptr)
		}
	}

	return kfuncs, nil
}
