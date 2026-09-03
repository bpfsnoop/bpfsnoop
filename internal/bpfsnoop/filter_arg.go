// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"
	"log"
	"slices"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"

	"github.com/bpfsnoop/bpfsnoop/internal/cc"
	"github.com/bpfsnoop/bpfsnoop/internal/strx"
)

const (
	injectStubFilterArg = "filter_arg"
)

var argFilter argumentFilter

type argumentFilter struct {
	args []funcArgument
}

type funcArgument struct {
	expr   string
	vars   []string
	retval bool
}

func getTypeDescFrom(s string) (string, error) {
	if s == "" || s[0] != '(' {
		return "", nil
	}

	for i := 1; i < len(s); i++ {
		if s[i] == ')' {
			return s[1:i], nil
		}
	}

	return "", fmt.Errorf("failed to get type description from %s", s)
}

func isValidChar(c byte) bool {
	return strx.IsChar(c) || c == '_' || strx.IsDigit(c)
}

func prepareFuncArgument(expr string) (funcArgument, error) {
	var arg funcArgument
	arg.expr = expr

	var err error
	arg.vars, err = cc.ExtractVarNames(expr)
	if err != nil {
		return arg, fmt.Errorf("failed to extract var names from %s: %w", expr, err)
	}
	if len(arg.vars) == 0 {
		return arg, fmt.Errorf("'%s' has no var names", expr)
	}
	arg.retval = slices.Contains(arg.vars, cc.RetvalName)

	return arg, nil
}

func prepareFuncArguments(exprs []string) argumentFilter {
	filter, err := prepareFuncArgumentsE(exprs)
	if err != nil {
		log.Fatalf("failed to prepare func arguments: %v", err)
	}
	return filter
}

func prepareFuncArgumentsE(exprs []string) (argumentFilter, error) {
	var argFilter argumentFilter
	for _, expr := range exprs {
		arg, err := prepareFuncArgument(expr)
		if err != nil {
			return argumentFilter{}, fmt.Errorf("failed to prepare func argument with expr '%s': %w", expr, err)
		}

		argFilter.args = append(argFilter.args, arg)
	}

	return argFilter, nil
}

func clearFilterArgSubprog(prog *ebpf.ProgramSpec) {
	clearFilterSubprog(prog, injectStubFilterArg)
}

func (arg *funcArgument) clear(prog *ebpf.ProgramSpec) {
	clearFilterSubprog(prog, injectStubFilterArg)
}

func (arg *funcArgument) matchParams(params []btf.FuncParam) bool {
	for _, name := range arg.vars {
		if name == cc.RetvalName {
			continue
		}

		if !slices.ContainsFunc(params, func(p btf.FuncParam) bool {
			return p.Name == name
		}) {
			return false
		}
	}

	return true
}

func (arg *funcArgument) inject(prog *ebpf.ProgramSpec, krnl, spec *btf.Spec, params []btf.FuncParam, ret btf.Type) error {
	mode := cc.MemoryReadModeProbeRead
	if _, err := krnl.AnyTypeByName("bpf_rdonly_cast"); err == nil {
		mode = cc.MemoryReadModeCoreRead
	}
	if forceProbeReadKernel {
		mode = cc.MemoryReadModeProbeRead
	}

	insns, err := cc.CompileFilterExpr(cc.CompileExprOptions{
		Expr:       arg.expr,
		Params:     params,
		RetvalType: ret,
		Spec:       spec,
		Kernel:     krnl,
		LabelExit:  "__label_cc_exit",

		MemoryReadMode: mode,
	})
	if err != nil {
		return fmt.Errorf("failed to compile expr '%s': %w", arg.expr, err)
	}

	injectInsns(prog, injectStubFilterArg, insns)

	return nil
}

func (f *argumentFilter) selectMatch(params []btf.FuncParam, ret btf.Type, spec *btf.Spec) (*funcArgument, error) {
	krnl := getKernelBTF()
	for i := range f.args {
		arg := &f.args[i]
		if arg.retval {
			matched, err := cc.MatchRetvalType(arg.expr, ret, spec, krnl)
			if err != nil {
				return nil, err
			}
			if !matched {
				continue
			}
		}

		// A return expression may also refer to regular parameters. It is a
		// match only when the return type and every non-return variable match.
		if arg.matchParams(params) {
			return arg, nil
		}
	}

	return nil, nil
}
