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
	expr string
	vars []string
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

	return arg, nil
}

func prepareFuncArguments(exprs []string) argumentFilter {
	var argFilter argumentFilter
	for _, expr := range exprs {
		arg, err := prepareFuncArgument(expr)
		if err != nil {
			log.Fatalf("failed to prepare func argument with expr '%s': %v", expr, err)
		}

		argFilter.args = append(argFilter.args, arg)
	}

	return argFilter
}

func clearFilterArgSubprog(prog *ebpf.ProgramSpec) {
	clearFilterSubprog(prog, injectStubFilterArg)
}

func (arg *funcArgument) clear(prog *ebpf.ProgramSpec) {
	clearFilterSubprog(prog, injectStubFilterArg)
}

func (arg *funcArgument) matchParams(params []btf.FuncParam) bool {
	for _, param := range params {
		if slices.Contains(arg.vars, param.Name) {
			return true
		}
	}

	return false
}

func (arg *funcArgument) inject(prog *ebpf.ProgramSpec, spec *btf.Spec, params []btf.FuncParam) error {
	insns, err := cc.CompileFilterExpr(cc.CompileExprOptions{
		Expr:      arg.expr,
		Params:    params,
		Spec:      spec,
		LabelExit: "__label_cc_exit",
	})
	if err != nil {
		return fmt.Errorf("failed to compile expr '%s': %w", arg.expr, err)
	}

	injectInsns(prog, injectStubFilterArg, insns)

	return nil
}

func (f *argumentFilter) inject(prog *ebpf.ProgramSpec, params []btf.FuncParam) (int, error) {
	if len(f.args) == 0 {
		return 0, errSkipped
	}

	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return 0, fmt.Errorf("failed to load kernel spec: %w", err)
	}

	for i, arg := range f.args {
		if !arg.matchParams(params) {
			continue
		}

		err := arg.inject(prog, spec, params)
		if err != nil {
			return 0, err
		}
		return i, nil
	}

	return 0, errSkipped
}
