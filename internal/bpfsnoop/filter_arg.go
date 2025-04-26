// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"

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

func prepareFuncArgument(expr string) funcArgument {
	var arg funcArgument
	arg.expr = expr
	return arg
}

func prepareFuncArguments(exprs []string) argumentFilter {
	var argFilter argumentFilter
	for _, expr := range exprs {
		argFilter.args = append(argFilter.args, prepareFuncArgument(expr))
	}

	return argFilter
}

func clearFilterArgSubprog(prog *ebpf.ProgramSpec) {
	clearFilterSubprog(prog, injectStubFilterArg)
}

func (arg *funcArgument) clear(prog *ebpf.ProgramSpec) {
	clearFilterSubprog(prog, injectStubFilterArg)
}

func (arg *funcArgument) inject(prog *ebpf.ProgramSpec, params []btf.FuncParam) error {
	if arg.expr == "" {
		return nil
	}

	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return fmt.Errorf("failed to load kernel spec: %w", err)
	}

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

	return ErrFinished
}

func (f *argumentFilter) inject(prog *ebpf.ProgramSpec, params []btf.FuncParam) (int, error) {
	if len(f.args) == 0 {
		return 0, errSkipped
	}

	for i, arg := range f.args {
		err := arg.inject(prog, params)
		switch err {
		case errSkipped:
			continue

		case ErrFinished:
			return i, nil

		default:
			return -1, err
		}
	}

	return 0, errSkipped
}
