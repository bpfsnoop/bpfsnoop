// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"
	"log"
	"strings"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/leonhwangprojects/bice"

	"github.com/bpfsnoop/bpfsnoop/internal/btfx"
	"github.com/bpfsnoop/bpfsnoop/internal/strx"
)

const (
	injectStubFilterArg = "filter_arg"
)

var argFilter []funcArgument

type funcArgument struct {
	typ  string
	expr string
	name string
	acce bool
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

	typ, err := getTypeDescFrom(expr)
	if err != nil {
		log.Fatalf("Failed to get type description for function argument: %v", err)
	}

	arg.typ = strings.TrimSpace(typ)
	arg.expr = strings.TrimSpace(expr)
	if arg.typ != "" {
		arg.expr = strings.TrimSpace(expr[len(arg.typ)+2:])
	}
	arg.acce = strings.Contains(arg.expr, ".") || strings.Contains(arg.expr, "->")

	expr = arg.expr
	for i := 0; i < len(expr); i++ {
		if !isValidChar(expr[i]) {
			arg.name = expr[:i]
			break
		}
	}

	return arg
}

func prepareFuncArguments(exprs []string) []funcArgument {
	for _, expr := range exprs {
		argFilter = append(argFilter, prepareFuncArgument(expr))
	}

	return argFilter
}

func matchFuncArgs(p btf.FuncParam) (*funcArgument, bool) {
	for i, arg := range argFilter {
		if arg.expr == "" {
			continue
		}
		if arg.name != p.Name {
			continue
		}
		if arg.typ != "" && arg.typ != btfx.Repr(p.Type) {
			continue
		}

		return &argFilter[i], true
	}

	return nil, false
}

func clearFilterArgSubprog(prog *ebpf.ProgramSpec) {
	clearFilterSubprog(prog, injectStubFilterArg)
}

func (arg *funcArgument) clear(prog *ebpf.ProgramSpec) {
	clearFilterSubprog(prog, injectStubFilterArg)
}

func (arg *funcArgument) inject(prog *ebpf.ProgramSpec, idx int, t btf.Type) error {
	if arg.expr == "" {
		return nil
	}

	_, isPtr := mybtf.UnderlyingType(t).(*btf.Pointer)
	if arg.acce && !isPtr {
		return fmt.Errorf("type of arg is expected as a pointer instead of %s", btfx.Repr(t))
	}

	insns, err := bice.SimpleCompile(arg.expr, t)
	if err != nil {
		return fmt.Errorf("failed to compile expression %s: %w", arg.expr, err)
	}

	insns = append(genAccessArg(idx, asm.R1), insns...)

	injectInsns(prog, injectStubFilterArg, insns)

	return nil
}
