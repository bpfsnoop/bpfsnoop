// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package btrace

import (
	"fmt"
	"log"
	"strings"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/leonhwangprojects/bice"

	"github.com/leonhwangprojects/btrace/internal/btfx"
	"github.com/leonhwangprojects/btrace/internal/strx"
)

const (
	injectStubFilterArg = "filter_fnarg"
)

var fnArg funcArgument

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

	for i := 0; i < len(expr); i++ {
		if !strx.IsChar(expr[i]) {
			arg.name = expr[:i]
			break
		}
	}

	return arg
}

func (arg *funcArgument) compile(idx int, t btf.Type) (asm.Instructions, error) {
	insns, err := bice.SimpleCompile(arg.expr, t)
	if err != nil {
		return nil, fmt.Errorf("failed to compile expression %s: %v", arg.expr, err)
	}

	return append(asm.Instructions{
		asm.Mov.Reg(asm.R3, asm.R10),
		asm.Add.Imm(asm.R3, -8),
		asm.Mov.Imm(asm.R2, int32(idx)),
		// r1 is ctx already
		asm.FnGetFuncArg.Call(),
		asm.LoadMem(asm.R1, asm.R10, -8, asm.DWord),
	}, insns...), nil
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

	insns, err := arg.compile(idx, t)
	if err != nil {
		return err
	}

	injectInsns(prog, injectStubFilterArg, insns)

	return nil
}
