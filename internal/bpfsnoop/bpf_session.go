// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

const (
	bpfSessionCookieKfunc   = "bpf_session_cookie"
	bpfSessionIsReturnKfunc = "bpf_session_is_return"
)

var (
	bpfSessionCookieKfuncID   btf.TypeID
	bpfSessionIsReturnKfuncID btf.TypeID
)

func getKfuncID(spec *btf.Spec, name string) (btf.TypeID, error) {
	typ, err := spec.AnyTypeByName(name)
	if err != nil {
		return 0, fmt.Errorf("failed to find kfunc %s: %w", name, err)
	}

	fn, ok := typ.(*btf.Func)
	if !ok {
		return 0, fmt.Errorf("type %s is not a function", name)
	}

	return spec.TypeID(fn)
}

func initBPFSessionKfuncIDs() error {
	if bpfSessionCookieKfuncID != 0 && bpfSessionIsReturnKfuncID != 0 {
		return nil
	}

	spec := getKernelBTF()

	var err error
	bpfSessionCookieKfuncID, err = getKfuncID(spec, bpfSessionCookieKfunc)
	if err != nil {
		return fmt.Errorf("failed to get kfunc ID for %s: %w", bpfSessionCookieKfunc, err)
	}

	bpfSessionIsReturnKfuncID, err = getKfuncID(spec, bpfSessionIsReturnKfunc)
	if err != nil {
		return fmt.Errorf("failed to get kfunc ID for %s: %w", bpfSessionIsReturnKfunc, err)
	}

	return nil
}

func bpfKfuncCall(id btf.TypeID) asm.Instruction {
	return asm.Instruction{
		OpCode:   asm.Call.Op(asm.ImmSource),
		Src:      asm.PseudoKfuncCall,
		Constant: int64(id),
	}
}

func patchBPFSessionInsns(prog *ebpf.ProgramSpec) error {
	if !hasKprobeSession {
		return nil
	}

	if err := initBPFSessionKfuncIDs(); err != nil {
		return err
	}

	for i := range prog.Instructions {
		if ref := prog.Instructions[i].Reference(); ref == bpfSessionCookieKfunc {
			prog.Instructions[i] = bpfKfuncCall(bpfSessionCookieKfuncID)
		} else if ref == bpfSessionIsReturnKfunc {
			prog.Instructions[i] = bpfKfuncCall(bpfSessionIsReturnKfuncID)
		}
	}

	return nil
}

func PatchBPFSessionInsns(spec *ebpf.CollectionSpec) error {
	for name, prog := range spec.Programs {
		if err := patchBPFSessionInsns(prog); err != nil {
			return fmt.Errorf("failed to patch BPF session insns for program %s: %w", name, err)
		}
	}
	return nil
}
