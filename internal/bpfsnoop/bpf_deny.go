// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

// Since patch [bpf: Add deny list of btf ids check for tracing programs](https://lore.kernel.org/bpf/20210429114712.43783-1-jolsa@kernel.org/)

import (
	"encoding/binary"
	"fmt"
	"slices"

	"github.com/cilium/ebpf/btf"
)

type DenyFuncs struct {
	// Functions that cannot be traced by fentry/fexit.
	Funcs []string
}

func PrepareDenyFuncs(ksyms *Kallsyms) (DenyFuncs, error) {
	if ksyms.btfIDDeny == 0 {
		return DenyFuncs{}, nil // No deny functions defined in the kernel.
	}

	const readBytes = 256
	data, err := readKernel(ksyms.btfIDDeny, readBytes)
	if err != nil {
		return DenyFuncs{}, fmt.Errorf("failed to read deny functions BTF ids: %w", err)
	}

	// The content of the data is a 32-bit count followed by 32-bit BTF IDs.
	/*
		struct btf_id_set {
			u32 cnt;
			u32 ids[];
		};
	*/

	cnt := binary.NativeEndian.Uint32(data[:4])
	if cnt == 0 {
		return DenyFuncs{}, nil
	}

	krnl := getKernelBTF()

	var dfuncs DenyFuncs
	dfuncs.Funcs = make([]string, 0, cnt)

	for i := range cnt {
		offset := 4 + i*4
		id := binary.NativeEndian.Uint32(data[offset : offset+4])
		typ, err := krnl.TypeByID(btf.TypeID(id))
		if err != nil {
			return DenyFuncs{}, fmt.Errorf("failed to get BTF type by ID %d: %w", id, err)
		}

		fn, ok := typ.(*btf.Func)
		if !ok {
			return DenyFuncs{}, fmt.Errorf("BTF type ID %d is not a function", id)
		}

		dfuncs.Funcs = append(dfuncs.Funcs, fn.Name)
	}

	return dfuncs, nil
}

func (df *DenyFuncs) IsDenied(funcName string) bool {
	return slices.Contains(df.Funcs, funcName)
}
