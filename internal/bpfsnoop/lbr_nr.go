// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"

	"github.com/bpfsnoop/bpfsnoop/internal/assert"
	"github.com/cilium/ebpf/btf"
)

var lbrNr uint32 = 32

// ReadLbrNr reads the LBR (Last Branch Record) depth from the kernel's x86_pmu
// global variable on AMD64 platforms and stores it in the package-level lbrNr
// variable. It requires kernelBtf to be initialized via PrepareKernelBTF before
// being called. On non-AMD64 platforms, this function returns nil without
// performing any operations.
func ReadLbrNr(ksyms *Kallsyms) error {
	if !onAmd64 {
		return nil
	}

	if ksyms.x86PMU == 0 {
		return fmt.Errorf("x86_pmu symbol not found in kallsyms")
	}

	pmuType, err := getKernelBTF().AnyTypeByName("x86_pmu")
	if err != nil {
		return fmt.Errorf("failed to get x86_pmu type from BTF: %w", err)
	}

	st, ok := pmuType.(*btf.Struct)
	if !ok {
		return fmt.Errorf("x86_pmu BTF should be a struct type")
	}

	var offset uint64
	found := false
	for _, member := range st.Members {
		if member.Name == "lbr_nr" {
			offset = uint64(member.Offset.Bytes())
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("lbr_nr field not found in x86_pmu struct")
	}

	data, err := readKernel(ksyms.x86PMU+offset, 4)
	if err != nil {
		return fmt.Errorf("failed to read x86_pmu.lbr_nr: %w", err)
	}

	lbrNr = ne.Uint32(data)
	assert.NotZero(lbrNr, "lbr_nr should not be zero")
	VerboseLog("LBR number is %d", lbrNr)

	return nil
}
