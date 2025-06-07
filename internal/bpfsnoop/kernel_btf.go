// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"
	"os"
	"slices"

	"github.com/cilium/ebpf/btf"
)

const (
	kernelBTFPath = "/sys/kernel/btf"
)

func iterateKernelBtfs(kmods []string, iter func(*btf.Spec)) error {
	if kfuncAllKmods {
		files, err := os.ReadDir(kernelBTFPath)
		if err != nil {
			return fmt.Errorf("failed to read /sys/kernel/btf: %w", err)
		}

		for _, file := range files {
			kmodBtf, err := btf.LoadKernelModuleSpec(file.Name())
			if err != nil {
				return fmt.Errorf("failed to load kernel module BTF: %w", err)
			}

			iter(kmodBtf)
		}
	} else if len(kmods) != 0 {
		kmods = append(kmods, "vmlinux")
		slices.Sort(kmods)
		kmods = slices.Compact(kmods)

		for _, kmod := range kmods {
			kmodBtf, err := btf.LoadKernelModuleSpec(kmod)
			if err != nil {
				return fmt.Errorf("failed to load kernel module BTF: %w", err)
			}

			iter(kmodBtf)
		}
	} else {
		kernelBtf, err := btf.LoadKernelSpec()
		if err != nil {
			return fmt.Errorf("failed to load kernel BTF: %w", err)
		}

		iter(kernelBtf)
	}

	return nil
}
