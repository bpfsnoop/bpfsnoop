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

func iterateKernelBtfs(allKmods bool, kmods []string, iter func(*btf.Spec) bool) error {
	if allKmods {
		files, err := os.ReadDir(kernelBTFPath)
		if err != nil {
			return fmt.Errorf("failed to read /sys/kernel/btf: %w", err)
		}

		fileNames := make([]string, 0, len(files))
		for _, file := range files {
			if file.IsDir() || file.Name() == "vmlinux" {
				continue // skip directories and vmlinux
			}
			fileNames = append(fileNames, file.Name())
		}

		slices.Sort(fileNames)
		fileNames = append([]string{"vmlinux"}, fileNames...) // search vmlinux first

		for _, file := range fileNames {
			kmodBtf, err := btf.LoadKernelModuleSpec(file)
			if err != nil {
				return fmt.Errorf("failed to load kernel module BTF: %w", err)
			}

			if iter(kmodBtf) {
				break // stop iterating if the iterator returns true
			}
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

			if iter(kmodBtf) {
				break // stop iterating if the iterator returns true
			}
		}
	} else {
		kernelBtf := getKernelBTF()
		iter(kernelBtf)
	}

	return nil
}
