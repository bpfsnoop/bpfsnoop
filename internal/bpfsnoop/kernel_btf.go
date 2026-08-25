// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"
	"os"
	"path/filepath"
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

		if iter(getKernelBTF()) {
			return nil
		}

		for _, file := range fileNames {
			kmodBtf, err := btfCache.Module(file)
			if err != nil {
				return fmt.Errorf("failed to load kernel module BTF %s: %w", file, err)
			}

			if iter(kmodBtf) {
				break // stop iterating if the iterator returns true
			}
		}
	} else if len(kmods) != 0 {
		kmods = sortCompact(kmods)
		if idx := slices.Index(kmods, "vmlinux"); idx != -1 {
			kmods = slices.Delete(kmods, idx, 1)
		}

		if iter(getKernelBTF()) {
			return nil
		}

		for _, kmod := range kmods {
			if !fileExists(filepath.Join(kernelBTFPath, kmod)) {
				continue
			}

			kmodBtf, err := btfCache.Module(kmod)
			if err != nil {
				return fmt.Errorf("failed to load kernel module BTF %s: %w", kmod, err)
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
