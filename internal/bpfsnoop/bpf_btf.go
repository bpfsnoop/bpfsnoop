// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"sync"

	"github.com/cilium/ebpf/btf"
)

var (
	kernelBtfLock sync.Mutex
	kernelBtf     *btf.Spec
)

func PrepareKernelBTF() error {
	kernelBtfLock.Lock()
	defer kernelBtfLock.Unlock()

	if kernelBtf != nil {
		return nil // already prepared
	}

	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return err
	}

	kernelBtf = spec
	return nil
}

func getKernelBTF() *btf.Spec {
	return kernelBtf
}
