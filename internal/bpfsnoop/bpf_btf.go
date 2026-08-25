// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"sync"

	"github.com/cilium/ebpf/btf"
)

var (
	kernelBtfLock sync.Mutex
	btfCache      *btf.Cache
)

func PrepareKernelBTF() error {
	kernelBtfLock.Lock()
	defer kernelBtfLock.Unlock()

	if btfCache != nil {
		return nil // already prepared
	}

	btfCache = btf.NewCache()
	_, err := btfCache.Kernel()
	return err
}

func getKernelBTF() *btf.Spec {
	spec, _ := btfCache.Kernel()
	return spec
}
