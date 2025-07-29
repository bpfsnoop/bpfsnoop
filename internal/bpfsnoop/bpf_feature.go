// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"

	"github.com/bpfsnoop/bpfsnoop/internal/bpf"
)

var (
	hasEndbr    bool
	requiredLbr bool
)

type BPFFeatures struct {
	Run               bool
	HasRingbuf        bool
	HasBranchSnapshot bool
	HasGetStackID     bool
}

func DetectBPFFeatures() error {
	spec, err := bpf.LoadFeat()
	if err != nil {
		return fmt.Errorf("failed to load feat bpf spec: %w", err)
	}

	spec.Programs["detect"].AttachTo = sysNanosleepSymbol
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		return fmt.Errorf("failed to create bpf collection: %w", err)
	}
	defer coll.Close()

	prog := coll.Programs["detect"]
	l, err := link.AttachTracing(link.TracingOptions{
		Program:    prog,
		AttachType: ebpf.AttachTraceFEntry,
	})
	if err != nil {
		return fmt.Errorf("failed to fentry nanosleep: %w", err)
	}
	defer l.Close()

	nanosleep()

	var feat BPFFeatures
	if err := coll.Maps[".bss"].Lookup(uint32(0), &feat); err != nil {
		return fmt.Errorf("failed to lookup .bss: %w", err)
	}

	if !feat.Run {
		return errors.New("detection not happened")
	}

	if !feat.HasRingbuf {
		return errors.New("ringbuf map not supported")
	}

	krnl := getKernelBTF()
	bpfFuncIDs, err := krnl.AnyTypeByName("bpf_func_id")
	if err != nil {
		return fmt.Errorf("failed to find bpf_func_id type: %w", err)
	}

	enum, ok := bpfFuncIDs.(*btf.Enum)
	if !ok {
		return fmt.Errorf("bpf_func_id is not an enum")
	}

	for _, val := range enum.Values {
		if val.Name == "BPF_FUNC_get_branch_snapshot" {
			feat.HasBranchSnapshot = true
			break
		}
	}

	if requiredLbr && !feat.HasBranchSnapshot {
		return errors.New("bpf_get_branch_snapshot() helper not supported for output LBR")
	}

	if outputFuncStack && !feat.HasGetStackID {
		return errors.New("bpf_get_stackid() helper not supported for --output-stack")
	}

	hasEndbr, err = haveEndbrInsn(prog)
	if err != nil {
		return fmt.Errorf("failed to check endbr insn: %w", err)
	}

	return nil
}
