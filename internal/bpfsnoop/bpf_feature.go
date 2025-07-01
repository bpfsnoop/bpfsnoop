// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
)

var hasEndbr bool

type BPFFeatures struct {
	Run               bool
	HasRingbuf        bool
	HasBranchSnapshot bool
	HasGetStackID     bool
}

func DetectBPFFeatures(spec *ebpf.CollectionSpec) error {
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

	if outputLbr {
		krnl, err := btf.LoadKernelSpec()
		if err != nil {
			return fmt.Errorf("failed to load kernel btf: %w", err)
		}

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

		if !feat.HasBranchSnapshot {
			return errors.New("bpf_get_branch_snapshot() helper not supported for --output-lbr")
		}
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
