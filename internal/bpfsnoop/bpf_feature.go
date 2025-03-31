// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
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

	if !feat.HasBranchSnapshot && outputLbr {
		return errors.New("bpf_get_branch_snapshot() helper not supported")
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
