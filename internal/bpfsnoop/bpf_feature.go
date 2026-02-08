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
	hasEndbr         bool
	requiredLbr      bool
	hasFsession      bool
	hasKprobeMulti   bool
	hasKprobeSession bool
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

	feat.HasBranchSnapshot, err = btfEnumValue("bpf_func_id", "BPF_FUNC_get_branch_snapshot")
	if err != nil {
		return err
	}

	if requiredLbr && !feat.HasBranchSnapshot {
		return errors.New("bpf_get_branch_snapshot() helper not supported for output LBR")
	}

	if outputFuncStack && !feat.HasGetStackID {
		return errors.New("bpf_get_stackid() helper not supported for --output-stack")
	}

	hasFsession, err = btfEnumValue("bpf_attach_type", "BPF_TRACE_FSESSION")
	if err != nil {
		return err
	}
	hasKprobeMulti, err = btfEnumValue("bpf_attach_type", "BPF_TRACE_KPROBE_MULTI")
	if err != nil {
		return err
	}
	hasKprobeSession, err = btfEnumValue("bpf_attach_type", "BPF_TRACE_KPROBE_SESSION")
	if err != nil {
		return err
	}

	hasEndbr, err = haveEndbrInsn(prog)
	if err != nil {
		return fmt.Errorf("failed to check endbr insn: %w", err)
	}

	return nil
}

func btfEnumValue(enum, value string) (bool, error) {
	krnl := getKernelBTF()
	bpfFuncIDs, err := krnl.AnyTypeByName(enum)
	if err != nil {
		return false, fmt.Errorf("failed to find %s type: %w", enum, err)
	}

	e, ok := bpfFuncIDs.(*btf.Enum)
	if !ok {
		return false, fmt.Errorf("%s is not an enum", enum)
	}

	for _, val := range e.Values {
		if val.Name == value {
			return true, nil
		}
	}

	return false, nil
}
