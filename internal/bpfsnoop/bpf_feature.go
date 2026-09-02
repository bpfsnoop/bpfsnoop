// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"

	"github.com/bpfsnoop/bpfsnoop/internal/atomix"
	"github.com/bpfsnoop/bpfsnoop/internal/bpf"
)

var (
	hasEndbr         bool
	requiredLbr      bool
	hasFsession      bool
	hasKprobeMulti   bool
	hasKprobeSession bool
	trampJmpMode     bool
)

type BPFFeatures struct {
	Run               bool
	HasRingbuf        bool
	HasBranchSnapshot bool
	HasGetStackID     bool
}

// KernelBPFFeatures combines the BPF-populated feature record with support
// detected from kernel BTF.
type KernelBPFFeatures struct {
	BPFFeatures
	HasKprobeMulti bool
}

func detectBPFFeatures() (KernelBPFFeatures, error) {
	var features KernelBPFFeatures
	feat := &features.BPFFeatures

	spec, err := bpf.LoadFeat()
	if err != nil {
		return features, fmt.Errorf("failed to load feat bpf spec: %w", err)
	}

	spec.Programs["detect"].AttachTo = bpfFentryTest1
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		return features, fmt.Errorf("failed to create bpf collection: %w", err)
	}
	defer coll.Close()

	prog := coll.Programs["detect"]
	l, err := link.AttachTracing(link.TracingOptions{
		Program:    prog,
		AttachType: ebpf.AttachTraceFEntry,
	})
	if err != nil {
		return features, fmt.Errorf("failed to fentry %s: %w", bpfFentryTest1, err)
	}
	defer l.Close()

	_, err = prog.Run(nil)
	if err != nil {
		return features, fmt.Errorf("failed to run detect program: %w", err)
	}

	if err := coll.Maps[".bss"].Lookup(uint32(0), feat); err != nil {
		return features, fmt.Errorf("failed to lookup .bss: %w", err)
	}

	if !feat.Run {
		return features, errors.New("detection not happened")
	}

	if !feat.HasRingbuf {
		return features, errors.New("ringbuf map not supported")
	}

	feat.HasBranchSnapshot, err = btfEnumValue("bpf_func_id", "BPF_FUNC_get_branch_snapshot")
	if err != nil {
		return features, err
	}

	hasFsession, err = btfEnumValue("bpf_attach_type", "BPF_TRACE_FSESSION")
	if err != nil {
		return features, err
	}
	hasKprobeMulti, err = btfEnumValue("bpf_attach_type", "BPF_TRACE_KPROBE_MULTI")
	if err != nil {
		return features, err
	}
	features.HasKprobeMulti = hasKprobeMulti
	debugLogIf(hasKprobeMulti, "kprobe.multi is supported")
	hasKprobeSession, err = btfEnumValue("bpf_attach_type", "BPF_TRACE_KPROBE_SESSION")
	if err != nil {
		return features, err
	}
	debugLogIf(hasKprobeSession, "kprobe.session is supported")

	hasEndbr, err = haveEndbrInsn(prog)
	if err != nil {
		return features, fmt.Errorf("failed to check endbr insn: %w", err)
	}

	return features, nil
}

var bpfFeaturesOnce = atomix.NewOnce(detectBPFFeatures)

// GetBPFFeatures returns process-cached facts about BPF support in the running
// kernel. These facts do not change during the process lifetime.
func GetBPFFeatures() (KernelBPFFeatures, error) {
	return bpfFeaturesOnce.Do()
}

func DetectBPFFeatures() error {
	feat, err := GetBPFFeatures()
	if err != nil {
		return err
	}
	if requiredLbr && !feat.HasBranchSnapshot {
		return errors.New("bpf_get_branch_snapshot() helper not supported for output LBR")
	}
	if outputFuncStack && !feat.HasGetStackID {
		return errors.New("bpf_get_stackid() helper not supported for --output-stack")
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

func haveTrampolineJmpMode(insns []byte) {
	if !onAmd64 || len(insns) < 9 {
		return
	}

	u32 := ne.Uint32(insns[:4])
	if isEndbrInsn(u32) {
		insns = insns[4:]
	}

	trampJmpMode = insns[0] == 0xE9 /* jmp rel32 */
	DebugLog("Trampoline jmp mode: %v", trampJmpMode)
}
