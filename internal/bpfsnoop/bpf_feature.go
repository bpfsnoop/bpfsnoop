// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/bpfsnoop/bpfsnoop/internal/assert"
	"github.com/bpfsnoop/bpfsnoop/internal/atomix"
	"github.com/bpfsnoop/bpfsnoop/internal/bpf"
)

var (
	hasPerCPUData    bool
	hasArena         bool
	hasEndbr         bool
	requiredLbr      bool
	hasFsession      bool
	hasGetFuncArgCnt bool
	hasKprobeMulti   bool
	hasKprobeSession bool
	hasNestedTracing bool
	hasStrncmp       bool
	trampJmpMode     bool
)

type BPFFeatures struct {
	Run               bool
	HasRingbuf        bool
	HasBranchSnapshot bool
}

// KernelBPFFeatures combines the BPF-populated feature record with support
// detected from kernel BTF.
type KernelBPFFeatures struct {
	BPFFeatures
	HasKprobeMulti   bool
	HasNestedTracing bool
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
	hasNestedTracing = probeTracingTarget(prog, "detect")
	features.HasNestedTracing = hasNestedTracing
	debugLogIf(hasNestedTracing, "nested tracing is supported")
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
	feat.HasBranchSnapshot = feat.HasBranchSnapshot && onAmd64 && haveLbr()

	hasGetFuncArgCnt, err = btfEnumValue("bpf_func_id", "BPF_FUNC_get_func_arg_cnt")
	if err != nil {
		return features, err
	}
	debugLogIf(!hasGetFuncArgCnt, "bpf_get_func_arg_cnt() is not supported, detecting trampoline arg count in userspace")

	hasStrncmp, err = btfEnumValue("bpf_func_id", "BPF_FUNC_strncmp")
	if err != nil {
		return features, err
	}
	debugLogIf(!hasStrncmp, "bpf_strncmp() is not supported, comparing strings 8 bytes at a time")

	hasFsession, err = btfEnumValue("bpf_attach_type", "BPF_TRACE_FSESSION")
	if err != nil {
		return features, err
	}
	hasPerCPUData = probePerCPUData()
	debugLogIf(hasPerCPUData, "global percpu data is supported")
	hasArena, err = haveArena()
	if err != nil {
		return features, fmt.Errorf("failed to probe arena map: %w", err)
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
		return errors.New("LBR is not supported on the current system")
	}
	return nil
}

func printFeatures() {
	assert.NoErr(rlimit.RemoveMemlock(), "Failed to remove memlock limit: %v")
	assert.NoErr(PrepareKernelBTF(), "Failed to prepare kernel BTF: %v")
	features, err := GetBPFFeatures()
	assert.NoVerifierErr(err, "Failed to detect BPF features: %v")

	for _, feature := range []struct {
		name  string
		value bool
	}{
		{"Ringbuf map", features.HasRingbuf},
		{"Branch Record", features.HasBranchSnapshot},
		{"Get arg_cnt", hasGetFuncArgCnt},
		{"strncmp", hasStrncmp},
		{"fsession", hasFsession},
		{"kprobe.multi", features.HasKprobeMulti},
		{"kprobe.session", hasKprobeSession},
		{"Nested tracing", features.HasNestedTracing},
		{"ENDBR insn", hasEndbr},
		{"arena map", hasArena},
		{"per-CPU data", hasPerCPUData},
		{"tracing union arg", haveTracingUnionArg()},
	} {
		fmt.Printf("%s:\t%t\n", feature.name, feature.value)
	}
}

// haveLbr reports whether the PMU has LBR, which bpf_get_branch_snapshot()
// requires as well. VMs usually don't have it.
func haveLbr() bool {
	ksyms, err := cachedKallsyms()
	if err != nil {
		return false
	}

	nr, err := readLbrNr(ksyms)
	if err != nil {
		return false
	}

	DebugLog("LBR number is %d", nr)
	return nr != 0
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

// Loading is sufficient: bpf_check_attach_target checks the target's
// aux->attach_tracing_prog during verification, before link creation.
// See 19bfcdf9498a ("bpf: Relax tracing prog recursive attach rules")
// kernel 6.8.
func probeTracingTarget(target *ebpf.Program, name string) bool {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:         ebpf.Tracing,
		AttachType:   ebpf.AttachTraceFEntry,
		AttachTarget: target,
		AttachTo:     name,
		License:      "GPL",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})
	if err != nil {
		return false
	}
	_ = prog.Close()
	return true
}

// bpf_check gained a by-value bpfptr_t argument after older kernels used a
// pointer. Probe the actual prototype and trampoline instead of a version.
func haveTracingUnionArg() bool {
	var fn *btf.Func
	if err := getKernelBTF().TypeByName("bpf_check", &fn); err != nil {
		return false
	}

	proto, ok := fn.Type.(*btf.FuncProto)
	if !ok || len(proto.Params) < 3 {
		return false
	}

	if _, ok := btf.UnderlyingType(proto.Params[2].Type).(*btf.Struct); !ok {
		return false
	}

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:       ebpf.Tracing,
		AttachType: ebpf.AttachTraceFEntry,
		AttachTo:   "bpf_check",
		License:    "GPL",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})
	if err != nil {
		return false
	}
	defer prog.Close()

	l, err := link.AttachTracing(link.TracingOptions{Program: prog})
	if err != nil {
		return false
	}
	_ = l.Close()
	return true
}

// haveArena reports whether an arena map can be created. A kernel with
// BPF_MAP_TYPE_ARENA refuses to create one if its JIT doesn't support arenas.
func haveArena() (bool, error) {
	err := features.HaveMapType(ebpf.Arena)
	if errors.Is(err, ebpf.ErrNotSupported) {
		return false, nil
	}
	return err == nil, err
}

// global percpu data was introduced by the commit
// 6e61f4f8b043 ("bpf: Introduce global percpu data") kernel 7.3.
func probePerCPUData() bool {
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 8, MaxEntries: 1,
	})
	if err != nil {
		return false
	}
	defer m.Close()

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:    ebpf.SocketFilter,
		License: "GPL",
		Instructions: asm.Instructions{
			asm.LoadMapValue(asm.R1, m.FD(), 0),
			asm.LoadMem(asm.R0, asm.R1, 0, asm.DWord),
			asm.Return(),
		},
	})
	if err != nil {
		return false
	}
	_ = prog.Close()

	return true
}
