// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"fmt"

	"golang.org/x/sys/unix"

	"github.com/bpfsnoop/bpfsnoop/internal/atomix"
	"github.com/bpfsnoop/bpfsnoop/internal/bpfsnoop"
	"github.com/bpfsnoop/bpfsnoop/internal/strx"
)

// KernelCapabilities describes tracing functionality available to bpfsnoop.
type KernelCapabilities struct {
	BTF         bool `json:"btf" jsonschema:"kernel BTF is available"`
	Fentry      bool `json:"fentry" jsonschema:"fentry tracing is available"`
	Fexit       bool `json:"fexit" jsonschema:"fexit tracing is available"`
	KprobeMulti bool `json:"kprobe.multi" jsonschema:"kprobe.multi tracing is available"`
	Tracepoint  bool `json:"tracepoint" jsonschema:"kernel tracepoint tracing is available"`
	Funcgraph   bool `json:"funcgraph" jsonschema:"bpfsnoop function graph tracing is available"`
	BPFProgram  bool `json:"bpf_program" jsonschema:"loaded BPF program tracing is available"`
	LBR         bool `json:"lbr" jsonschema:"last branch record capture is available"`
}

// KernelDetails identifies the running kernel.
type KernelDetails struct {
	Release string `json:"release" jsonschema:"running kernel release"`
	Arch    string `json:"arch" jsonschema:"running kernel architecture"`
}

// KernelInfo contains the running kernel identity and tracing capabilities.
type KernelInfo struct {
	Kernel       KernelDetails      `json:"kernel"`
	Capabilities KernelCapabilities `json:"capabilities"`
}

func probeKernelInfo() (KernelInfo, error) {
	var info KernelInfo
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return info, fmt.Errorf("failed to get kernel identity: %w", err)
	}
	info.Kernel.Release = strx.NullTerminated(uts.Release[:])
	info.Kernel.Arch = strx.NullTerminated(uts.Machine[:])

	if err := bpfsnoop.PrepareKernelBTF(); err != nil {
		return info, fmt.Errorf("failed to prepare kernel BTF: %w", err)
	}
	info.Capabilities.BTF = true

	feat, err := bpfsnoop.GetBPFFeatures()
	if err != nil {
		return info, fmt.Errorf("failed to detect BPF features: %w", err)
	}

	tracing := feat.Run && feat.HasRingbuf
	info.Capabilities.Fentry = tracing
	info.Capabilities.Fexit = tracing
	info.Capabilities.Tracepoint = tracing
	info.Capabilities.Funcgraph = tracing
	info.Capabilities.BPFProgram = tracing
	info.Capabilities.KprobeMulti = feat.HasKprobeMulti
	if feat.HasBranchSnapshot {
		lbr, err := bpfsnoop.OpenLbrPerfEvent([]string{"any"})
		if err == nil {
			info.Capabilities.LBR = true
			lbr.Close()
		}
	}

	return info, nil
}

var kernelInfoOnce = atomix.NewOnce(probeKernelInfo)

// GetKernelInfo returns the process-cached kernel identity and bpfsnoop
// capabilities.
func GetKernelInfo() (KernelInfo, error) {
	return kernelInfoOnce.Do()
}
