// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type bpfLinkInfo struct {
	progID     ebpf.ProgramID
	attachType ebpf.AttachType
	attachProg ebpf.ProgramID
	isTracing  bool
}

type bpfLinks struct {
	links map[ebpf.ProgramID]bpfLinkInfo
}

func newBPFLinks() (*bpfLinks, error) {
	var links bpfLinks
	links.links = make(map[ebpf.ProgramID]bpfLinkInfo)

	var iter link.Iterator
	for iter.Next() {
		info, err := iter.Link.Info()
		if err != nil {
			return nil, fmt.Errorf("failed to get link info of link ID %d: %w", iter.ID, err)
		}

		tracing := info.Tracing()
		if tracing == nil {
			continue
		}

		links.links[info.Program] = bpfLinkInfo{
			progID:     info.Program,
			attachType: ebpf.AttachType(tracing.AttachType),
			attachProg: ebpf.ProgramID(tracing.TargetObjId),
			isTracing:  true,
		}
	}

	return &links, nil
}
