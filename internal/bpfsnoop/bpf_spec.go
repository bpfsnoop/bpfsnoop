// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import "github.com/cilium/ebpf"

// TrimSpec trims unused bpf subprogs from the spec if it's unnecessary to inject
// `--filter-arg` or `--filter-pkt` expressions.
func TrimSpec(spec *ebpf.CollectionSpec) {
	for _, prog := range spec.Programs {
		if pktFilter.expr == "" {
			pktFilter.clear(prog)
		}

		if len(argFilter.args) == 0 {
			clearFilterArgSubprog(prog)
		}

		if len(argOutput.args) == 0 {
			argOutput.clear(prog)
		}

		if !outputPkt {
			pktOutput.clear(prog)
		}
	}
}
