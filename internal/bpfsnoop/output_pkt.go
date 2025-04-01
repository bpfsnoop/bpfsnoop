// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

const (
	outputPktTupleFunc = "output_pkt_data"
	outputSkbTupleFunc = "output_skb_tuple"
	outputXdpTupleFunc = "output_xdp_tuple"
)

var pktOutput packetOutput

type packetOutput struct{}

func (p *packetOutput) injectStub(prog *ebpf.ProgramSpec, index int, stub, other string) {
	clearOutputSubprog(prog, other)

	// R1: args
	// R2: pkt data
	// R3: session ID

	var insns asm.Instructions
	insns = append(insns, genAccessArg(index, asm.R1)...)
	insns = append(insns, asm.Instructions{
		asm.Call.Label(stub), // call stub()
		asm.Return(),
	}...)

	injectInsns(prog, outputPktTupleFunc, insns)
}

func (p *packetOutput) outputSkb(prog *ebpf.ProgramSpec, index int) {
	p.injectStub(prog, index, outputSkbTupleFunc, outputXdpTupleFunc)
}

func (p *packetOutput) outputXdp(prog *ebpf.ProgramSpec, index int) {
	p.injectStub(prog, index, outputXdpTupleFunc, outputSkbTupleFunc)
}

func (p *packetOutput) clear(prog *ebpf.ProgramSpec) {
	clearOutputSubprog(prog, outputPktTupleFunc)
	clearOutputSubprog(prog, outputSkbTupleFunc)
	clearOutputSubprog(prog, outputXdpTupleFunc)
}
