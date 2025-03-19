// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

const (
	outputPktTupleFunc = "output_pkt_tuple"
	outputSkbTupleFunc = "output_skb_tuple"
	outputXdpTupleFunc = "output_xdp_tuple"
)

var pktOutput packetOutput

type packetOutput struct{}

func (p *packetOutput) injectStub(prog *ebpf.ProgramSpec, index int, stub, other string, getFuncArg bool) {
	clearOutputSubprog(prog, other)

	// R1: ctx
	// R2: pkt data
	// R3: session ID

	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R2), // R6 = pkt data
		asm.Mov.Reg(asm.R7, asm.R3), // R7 = session ID
	}
	if getFuncArg {
		insns = append(insns, genGetFuncArg(index, asm.R3)...) // R3 = skb/xdp
	} else {
		insns = append(insns, genAccessArg(index, asm.R3)...)
	}
	insns = append(insns, asm.Instructions{
		asm.Mov.Reg(asm.R2, asm.R7), // R2 = session ID
		asm.Mov.Reg(asm.R1, asm.R6), // R1 = pkt data
		asm.Call.Label(stub),        // call stub()
		asm.Return(),
	}...)

	injectInsns(prog, outputPktTupleFunc, insns)
}

func (p *packetOutput) outputSkb(prog *ebpf.ProgramSpec, index int, getFuncArg bool) {
	p.injectStub(prog, index, outputSkbTupleFunc, outputXdpTupleFunc, getFuncArg)
}

func (p *packetOutput) outputXdp(prog *ebpf.ProgramSpec, index int, getFuncArg bool) {
	p.injectStub(prog, index, outputXdpTupleFunc, outputSkbTupleFunc, getFuncArg)
}

func (p *packetOutput) clear(prog *ebpf.ProgramSpec) {
	clearOutputSubprog(prog, outputPktTupleFunc)
	clearOutputSubprog(prog, outputSkbTupleFunc)
	clearOutputSubprog(prog, outputXdpTupleFunc)
}
