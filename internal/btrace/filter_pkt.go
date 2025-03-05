// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package btrace

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/jschwinger233/elibpcap"
)

const (
	pcapFilterL2Stub = "filter_pcap_l2"
	pcapFilterL3Stub = "filter_pcap_l3"

	pcapFilterL2StubSpecialized = "filter_pcap_l2.specialized.1"
	pcapFilterL3StubSpecialized = "filter_pcap_l3.specialized.1"

	filterSkbFunc = "filter_skb"
	filterXdpFunc = "filter_xdp"
	filterPktFunc = "filter_pkt"
)

var pktFilter packetFilter

type packetFilter struct {
	expr string
}

func preparePacketFilter(expr string) packetFilter {
	var pf packetFilter
	pf.expr = expr
	return pf
}

func (pf *packetFilter) genGetFuncArg(index int, dst asm.Register) asm.Instructions {
	return asm.Instructions{
		asm.Mov.Reg(asm.R3, asm.R10),
		asm.Add.Imm(asm.R3, -8),
		asm.Mov.Imm(asm.R2, int32(index)),
		asm.FnGetFuncArg.Call(),
		asm.LoadMem(dst, asm.R10, -8, asm.DWord),
	}
}

func (pf *packetFilter) filterSkb(prog *ebpf.ProgramSpec, index int, t btf.Type) error {
	if pf.expr == "" {
		return nil
	}

	var err error
	prog.Instructions, err = elibpcap.Inject(pf.expr, prog.Instructions, elibpcap.Options{
		AtBpf2Bpf:  pcapFilterL2Stub,
		DirectRead: false,
		L2Skb:      true,
	})
	if err != nil {
		return fmt.Errorf("failed to inject l2 pcap-filter: %w", err)
	}
	prog.Instructions, err = elibpcap.Inject(pf.expr, prog.Instructions, elibpcap.Options{
		AtBpf2Bpf:  pcapFilterL3Stub,
		DirectRead: false,
		L2Skb:      false,
	})
	if err != nil {
		VerboseLog("Failed to inject l3 pcap-filter: %v", err)
		prog.Instructions, _ = elibpcap.Inject("__reject_all__", prog.Instructions, elibpcap.Options{
			AtBpf2Bpf:  pcapFilterL3Stub,
			DirectRead: false,
			L2Skb:      false,
		})
	}

	pf.clearSpecializedStubs(prog)
	clearSubprog(prog, filterXdpFunc)

	insns := pf.genGetFuncArg(index, asm.R1) // R1 = skb
	insns = append(insns,
		asm.Call.Label(filterSkbFunc),
		asm.Return(),
	)

	// update filter_pkt stub
	injectInsns(prog, filterPktFunc, insns)

	return nil
}

func (pf *packetFilter) filterXdp(prog *ebpf.ProgramSpec, index int, t btf.Type) error {
	if pf.expr == "" {
		return nil
	}

	var err error
	prog.Instructions, err = elibpcap.Inject(pf.expr, prog.Instructions, elibpcap.Options{
		AtBpf2Bpf:  pcapFilterL2Stub,
		DirectRead: false,
		L2Skb:      true,
	})
	if err != nil {
		return fmt.Errorf("failed to inject l2 pcap-filter: %w", err)
	}

	pf.clearSpecializedStubs(prog)
	clearSubprog(prog, filterSkbFunc)
	clearSubprog(prog, pcapFilterL3Stub)

	insns := pf.genGetFuncArg(index, asm.R1) // R1 = xdp
	insns = append(insns,
		asm.Call.Label(filterXdpFunc),
		asm.Return(),
	)

	// update filter_pkt stub
	injectInsns(prog, filterPktFunc, insns)

	return nil
}

func (pf *packetFilter) clearSpecializedStubs(prog *ebpf.ProgramSpec) {
	clearSubprog(prog, pcapFilterL2StubSpecialized)
	clearSubprog(prog, pcapFilterL3StubSpecialized)
}

func (pf *packetFilter) clear(prog *ebpf.ProgramSpec) {
	pf.clearSpecializedStubs(prog)
	clearSubprog(prog, pcapFilterL2Stub)
	clearSubprog(prog, pcapFilterL3Stub)
	clearSubprog(prog, filterSkbFunc)
	clearSubprog(prog, filterXdpFunc)
	clearSubprog(prog, filterPktFunc)
}
