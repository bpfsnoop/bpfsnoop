// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

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

	filterSkbFunc      = "filter_skb"
	filterXdpBuffFunc  = "filter_xdp_buff"
	filterXdpFrameFunc = "filter_xdp_frame"
	filterPktFunc      = "filter_pkt"
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
	clearFilterSubprog(prog, filterXdpBuffFunc)
	clearFilterSubprog(prog, filterXdpFrameFunc)

	insns := append(genAccessArg(index, asm.R1),
		asm.Call.Label(filterSkbFunc),
		asm.Return(),
	)

	// update filter_pkt stub
	injectInsns(prog, filterPktFunc, insns)

	return nil
}

func (pf *packetFilter) injectFilterXdp(prog *ebpf.ProgramSpec, index int, t btf.Type, stub, otherStub string) error {
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
	clearFilterSubprog(prog, filterSkbFunc)
	clearFilterSubprog(prog, otherStub)
	clearFilterSubprog(prog, pcapFilterL3Stub)

	insns := append(genAccessArg(index, asm.R1),
		asm.Call.Label(stub),
		asm.Return(),
	)

	// update filter_pkt stub
	injectInsns(prog, filterPktFunc, insns)

	return nil
}

func (pf *packetFilter) filterXdp(prog *ebpf.ProgramSpec, index int, t btf.Type) error {
	return pf.injectFilterXdp(prog, index, t, filterXdpBuffFunc, filterXdpFrameFunc)
}

func (pf *packetFilter) filterXdpFrame(prog *ebpf.ProgramSpec, index int, t btf.Type) error {
	return pf.injectFilterXdp(prog, index, t, filterXdpFrameFunc, filterXdpBuffFunc)
}

func (pf *packetFilter) clearSpecializedStubs(prog *ebpf.ProgramSpec) {
	clearFilterSubprog(prog, pcapFilterL2StubSpecialized)
	clearFilterSubprog(prog, pcapFilterL3StubSpecialized)
}

func (pf *packetFilter) clear(prog *ebpf.ProgramSpec) {
	pf.clearSpecializedStubs(prog)
	clearFilterSubprog(prog, pcapFilterL2Stub)
	clearFilterSubprog(prog, pcapFilterL3Stub)
	clearFilterSubprog(prog, filterSkbFunc)
	clearFilterSubprog(prog, filterXdpBuffFunc)
	clearFilterSubprog(prog, filterXdpFrameFunc)
	clearFilterSubprog(prog, filterPktFunc)
}
