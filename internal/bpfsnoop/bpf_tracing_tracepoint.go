// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"slices"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

const (
	handleTpEventStub = "handle_tp_event"
)

func (t *bpfTracing) injectTpBtfFn(prog *ebpf.ProgramSpec, fp *btf.FuncProto, tpName string) error {
	// The original insns are:
	//  ; int BPF_PROG(tp_btf_fn)
	//    0: MovImm dst: r2 imm: 0
	//  ; volatile __u64 args[MAX_FN_ARGS] = {};
	//    1: StXMemDW dst: rfp src: r2 off: -8 imm: 0
	//    2: StXMemDW dst: rfp src: r2 off: -16 imm: 0
	//    3: StXMemDW dst: rfp src: r2 off: -24 imm: 0
	//    4: StXMemDW dst: rfp src: r2 off: -32 imm: 0
	//    5: StXMemDW dst: rfp src: r2 off: -40 imm: 0
	//    6: StXMemDW dst: rfp src: r2 off: -48 imm: 0
	//    7: StXMemDW dst: rfp src: r2 off: -56 imm: 0
	//    8: StXMemDW dst: rfp src: r2 off: -64 imm: 0
	//    9: StXMemDW dst: rfp src: r2 off: -72 imm: 0
	//   10: StXMemDW dst: rfp src: r2 off: -80 imm: 0
	//   11: StXMemDW dst: rfp src: r2 off: -88 imm: 0
	//   12: StXMemDW dst: rfp src: r2 off: -96 imm: 0
	//   13: MovReg dst: r2 src: rfp
	//   14: AddImm dst: r2 imm: -96
	//  ; return handle_tp_event(ctx, args);
	//   15: Call -1 <handle_tp_event>
	//  ; int BPF_PROG(tp_btf_fn)
	//   16: MovImm dst: r0 imm: 0
	//   17: Exit

	var insns asm.Instructions
	insns = slices.Clone(prog.Instructions[:13])

	// Store args on stack

	// NOTE: Because "func 'xdp_redirect_err' arg2 type UNKNOWN is not a struct".
	// for i := 0; i < len(fp.Params); i++ {
	// 	argReg := asm.R0
	// 	insns = append(insns,
	// 		asm.LoadMem(argReg, asm.R1, int16(8*i), asm.DWord),
	// 		asm.StoreMem(asm.RFP, int16(-8*(MAX_BPF_FUNC_ARGS-i)), argReg, asm.DWord),
	// 	)
	// }

	// copy memory by `bpf_probe_read_kernel` helper.
	insns = append(insns,
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.Mov.Reg(asm.R3, asm.R1),
		asm.Mov.Imm(asm.R2, int32(8*len(fp.Params))),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -8*MAX_BPF_FUNC_ARGS),
		asm.FnProbeReadKernel.Call(),
		asm.Mov.Reg(asm.R1, asm.R6),
	)

	prog.Instructions = append(insns, prog.Instructions[13:]...)

	return nil
}
