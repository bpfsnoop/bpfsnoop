// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"context"
	"fmt"
)

var fgraphDenyList = []string{
	"*htab_map_lookup_elem",
	"bpf_ringbuf_reserve",
	"bpf_ringbuf_submit",
	"bpf_ktime_get_ns",
	"bpf_get_smp_processor_id",
	"bpf_probe_read_kernel",
	"bpf_probe_read_kernel_str",

	// before commit c86df29 ("bpf: Convert BPF_DISPATCHER to use static_call() (not ftrace)"),
	// the kernel would panic:
	/*
		[82392.214476] WARNING: CPU: 2 PID: 99624 at arch/x86/kernel/ftrace.c:96 ftrace_verify_code+0x38/0x70
		[82392.214510] Modules linked in: ip6table_filter ip6_tables nf_tables tcp_diag udp_diag inet_diag netdevsim xt_conntrack xt_MASQUERADE nf_conntrack_netlink nfnetlink xfrm_user iptable_nat nf_nat nf_conntrack nf_defrag_ipv6 nf_defrag_i
		pv4 xt_addrtype iptable_filter ip_tables br_netfilter bridge stp llc aufs xt_tcpudp bpfilter overlay bonding sch_fq_codel 9p fscache netfs knem(OE) toa uoa ixgbe xfrm_algo mdio dca ice(OE) msr
		 parport_pc ppdev lp parport rdma_ucm(OE) rdma_cm(OE) iw_cm(OE) ib_ipoib(OE) ib_cm(OE) ib_umad(OE) mlx5_ib(OE) ib_uverbs(OE) mlx5_core(OE) mlxdevm(OE) mlxfw(OE) psample tls pci_hyperv_intf ib_core(OE) mlx_compat(OE) nls_iso8859_1 dm_mu
		ltipath scsi_dh_rdac scsi_dh_emc scsi_dh_alua intel_rapl_msr intel_rapl_common isst_if_common nfit kvm_intel kvm snd_hda_codec_generic ledtrig_audio snd_hda_intel snd_intel_dspcfg snd_intel_sdw_acpi snd_hda_codec snd_hda_core snd_hwdep
		 snd_pcm snd_seq_midi snd_seq_midi_event snd_rawmidi snd_seq
		[82392.214580]  snd_seq_device joydev snd_timer input_leds 9pnet_virtio serio_raw 9pnet mac_hid snd qemu_fw_cfg soundcore binfmt_misc ramoops reed_solomon pstore_blk pstore_zone efi_pstore virtio_rng x_tables autofs4 btrfs blake2b_gene
		ric zstd_compress raid10 raid456 async_raid6_recov async_memcpy async_pq async_xor async_tx xor raid6_pq libcrc32c raid1 raid0 multipath linear qxl drm_ttm_helper ttm drm_kms_helper crct10dif_pclmul crc32_pclmul syscopyarea sysfillrect
		 ghash_clmulni_intel sysimgblt fb_sys_fops cec rc_core aesni_intel psmouse crypto_simd drm lpc_ich i2c_i801 cryptd i2c_smbus ahci libahci virtio_blk hid_generic usbhid hid [last unloaded: nf_defrag_ipv6]
		[82392.214628] CPU: 2 PID: 99624 Comm: bpfsnoop Kdump: loaded Tainted: G           OE     5.15.0-18-xxx-generic #18~20.04.4
		[82392.214631] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.13.0-1ubuntu1.1 04/01/2014
		[82392.214650] RIP: 0010:ftrace_verify_code+0x38/0x70
		[82392.214654] Code: 89 fe 48 8d 7d eb 48 83 ec 10 65 48 8b 04 25 28 00 00 00 48 89 45 f0 31 c0 e8 24 55 21 00 48 85 c0 75 31 8b 03 39 45 eb 74 1d <0f> 0b b8 ea ff ff ff 48 8b 4d f0 65 48 33 0c 25 28 00 00 00 75 1d
		[82392.214671] RSP: 0018:ffffb5a7c13a7a08 EFLAGS: 00010212
		[82392.214674] RAX: 0000000000441f0f RBX: ffffffffa340730a RCX: ffffb5a7c13a7a0f
		[82392.214676] RDX: 0000000065d1db1e RSI: 0000000000000005 RDI: ffffffffa2c93e20
		[82392.214678] RBP: ffffb5a7c13a7a20 R08: 0000000000000001 R09: 0000000000000000
		[82392.214679] R10: 0000000040000000 R11: 0000000000000001 R12: 0000000000000001
		[82392.214681] R13: ffff990c801224e0 R14: ffffffffa4898e10 R15: 0000000000000001
		[82392.214682] FS:  00007f047a7fc700(0000) GS:ffff990fefc80000(0000) knlGS:0000000000000000
		[82392.214685] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
		[82392.214687] CR2: 000000c01efc3000 CR3: 00000002c0352001 CR4: 0000000000770ee0
		[82392.214691] PKRU: 55555554
		[82392.214708] Call Trace:
		[82392.214726]  <TASK>
		[82392.214729]  ftrace_replace_code+0x9f/0x170
		[82392.214733]  ftrace_modify_all_code+0xcd/0x160
		[82392.214737]  arch_ftrace_update_code+0x9/0x10
		[82392.214755]  ftrace_run_update_code+0x1a/0x70
		[82392.214758]  ftrace_hash_move_and_update_ops+0x1c7/0x1f0
		[82392.214761]  ftrace_set_hash+0x121/0x1d0
		[82392.214765]  ? 0xffffffffc14f3000
		[82392.214771]  ? sk_lookup_convert_ctx_access+0x260/0x260
		[82392.214775]  ftrace_set_filter_ip+0x2f/0x70
		[82392.214778]  ? sk_lookup_convert_ctx_access+0x260/0x260
		[82392.214795]  register_ftrace_direct+0x154/0x380
		[82392.214799]  ? 0xffffffffc14f3000
		[82392.214801]  ? sk_lookup_convert_ctx_access+0x260/0x260
		[82392.214803]  bpf_trampoline_update+0x429/0x540
		[82392.214807]  ? 0xffffffffc14f3000
		[82392.214808]  bpf_trampoline_link_prog+0xc8/0x1b0
		[82392.214811]  ? bpf_link_prime+0x8f/0x100
		[82392.214814]  bpf_tracing_prog_attach+0x38f/0x4b0
		[82392.214817]  ? __fget_light+0x62/0x80
		[82392.214821]  ? fput+0x13/0x20
		[82392.214825]  bpf_raw_tracepoint_open+0x184/0x200
		[82392.214827]  ? __check_object_size+0x4d/0x150
		[82392.214830]  ? __sys_bpf+0x953/0x1e50
		[82392.214833]  ? security_capable+0x3d/0x60
		[82392.214837]  __sys_bpf+0x4f4/0x1e50
		[82392.214839]  ? exit_to_user_mode_prepare+0x3d/0x1c0
		[82392.214844]  __x64_sys_bpf+0x1c/0x20
		[82392.214847]  do_syscall_64+0x5c/0xc0
		[82392.214853]  ? do_syscall_64+0x69/0xc0
		[82392.214856]  ? syscall_exit_to_user_mode+0x27/0x50
		[82392.214860]  ? __x64_sys_mmap+0x33/0x40
		[82392.214863]  ? do_syscall_64+0x69/0xc0
		[82392.214866]  entry_SYSCALL_64_after_hwframe+0x44/0xae
		[82392.214871] RIP: 0033:0x40ac6e
		[82392.214874] Code: 24 28 44 8b 44 24 2c e9 70 ff ff ff cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc 49 89 f2 48 89 fa 48 89 ce 48 89 df 0f 05 <48> 3d 01 f0 ff ff 76 15 48 f7 d8 48 89 c1 48 c7 c0 ff ff ff ff 48
		[82392.214876] RSP: 002b:000000c01efc3ad8 EFLAGS: 00000202 ORIG_RAX: 0000000000000141
		[82392.214879] RAX: ffffffffffffffda RBX: 0000000000000011 RCX: 000000000040ac6e
		[82392.214880] RDX: 0000000000000018 RSI: 000000c01efc3cf0 RDI: 0000000000000011
		[82392.214881] RBP: 000000c01efc3b18 R08: 0000000000000000 R09: 0000000000000000
		[82392.214883] R10: 0000000000000000 R11: 0000000000000202 R12: 0000000000000000
		[82392.214884] R13: 0000000000000077 R14: 000000c01ac5ae00 R15: 000000c018592b10
		[82392.214887]  </TASK>
		[82392.214888] ---[ end trace 02b95c58d53a1422 ]---
		[82392.214894] ------------[ ftrace bug ]------------
		[82392.214895] ftrace failed to modify
		[82392.214910] [<ffffffffa2c93e20>] bpf_dispatcher_xdp_func+0x0/0x10
		[82392.214914]  actual:   ffffffe9:ffffffdb:ffffffd1:65:1e
		[82392.214919] Setting ftrace call site to call ftrace function
		[82392.214919] ftrace record flags: 55000001
		[82392.214920]  (1) R
		                expected tramp: ffffffffa2283b40
	*/
	"bpf_dispatcher_xdp_func",
}

type FuncGraph struct {
	Func     string
	IP       uint64
	MaxDepth uint
	Kfunc    *KFunc
	Bprog    *bpfProgFuncInfo
	ArgsEnSz int
	ArgsExSz int
	bytes    uint
	traced   bool
}

type FuncGraphs map[uint64]*FuncGraph // key is the func IP

func (fg FuncGraphs) Close() {
	for _, g := range fg {
		if g.Bprog != nil {
			_ = g.Bprog.prog.Close()
		}
	}
}

func FindGraphFuncs(ctx context.Context, flags *Flags, kfuncs KFuncs, bprogs *bpfProgs, ksyms *Kallsyms, maxArgs int) (FuncGraphs, error) {
	if !canDisasm() {
		return nil, fmt.Errorf("current architecture does not support fgraph")
	}

	var kfs []*KFunc
	for _, kf := range kfuncs {
		if kf.Flag.graph {
			kfs = append(kfs, kf)
		}
	}

	var bps []*bpfTracingInfo
	for _, bp := range bprogs.tracings {
		if bp.flag.graph {
			bps = append(bps, bp)
		}
	}

	if len(kfs) == 0 && len(bps) == 0 {
		return nil, nil
	}

	bprogs, err := NewBPFProgs([]ProgFlag{{all: true}}, false, true)
	if err != nil {
		return FuncGraphs{}, fmt.Errorf("failed to prepare bpf progs: %w", err)
	}
	defer bprogs.Close()

	includes, err := kfuncFlags2matches(flags.fgraphInclude)
	if err != nil {
		return FuncGraphs{}, fmt.Errorf("failed to parse include flags: %w", err)
	}

	excludes, err := kfuncFlags2matches(flags.fgraphExclude)
	if err != nil {
		return FuncGraphs{}, fmt.Errorf("failed to parse exclude flags: %w", err)
	}

	extraKfuncs, err := FindKernelFuncs(flags.fgraphExtra, ksyms, maxArgs)
	if err != nil {
		return FuncGraphs{}, fmt.Errorf("failed to find extra kfuncs: %w", err)
	}

	denyKfuncs, err := FindKernelFuncs(fgraphDenyList, ksyms, maxArgs)
	if err != nil {
		return FuncGraphs{}, fmt.Errorf("failed to find deny kfuncs: %w", err)
	}

	engine, err := createGapstoneEngine()
	if err != nil {
		return FuncGraphs{}, fmt.Errorf("failed to create gapstone engine: %w", err)
	}
	defer engine.Close()

	parser := newFuncGraphParser(ctx, ksyms, bprogs, engine, flags.fgraphDepth, maxArgs, includes, excludes)

	for _, deny := range denyKfuncs {
		addr := deny.Ksym.addr
		if err := parser.add(addr, 0); err != nil {
			return nil, fmt.Errorf("failed to add deny kfunc %s: %w", deny.Ksym.name, err)
		}
	}

	if err := parser.wait(); err != nil {
		return nil, fmt.Errorf("failed to wait for initial parsing: %w", err)
	}

	denylist := parser.graphs

	// renew the parser to avoid reusing the same errgroup
	parser = newFuncGraphParser(ctx, ksyms, bprogs, engine, flags.fgraphDepth, maxArgs, includes, excludes)

	for _, kf := range kfs {
		addr := kf.Ksym.addr
		bytes := guessBytes(uintptr(addr), ksyms, 0)
		parser.addParse(addr, bytes, 0, false, kf.Ksym.name)
	}

	for _, bp := range bps {
		addr := bp.funcIP
		bytes := bp.jitedLen
		parser.addParse(uint64(addr), uint(bytes), 0, true, bp.funcName+"[bpf]")
	}

	for _, kf := range extraKfuncs {
		addr := kf.Ksym.addr
		DebugLog("Adding extra fgraph func %s at %#x", kf.Ksym.name, addr)
		if err := parser.add(addr, 1); err != nil {
			return nil, fmt.Errorf("failed to add extra kfunc %s: %w", kf.Ksym.name, err)
		}
	}

	err = parser.wait()
	if err != nil {
		return nil, fmt.Errorf("failed to parse func graphs: %w", err)
	}

	for ip, graph := range parser.graphs {
		if g, ok := denylist[ip]; ok && !flags.fgraphDebug {
			if g.Bprog != nil {
				_ = g.Bprog.prog.Close() // close the bpf prog if it was denied
			}
			delete(parser.graphs, ip)
			continue
		}

		if graph.Kfunc == nil && graph.Bprog == nil {
			delete(parser.graphs, ip) // remove empty graphs
		}
	}
	return parser.graphs, nil
}

func FgraphExceedMaxDepth(flags *Flags, graphs FuncGraphs) bool {
	return len(graphs) > 0 && flags.fgraphDepth > 10 && !tailcallInfo.supportTailcallInBpf2bpf
}
