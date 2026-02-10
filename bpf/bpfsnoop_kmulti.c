// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2026 Leon Hwang */
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_map_helpers.h"

#include "bpfsnoop.h"
#include "bpfsnoop_arg_filter.h"
#include "bpfsnoop_arg_output.h"
#include "bpfsnoop_cfg.h"
#include "bpfsnoop_event.h"
#include "bpfsnoop_event_output.h"
#include "bpfsnoop_fn_args_output.h"
#include "bpfsnoop_lbr.h"
#include "bpfsnoop_mode.h"
#include "bpfsnoop_pkt_filter.h"
#include "bpfsnoop_pkt_output.h"
#include "bpfsnoop_sess.h"
#include "bpfsnoop_stack.h"
#include "bpfsnoop_stack_map.h"
#include "bpfsnoop_tracing.h"

volatile const __u32 PID = -1;
volatile const __u32 CPU_MASK = 0xFFFF;
volatile const __u64 FUNC_IP = 0;

__u32 ready SEC(".data.ready") = 0;

static __always_inline __u32
read_args_from_ctx(struct pt_regs *ctx, __u64 *args)
{
#if defined(bpf_target_x86)
    args[0] = PT_REGS_PARM1(ctx);
    args[1] = PT_REGS_PARM2(ctx);
    args[2] = PT_REGS_PARM3(ctx);
    args[3] = PT_REGS_PARM4(ctx);
    args[4] = PT_REGS_PARM5(ctx);
    args[5] = PT_REGS_PARM6(ctx);
    return 6;
#elif defined(bpf_target_arm64)
    args[0] = PT_REGS_PARM1(ctx);
    args[1] = PT_REGS_PARM2(ctx);
    args[2] = PT_REGS_PARM3(ctx);
    args[3] = PT_REGS_PARM4(ctx);
    args[4] = PT_REGS_PARM5(ctx);
    args[5] = PT_REGS_PARM6(ctx);
    args[6] = PT_REGS_PARM7(ctx);
    args[7] = PT_REGS_PARM8(ctx);
    return 8;
#else
    /* Keep x86-like behavior as a conservative fallback. */
    args[0] = PT_REGS_PARM1(ctx);
    args[1] = PT_REGS_PARM2(ctx);
    args[2] = PT_REGS_PARM3(ctx);
    args[3] = PT_REGS_PARM4(ctx);
    args[4] = PT_REGS_PARM5(ctx);
    args[5] = PT_REGS_PARM6(ctx);
    return 6;
#endif
}

static __always_inline bool
filter_kmulti(__u64 *args, __u64 session_id)
{
    return filter_arg(args) && filter_pkt(args, session_id);
}

static __always_inline __u64
gen_session_id(struct pt_regs *ctx)
{
    __u64 fnip = bpf_get_func_ip(ctx);
    __u32 rnd = bpf_get_prandom_u32();

    /* Don't rely on attach_cookie for kprobe.multi: one program can be
     * attached to many symbols and cookie isn't guaranteed to identify each
     * target unless userspace explicitly populates per-symbol cookies.
     */
    return ((__u64) rnd) << 32 | (fnip & 0xFFFFFFFF);
}

static __always_inline __u64
get_kmulti_session_key(struct pt_regs *ctx)
{
    return bpf_get_func_ip(ctx);
}

static __always_inline int
emit_bpfsnoop_kmulti_event(struct pt_regs *ctx)
{
    bool output_pkt = cfg->flags.output_pkt;
    bool output_arg = cfg->flags.output_arg;
    __u64 args[MAX_FN_ARGS] = {}, key = 0;
    __u64 retval = 0, session_id = 0;
    struct bpfsnoop_lbr_data *lbr;
    enum bpfsnoop_mode mode;
    bool can_output_lbr;
    __u16 event_type;
    __u32 cpu, pid;

    if (!ready)
        return BPF_OK;

    cpu = bpf_get_smp_processor_id() & CPU_MASK;
    lbr = &bpfsnoop_lbr_buff[cpu];
    mode = get_bpfsnoop_mode(ctx);

    can_output_lbr = !cfg->flags.both_entry_exit || (mode == BPFSNOOP_MODE_SESSION_ENTRY);
    if (cfg->flags.output_lbr && can_output_lbr)
        lbr->nr_bytes = bpf_get_branch_snapshot(lbr->entries, sizeof(lbr->entries), 0);

    (void) read_args_from_ctx(ctx, args);
    if (mode == BPFSNOOP_MODE_EXIT || mode == BPFSNOOP_MODE_SESSION_EXIT)
        retval = PT_REGS_RC(ctx);

    pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == PID)
        return BPF_OK;
    if (cfg->pid && pid != cfg->pid)
        return BPF_OK;

    key = get_kmulti_session_key(ctx);

    switch (mode) {
    case BPFSNOOP_MODE_SESSION_ENTRY:
        session_id = gen_session_id(ctx);
        if (!bpfsnoop_session_enter(ctx, key, session_id,
                                    filter_kmulti(args, session_id),
                                    &session_id, cfg->flags.is_session))
            return BPF_OK;

        event_type = BPFSNOOP_EVENT_TYPE_FUNC_ENTRY;
        break;

    case BPFSNOOP_MODE_SESSION_EXIT:
        if (!bpfsnoop_session_exit(ctx, key, &session_id, cfg->flags.is_session))
            return BPF_OK;

        event_type = BPFSNOOP_EVENT_TYPE_FUNC_EXIT;
        output_pkt = false;
        output_arg = false;
        break;

    case BPFSNOOP_MODE_ENTRY:
    case BPFSNOOP_MODE_EXIT:
        session_id = gen_session_id(ctx);
        if (!filter_kmulti(args, session_id))
            return BPF_OK;

        event_type = (mode == BPFSNOOP_MODE_ENTRY) ? BPFSNOOP_EVENT_TYPE_FUNC_ENTRY
                                                   : BPFSNOOP_EVENT_TYPE_FUNC_EXIT;
        break;
    }

    return output_event(ctx, event_type, session_id, bpf_get_func_ip(ctx),
                        cpu, pid, lbr, can_output_lbr, args, retval, output_pkt,
                        output_arg);
}

SEC("kprobe.multi")
int BPF_KPROBE(bpfsnoop_kmulti)
{
    return emit_bpfsnoop_kmulti_event(ctx);
}

char __license[] SEC("license") = "GPL";
