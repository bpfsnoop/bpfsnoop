// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2024 Leon Hwang */
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
#include "bpfsnoop_session.h"
#include "bpfsnoop_stack.h"
#include "bpfsnoop_stack_map.h"
#include "bpfsnoop_tracing.h"

volatile const __u32 PID = -1;
volatile const __u32 CPU_MASK = 0xFFFF;
volatile const __u64 FUNC_IP = 0;

__u32 ready SEC(".data.ready") = 0;

static __always_inline bool
filter(__u64 *args, __u64 session_id)
{
    return filter_arg(args) && filter_pkt(args, session_id);
}

static __always_inline __u64
get_tracee_caller_fp(void *ctx, __u32 args_nr, bool retval)
{
    u64 fp, fp_caller;

    fp = get_tramp_fp(ctx, args_nr, retval); /* read tramp fp */
    (void) bpf_probe_read_kernel(&fp_caller, sizeof(fp_caller), (void *) fp); /* fp of tracee caller */
    return fp_caller;
}

static __always_inline __u64
gen_session_id(__u64 fp)
{
    __u32 rnd = bpf_get_prandom_u32();

    return ((__u64) rnd) << 32 | (fp & 0xFFFFFFFF);
}

static __always_inline int
emit_bpfsnoop_event(void *ctx)
{
    struct bpfsnoop_lbr_data *lbr;
    __u64 fp, session_id = 0;
    enum bpfsnoop_mode mode;
    __u64 args[MAX_FN_ARGS];
    bool can_output_lbr;
    __u64 retval = 0;
    __u16 event_type;
    __u32 cpu, pid;

    if (!ready)
        return BPF_OK;

    cpu = bpf_get_smp_processor_id() & CPU_MASK;
    lbr = &bpfsnoop_lbr_buff[cpu];

    mode = get_bpfsnoop_mode(ctx);

    can_output_lbr = !cfg->flags.both_entry_exit || (mode == BPFSNOOP_MODE_SESSION_ENTRY);
    if (cfg->flags.output_lbr && can_output_lbr)
        lbr->nr_bytes = bpf_get_branch_snapshot(lbr->entries, sizeof(lbr->entries), 0); /* required 5.16 kernel. */

    /* Other filters must be after bpf_get_branch_snapshot() to avoid polluting
     * LBR entries.
     */
    (void) bpf_probe_read_kernel(args, 8*cfg->fn_args.args_nr, ctx);
    if (cfg->fn_args.with_retval && (mode == BPFSNOOP_MODE_EXIT ||
                                     mode == BPFSNOOP_MODE_SESSION_EXIT))
        (void) bpf_probe_read_kernel(&retval, sizeof(retval), ctx + 8*cfg->fn_args.args_nr);

    pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == PID)
        return BPF_OK;
    if (cfg->pid && pid != cfg->pid)
        return BPF_OK;

    /* fp of tracee caller */
    fp = get_tracee_caller_fp(ctx, cfg->fn_args.args_nr,
                              cfg->flags.both_entry_exit || cfg->fn_args.with_retval);

    switch (mode) {
    case BPFSNOOP_MODE_SESSION_ENTRY:
        session_id = gen_session_id(fp);
        if (!bpfsnoop_session_enter(ctx, fp, session_id, filter(args, session_id),
                                    &session_id, cfg->flags.is_session))
            return BPF_OK;

        event_type = BPFSNOOP_EVENT_TYPE_FUNC_ENTRY;
        break;

    case BPFSNOOP_MODE_SESSION_EXIT:
        if (!bpfsnoop_session_exit(ctx, fp, &session_id, cfg->flags.is_session))
            return BPF_OK;

        event_type = BPFSNOOP_EVENT_TYPE_FUNC_EXIT;
        break;

    case BPFSNOOP_MODE_ENTRY:
    case BPFSNOOP_MODE_EXIT:
        session_id = gen_session_id(fp);
        if (!filter(args, session_id))
            return BPF_OK;

        event_type = (mode == BPFSNOOP_MODE_ENTRY) ? BPFSNOOP_EVENT_TYPE_FUNC_ENTRY
                                                   : BPFSNOOP_EVENT_TYPE_FUNC_EXIT;
        break;
    }

    return output_event(ctx, event_type, session_id, FUNC_IP, cpu, pid,
                        lbr, can_output_lbr, args, retval, cfg->flags.output_pkt,
                        cfg->flags.output_arg);
}

SEC("fexit")
int BPF_PROG(bpfsnoop_fn)
{
    return emit_bpfsnoop_event(ctx);
}

char __license[] SEC("license") = "GPL";
