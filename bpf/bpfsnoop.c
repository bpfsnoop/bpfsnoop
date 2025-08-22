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
#include "bpfsnoop_fn_args_output.h"
#include "bpfsnoop_lbr.h"
#include "bpfsnoop_pkt_filter.h"
#include "bpfsnoop_pkt_output.h"
#include "bpfsnoop_sess.h"
#include "bpfsnoop_stack.h"
#include "bpfsnoop_tracing.h"

volatile const __u32 PID = -1;
volatile const __u32 CPU_MASK = 0xFFFF;
volatile const __u64 FUNC_IP = 0;

__u32 ready SEC(".data.ready") = 0;

/* Must LE sysctl kernel.perf_event_max_stack = 127 */
#define MAX_STACK_DEPTH 127
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 256);
    __uint(key_size, sizeof(u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(u64)); /* Being updated to kernel.perf_event_max_depth in Go */
} bpfsnoop_stacks SEC(".maps");

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

enum bpfsnoop_mode {
    BPFSNOOP_MODE_ENTRY = 0,
    BPFSNOOP_MODE_EXIT,
    BPFSNOOP_MODE_SESSION_ENTRY,
    BPFSNOOP_MODE_SESSION_EXIT,
};

static __always_inline enum bpfsnoop_mode
get_bpfsnoop_mode(void *ctx)
{
    bool is_entry = cfg->is_entry;

    if (cfg->both_entry_exit && cfg->is_fsession)
        is_entry = !bpf_session_is_return(ctx);

    if (cfg->both_entry_exit)
        return is_entry ? BPFSNOOP_MODE_SESSION_ENTRY : BPFSNOOP_MODE_SESSION_EXIT;

    return is_entry ? BPFSNOOP_MODE_ENTRY : BPFSNOOP_MODE_EXIT;
}

static __always_inline bool
init_session_entry(void *ctx, __u64 fp, __u64 *args, __u64 *session_id)
{
    struct bpfsnoop_sess sess_init = {};
    __u64 *cookie, sid;

    sid = gen_session_id(fp);
    if (!filter(args, sid))
        return false;

    if (cfg->is_fsession) {
        /* The cookie has been cleared in trampoline. */
        cookie = bpf_session_cookie(ctx);
        *cookie = sid;
    } else {
        sess_init.session_id = sid;
        add_session(fp, &sess_init);
    }

    *session_id = sid;
    return true;
}

static __always_inline bool
init_session_exit(void *ctx, __u64 fp, __u64 *session_id)
{
    struct bpfsnoop_sess *sess;
    __u64 *cookie, sid;

    if (cfg->is_fsession) {
        cookie = bpf_session_cookie(ctx);
        sid = *cookie;
        if (!sid)
            return false;

        *session_id = sid - 1;
    } else {
        sess = get_and_del_session(fp);
        if (!sess)
            return false;

        *session_id = sess->session_id - 1;
    }

    return true;
}

static __always_inline int
emit_bpfsnoop_event(void *ctx)
{
    struct bpfsnoop_lbr_data *lbr;
    __u64 fp, session_id = 0;
    enum bpfsnoop_mode mode;
    __u64 args[MAX_FN_ARGS];
    bool can_output_lbr;
    void *buffer, *ptr;
    struct event *evt;
    size_t buffer_sz;
    __u64 retval = 0;
    __u16 event_type;
    __u32 cpu, pid;

    if (!ready)
        return BPF_OK;

    cpu = bpf_get_smp_processor_id() & CPU_MASK;
    lbr = &bpfsnoop_lbr_buff[cpu];

    mode = get_bpfsnoop_mode(ctx);

    can_output_lbr = !cfg->both_entry_exit || (mode == BPFSNOOP_MODE_SESSION_ENTRY);
    if (cfg->output_lbr && can_output_lbr)
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
                              cfg->both_entry_exit || cfg->fn_args.with_retval);

    switch (mode) {
    case BPFSNOOP_MODE_SESSION_ENTRY:
        if (!init_session_entry(ctx, fp, args, &session_id))
            return BPF_OK;

        event_type = BPFSNOOP_EVENT_TYPE_FUNC_ENTRY;
        break;

    case BPFSNOOP_MODE_SESSION_EXIT:
        if (!init_session_exit(ctx, fp, &session_id))
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

    buffer_sz = sizeof(*evt) + cfg->fn_args.buf_size + cfg->fn_args.data_size;
    buffer_sz += cfg->output_pkt ? sizeof(struct bpfsnoop_pkt_data) : 0;
    buffer = bpf_ringbuf_reserve(&bpfsnoop_events, buffer_sz, 0);
    if (!buffer)
        return BPF_OK;

    evt = buffer;
    evt->type = event_type;
    evt->length = sizeof(*evt);
    evt->kernel_ts = (__u32) bpf_ktime_get_ns();
    evt->session_id = session_id;
    evt->func_ip = FUNC_IP;
    evt->cpu = cpu;
    evt->pid = pid;
    bpf_get_current_comm(evt->comm, sizeof(evt->comm));
    evt->func_stack_id = -1;
    if (cfg->output_stack)
        evt->func_stack_id = bpf_get_stackid(ctx, &bpfsnoop_stacks, BPF_F_FAST_STACK_CMP);
    evt->lbr_retval = lbr->nr_bytes;
    if (cfg->output_lbr && can_output_lbr && lbr->nr_bytes > 0)
        output_lbr_data(lbr, session_id);
    ptr = buffer + sizeof(*evt);
    output_fn_args(args, ptr, retval);
    ptr += cfg->fn_args.buf_size;
    if (cfg->output_pkt) {
        output_pkt(args, ptr);
        ptr += sizeof(struct bpfsnoop_pkt_data);
    }
    if (cfg->output_arg) {
        output_arg(args, ptr);
        ptr += cfg->fn_args.data_size;
    }

    bpf_ringbuf_submit(evt, 0);

    return BPF_OK;
}

SEC("fexit")
int BPF_PROG(bpfsnoop_fn)
{
    return emit_bpfsnoop_event(ctx);
}

char __license[] SEC("license") = "GPL";
