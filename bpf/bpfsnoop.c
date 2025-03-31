// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2024 Leon Hwang */
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_map_helpers.h"

#include "bpfsnoop.h"
#include "bpfsnoop_arg_filter.h"
#include "bpfsnoop_arg_output.h"
#include "bpfsnoop_fn_data_output.h"
#include "bpfsnoop_lbr.h"
#include "bpfsnoop_pkt_filter.h"
#include "bpfsnoop_pkt_output.h"

volatile const __u32 PID = -1;

__u32 ready SEC(".data.ready") = 0;

volatile const __u64 FUNC_IP = 0;
volatile const __u32 CPU_MASK = 0xFFFF;

#define MAX_STACK_DEPTH 50
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 256);
    __uint(key_size, sizeof(u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
} bpfsnoop_stacks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096<<8);
} bpfsnoop_events SEC(".maps");

struct event bpfsnoop_evt_buff[1] SEC(".data.events");

static __always_inline bool
filter(__u64 *args, __u64 session_id)
{
    return filter_arg(args) && filter_pkt(args, session_id);
}

static __always_inline __u64
get_tracee_caller_fp(void)
{
    u64 fp, fp_caller;

    /* get frame pointer */
    asm volatile ("%[fp] = r10" : [fp] "+r"(fp) :); /* fp of current bpf prog */
    (void) bpf_probe_read_kernel(&fp_caller, sizeof(fp_caller), (void *) fp); /* fp of trampoline */
    (void) bpf_probe_read_kernel(&fp_caller, sizeof(fp_caller), (void *) fp_caller); /* fp of tracee caller */
    return fp_caller;
}

static __always_inline __u64
gen_session_id(void)
{
    __u64 fp = get_tracee_caller_fp();
    __u32 rnd = bpf_get_prandom_u32();

    return ((__u64) rnd) << 32 | (fp & 0xFFFFFFFF);
}

static __always_inline int
emit_bpfsnoop_event(void *ctx)
{
    struct bpfsnoop_lbr_data *lbr;
    struct bpfsnoop_str_data *str;
    struct bpfsnoop_pkt_data *pkt;
    struct bpfsnoop_arg_data *arg;
    __u64 args[MAX_FN_ARGS];
    struct event *evt;
    __u64 retval = 0;
    __u64 session_id;
    size_t event_sz;
    __u32 cpu, pid;

    if (!ready)
        return BPF_OK;

    cpu = bpf_get_smp_processor_id() & CPU_MASK;
    lbr = &bpfsnoop_lbr_buff[cpu];
    pkt = &bpfsnoop_pkt_buff[cpu];
    str = &bpfsnoop_str_buff[cpu];
    arg = &bpfsnoop_arg_buff[cpu];
    evt = &bpfsnoop_evt_buff[cpu];

    if (cfg->output_lbr)
        lbr->nr_bytes = bpf_get_branch_snapshot(lbr->entries, sizeof(lbr->entries), 0); /* required 5.16 kernel. */

    /* Other filters must be after bpf_get_branch_snapshot() to avoid polluting
     * LBR entries.
     */
    (void) bpf_probe_read_kernel(args, 8*cfg->fn_args.nr_fn_args, ctx);
    if (cfg->fn_args.with_retval)
        (void) bpf_probe_read_kernel(&retval, sizeof(retval), ctx + 8*cfg->fn_args.nr_fn_args);

    pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == PID)
        return BPF_OK;
    if (cfg->pid && pid != cfg->pid)
        return BPF_OK;

    session_id = gen_session_id();
    if (!filter(args, session_id))
        return BPF_OK;

    evt->session_id = session_id;
    evt->func_ip = FUNC_IP;
    evt->cpu = cpu;
    evt->pid = pid;
    bpf_get_current_comm(evt->comm, sizeof(evt->comm));
    evt->func_stack_id = -1;
    if (cfg->output_stack)
        evt->func_stack_id = bpf_get_stackid(ctx, &bpfsnoop_stacks, BPF_F_FAST_STACK_CMP);
    if (cfg->output_lbr)
        output_lbr_data(lbr, session_id);
    output_fn_data(evt, str, args, retval);
    if (cfg->output_pkt)
        output_pkt_data(args, pkt, session_id);
    if (cfg->output_arg)
        output_arg_data(args, arg, session_id);

    event_sz  = offsetof(struct event, fn_data) + sizeof(struct bpfsnoop_fn_arg_data);
    event_sz += sizeof(struct bpfsnoop_fn_arg_data) * cfg->fn_args.nr_fn_args;
    bpf_ringbuf_output(&bpfsnoop_events, evt, event_sz, 0);

    return BPF_OK;
}

SEC("fexit")
int BPF_PROG(bpfsnoop_fn)
{
    return emit_bpfsnoop_event(ctx);
}

char __license[] SEC("license") = "GPL";
