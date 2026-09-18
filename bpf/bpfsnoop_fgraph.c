// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2025 Leon Hwang */
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_map_helpers.h"

#include "bpfsnoop_event.h"
#include "bpfsnoop_fgraph_active.h"
#include "bpfsnoop_fn_args_output.h"
#include "bpfsnoop_sess.h"
#include "bpfsnoop_session.h"
#include "bpfsnoop_tracing.h"

enum bpfsnoop_hook_mode {
    BPFSNOOP_HOOK_ENTRY = 0,
    BPFSNOOP_HOOK_EXIT,
    BPFSNOOP_HOOK_SESSION,
};

struct bpfsnoop_fn_args {
    __u32 args_nr;
    bool with_retval;
    __u8 pad[3];
    __u32 buf_size;
} __attribute__((packed));

struct bpfsnoop_fgraph_configs {
    __u64 func_ip;
    __u32 max_depth;
    __u8 hook_mode;
    __u8 tailcall_in_bpf2bpf; /* supported since v5.10 for x86_64 */
    __u8 pad[2];
    __u32 mypid;
    struct bpfsnoop_fn_args fn_args;
} __attribute__((packed));

volatile const struct bpfsnoop_fgraph_configs BSN_FGRAPH_CFG;
#define cfg (&BSN_FGRAPH_CFG)

__u32 ready SEC(".data.ready") = 0;

struct bpfsnoop_fgraph_event {
    __u16 type;
    __u16 length;
    __u32 kernel_ts;
    __u64 session_id;
    __u64 func_ip;
    __u32 cpu;
    __u32 depth;
};

#define BPFSNOOP_FGRAPH_STACK_DEPTH 127
volatile const __u32 STACK_DEPTH = 127;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64[BPFSNOOP_FGRAPH_STACK_DEPTH]);
    __uint(max_entries, 1);
} bpfsnoop_fgraph_stack SEC(".maps");

static __always_inline __u64 *
get_fgraph_stack_buf(void)
{
    __u64 *buf;
    __u32 key = 0;

    buf = bpf_map_lookup_elem(&bpfsnoop_fgraph_stack, &key);
    return buf;
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u64);
    __uint(max_entries, 1024 * 1024); // 1Mi entries
} bpfsnoop_fgraph_tracee_ips SEC(".maps");

/* Stack frames are expected to contain the return-site IP immediately after
 * the trampoline call rather than the traced function entry IP itself.
 * Userspace populates this map with return_site_ip -> function_entry_ip so
 * fgraph can look up graph sessions by the same func_ip key used by the
 * regular tracing programs, including graph roots traced normally.
 */
static __always_inline __u64
get_fgraph_func_ip(__u64 ip)
{
    __u64 *func_ip;

    func_ip = bpf_map_lookup_elem(&bpfsnoop_fgraph_tracee_ips, &ip);
    return func_ip ? *func_ip : 0;
}

static __always_inline __u64
try_get_session(void *ctx, int *depth, __u64 pid_tgid)
{
    __u64 *stack, func_ip, session_id;
    bool after_current = false;
    int nr_bytes, nr_ips;
    __u32 max_stack;

    if (!is_fgraph_active(bpf_get_current_task_btf()))
        return 0;

    stack = get_fgraph_stack_buf();
    if (!stack)
        return 0;

    max_stack = STACK_DEPTH;
    nr_bytes = bpf_get_stack(ctx, stack, sizeof(*stack) * max_stack, 0);
    if (nr_bytes <= 0)
        return 0;

    nr_ips = nr_bytes / sizeof(*stack);
    *depth = 1;

    for (int i = 0; i < max_stack; i++) {
        if (i >= nr_ips)
            break;

        func_ip = get_fgraph_func_ip(stack[i]);
        if (!func_ip)
            continue;

        if (after_current) {
            session_id = get_session(pid_tgid, func_ip);
            if (session_id)
                return session_id;

            if (++(*depth) > cfg->max_depth)
                return 0;
        } else if (func_ip == cfg->func_ip) {
            after_current = true;
        }
    }

    return 0;
}

SEC("fexit")
int BPF_PROG(bpfsnoop_fgraph)
{
    struct bpfsnoop_fgraph_event *evt;
    __u64 args[MAX_FN_ARGS];
    __u64 session_id;
    __u64 retval = 0;
    size_t buffer_sz;
    __u64 pid_tgid;
    bool is_entry;
    int depth = 0;
    void *buffer;

    if (!ready)
        return BPF_OK;

    pid_tgid = bpf_get_current_pid_tgid();
    if (cfg->mypid == (pid_tgid >> 32))
        return BPF_OK;

    session_id = try_get_session(ctx, &depth, pid_tgid);
    if (!session_id)
        return BPF_OK;

    buffer_sz = sizeof(*evt) + cfg->fn_args.buf_size;
    buffer = bpf_ringbuf_reserve(&bpfsnoop_events, buffer_sz, 0);
    if (!buffer)
        return BPF_OK;

    is_entry = cfg->hook_mode == BPFSNOOP_HOOK_ENTRY;
    if (cfg->hook_mode == BPFSNOOP_HOOK_SESSION)
        is_entry = !bpfsnoop_session_is_return(ctx);

    (void) bpf_probe_read_kernel(args, 8*cfg->fn_args.args_nr, ctx);
    if (cfg->fn_args.with_retval && !is_entry)
        /* typeof(ctx) is 'unsigned long long *', not 'void *'. */
        (void) bpf_probe_read_kernel(&retval, sizeof(retval), (void *)ctx + 8*cfg->fn_args.args_nr);

    evt = (typeof(evt)) buffer;
    evt->type = is_entry ? BPFSNOOP_EVENT_TYPE_GRAPH_ENTRY
                         : BPFSNOOP_EVENT_TYPE_GRAPH_EXIT;
    evt->length = buffer_sz;
    evt->kernel_ts = (__u32) bpf_ktime_get_ns();
    evt->session_id = session_id;
    evt->func_ip = cfg->func_ip;
    evt->cpu = bpf_get_smp_processor_id();
    evt->depth = depth;

    buffer += sizeof(*evt);
    output_fn_args(args, buffer, retval);

    bpf_ringbuf_submit(evt, 0);

    return BPF_OK;
}

char __license[] SEC("license") = "GPL";
