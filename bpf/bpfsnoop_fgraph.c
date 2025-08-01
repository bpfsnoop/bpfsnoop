// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2025 Leon Hwang */
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_map_helpers.h"

#include "bpfsnoop_event.h"
#include "bpfsnoop_fn_args_output.h"
#include "bpfsnoop_sess.h"
#include "bpfsnoop_stack.h"

struct bpfsnoop_fn_args {
    __u32 args_nr;
    bool with_retval;
    __u8 pad[3];
    __u32 buf_size;
} __attribute__((packed));

struct bpfsnoop_fgraph_configs {
    __u64 func_ip;
    __u32 max_depth;
    __u8 entry; /* 1 for entry, 0 for exit */
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

struct bpfsnoop_fgraph_tailcall_data {
    __u64 fp;
    int depth;
    int max_depth;
    __u64 sess;
    bool found;
    bool oo_depth;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct bpfsnoop_fgraph_tailcall_data);
    __uint(max_entries, 1);
} bpfsnoop_fgraph_tailcall SEC(".maps");

static __always_inline struct bpfsnoop_fgraph_tailcall_data *
get_fgraph_tailcall_data(void)
{
    struct bpfsnoop_fgraph_tailcall_data *data;
    __u32 key = 0;

    data = bpf_map_lookup_elem(&bpfsnoop_fgraph_tailcall, &key);
    return data;
}

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} bpfsnoop_fgraph_tailcall_prog_array SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u32);
    __uint(max_entries, 1024 * 1024); // 1Mi entries
} bpfsnoop_fgraph_tracee_ips SEC(".maps");

/* Check the tracee ip in the following stack layout:
 * +----+ tracee caller fp
 * | .. |
 * | ip | tracee caller ip
 * | ip | tracee ip        <-- check this ip
 * | fp | tracee caller fp
 * +----+ tramp fp
 * | .. |
 * | ip | tramp ip
 * | fp | tramp fp
 * +----+ fgraph prog fp
 * | .. |
 *
 * As a result, if the eip is in the tracee ips map, it means current fp is a
 * tramp fp.
 */
static __always_inline bool
is_tramp_fp(__u64 ip)
{
    __u32 *val;

    val = bpf_map_lookup_elem(&bpfsnoop_fgraph_tracee_ips, &ip);
    return val != NULL;
}

static __always_inline struct bpfsnoop_sess *
try_get_session_limited(int *depth)
{
    struct bpfsnoop_sess *sess;
    __u32 max_depth, max_tries;
    __u64 buff[2]; /* [FP|IP] */
    __u64 fp;
    int i;

    max_depth = cfg->max_depth;
    if (max_depth > 10)
        return NULL; /* max depth is too large, avoid 'BPF program is too large' */

    fp = get_tramp_fp(); /* read tramp fp */
    (void) bpf_probe_read_kernel(&fp, sizeof(fp), (void *) fp); /* read caller fp */

    *depth = 0;
    max_tries = max_depth * 2;
    for (i = 0; i < max_tries; i++) {
        (void) bpf_probe_read_kernel(&buff, sizeof(buff), (void *) fp); /* read both fp&ip at same time */
        sess = get_session(buff[0]);
        if (sess)
            return sess;

        if (!is_tramp_fp(buff[1]) && ++(*depth) > max_depth)
            break;

        fp = buff[0]; /* next frame pointer */
    }

    return NULL;
}

SEC("fexit")
int BPF_PROG(bpfsnoop_fgraph_tailcallee)
{
    struct bpfsnoop_fgraph_tailcall_data *data;
    struct bpfsnoop_sess *sess;
    __u64 buff[2]; /* [FP|IP] */
    __u64 fp;
    int i;

    data = get_fgraph_tailcall_data();
    if (!data) /* won't failed, but required to check it in bpf code */
        return false;

    fp = data->fp;
    for (i = 0; i < 100; i++) {
        (void) bpf_probe_read_kernel(&buff, sizeof(buff), (void *) fp); /* read both fp&ip at same time */
        sess = get_session(buff[0]);
        if (sess) {
            data->sess = (__u64) sess;
            data->found = true;
            return false;
        }

        if (!is_tramp_fp(buff[1]) && ++(data->depth) > data->max_depth) {
            data->oo_depth = true; /* out of depth */
            return false;
        }

        data->fp = fp = buff[0]; /* next frame pointer */
    }

    return false;
}

static __noinline int
get_session_from_tailcall(void *ctx)
{
    /* tailcall bpfsnoop_fgraph_tailcallee */
    bpf_tail_call_static(ctx, &bpfsnoop_fgraph_tailcall_prog_array, 0);
    return 0; /* won't failed, as tailcall must succeed when prog_array is populated */
}

static __always_inline struct bpfsnoop_sess *
try_get_session(void *ctx, int *depth)
{
    struct bpfsnoop_fgraph_tailcall_data *data;
    __u64 fp;

    if (!cfg->tailcall_in_bpf2bpf)
        return try_get_session_limited(depth);

    data = get_fgraph_tailcall_data();
    if (!data)
        return NULL;

    fp = get_tramp_fp(); /* read tramp fp */
    (void) bpf_probe_read_kernel(&fp, sizeof(fp), (void *) fp); /* read caller fp */

    __builtin_memset(data, 0, sizeof(*data));
    data->fp = fp;
    data->max_depth = cfg->max_depth;

    const int max_loop = 10;
    for (int i = 0; i < max_loop; i++) {
        (void) get_session_from_tailcall(ctx);
        if (data->found) {
            *depth = data->depth;
            return (struct bpfsnoop_sess *) data->sess;
        }
        if (data->oo_depth)
            return NULL; /* out of max depth */
    }

    return NULL; /* not found */
}

static __always_inline int
bpfsnoop_fgraph(void *ctx)
{
    struct bpfsnoop_fgraph_event *evt;
    struct bpfsnoop_sess *sess;
    __u64 args[MAX_FN_ARGS];
    __u64 retval = 0;
    size_t buffer_sz;
    int depth = 0;
    void *buffer;

    if (!ready)
        return BPF_OK;

    if (cfg->mypid == (bpf_get_current_pid_tgid() >> 32))
        return BPF_OK;

    sess = try_get_session(ctx, &depth);
    if (!sess)
        return BPF_OK;

    buffer_sz = sizeof(*evt) + cfg->fn_args.buf_size;
    buffer = bpf_ringbuf_reserve(&bpfsnoop_events, buffer_sz, 0);
    if (!buffer)
        return BPF_OK;

    (void) bpf_probe_read_kernel(args, 8*cfg->fn_args.args_nr, ctx);
    if (cfg->fn_args.with_retval)
        (void) bpf_probe_read_kernel(&retval, sizeof(retval), ctx + 8*cfg->fn_args.args_nr);

    evt = (typeof(evt)) buffer;
    evt->type = cfg->entry ? BPFSNOOP_EVENT_TYPE_GRAPH_ENTRY
                           : BPFSNOOP_EVENT_TYPE_GRAPH_EXIT;
    evt->length = buffer_sz;
    evt->kernel_ts = (__u32) bpf_ktime_get_ns();
    if (cfg->tailcall_in_bpf2bpf)
        (void) bpf_probe_read_kernel(&evt->session_id, sizeof(evt->session_id), &sess->session_id);
    else
        evt->session_id = sess->session_id;
    evt->func_ip = cfg->func_ip;
    evt->cpu = bpf_get_smp_processor_id();
    evt->depth = depth;

    buffer += sizeof(*evt);
    output_fn_args(args, buffer, retval);

    bpf_ringbuf_submit(evt, 0);

    return BPF_OK;
}

SEC("fentry")
int BPF_PROG(bpfsnoop_fgraph_entry)
{
    return bpfsnoop_fgraph(ctx);
}

SEC("fexit")
int BPF_PROG(bpfsnoop_fgraph_exit)
{
    return bpfsnoop_fgraph(ctx);
}

char __license[] SEC("license") = "GPL";
