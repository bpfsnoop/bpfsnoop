// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2025 Leon Hwang */
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_map_helpers.h"

#include "bpfsnoop_event.h"
#include "bpfsnoop_sess.h"

volatile const __u64 INSN_IP = 0;

__u32 ready SEC(".data.ready") = 0;

struct bpfsnoop_insn_event {
    __u16 type;
    __u16 length;
    __u32 kernel_ts;
    __u64 session_id;
    __u64 insn_ip;
    __u32 cpu;
};

static __always_inline struct bpfsnoop_sess *
try_get_session(struct pt_regs *ctx)
{
    struct bpfsnoop_sess *sess;
    __u64 fp;
    int i;

    fp = PT_REGS_FP(ctx);
    const int max_tries = 3;
    for (i = 0; i < max_tries; i++) {
        (void) bpf_probe_read_kernel(&fp, sizeof(fp), (void *) fp);
        sess = get_session(fp);
        if (sess)
            return sess;
    }

    return NULL;
}

SEC("kprobe")
int k_insn(struct pt_regs *ctx)
{
    struct bpfsnoop_insn_event init_event = {}, *evt = &init_event;
    struct bpfsnoop_sess *sess;

    if (!ready)
        return BPF_OK;

    sess = try_get_session(ctx);
    if (!sess)
        return BPF_OK;

    evt->type = BPFSNOOP_EVENT_TYPE_INSN;
    evt->length = sizeof(*evt);
    evt->kernel_ts = (__u32) bpf_ktime_get_ns();
    evt->session_id = sess->session_id;
    evt->insn_ip = INSN_IP;
    evt->cpu = bpf_get_smp_processor_id();

    bpf_ringbuf_output(&bpfsnoop_events, evt, sizeof(*evt), 0);

    return BPF_OK;
}

char __license[] SEC("license") = "GPL";
