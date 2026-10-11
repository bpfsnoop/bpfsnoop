// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2025 Leon Hwang */
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_map_helpers.h"

#include "bpfsnoop_event.h"
#include "bpfsnoop_sess.h"

volatile const __u64 INSN_IP = 0;
volatile const __u64 FUNC_IP = 0;

__u32 ready SEC(".data.ready") = 0;

struct bpfsnoop_insn_event {
    __u16 type;
    __u16 length;
    __u32 kernel_ts;
    __u64 session_id;
    __u64 insn_ip;
    __u32 cpu;
};

static __always_inline __u64
try_get_session(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 func_ip = FUNC_IP;

    return get_session(pid_tgid, func_ip);
}

SEC("kprobe")
int bpfsnoop_insn(struct pt_regs *ctx)
{
    struct bpfsnoop_insn_event *evt;
    __u64 session_id;
    void *ringbuf;
    __u32 cpu;

    if (!ready)
        return BPF_OK;

    session_id = try_get_session(ctx);
    if (!session_id)
        return BPF_OK;

    cpu = bpf_get_smp_processor_id();
    ringbuf = bpfsnoop_event_ringbuf(cpu);
    if (!ringbuf)
        return BPF_OK;

    evt = bpf_ringbuf_reserve(ringbuf, sizeof(*evt), 0);
    if (!evt)
        return BPF_OK;

    evt->type = BPFSNOOP_EVENT_TYPE_INSN;
    evt->length = sizeof(*evt);
    evt->kernel_ts = (__u32) bpf_ktime_get_ns();
    evt->session_id = session_id;
    evt->insn_ip = INSN_IP;
    evt->cpu = cpu;

    bpf_ringbuf_submit(evt, 0);

    return BPF_OK;
}

char __license[] SEC("license") = "GPL";
