// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2025 Leon Hwang */

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

#include "bpfsnoop_str.h"

#define BUFF_SIZE 65536

__u64 target_pid_tgid SEC(".data.target");
__u64 target_addr SEC(".data.target");
__u32 target_size SEC(".data.target");
__u8 buff[BUFF_SIZE] SEC(".data.buff");
bool run SEC(".data.run");

SEC("fentry/bpf_fentry_test1")
int BPF_PROG(read)
{
    if (bpf_get_current_pid_tgid() != target_pid_tgid)
        return BPF_OK;

    if (run)
        return BPF_OK;
    run = true;

    bpf_probe_read_kernel(&buff, target_size&(BUFF_SIZE-1), (void *) target_addr);

    return BPF_OK;
}

static __noinline int
read_stub(__u8 *b)
{
    return b[0];
}

SEC("fentry/bpf_fentry_test1")
int BPF_PROG(read_data)
{
    int ret;
    __u8 *b;

    if (bpf_get_current_pid_tgid() != target_pid_tgid)
        return BPF_OK;

    if (run)
        return BPF_OK;
    run = true;

    b = buff;
    barrier_var(b);
    ret = read_stub(b);
    barrier_var(ret);
    return BPF_OK;
}

char __license[] SEC("license") = "GPL";
