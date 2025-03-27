// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2025 Leon Hwang */

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

volatile const __u64 __addr;
volatile const __u32 __size = 0;
__u8 buff[4096];
bool run SEC(".data.run");

SEC("fentry/__x64_sys_nanosleep")
int BPF_PROG(read, struct pt_regs *regs)
{
    if (run)
        return BPF_OK;
    run = true;

    bpf_probe_read_kernel(&buff, __size, (void *) __addr);

    return BPF_OK;
}

char __license[] SEC("license") = "GPL";
