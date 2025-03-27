// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2025 Leon Hwang */

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} prog_array SEC(".maps");

static __noinline int
subprog(void *ctx, int index)
{
    bpf_tail_call(ctx, &prog_array, index);

    return BPF_OK;
}

SEC("kprobe/__x64_sys_nanosleep")
int BPF_KPROBE(entry, struct pt_regs *regs)
{
    subprog(ctx, 0);

    return BPF_OK;
}

char __license[] SEC("license") = "GPL";
