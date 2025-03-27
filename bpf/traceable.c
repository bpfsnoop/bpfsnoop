// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2025 Leon Hwang */

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

#define ADDR_CAP 1024

volatile const u64 addrs[ADDR_CAP];
volatile const u32 nr_addrs SEC(".rodata.nr_addrs");
volatile const u32 has_endbr SEC(".rodata.endbr") = 0;
bool traceables[ADDR_CAP];
bool run SEC(".data.run");

static __noinline bool
is_traceable(u64 addr)
{
    u8 buff[16];

    if (bpf_probe_read_kernel(&buff, 16, (void *) addr))
        return false;

    if (!has_endbr ? buff[0] == 0xE8 : buff[4] == 0xE8) /* callq */
        return true;

    static const u64 nop5 = 0x0000441F0F;
    return !has_endbr ? ((((u64) buff[4]) << 32 | (u64)(*(u32 *) buff)) == nop5) :
                        ((((u64) buff[8]) << 32 | (u64)(*(u32 *) (buff + 4))) == nop5);
}

SEC("fentry/__x64_sys_nanosleep")
int BPF_PROG(detect, struct pt_regs *regs)
{
    if (run)
        return BPF_OK;
    run = true;

    for (int i = 0; i < ADDR_CAP; i++) {
        if (i >= nr_addrs)
            break;
        traceables[i] = is_traceable(addrs[i]);
    }

    return BPF_OK;
}

char __license[] SEC("license") = "GPL";
