// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2025 Leon Hwang */

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

#define TP_MAX 256

volatile const u64 __start;
volatile const u32 nr_tps SEC(".rodata.nr_tps");
bool run SEC(".data.run");

struct tp_info {
    char name[64]; /* The longest tp name has over 40 chars. */
    __u64 func_proto_symbol;
    __u32 num_args;
};

struct tp_info tps[TP_MAX];

static __noinline void
probe_tp_info(struct bpf_raw_event_map *btp, int i)
{
    struct tp_info *tp = &tps[i];
    const char *str;

    str = BPF_CORE_READ(btp, tp, name);
    bpf_probe_read_kernel_str(tp->name, sizeof(tp->name), str);
    BPF_CORE_READ_INTO(&tp->func_proto_symbol, btp, bpf_func);
    BPF_CORE_READ_INTO(&tp->num_args, btp, num_args);
}

SEC("fentry/__x64_sys_nanosleep")
int BPF_PROG(probe, struct pt_regs *regs)
{
    struct bpf_raw_event_map *btp = (typeof(btp)) __start;

    if (run)
        return BPF_OK;
    run = true;

    for (int i = 0; i < TP_MAX; i++) {
        if (i >= nr_tps)
            break;

        probe_tp_info(btp, i);
        btp++;
    }

    return BPF_OK;
}

char __license[] SEC("license") = "GPL";
