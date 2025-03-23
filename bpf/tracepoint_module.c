// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2025 Leon Hwang */

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

#define TP_MODULE_MAX 256

/*
struct bpf_trace_module {
    struct module *module;
    struct list_head list;
};
 */

volatile const __u64 __head;
volatile const __u64 __start;
__u64 next_module;
__u32 nr_modules;
bool end;
bool run;

struct module_info {
    char name[56];
    __u64 num_bpf_raw_events;
    __u64 bpf_raw_events;
};

struct module_info modules[TP_MODULE_MAX];

static __noinline void
probe_module_info(struct bpf_trace_module *mod, int i)
{
    struct module_info *info = &modules[i];
    struct module *module;

    module = BPF_CORE_READ(mod, module);
    bpf_probe_read_kernel_str(info->name, sizeof(info->name), &module->name);
    BPF_CORE_READ_INTO(&info->num_bpf_raw_events, mod, module, num_bpf_raw_events);
    BPF_CORE_READ_INTO(&info->bpf_raw_events, mod, module, bpf_raw_events);
}

SEC("fentry/__x64_sys_nanosleep")
int probe(struct pt_regs *regs)
{
    struct list_head *start = (typeof(start)) __start, *next;
    struct list_head *modules = (typeof(modules)) __head;
    struct bpf_trace_module *btm;
    int i;

    if (run)
        return BPF_OK;
    run = true;

    next = start ? : BPF_CORE_READ(modules, next);
    for (i = 0; i < TP_MODULE_MAX; i++) {
        if (next == modules)
            break;

        btm = container_of(next, struct bpf_trace_module, list);
        probe_module_info(btm, i);
        next = BPF_CORE_READ(btm, list.next);
    }

    end = next == modules;
    next_module = (__u64) next;
    nr_modules = i;

    return BPF_OK;
}

char __license[] SEC("license") = "GPL";
