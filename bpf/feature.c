// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2024 Leon Hwang */

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"

struct bpf_features {
    bool kprobe_happened;
    bool has_ringbuf;
    bool has_branch_snapshot;
    bool has_func_ret;
    bool has_func_ip;
    bool has_stack_id;
} features;

SEC("fentry/__x64_sys_nanosleep")
int BPF_PROG(detect, struct pt_regs *regs)
{
    features.kprobe_happened = true;

    /* Detect if bpf_get_func_ip() helper is supported by the kernel.
     * Added in: 9b99edcae5c8 ("bpf: Add bpf_get_func_ip helper for tracing programs")
     */
    features.has_func_ip = bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_get_func_ip);

    /* Detect if bpf_get_func_ret() helper is supported by the kernel.
     * Added in: f92c1e183604 ("bpf: Add get_func_[arg|ret|arg_cnt] helpers ")
     */
    features.has_func_ret = bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_get_func_ret);

    /* Detect if bpf_get_branch_snapshot() helper is supported.
     * Added in: 856c02dbce4f ("bpf: Introduce helper bpf_get_branch_snapshot")
     */
    features.has_branch_snapshot = bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_get_branch_snapshot);

    /* Detect if BPF_MAP_TYPE_RINGBUF map is supported.
     * Added in: 457f44363a88 ("bpf: Implement BPF ring buffer and verifier support for it")
     */
    features.has_ringbuf = bpf_core_enum_value_exists(enum bpf_map_type, BPF_MAP_TYPE_RINGBUF);

    /* Detect if bpf_get_stackid() helper is supported.
     * Added in: d5a3b1f69186 ("bpf: introduce BPF_MAP_TYPE_STACK_TRACE")
     */
    features.has_stack_id = bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_get_stackid);

    return 0;
}

char __license[] SEC("license") = "GPL";
