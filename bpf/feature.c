// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2024 Leon Hwang */

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"

struct bpf_features {
    bool run;
    bool has_ringbuf;
    bool has_branch_snapshot;
    bool has_stack_id;
} features;

SEC("fentry/__x64_sys_nanosleep")
int BPF_PROG(detect, struct pt_regs *regs)
{
    features.run = true;

    /* Detect if bpf_get_branch_snapshot() helper is supported.
     * Added in: 856c02dbce4f ("bpf: Introduce helper bpf_get_branch_snapshot")
     */
    /* check in Go instead, to avoid missing BPF_FUNC_get_branch_snapshot in vmlinux.h */
    /* features.has_branch_snapshot = bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_get_branch_snapshot); */

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
