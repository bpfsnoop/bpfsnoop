// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2024 Leon Hwang */

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"

struct __features {
    bool run;
    bool has_ringbuf;
    bool has_branch_snapshot;
} features;

SEC("fentry/bpf_fentry_test1")
int BPF_PROG(detect)
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

    return 0;
}

char __license[] SEC("license") = "GPL";
