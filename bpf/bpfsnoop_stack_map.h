// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2026 Leon Hwang */

#ifndef __BPFSNOOP_STACK_MAP_H_
#define __BPFSNOOP_STACK_MAP_H_

#include "vmlinux.h"
#include "bpf_helpers.h"

/* Must LE sysctl kernel.perf_event_max_stack = 127 */
#define MAX_STACK_DEPTH 127
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 256);
    __uint(key_size, sizeof(u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(u64)); /* Being updated to kernel.perf_event_max_depth in Go */
} bpfsnoop_stacks SEC(".maps");

#endif // __BPFSNOOP_STACK_MAP_H_
