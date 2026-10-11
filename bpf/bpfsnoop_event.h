// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2025 Leon Hwang */

#ifndef __BPFSNOOP_EVENT_H_
#define __BPFSNOOP_EVENT_H_

#include "vmlinux.h"

#include "bpfsnoop.h"
#include "bpfsnoop_cfg_flags.h"

enum {
    BPFSNOOP_EVENT_TYPE_UNSPEC = 0,
    BPFSNOOP_EVENT_TYPE_FUNC_ENTRY,
    BPFSNOOP_EVENT_TYPE_FUNC_EXIT,
    BPFSNOOP_EVENT_TYPE_INSN,
    BPFSNOOP_EVENT_TYPE_GRAPH_ENTRY,
    BPFSNOOP_EVENT_TYPE_GRAPH_EXIT,
};

struct event {
    __u16 type;
    __u16 length;
    __u32 kernel_ts;
    __u64 session_id;
    __u64 func_ip;
    __u32 cpu;
    __u32 pid;
    __u8 comm[16];
    __s64 func_stack_id;
    TRACEE_FLAGS;
    __u32 tracee_arg_entry_size;
    __u32 tracee_arg_exit_size;
    __u32 tracee_arg_data_size;
    __s64 lbr_retval;
};

struct bpfsnoop_ringbuf {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 * 1024); /* 8MiB per CPU */
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 1); /* Set to the possible CPU count by userspace. */
    __type(key, __u32);
    __array(values, struct bpfsnoop_ringbuf);
} bpfsnoop_events SEC(".maps");

static __always_inline void *
bpfsnoop_event_ringbuf(__u32 cpu)
{
    return bpf_map_lookup_elem(&bpfsnoop_events, &cpu);
}

#endif // __BPFSNOOP_EVENT_H_
