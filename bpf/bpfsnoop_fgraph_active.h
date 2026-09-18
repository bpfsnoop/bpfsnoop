// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2026 Leon Hwang */

#ifndef __BPFSNOOP_FGRAPH_ACTIVE_H_
#define __BPFSNOOP_FGRAPH_ACTIVE_H_

#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_map_helpers.h"

#include "bpfsnoop.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, BPFSNOOP_MAX_ENTRIES);
    __type(key, struct task_struct *);
    __type(value, u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} bpfsnoop_fgraph_active SEC(".maps");

static __always_inline void
mark_fgraph_active(struct task_struct *tsk)
{
    u32 v = 0, *val;

    val = bpf_map_lookup_or_try_init(&bpfsnoop_fgraph_active, &tsk, &v);
    if (val)
        (*val)++;
}

static __always_inline void
unset_fgraph_active(struct task_struct *tsk)
{
    u32 *val;

    val = bpf_map_lookup_elem(&bpfsnoop_fgraph_active, &tsk);
    if (!val)
        return;

    if (!--(*val))
        bpf_map_delete_elem(&bpfsnoop_fgraph_active, &tsk);
}

static __always_inline bool
is_fgraph_active(struct task_struct *tsk)
{
    u32 *val;

    val = bpf_map_lookup_elem(&bpfsnoop_fgraph_active, &tsk);
    return val != NULL;
}

#endif // __BPFSNOOP_FGRAPH_ACTIVE_H_
