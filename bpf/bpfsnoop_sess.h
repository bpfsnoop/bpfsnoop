// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2025 Leon Hwang */

#ifndef __BPFSNOOP_SESS_H_
#define __BPFSNOOP_SESS_H_

#include "vmlinux.h"

#include "bpf_helpers.h"

#include "bpfsnoop.h"

struct bpfsnoop_sess {
    __u64 session_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, BPFSNOOP_MAX_ENTRIES);
    __type(key, __u64);
    __type(value, struct bpfsnoop_sess);
} bpfsnoop_sessions SEC(".maps");

static __always_inline void
add_session(__u64 fp, struct bpfsnoop_sess *sess)
{
    (void) bpf_map_update_elem(&bpfsnoop_sessions, &fp, sess, BPF_ANY);
}

static __always_inline struct bpfsnoop_sess *
get_session(__u64 fp)
{
    return (struct bpfsnoop_sess *) bpf_map_lookup_elem(&bpfsnoop_sessions, &fp);
}

static __always_inline struct bpfsnoop_sess *
get_and_del_session(__u64 fp)
{
    struct bpfsnoop_sess *sess;

    sess = (typeof(sess)) bpf_map_lookup_elem(&bpfsnoop_sessions, &fp);
    if (sess)
        (void) bpf_map_delete_elem(&bpfsnoop_sessions, &fp);

    return sess;
}

#endif // __BPFSNOOP_SESS_H_
