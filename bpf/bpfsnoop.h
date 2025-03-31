// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2025 Leon Hwang */

#ifndef __BPFSNOOP_H_
#define __BPFSNOOP_H_

#include "vmlinux.h"

#define BPFSNOOP_MAX_ENTRIES 65536

struct bpfsnoop_fn_arg_flags {
    bool is_number_ptr;
    bool is_str;
};

#define MAX_FN_ARGS 12
struct bpfsnoop_fn_args {
    struct bpfsnoop_fn_arg_flags args[MAX_FN_ARGS];
    __u32 nr_fn_args;
    struct bpfsnoop_fn_arg_flags ret;
    bool with_retval;
    __u8 pad;
} __attribute__((packed));

struct bpfsnoop_config {
    __u32 output_lbr:1;
    __u32 output_stack:1;
    __u32 output_pkt:1;
    __u32 output_arg:1;
    __u32 pad:28;
    __u32 pid;

    struct bpfsnoop_fn_args fn_args;
} __attribute__((packed));

volatile const struct bpfsnoop_config bpfsnoop_config = {};
#define cfg (&bpfsnoop_config)

struct bpfsnoop_fn_arg_data {
    __u64 raw_data;
    __u64 ptr_data;
};

struct bpfsnoop_fn_data {
    struct bpfsnoop_fn_arg_data retval;
    struct bpfsnoop_fn_arg_data args[MAX_FN_ARGS];
};

struct event {
    __u64 session_id;
    __u64 func_ip;
    __u32 cpu;
    __u32 pid;
    __u8 comm[16];
    __s64 func_stack_id;

    /* fn_data must be the last attr of event in order to output arg data on
     * demand.
     */
    struct bpfsnoop_fn_data fn_data;
};

#endif // __BPFSNOOP_H_
