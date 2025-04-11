// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2025 Leon Hwang */

#ifndef __BPFSNOOP_CFG_H_
#define __BPFSNOOP_CFG_H_

#include "vmlinux.h"

#include "bpfsnoop.h"

struct bpfsnoop_fn_arg_flags {
    bool is_number_ptr;
    bool is_str;
};

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
    __u32 both_entry_exit:1;
    __u32 is_entry:1;
    __u32 pad:26;
    __u32 pid;

    struct bpfsnoop_fn_args fn_args;
} __attribute__((packed));

volatile const struct bpfsnoop_config bpfsnoop_config = {};
#define cfg (&bpfsnoop_config)

#endif // __BPFSNOOP_CFG_H_
