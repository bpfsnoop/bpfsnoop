// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2025 Leon Hwang */

#ifndef __BPFSNOOP_CFG_H_
#define __BPFSNOOP_CFG_H_

#include "vmlinux.h"

#include "bpfsnoop.h"

struct bpfsnoop_fn_args {
    __u32 args_nr;
    bool with_retval;
    __u8 pad[3];
    __u32 buf_size;
    __u32 data_size;
} __attribute__((packed));

struct bpfsnoop_config {
    union {
        struct {
            __u32 output_lbr:1;
            __u32 output_stack:1;
            __u32 output_pkt:1;
            __u32 output_arg:1;
            __u32 both_entry_exit:1;
            __u32 is_entry:1;
            __u32 is_session:1;
            __u32 insn_mode:1;
            __u32 graph_mode:1;
            __u32 is_tp:1;
            __u32 is_prog:1;
            __u32 kmulti_mode:1;
            __u32 pad:20;
        } flags;
        __u32 tracee_flags;
    };
    __u32 pid;

    struct bpfsnoop_fn_args fn_args;
    __u32 tracee_arg_entry_size;
    __u32 tracee_arg_exit_size;
    __u32 tracee_arg_data_size;
} __attribute__((packed));

volatile const struct bpfsnoop_config bpfsnoop_config = {};
#define cfg (&bpfsnoop_config)

#endif // __BPFSNOOP_CFG_H_
