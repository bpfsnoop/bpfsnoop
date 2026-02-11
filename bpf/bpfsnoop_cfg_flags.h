// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2026 Leon Hwang */

#ifndef __BPFSNOOP_CFG_FLAGS_H_
#define __BPFSNOOP_CFG_FLAGS_H_

#include "vmlinux.h"

#define TRACEE_FLAGS                    \
    union {                             \
        struct {                        \
            __u32 output_lbr:1;         \
            __u32 output_stack:1;       \
            __u32 output_pkt:1;         \
            __u32 output_arg:1;         \
            __u32 both_entry_exit:1;    \
            __u32 is_entry:1;           \
            __u32 is_session:1;         \
            __u32 insn_mode:1;          \
            __u32 graph_mode:1;         \
            __u32 is_tp:1;              \
            __u32 is_prog:1;            \
            __u32 kmulti_mode:1;        \
            __u32 pad:20;               \
        } flags;                        \
        __u32 tracee_flags;             \
    }

#endif // __BPFSNOOP_CFG_FLAGS_H_
