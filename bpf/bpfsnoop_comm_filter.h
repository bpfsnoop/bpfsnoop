// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

#ifndef __BPFSNOOP_COMM_FILTER_H_
#define __BPFSNOOP_COMM_FILTER_H_

#include "vmlinux.h"

#include "bpfsnoop_cfg.h"

static __always_inline bool
filter_comm(__u8 comm[16])
{
    if (!cfg->comm_len)
        return true;

#pragma unroll
    for (__u32 i = 0; i < 16; i++) {
        if (i == cfg->comm_len)
            return comm[i] == '\0';
        if (cfg->comm[i] != comm[i])
            return false;
    }

    return true;
}

#endif // __BPFSNOOP_COMM_FILTER_H_
