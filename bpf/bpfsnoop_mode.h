// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2026 Leon Hwang */

#ifndef __BPFSNOOP_MODE_H_
#define __BPFSNOOP_MODE_H_

#include "vmlinux.h"

#include "bpf_helpers.h"

#include "bpfsnoop_cfg.h"
#include "bpfsnoop_tracing.h"

enum bpfsnoop_mode {
    BPFSNOOP_MODE_ENTRY = 0,
    BPFSNOOP_MODE_EXIT,
    BPFSNOOP_MODE_SESSION_ENTRY,
    BPFSNOOP_MODE_SESSION_EXIT,
};

static __always_inline enum bpfsnoop_mode
get_bpfsnoop_mode(void *ctx)
{
    bool is_entry = cfg->flags.is_entry;

    if (cfg->flags.both_entry_exit && cfg->flags.is_session)
        is_entry = !bpf_session_is_return(ctx);

    if (cfg->flags.both_entry_exit)
        return is_entry ? BPFSNOOP_MODE_SESSION_ENTRY : BPFSNOOP_MODE_SESSION_EXIT;

    return is_entry ? BPFSNOOP_MODE_ENTRY : BPFSNOOP_MODE_EXIT;
}

#endif // __BPFSNOOP_MODE_H_
