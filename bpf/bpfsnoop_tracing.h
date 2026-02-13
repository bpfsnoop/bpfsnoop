// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2026 Leon Hwang */

#ifndef __BPFSNOOP_TRACING_H_
#define __BPFSNOOP_TRACING_H_

#include "vmlinux.h"

#include "bpf_helpers.h"

/*
 * Unused actually.
 *
 * It is to avoid making kprobe_write_ctx.
 */
static volatile __u64 __cookie;

/*
 * The following two stub functions will be dropped by Go, when it is
 * going to run with kprobe.session or fsession.
 *
 * Meanwhile, the callsites of them will be patched with the
 * corresponding kfunc call insn.
 */

static __noinline __u64 *
bpfsnoop_session_cookie(void *ctx)
{
    return (__u64 *) &__cookie;
}

static __noinline bool
bpfsnoop_session_is_return(void *ctx)
{
    return ctx != NULL;
}

#endif // __BPFSNOOP_TRACING_H_
