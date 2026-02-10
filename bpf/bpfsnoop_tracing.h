// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2026 Leon Hwang */

#ifndef __BPFSNOOP_TRACING_H_
#define __BPFSNOOP_TRACING_H_

#include "vmlinux.h"

#include "bpf_helpers.h"

extern __u64 *bpf_session_cookie(void *ctx) __weak __ksym;
extern bool bpf_session_is_return(void *ctx) __weak __ksym;

#endif // __BPFSNOOP_TRACING_H_
