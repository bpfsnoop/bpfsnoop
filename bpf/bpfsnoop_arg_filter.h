// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2025 Leon Hwang */

#ifndef __BPFSNOOP_ARG_FILTER_H_
#define __BPFSNOOP_ARG_FILTER_H_

#include "vmlinux.h"

#include "bpf_helpers.h"

static __noinline bool
filter_arg(__u64 *args)
{
    return args != NULL;
}

#endif // __BPFSNOOP_ARG_FILTER_H_
