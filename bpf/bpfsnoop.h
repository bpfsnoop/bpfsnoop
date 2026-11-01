// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2025 Leon Hwang */

#ifndef __BPFSNOOP_H_
#define __BPFSNOOP_H_

#define BPFSNOOP_MAX_ENTRIES 65536
#define MAX_FN_ARGS 12

/* A func that no C code calls, for the insns that bpfsnoop generates. Loading
 * links it into the progs whose insns call it. It stays static, so that the
 * verifier checks it with the args of each call.
 */
#define __stub SEC(".text.stub") static __noinline

const volatile bool has_percpu_data = false;

#endif // __BPFSNOOP_H_
