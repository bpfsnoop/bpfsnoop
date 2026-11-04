// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2026 Liang Tang */

#ifndef __BPFSNOOP_STR_H_
#define __BPFSNOOP_STR_H_

#include "vmlinux.h"

#include "bpf_helpers.h"

#include "bpfsnoop_cfg.h"
#include "bpfsnoop_event.h"

/* The most bytes of a string compared with a literal, with its NUL. A literal
 * takes this many bytes in .rodata.strlit, with its NUL and zero padding.
 *
 * The string is read to a buffer of this size reserved from the event ringbuf
 * of the CPU, as the stack is too small: the kernel limits the stacks of the
 * prog and of the funcs it calls to 512 bytes together.
 */
#define BPFSNOOP_STRLIT_SIZE 256

/* The string literals that str() is compared with, and their lengths with the
 * NUL. bpfsnoop sizes and fills them when loading the prog.
 */
const volatile char bpfsnoop_strlit[1] SEC(".rodata.strlit");
const volatile __u32 bpfsnoop_strlit_len[1] SEC(".rodata.strlit.length");

/* bpfsnoop_str_eq reports whether the string at src, of at most size bytes with
 * its NUL, equals string literal idx. The insns of 'str(x) == "..."' call it.
 *
 * The string is read once, and its length tells most differences. Then it's
 * compared with bpf_strncmp(), or 8 bytes at a time without it. A NULL or
 * unreadable string equals no literal, and so does any string if the ringbuf
 * is full.
 */
__stub bool
bpfsnoop_str_eq(const void *src, __u32 size, __u32 idx)
{
    const volatile __u32 *lens = bpfsnoop_strlit_len;
    const volatile char *lits = bpfsnoop_strlit;
    bool eq = false;
    void *ringbuf;
    char *s;

    /* The arrays are resized when loading: hide their size from the
     * compiler, which would take idx for 0 otherwise.
     */
    barrier_var(lens);
    barrier_var(lits);

    const volatile char *lit = lits + idx * BPFSNOOP_STRLIT_SIZE;
    __u32 len = lens[idx];

    if (len == 0 || len > BPFSNOOP_STRLIT_SIZE)
        return false;
    if (size > BPFSNOOP_STRLIT_SIZE)
        size = BPFSNOOP_STRLIT_SIZE;

    /* The buffer is discarded in the end without waking the reader of the
     * ringbuf, which bpfsnoop wakes regularly instead: see flushPending() in
     * internal/bpfsnoop/event_reader.go.
     */
    ringbuf = bpfsnoop_event_ringbuf(bpf_get_smp_processor_id());
    if (!ringbuf)
        return false;
    s = bpf_ringbuf_reserve(ringbuf, BPFSNOOP_STRLIT_SIZE, 0);
    if (!s)
        return false;

    /* bpf_probe_read_kernel_str() leaves the bytes after the NUL as they are.
     * Zero the last 8 bytes to compare, which hold the NUL, first.
     */
    *(__u64 *) &s[(len - 1) & ~7] = 0;

    if (bpf_probe_read_kernel_str(s, size, src) != len)
        goto out;

    /* has_strncmp tells whether the kernel has bpf_strncmp(), since 5.17: the
     * verifier drops the code of the other case. The literal must be at a
     * constant offset in .rodata.strlit: idx is a constant in the insns
     * calling this func.
     */
    if (cfg->flags.has_strncmp) {
        eq = bpf_strncmp(s, BPFSNOOP_STRLIT_SIZE, (const char *) lit) == 0;
        goto out;
    }

    eq = true;
    for (__u32 i = 0; i < len; i += 8) {
        if (*(__u64 *) &s[i] != *(const volatile __u64 *) &lit[i]) {
            eq = false;
            break;
        }
    }

out:
    bpf_ringbuf_discard(s, BPF_RB_NO_WAKEUP);
    return eq;
}

#endif // __BPFSNOOP_STR_H_
