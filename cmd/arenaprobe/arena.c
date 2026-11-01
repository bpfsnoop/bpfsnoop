// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2026 Liang Tang */

//go:build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

/* arenaprobe mmaps this arena and builds a two-node list in it, then runs
 * arena_main, which passes pointers into the arena to the funcs below for
 * bpfsnoop to trace.
 */
struct {
    __uint(type, 33 /* BPF_MAP_TYPE_ARENA, may be absent from older vmlinux.h */);
    __uint(map_flags, BPF_F_MMAPABLE);
    __uint(max_entries, 1); /* pages */
} arenaprobe SEC(".maps");

/* A pointer into the arena, address space 1 for the compiler. */
#define __arena __attribute__((address_space(1)))
/* Tells the verifier, and bpfsnoop through BTF, that an argument of a global
 * function points into the arena.
 */
#define __arg_arena __attribute((btf_decl_tag("arg:arena")))

/* Keep in sync with main.go. */
struct arena_node {
    int val;
    char name[12];
    struct arena_node __arena *next;
};

/* After the list, a kernel pointer stored in the arena. */
struct arena_task {
    struct task_struct *task;
};

/* The user address of the first node, set by arenaprobe before loading. */
volatile const __u64 head;
volatile const __u64 task_off;

/* Traced by the arena tests. Global, so the verifier checks them on their own
 * and honors the arg:arena tag.
 */
__noinline int arena_probe(struct arena_node __arena *n __arg_arena)
{
    return n != NULL;
}

/* Like arena_probe, with a number pointer, whose pointee bpfsnoop prints. */
__noinline int arena_probe_val(int __arena *val __arg_arena)
{
    return val != NULL;
}

__noinline int arena_probe_task(struct arena_task __arena *t __arg_arena)
{
    return t != NULL;
}

SEC("xdp")
int arena_main(struct xdp_md *ctx)
{
    int ret;

    /* Associate the arena with this program: a program can use one arena,
     * and it must reference the arena map.
     */
    asm volatile("" :: "r"(&arenaprobe));

    ret = arena_probe((struct arena_node __arena *) head);
    asm volatile("" :: "r"(ret));
    ret = arena_probe_val((int __arena *) head);
    asm volatile("" :: "r"(ret));
    ret = arena_probe_task((struct arena_task __arena *) (head + task_off));
    asm volatile("" :: "r"(ret));

    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
