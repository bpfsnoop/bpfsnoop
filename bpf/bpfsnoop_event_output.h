// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2026 Leon Hwang */

#ifndef __BPFSNOOP_EVENT_OUTPUT_H_
#define __BPFSNOOP_EVENT_OUTPUT_H_

#include "vmlinux.h"

#include "bpf_helpers.h"

#include "bpfsnoop_arg_output.h"
#include "bpfsnoop_cfg.h"
#include "bpfsnoop_event.h"
#include "bpfsnoop_fn_args_output.h"
#include "bpfsnoop_lbr.h"
#include "bpfsnoop_pkt.h"
#include "bpfsnoop_pkt_output.h"
#include "bpfsnoop_stack_map.h"

static __always_inline int
output_event(void *ctx, __u16 event_type, __u64 session_id, __u64 func_ip,
             __u32 cpu, __u32 pid, struct bpfsnoop_lbr_data *lbr,
             bool can_output_lbr, __u64 *args, __u64 retval)
{
    void *buffer, *ptr;
    struct event *evt;
    size_t buffer_sz;

    buffer_sz = sizeof(*evt) + cfg->fn_args.buf_size + cfg->fn_args.data_size;
    buffer_sz += cfg->flags.output_pkt ? sizeof(struct bpfsnoop_pkt_data) : 0;
    buffer = bpf_ringbuf_reserve(&bpfsnoop_events, buffer_sz, 0);
    if (!buffer)
        return BPF_OK;

    evt = buffer;
    evt->type = event_type;
    evt->length = sizeof(*evt);
    evt->kernel_ts = (__u32) bpf_ktime_get_ns();
    evt->session_id = session_id;
    evt->func_ip = func_ip;
    evt->cpu = cpu;
    evt->pid = pid;
    bpf_get_current_comm(evt->comm, sizeof(evt->comm));
    evt->func_stack_id = -1;
    evt->tracee_flags = cfg->tracee_flags;
    evt->tracee_arg_entry_size = cfg->tracee_arg_entry_size;
    evt->tracee_arg_exit_size = cfg->tracee_arg_exit_size;
    evt->tracee_arg_data_size = cfg->tracee_arg_data_size;
    if (cfg->flags.output_stack)
        evt->func_stack_id = bpf_get_stackid(ctx, &bpfsnoop_stacks, BPF_F_FAST_STACK_CMP);
    if (cfg->flags.output_lbr && can_output_lbr)
        output_lbr_data(lbr, session_id);

    ptr = buffer + sizeof(*evt);
    output_fn_args(args, ptr, retval);
    ptr += cfg->fn_args.buf_size;
    if (cfg->flags.output_pkt) {
        output_pkt(args, ptr);
        ptr += sizeof(struct bpfsnoop_pkt_data);
    }
    if (cfg->flags.output_arg) {
        output_arg(args, ptr);
        ptr += cfg->fn_args.data_size;
    }

    bpf_ringbuf_submit(evt, 0);
    return BPF_OK;
}

#endif // __BPFSNOOP_EVENT_OUTPUT_H_
