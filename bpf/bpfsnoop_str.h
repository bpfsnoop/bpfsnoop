// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2025 Leon Hwang */

#ifndef __BPFSNOOP_STR_H_
#define __BPFSNOOP_STR_H_

#include "vmlinux.h"

#include "bpf_helpers.h"

#include "bpfsnoop.h"

struct bpfsnoop_str_data {
    __u8 arg[32];
    __u8 ret[32];
};

struct bpfsnoop_str_data bpfsnoop_str_buff[1] SEC(".data.strs");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, BPFSNOOP_MAX_ENTRIES);
    __type(key, __u64);
    __type(value, struct bpfsnoop_str_data);
} bpfsnoop_strs SEC(".maps");

static __always_inline void
output_fn_data(struct event *event, void *ctx, void *retval, struct bpfsnoop_str_data *str)
{
    const volatile struct bpfsnoop_fn_arg_flags *arg_flags;
    const volatile struct bpfsnoop_fn_args *arg_cfg;
    bool is_str, is_number_ptr, use_str = false;
    struct bpfsnoop_fn_arg_data *arg_data;
    __u64 arg;
    __u32 i;

    arg_cfg = &cfg->fn_args;
    for (i = 0; i < MAX_FN_ARGS; i++) {
        if (i >= cfg->fn_args.nr_fn_args)
            break;

        (void) bpf_get_func_arg(ctx, i, &arg); /* required 5.17 kernel. */

        arg_data = &event->fn_data.args[i];
        arg_data->raw_data = arg;

        if (!arg)
            continue;

        arg_flags = &arg_cfg->args[i];
        is_str = arg_flags->is_str;
        is_number_ptr = arg_flags->is_number_ptr;
        if (is_str) {
            use_str = true;
            (void) bpf_probe_read_kernel_str(&str->arg, sizeof(str->arg), (void *) arg);
        } else if (is_number_ptr) {
            (void) bpf_probe_read_kernel(&arg_data->ptr_data, sizeof(arg_data->ptr_data), (void *) arg);
        }
    }

    if (cfg->is_ret_str && retval) {
        use_str = true;
        (void) bpf_probe_read_kernel_str(&str->ret, sizeof(str->ret), (void *) retval);
    }

    if (use_str)
        (void) bpf_map_update_elem(&bpfsnoop_strs, &event->session_id, str, BPF_ANY);
}

static __noinline bool
filter_fnarg(void *ctx)
{
    return ctx != NULL;
}

static __always_inline void
output_fn_data_vol(struct event *event, struct bpfsnoop_str_data *str, volatile __u64 *args)
{
    const volatile struct bpfsnoop_fn_arg_flags *arg_flags;
    const volatile struct bpfsnoop_fn_args *arg_cfg;
    bool is_str, is_number_ptr, use_str = false;
    struct bpfsnoop_fn_arg_data *arg_data;
    __u64 arg;
    __u32 i;

    arg_cfg = &cfg->fn_args;
    for (i = 0; i < MAX_FN_ARGS; i++) {
        if (i >= arg_cfg->nr_fn_args)
            break;

        arg = args[i];
        arg_data = &event->fn_data.args[i];
        arg_data->raw_data = arg;

        if (!arg)
            continue;

        arg_flags = &arg_cfg->args[i];
        is_str = arg_flags->is_str;
        is_number_ptr = arg_flags->is_number_ptr;
        if (is_str) {
            use_str = true;
            (void) bpf_probe_read_kernel_str(&str->arg, sizeof(str->arg), (void *) arg);
        } else if (is_number_ptr) {
            (void) bpf_probe_read_kernel(&arg_data->ptr_data, sizeof(arg_data->ptr_data), (void *) arg);
        }
    }

    if (use_str)
        (void) bpf_map_update_elem(&bpfsnoop_strs, &event->session_id, str, BPF_ANY);
}

#endif // __BPFSNOOP_STR_H_
