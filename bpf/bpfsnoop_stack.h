// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2025 Leon Hwang */

#ifndef __BPFSNOOP_STACK_H_
#define __BPFSNOOP_STACK_H_

#include "vmlinux.h"
#include "bpf_helpers.h"

/* Stack layout on x86:
 * +-----+ FP of tracee's caller
 * | ... |
 * | rip | IP of tracee's caller
 * | rip | IP of tracee
 * | rbp | FP of tracee's caller
 * +-----+ FP of trampoline
 * | ret | retval on stack
 * | arg | args[...]
 * +-----+ ctx of current prog
 * | ... |
 * | rip | IP of trampoline
 * | rbp | FP of trampoline
 * +-----+ FP of current prog
 * | ... |
 * +-----+ SP of current prog
 *
 * Stack layout on loongarch:
 * +-----+ FP of tracee's caller
 * | ... |
 * | ret | return address
 * | rbp | FP of tracee's caller
 * +-----+ FP of trampoline
 * | ret | return address
 * | rbp | FP of tracee
 * | R0  | retval on stack
 * | A0  | retval on stack
 * | arg | args[...]
 * +-----+ ctx of current prog
 * | ... |
 * | rip | IP of trampoline
 * | rbp | FP of trampoline
 * +-----+ FP of current prog
 * | ... |
 * +-----+ SP of current prog
 *
 * Stack layout on arm64:
 * |  r9  |
 * |  fp  | FP of tracee's caller
 * +------+ FP of tracee
 * |  lr  | IP of tracee
 * |  fp  | FP of tracee
 * +------+ FP of trampoline  <--------- detect it
 * |  ..  | padding
 * |  ..  | x19, x20
 * | retv | retval of tracee
 * | regs | regs of tracee
 * +------+ ctx of bpf prog
 * | nreg | number of regs
 * |  ip  | IP of tracee if needed
 * | rctx | bpf_tramp_run_ctx
 * |  lr  | IP of trampoline
 * |  fp  | FP of trampoline
 * +------+ FP of current prog
 * | regs | callee saved regs
 * +------+ R10 of bpf prog
 * |  ..  |
 * +------+ SP of current prog
 */

static __always_inline u64
__get_ptr(void *ctx, __u32 args_nr, bool retval)
{
	int offset;

	offset = (args_nr & 0xF) * 8; /* each arg is 8 bytes */
	offset += retval ? 8 : 0; /* retval */
	return (__u64) ctx + offset;
}

#if defined(bpf_target_x86)
static __always_inline u64
get_tramp_fp(void *ctx, __u32 args_nr, bool retval)
{
	return __get_ptr(ctx, args_nr, retval);
}

#elif defined(bpf_target_loongarch)
static __always_inline u64
get_tramp_fp(void *ctx, __u32 args_nr, bool retval)
{
	int offset;

	offset = (args_nr & 0xF) * 8; /* each arg is 8 bytes */
	offset += retval ? 16 : 0; /* retval */
	offset += 16; /* room for return address and frame pointer */
	return (__u64) ctx + offset;
}

#elif defined(bpf_target_arm64)

/* This offset is different for each tracee because of the number of tracee's
 * arguments.
 *
 * It's the bytes number between ctx and the true fp of tracee.
 */
u32 tramp_fp_offset;

/* As R10 of bpf is not A64_FP, we need to detect the FP of trampoline
 * by scanning the stack of the trampoline.
 *
 * Since commit 5d4fa9ec5643 ("bpf, arm64: Avoid blindly saving/restoring all callee-saved registers"),
 * the number of callee-saved registers saved in the bpf prog prologue is
 * dynamic, not fixed anymore.
 *
 * Since commit 9014cf56f13d ("bpf, arm64: Support up to 12 function arguments"),
 * the stack layout of the trampoline becomes more complicate.
 *
 * To get rid of the complicate stack layout, detect the FP of the
 * trampoline by utilizing `ctx` of current prog and checking tracee's IP.
 */
static __always_inline u64
detect_tramp_fp_offset(void *ctx, bool retval)
{
	__u32 nregs = bpf_get_func_arg_cnt(ctx);
	__u64 fp, ptr, ip;

	ip = bpf_get_func_ip(ctx);
	ip += 8; /* The IP of tracee stored on stack has 8B far from its original entry. */
	ptr = __get_ptr(ctx, nregs, retval);
	ptr += 16; /* x19 and x20 always */

	for (int i = 0; i < 6; i++) {
		fp = bpf_probe_read_kernel(&fp, sizeof(fp), (void *) (ptr + i * 8));
		if (fp == ip) {
			tramp_fp_offset = i * 8 - 8;
			return fp - 8;
		}
	}

	return ptr;
}

static __always_inline u64
get_tramp_fp(void *ctx, __u32 args_nr, bool retval)
{
	u64 fp;

	if (tramp_fp_offset) {
		(void) bpf_probe_read_kernel(&fp, sizeof(fp), ctx + tramp_fp_offset);
		return fp;
	}

	fp = detect_tramp_fp_offset(ctx, retval);
	return fp;
}
#else
# error "Unsupported architecture for bpfsnoop"
#endif

#endif // __BPFSNOOP_STACK_H_
