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
 * |  lr  | IP of tracee
 * |  fp  | FP of tracee
 * +------+ FP of trampoline  <-------+
 * |  ..  | padding                   |
 * |  ..  | callee saved regs         |
 * | retv | retval of tracee          |
 * | regs | regs of tracee            |
 * | nreg | number of regs            |
 * |  ip  | IP of tracee if needed    | possible range of
 * | rctx | bpf_tramp_run_ctx         | detection
 * |  lr  | IP of trampoline          |
 * |  fp  | FP of trampoline  <--------- detect it
 * +------+ FP of current prog        |
 * | regs | callee saved regs         |
 * +------+ R10 of bpf prog   <-------+
 * |  ..  |
 * +------+ SP of current prog
 */

static __always_inline u64
get_tracing_fp(void)
{
	u64 fp;

	/* get frame pointer */
	asm volatile ("%[fp] = r10" : [fp] "+r"(fp) :);
	return fp;
}

#if defined(bpf_target_x86)
static __always_inline u64
get_tramp_fp(void)
{
	u64 fp, fp_tramp = 0;

	fp = get_tracing_fp();
	bpf_probe_read_kernel(&fp_tramp, sizeof(fp_tramp), (void *) fp);
	return fp_tramp;
}

#elif defined(bpf_target_arm64)
/* As R10 of bpf is not A64_FP, we need to detect the FP of trampoline
 * by scanning the stacks of current bpf prog and the trampoline.
 *
 * Since commit 5d4fa9ec5643 ("bpf, arm64: Avoid blindly saving/restoring all callee-saved registers"),
 * the number of callee-saved registers saved in the bpf prog prologue is
 * dynamic, not fixed anymore.
 */
static __always_inline u64
detect_tramp_fp(void)
{
	static const int range_of_detection = 256;
	u64 fp, r10;

	r10 = get_tracing_fp(); /* R10 of current bpf prog */
	for (int i = 6; i >= 0; i--) {
		bpf_probe_read_kernel(&fp, sizeof(fp), (void *) (r10 + i * 16));
		if (r10 < fp && fp < r10 + range_of_detection)
			return fp;
	}

	return r10;
}

static __always_inline u64
get_tramp_fp(void)
{
	return detect_tramp_fp();
}
#else
# error "Unsupported architecture for bpfsnoop"
#endif

#endif // __BPFSNOOP_STACK_H_
