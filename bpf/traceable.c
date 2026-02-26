// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2025 Leon Hwang */

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

#define ADDR_CAP 1024

volatile const u64 addrs[ADDR_CAP];
volatile const u32 nr_addrs SEC(".rodata.nr_addrs");
volatile const u32 has_endbr SEC(".rodata.endbr") = 0;
bool traceables[ADDR_CAP];
bool run SEC(".data.run");

static inline bool loongarch_is_call_insn(u32 insn)
{
    u32 op = insn >> 26;        // bits [31:26]
    u32 rd = insn & 0x1f;       // bits [4:0]

    /* BL */
    if (op == 0x15)                  // bl
        return true;

    /* JIRL with link: rd == $ra (1) */
    if (op == 0x13 && rd == 1)       // jirl && LOONGARCH_GPR_RA
        return true;

    return false;
}

static __noinline bool
is_traceable(u64 addr)
{
    u8 buff[16], *ptr;

    if (bpf_probe_read_kernel(&buff, 16, (void *) addr))
        return false;

#if defined(bpf_target_x86)
    static const u64 nop5 = 0x0000441F0F;
    u64 a, b;

    ptr = has_endbr ? buff + 4 : buff;
    /* Avoid 'misaligned stack access off 0+-12+0 size 8' */
    a = *(u32 *) ptr;
    b = *(u8 *) (ptr + 4);
    return (b<<32 | a) == nop5 /* nop5 */ || ptr[0] == 0xE8 /* callq */;

#elif defined(bpf_target_arm64)
    ptr = buff + 4;
    u32 insn = *(u32 *) ptr;

    return insn == 0xD503201F /* nop */ || ptr[3] == 0x97 /* bl */ ||
           ptr[3] == 0x94 /* blr */;

#elif defined(bpf_target_loongarch)
    static const u64 nop = 0x03400000;

    ptr = buff + 4;
    u32 insn = *(u32 *) ptr;

    return insn == nop || loongarch_is_call_insn(insn);
#else
# error "Unsupported architecture"
#endif
}

SEC("fentry/__x64_sys_nanosleep")
int BPF_PROG(detect, struct pt_regs *regs)
{
    if (run)
        return BPF_OK;
    run = true;

    for (int i = 0; i < ADDR_CAP; i++) {
        if (i >= nr_addrs)
            break;
        traceables[i] = is_traceable(addrs[i]);
    }

    return BPF_OK;
}

char __license[] SEC("license") = "GPL";
