// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2025 Leon Hwang */

#ifndef __BPFSNOOP_PKT_FILTER_H_
#define __BPFSNOOP_PKT_FILTER_H_

#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_core_read.h"

enum {
    FILTER_PKT_SKB = 0,
    FILTER_PKT_XDP,
    FILTER_PKT_XDP_FRAME,
};

static __noinline bool
filter_pcap_l2(void *_pkt, void *__pkt , void *___pkt, void *data, void *data_end)
{
    return _pkt == __pkt && _pkt == ___pkt && data != data_end;
}

static __noinline bool
filter_pcap_l3(void *_pkt, void *__pkt , void *___pkt, void *data, void *data_end)
{
    return _pkt == __pkt && _pkt == ___pkt && data != data_end;
}

static __noinline bool
filter_skb(struct sk_buff *skb)
{
    void *head = (void *) BPF_CORE_READ(skb, head);
    void *data, *data_end;
    __u16 mac_len;

    mac_len = BPF_CORE_READ(skb, mac_len);
    data = head + (mac_len ? BPF_CORE_READ(skb, mac_header)
                           : BPF_CORE_READ(skb, network_header));
    data_end = head + BPF_CORE_READ(skb, tail);

    return mac_len ? filter_pcap_l2(skb, skb, skb, data, data_end)
                   : filter_pcap_l3(skb, skb, skb, data, data_end);
}

static __noinline bool
filter_xdp(struct xdp_buff *xdp)
{
    void *data = (void *) BPF_CORE_READ(xdp, data);
    void *data_end = (void *) BPF_CORE_READ(xdp, data_end);

    return filter_pcap_l2(xdp, xdp, xdp, data, data_end);
}

static __noinline bool
filter_xdp_frame(struct xdp_frame *xdp_frame)
{
    void *data = (void *) BPF_CORE_READ(xdp_frame, data);
    void *data_end = data + BPF_CORE_READ(xdp_frame, len);

    return filter_pcap_l2(xdp_frame, xdp_frame, xdp_frame, data, data_end);
}

static __noinline bool
filter_pkt(__u64 *args, int filter)
{
    /* This function will be rewrote by Go totally. */
    switch (filter) {
    case FILTER_PKT_XDP:
        return filter_xdp((struct xdp_buff *) args[0]);

    case FILTER_PKT_XDP_FRAME:
        return filter_xdp_frame((struct xdp_frame *) args[0]);

    default:
        return filter_skb((struct sk_buff *) args[0]);
    }
}

#endif // __BPFSNOOP_PKT_FILTER_H_
