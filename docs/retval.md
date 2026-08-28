# Typed return values

`--filter-arg` and `--output-arg` expose a function return value as `$retval` when exit tracing is enabled. The pseudo-variable always requires an explicit concrete cast:

```sh
bpfsnoop -k tcp_v4_connect -m exit \
  --filter-arg '(int)$retval != 0' \
  --output-arg '(int)$retval'
```

The cast must match the function's declared return type after BTF typedef and qualifier wrappers are removed. For example, `(int)$retval` does not select a pointer-returning function. `$retval` is distinct from a real parameter named `retval`.

Return expressions work in `--mode exit` and `--mode entry,exit`. An entry-only target is skipped when its filter needs `$retval`, while return-only output expressions are ignored. Tracepoints and void-returning functions do not provide `$retval`.

In combined entry/exit mode, a return-dependent filter is evaluated at exit. bpfsnoop buffers the related entry, function-graph, and instruction data until that decision is known. A rejected session produces no output, does not consume `--limit-events`, and does not update histogram, t-digest, or flamegraph aggregates.

Packet options use only real function parameters by default. Prefix them with `(r)` to explicitly select a packet-typed return value:

```sh
bpfsnoop -k skb_recv_datagram -m exit \
  --filter-pkt '(r) icmp' \
  --output-pkt '(r)'
```

The same deferred decision applies to packet-return filters in combined entry/exit, function-graph, and instruction tracing.
