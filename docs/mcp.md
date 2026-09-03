<!--
 Copyright 2026 Leon Hwang.
 SPDX-License-Identifier: Apache-2.0
-->

# bpfsnoop MCP server

The `bpfsnoop-mcp` launcher makes bpfsnoop available to MCP clients. Configure
an agent to run this launcher directly; it handles communication with the
privileged bpfsnoop daemon.

## Tools

The initial tool surface is:

- `kernel_info`: inspect the running kernel and bpfsnoop tracing capabilities;
- `find`: discover kernel functions, tracepoints, loaded BPF programs, and BTF
  types;
- `read`: evaluate typed C expressions against kernel memory;
- `disasm`: inspect bounded native disassembly for a kernel function or loaded
  BPF program;
- `trace`: run one bounded tracing experiment and return structured events;
- `abort`: cancel the active trace without closing the MCP session.

All six tools are available. `trace` supports kernel-function, tracepoint, and
loaded BPF program targets.

`read` accepts one or more typed C expressions and returns ordered records with
separate `expression`, `type`, and `value` fields. Values use native JSON types:
arrays are arrays, structs and unions are objects, and scalar values remain
numbers, strings, booleans, or null. Integers outside JSON's exact integer range
are returned as decimal strings to avoid precision loss in MCP clients.

`disasm` returns bounded structured native instructions for an exact kernel
function, kernel address, loaded BPF program, or BPF subprogram. Each
instruction carries its source location when line metadata is available.
Resolved direct branch and call targets also carry their symbol, offset, and
source location. BPF metadata can include file, line, column, and source text;
kernel and module DWARF can additionally identify inlined locations. Missing
debug symbols do not prevent disassembly.

`trace` runs one bounded experiment. It accepts kernel-function names or globs,
tracepoint names, and loaded BPF program IDs or program names with an optional
exact subprogram name. Function targets default to fentry/fexit and may select
`kprobe_multi` explicitly. fentry/fexit requests may resolve to at most 200
kernel functions. A kprobe.multi request has no function-count cap, and the
number of loaded BPF program targets is not capped. kprobe.multi without a
common typed argument does not support an argument expression filter.

Optional filters select PID, exact `comm`, a bpfsnoop argument expression, and
a pcap packet expression. Capture switches control typed arguments, selected
argument expressions, return values, duration, structured packet tuples,
kernel stacks, aggregated flame graphs, function graphs, and executed native
instructions. Omitting `capture` returns arguments and the return value.
Requesting duration pairs function entry and exit and implies a return value.
Function-graph depth defaults to 3 and is capped at 20. Executed instructions
require fentry kernel-function targets and cannot be combined with a function
graph.

The duration defaults to 3000 ms and must be between 100 and 30000 ms. The
event limit defaults to 100 and must be between 1 and 1000. Duration starts
only after all tracing programs have attached. Results report `stopped_by` as
`duration`, `max_events`, or `abort`, statistics, and ordered structured
events. Values retain their BTF type and native JSON representation where
possible; pointers and integers outside JSON's exact range are strings.

Use `abort` when a trace is waiting for an event that cannot be triggered. It
waits for tracing resources to be released, leaves the MCP session connected,
and reports whether an active trace was found. The interrupted `trace` call
returns any events already collected with `status: "aborted"`.

`find` accepts an exact name or glob pattern. Its optional `kind` narrows the
search to `function`, `tracepoint`, `bpf_program`, or `btf_type`; omitting it
searches all four classes. Results are capped at 50 by default and 200 at most.
The `total` and `truncated` fields help agents refine broad queries.

Function results include their prototypes, arguments, return types, BTF IDs,
symbol addresses, modules, sizes, and traceability through fentry, fexit, and
kprobe.multi. Functions that are not traceable are still returned.

BPF program results include identifiers, names, type, tag, load information,
sizes, referenced map IDs, BTF function and line information, and available
JIT metadata. Instruction payloads are omitted by default. With
`kind: "bpf_program"`, use `include_xlated_insns` to request translated eBPF
instructions or `include_jited_insns` to request JITed native instruction
bytes.

BTF type results include details appropriate to each type, such as struct and
union members, function arguments and return types, array dimensions, enum
values, integer encoding, linkage, data-section variables, tags, and forward
declarations.

## Build

```sh
make bpfsnoop
```

## Start the daemon

Kernel and BPF inspection requires root privilege. Start the daemon in a user
terminal and leave it running:

```sh
sudo ./bpfsnoop-mcp-daemon
```

When launched through `sudo`, the daemon permits only the invoking user to
connect. The daemon serves one active MCP session at a time; another frontend
is rejected immediately and can retry after the active session ends.

If the daemon is not available, the frontend exits with an instruction asking
the user to start `bpfsnoop-mcp-daemon`; it never attempts to prompt for a
password through MCP stdin.

## Configure an MCP client

Configure the client to launch the frontend directly, without `sudo`:

```json
{
  "mcpServers": {
    "bpfsnoop": {
      "command": "/absolute/path/to/bpfsnoop-mcp"
    }
  }
}
```

Run `bpfsnoop -h` for command-line usage.
