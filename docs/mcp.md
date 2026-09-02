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
- `trace`: run one bounded tracing experiment and return structured events.

`kernel_info` and `find` are available. The `trace` tool currently returns a
not-implemented error until its backend is added.

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
