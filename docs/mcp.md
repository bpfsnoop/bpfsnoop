<!--
 Copyright 2026 Leon Hwang.
 SPDX-License-Identifier: Apache-2.0
-->

# bpfsnoop MCP server

`bpfsnoop --mcp` exposes bpfsnoop to AI agents through MCP over stdin/stdout.
The `bpfsnoop-mcp` launcher selects this hidden execution mode. An MCP client
launches one server process and normally keeps it running while the client
connection is open. Standard output is reserved for MCP messages; server
diagnostics are written to standard error.

The initial tool surface is:

- `kernel_info`: inspect the running kernel and bpfsnoop tracing capabilities;
- `find`: discover kernel functions, tracepoints, loaded BPF programs, and BTF
  types;
- `trace`: run one bounded tracing experiment and return structured events.

The tools are currently registered as a skeleton and return a not-implemented
error until their backends are added.

## Build

```sh
make bpfsnoop
```

## Root privilege

Kernel and BPF inspection requires root privilege, so `bpfsnoop --mcp` refuses
to start when its effective user ID is not zero. Elevation must happen when the
MCP client launches the server; a tool call cannot elevate an existing process.

Do not use interactive `sudo` for an MCP stdio command because its prompt would
block the connection. One possible client configuration is:

```json
{
  "mcpServers": {
    "bpfsnoop": {
      "command": "sudo",
      "args": ["-n", "/absolute/path/to/bpfsnoop-mcp"]
    }
  }
}
```

This requires either an existing root execution environment or a narrowly
scoped passwordless sudo rule for the exact trusted `bpfsnoop-mcp` binary.

Run `bpfsnoop-mcp -h` for command-line usage. When started normally, the server
reads newline-delimited MCP JSON messages from stdin and writes responses to
stdout until the client disconnects or the process receives `SIGINT` or
`SIGTERM`.
