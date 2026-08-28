<!--
 Copyright 2026 Leon Hwang.
 SPDX-License-Identifier: Apache-2.0
-->

# bpfsnoop MCP server

`bpfsnoop --mcp` serves bpfsnoop to MCP clients over stdin/stdout. The
`bpfsnoop-mcp` launcher selects that mode for AI agents. When it runs as root,
bpfsnoop serves MCP directly. When it runs as a normal user, it transparently
proxies MCP messages to a persistent privileged daemon. The launcher contains
all local transport details, so MCP clients only need to run `bpfsnoop-mcp`.

The initial tool surface is:

- `kernel_info`: inspect the running kernel and bpfsnoop tracing capabilities;
- `find`: discover kernel functions, tracepoints, loaded BPF programs, and BTF
  types;
- `trace`: run one bounded tracing experiment and return structured events.

`kernel_info` is available. The `find` and `trace` tools currently return a
not-implemented error until their backends are added.

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

This launcher executes `bpfsnoop --mcp-daemon`. It is also possible to invoke
that mode directly.

When launched through `sudo`, the daemon permits only the invoking user to
connect. It cleans up its private local endpoint when stopped with `SIGINT` or
`SIGTERM`. The daemon serves one active MCP session at a time; another frontend
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

Run `bpfsnoop -h` for command-line usage. The launchers forward their arguments
to the corresponding bpfsnoop mode.
