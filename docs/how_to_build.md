# Building bpfsnoop

Note: It is recommended to run the building commands with root privilege.

## Table of Contents

- [Building on Ubuntu 24.04](#building-on-ubuntu-2404)

---

## Building on Ubuntu 24.04

### 1. Install Dependencies

Open a terminal and run the following commands to install the required dependencies:

```sh
sudo apt update
sudo apt install cmake autoconf
```

#### Install Clang

It is recommended to install Clang using the official LLVM script:

```sh
wget https://apt.llvm.org/llvm.sh
sudo bash llvm.sh 21
```

#### Install Go

It is recommended to install Go using the following shell functions, which will download and install the specified version for your architecture:

```sh
march2goarch () {
    march=$(uname -m)
    case "$march" in
        (aarch64) echo "arm64" ;;
        (x86_64) echo "amd64" ;;
        (*) echo "unknown" ;;
    esac
}

goupgrade () {
    goversion="$1"
    goarch="$(march2goarch)"
    gotgz="go${goversion}.linux-${goarch}.tar.gz"
    gourl="https://go.dev/dl/${gotgz}"
    if [ -z $goversion ]
    then
        return 1
    fi
    if [ "${goarch}" = "unknown" ]
    then
        echo "Unsupported arch: $(uname -m)"
        return 1
    fi
    test ! -f "${gotgz}" && wget "${gourl}"
    test ! -f "${gotgz}" && return 1
    test -d /usr/local/go && sudo /bin/rm -rf /usr/local/go
    sudo tar -xzf "${gotgz}" -C /usr/local
    test ! /usr/local/bin/go && sudo ln -s /usr/local/go/bin/go /usr/local/bin/go
    go version
}

goupgrade 1.25.4
```

### 2. Build bpfsnoop

In the project root directory, run:

```sh
make
```

### 3. Verify the Build

After building, you can verify the binary with:

```sh
$ ./bpfsnoop --help
Usage of bpfsnoop:
  -d, --disasm                      disasm bpf prog or kernel function
  -B, --disasm-bytes uint           disasm bytes of kernel function, 0 to guess it automatically
      --disasm-intel-syntax         use Intel asm syntax for disasm, ATT asm syntax by default
      --fgraph-exclude strings      exclude functions in function call graph, empty means no exclude, rules are same as -k
      --fgraph-extra strings        extra functions in function call graph as depth 1, rules are same as -k
      --fgraph-include strings      limited functions in function call graph, empty means all functions, rules are same as -k
      --fgraph-max-depth uint       maximum depth of function call graph, larger means slower to start bpfsnoop, 5 by default (default 5)
      --fgraph-proto                output function prototype in function call graph, like --show-func-proto
      --filter-arg strings          filter function arguments with a C expression; typed $retval is available in exit modes
      --filter-pid uint32           filter pid for tracing
      --filter-pkt string           filter skb/xdp argument with a pcap-filter(7) expression; prefix with '(r)' for a packet-typed return value
      --kernel-vmlinux string       specific kernel vmlinux directory to search vmlinux and modules dbgsym files
  -k, --kfunc strings               filter kernel functions, '(i)' prefix means insn tracing, '<kfunc>[:<arg>][:<type>]' format, e.g. 'tcp_v4_connect:sk:struct sock *', '*:(struct sk_buff *)skb'
      --kfunc-all-kmods             filter functions in all kernel modules
      --kfunc-kmods strings         filter functions in specified kernel modules
      --limit-events uint           limited number events to output, 0 to output all events
  -m, --mode strings                mode of bpfsnoop, exit and/or entry (default [exit])
  -o, --output string               output file for the result, default is stdout
      --output-arg stringArray      output a C expression over function arguments; e.g. 'prog->type' or '(int)$retval'
  -g, --output-fgraph               output function call graph, works with -k,-p
      --output-insns                output function's insns exec path, same as '(i)' in -k, only works with -k
      --output-lbr                  output LBR perf event
      --output-pkt                  output packet tuple; append '(r)' to select a packet-typed return value
      --output-stack                output function call stack
  -p, --prog strings                bpf prog info for bpfsnoop in format PROG[,PROG,..], PROG: PROGID[:<prog function name>], PROGID: <prog ID> or 'i/id:<prog ID>' or 'p/pinned:<pinned file>' or 't/tag:<prog tag>' or 'n/name:<prog full name>' or 'pid:<pid>'; all bpf progs will be traced if '*' is specified
      --read stringArray            read kernel memory using C expressions
      --show-func-proto             show function prototype of -p,-k,-t
  -C, --show-type-proto pahole -C   show struct/union/enum prototype like pahole -C
      --skip-tunnel                 skip tunnel (vxlan) header when parsing packet, applied for both --filter-pkt and --output-pkt
  -t, --tracepoint strings          filter kernel tracepoints
  -v, --verbose                     output verbose log
```

## Test across kernels

The `Kernel e2e tests` GitHub Actions workflow runs on GitHub-hosted Ubuntu
runners. It builds `bpfsnoop`, `localtest`, and `xdpcrc` on the host, then uses
QEMU/KVM and [vimto](https://github.com/lmb/vimto) to run the CLI and MCP suites in
separate guests for Linux 5.10, 5.15, 6.1, 6.6, 6.12, stable, and mainline.
The kernel images come from `ghcr.io/cilium/ci-kernels`, as in cilium/ebpf CI.
These tags track the image publisher's builds; the guest log records `uname -a`.
Feature-gated cases may be skipped on older kernels; test failures fail the job.
Each job uploads its test output and guest kernel messages.

To run locally on an amd64 Linux host with KVM, install the build dependencies
and QEMU, make, bash, iproute2, ping, curl, Python 3, and bpftool. Download Go
dependencies on the host before starting the guest:

```sh
CGO_ENABLED=0 go install lmb.io/vimto@latest
go mod download
make -j"$(nproc)" all
vimto -kernel :5.15 exec -- /bin/bash scripts/test-kernel.sh < /dev/null
```

The `.vimto.toml` configuration runs the guest command as root. Only loopback
networking is used by these tests. The guest uses `make testlocal-run` and
`make testmcp-run` to run the host-built binaries without rebuilding them.
BTF headers and BPF objects are generated on the host. The existing
`Pull Request` workflow continues to run separately.
