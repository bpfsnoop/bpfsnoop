<!--
 Copyright 2024 Leon Hwang.
 SPDX-License-Identifier: Apache-2.0
-->

# bpfsnoop

![](./img/logo.png)

`bpfsnoop` is a modernized kernel functions, kernel tracepoints and bpf programs tracing tool for the bpf era.

## Features and Usages

Please check [bpfsnoop.com](https://bpfsnoop.com) for more details.

## Acknowledgments

- [cilium/ebpf](https://github.com/cilium/ebpf) for interacting with bpf subsystem.
- [daludaluking/addr2line](https://github.com/daludaluking/addr2line) for translating addresses to file and line number by parsing debug info from vmlinux.
- [bpfsnoop/gapstone](https://github.com/bpfsnoop/gapstone) for disassembling machine native instructions.
- [jschwinger233/elibpcap](github.com/jschwinger233/elibpcap) for injecting pcap-filter expressions to bpf stubs.

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) file for details.
