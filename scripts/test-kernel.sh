#!/bin/bash
# Copyright 2026 Leon Hwang.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$PWD:$PATH"

if [[ $(id -u) != 0 ]]; then
    echo "Kernel e2e tests must run as root inside the guest" >&2
    exit 1
fi

uname -a
test -r /sys/kernel/btf/vmlinux
ip link set dev lo up
for binary in bpfsnoop localtest xdpcrc; do
    if [[ ! -x ./$binary ]]; then
        echo "Missing executable $binary; run make all on the host first" >&2
        exit 1
    fi
done
./bpfsnoop --detect-features

# Run both suites even when one fails.
status=0
make testlocal-run || status=1
make testmcp-run || status=1
exit "$status"
