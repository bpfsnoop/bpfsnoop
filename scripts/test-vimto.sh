#!/bin/bash
# Copyright 2026 Leon Hwang.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
cd "$(dirname "$0")/.."

vimto=${VIMTO:-vimto}
log_dir=${VIMTO_LOG_DIR:-log/vimto}
test_timeout=${VIMTO_TIMEOUT:-30m}

if ! command -v "$vimto" > /dev/null; then
  echo "vimto not found; install it with CGO_ENABLED=0 go install lmb.io/vimto@latest" >&2
  exit 1
fi
if [[ $# == 0 ]]; then
  echo "Specify kernel tags, or use make vimto to run the CI kernel matrix" >&2
  exit 1
fi

# Allow local runs on machines without access to hardware virtualization.
if [[ ! -v VIMTO_DISABLE_KVM && (! -r /dev/kvm || ! -w /dev/kvm) ]]; then
  export VIMTO_DISABLE_KVM=true
  echo "KVM unavailable; using QEMU software emulation"
fi

mkdir -p "$log_dir"
status=0
results=()
for kernel in "$@"; do
  log_file="$log_dir/$kernel.log"
  echo "Running Linux $kernel (log: $log_file)"
  if timeout --signal=INT --kill-after=30s "$test_timeout" \
    "$vimto" -kernel "ghcr.io/cilium/ci-kernels:$kernel" \
    exec -- /bin/bash scripts/test-kernel.sh < /dev/null 2>&1 | tee "$log_file"; then
    results+=("Linux $kernel: PASS ($log_file)")
  else
    results+=("Linux $kernel: FAIL ($log_file)")
    status=1
  fi
done

printf '\n%s\n' "${results[@]}"
exit "$status"
