#!/bin/sh
# Copyright 2026 Leon Hwang.
# SPDX-License-Identifier: Apache-2.0

set -eu

src=$1
dir=${src%/*}

sed -n 's/^[[:space:]]*#[[:space:]]*include[[:space:]]*"\([^"]*\)".*/\1/p' "$src" |
	while IFS= read -r header; do
		if [ -f "$dir/$header" ]; then
			printf '%s/%s\n' "$dir" "$header"
		fi
	done
