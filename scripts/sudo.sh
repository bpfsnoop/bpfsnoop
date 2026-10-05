#!/bin/sh
# Copyright 2026 Leon Hwang.
# SPDX-License-Identifier: Apache-2.0

set -eu

if [ "$(uname -s)" != Linux ]; then
	echo "Skipping sudo: passwordless sudo is only configured on Linux."
	exit 0
fi

user_id=$(id -u)
if [ "$user_id" -eq 0 ]; then
	exit 0
fi

if [ "$#" -eq 0 ]; then
	echo "Usage: $0 /absolute/path/to/binary ..." >&2
	exit 1
fi

# Use absolute, literal paths so the rule grants access to these binaries only.
newline='
'
for binary do
	case "$binary" in
		/*) ;;
		*) echo "Expected an absolute binary path: $binary" >&2; exit 1 ;;
	esac
	case "$binary" in
		*[\*\?\[\]]* | *"$newline"*)
			echo "Unsupported wildcard or newline in binary path: $binary" >&2
			exit 1
			;;
	esac
done

# Listing a particular command omits its authentication options. Inspect the
# full verbose listing to distinguish NOPASSWD from ordinary sudo access.
listing=$(LC_ALL=C sudo -n -ll 2>/dev/null) || listing=
configured=true
for binary do
	if ! printf '%s\n' "$listing" | SUDO_BINARY="$binary" awk '
		/^[[:space:]]*Sudoers entry:/ { root = 0; nopass = 0 }
		/^[[:space:]]*RunAsUsers: root$/ { root = 1 }
		/^[[:space:]]*Options:.*!authenticate/ { nopass = 1 }
		{
			sub(/^[[:space:]]+/, "")
			if (root && nopass && $0 == ENVIRON["SUDO_BINARY"]) found = 1
		}
		END { exit !found }
	'; then
		configured=false
	fi
done
if "$configured"; then
	exit 0
fi

rule=$(mktemp)
trap 'rm -f "$rule"' EXIT HUP INT TERM
printf '#%s ALL=(root) NOPASSWD: ' "$user_id" > "$rule"
separator=
for binary do
	escaped=$(printf '%s' "$binary" | sed 's/[\\,:=[:space:]#!"]/\\&/g')
	printf '%s%s' "$separator" "$escaped" >> "$rule"
	separator=', '
done
printf '\n' >> "$rule"

sudo visudo -cf "$rule"
sudo install -o root -g root -m 0440 "$rule" "/etc/sudoers.d/bpfsnoop-$user_id"
