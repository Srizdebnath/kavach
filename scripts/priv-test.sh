#!/usr/bin/env bash
# Build the privileged eBPF test-suite as the current user, then run it as root.
# Usage: scripts/priv-test.sh [test-name-filter]
set -euo pipefail
cd "$(dirname "$0")/.."
bin=$(cargo test -p kavachd --test bpf --no-run --message-format=json 2>/dev/null \
  | grep -o '"executable":"[^"]*"' | tail -1 | cut -d'"' -f4)
[ -n "$bin" ] || { echo "build failed"; exit 1; }
exec sudo "$bin" --ignored --test-threads=1 "$@"
