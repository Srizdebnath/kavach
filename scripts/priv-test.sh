#!/usr/bin/env bash
# Build the privileged eBPF test-suite as the current user, then run it as root.
# Usage: scripts/priv-test.sh [test-name-filter]
set -euo pipefail
cd "$(dirname "$0")/.."
cargo test -p kavachd --test bpf --no-run
target=$(cargo metadata --format-version 1 --no-deps | grep -o '"target_directory":"[^"]*"' | cut -d'"' -f4)
bin=$(find "$target/debug/deps" -maxdepth 1 -type f -executable -name 'bpf-*' -printf '%T@ %p\n' \
  | sort -n | tail -1 | cut -d' ' -f2)
[ -n "$bin" ] || { echo "could not locate the bpf test binary"; exit 1; }
echo "running $bin as root"
exec sudo "$bin" --ignored --test-threads=1 "$@"
