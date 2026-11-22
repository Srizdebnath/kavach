#!/usr/bin/env bash
# Build the privileged eBPF test-suite as the current user, then run it as root.
# Usage: scripts/priv-test.sh [test-name-filter]
set -euo pipefail
cd "$(dirname "$0")/.."
cargo test -p kavachd --test bpf --no-run
json=$(cargo test -p kavachd --test bpf --no-run --message-format=json 2>/dev/null)
bin=$(grep -o '"executable":"[^"]*/bpf-[0-9a-f]*"' <<<"$json" | tail -1 | cut -d'"' -f4 || true)
[ -n "$bin" ] || { echo "could not locate the bpf test binary"; exit 1; }
echo "running $bin as root"
exec sudo "$bin" --ignored --test-threads=1 "$@"
