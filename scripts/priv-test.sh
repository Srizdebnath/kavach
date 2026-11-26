#!/usr/bin/env bash
# Build the privileged test suites as the current user, then run them as root:
#   bpf          the eBPF programs in the running kernel (crates/kavachd/tests/bpf.rs)
#   gateway_e2e  a real kavachd + L7 gateway end to end (crates/kavachd/tests/gateway_e2e.rs)
# Usage: scripts/priv-test.sh [test-name-filter]
# Run as root, the suites run directly; otherwise each runs under sudo.
set -euo pipefail
cd "$(dirname "$0")/.."
suites=(bpf gateway_e2e)
args=()
for s in "${suites[@]}"; do args+=(--test "$s"); done
cargo test -p kavachd "${args[@]}" --no-run
json=$(cargo test -p kavachd "${args[@]}" --no-run --message-format=json 2>/dev/null)
sudo=(sudo)
[ "$(id -u)" -eq 0 ] && sudo=()
for s in "${suites[@]}"; do
    bin=$(grep -o "\"executable\":\"[^\"]*/$s-[0-9a-f]*\"" <<<"$json" | tail -1 | cut -d'"' -f4 || true)
    [ -n "$bin" ] || { echo "could not locate the $s test binary"; exit 1; }
    echo "running $bin as root"
    "${sudo[@]}" "$bin" --ignored --test-threads=1 "$@"
done
