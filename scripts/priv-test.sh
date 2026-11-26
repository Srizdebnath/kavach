#!/usr/bin/env bash
# Build the privileged test suites as the current user, then run them as root:
#   bpf          the eBPF programs in the running kernel (crates/kavachd/tests/bpf.rs)
#   gateway_e2e  a real kavachd + L7 gateway end to end (crates/kavachd/tests/gateway_e2e.rs)
# Usage: scripts/priv-test.sh [test-name-filter]
# Already root: the suites run directly. Otherwise they run under one sudo, which reads the
# password from stdin when stdin is not a terminal (sudo -S), so unattended runs can pipe it in.
set -euo pipefail
cd "$(dirname "$0")/.."
suites=(bpf gateway_e2e)
args=()
for s in "${suites[@]}"; do args+=(--test "$s"); done
cargo test -p kavachd "${args[@]}" --no-run
json=$(cargo test -p kavachd "${args[@]}" --no-run --message-format=json 2>/dev/null)
bins=()
for s in "${suites[@]}"; do
    bin=$(grep -o "\"executable\":\"[^\"]*/$s-[0-9a-f]*\"" <<<"$json" | tail -1 | cut -d'"' -f4 || true)
    [ -n "$bin" ] || { echo "could not locate the $s test binary"; exit 1; }
    bins+=("$bin")
done
# Every suite runs (a failure does not skip the next); the exit status is the first failure's.
runner=$(cat <<'EOF'
nbins=$1; shift
bins=("${@:1:nbins}"); shift "$nbins"
rc=0
for b in "${bins[@]}"; do
    echo "running $b as root"
    "$b" --ignored --test-threads=1 "$@" || { s=$?; [ "$rc" -eq 0 ] && rc=$s; }
done
exit "$rc"
EOF
)
if [ "$(id -u)" -eq 0 ]; then
    exec bash -c "$runner" _ "${#bins[@]}" "${bins[@]}" "$@"
elif [ -t 0 ]; then
    exec sudo bash -c "$runner" _ "${#bins[@]}" "${bins[@]}" "$@"
else
    exec sudo -S bash -c "$runner" _ "${#bins[@]}" "${bins[@]}" "$@"
fi
