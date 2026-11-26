#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# Compile kavach.ko's Rust half (kavach_ko.rs + the vendor.sh output) on the host against a stub
# `kernel` crate (host-check/kernel_stub.rs) and run its unit tests (host-check/harness.rs).
#
# This needs no kernel tree, so it runs everywhere (CI lint job, any laptop). It proves the
# module source compiles as Rust (edition 2021, no_std vendored crates, the lints Kbuild
# enforces) and that the kfunc body agrees with kavach-core; it does NOT prove the module builds
# against a real kernel's `kernel` crate or loads — that is the Rust-kernel job in
# .github/workflows/kernels.yml (see README.md).
#
# usage: kernel/kavach-ko/host-check.sh   [RUSTC=rustc]
set -eu

here=$(cd "$(dirname "$0")" && pwd)
rustc=${RUSTC:-rustc}
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT

"$here/vendor.sh" >"$out/kavach_vendor.rs"
cp "$here/kavach_ko.rs" "$here/host-check/harness.rs" "$out/"

# Kbuild's Rust flags that matter for this source (scripts/Makefile.build, Makefile).
lints="-D unsafe_op_in_unsafe_fn -D non_ascii_idents -D rust_2018_idioms -D warnings"

"$rustc" --edition 2021 --crate-type rlib --crate-name kernel $lints \
	"$here/host-check/kernel_stub.rs" -o "$out/libkernel.rlib"
# `kernel` symbols stay unused on the host (no module! expansion): allow only dead_code there.
"$rustc" --edition 2021 --test --crate-name kavach_ko_host $lints -A dead_code \
	--extern kernel="$out/libkernel.rlib" -L "$out" "$out/harness.rs" -o "$out/host-check"
"$out/host-check" --nocapture
