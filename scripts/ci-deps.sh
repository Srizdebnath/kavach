#!/usr/bin/env bash
# Install clang + a working bpftool on Ubuntu CI runners (x86_64 and aarch64).
# Local dev: use your distro's packages.
#
# /usr/bin/bpftool from linux-tools-common is only a wrapper that refuses to run unless the
# linux-tools package for the *running* kernel exists, which is often not the case on hosted
# runners (e.g. arm64 azure kernels). So: use a real binary from /usr/lib/linux-tools*, else the
# distro `bpftool` package, else the official static release from github.com/libbpf/bpftool.
set -euo pipefail
BPFTOOL_VERSION=v7.5.0

sudo apt-get update -qq
sudo apt-get install -y -qq clang llvm libelf-dev libbpf-dev
sudo apt-get install -y -qq linux-tools-common "linux-tools-$(uname -r)" 2>/dev/null \
  || sudo apt-get install -y -qq linux-tools-common linux-tools-azure 2>/dev/null || true

works() { [ -x "$1" ] && "$1" version >/dev/null 2>&1; }
real=""
for b in /usr/lib/linux-tools/*/bpftool /usr/lib/linux-tools-*/bpftool /usr/sbin/bpftool; do
  if works "$b"; then real=$b; break; fi
done
if [ -z "$real" ] && sudo apt-get install -y -qq bpftool 2>/dev/null && works /usr/sbin/bpftool; then
  real=/usr/sbin/bpftool
fi
if [ -z "$real" ]; then
  case "$(uname -m)" in
    x86_64)  a=amd64 sum=6b81db78c797e63f13e644ceb2064e5236afaf904bbaaa367785170819768f0a ;;
    aarch64) a=arm64 sum=80e0d5b59bfbc7ecce06985802babf4c2b4ff78be3640202a19e3d7278fceb7b ;;
    *) echo "no bpftool for $(uname -m)"; exit 1 ;;
  esac
  t=$(mktemp -d)
  curl -fsSL -o "$t/b.tgz" \
    "https://github.com/libbpf/bpftool/releases/download/$BPFTOOL_VERSION/bpftool-$BPFTOOL_VERSION-$a.tar.gz"
  echo "$sum  $t/b.tgz" | sha256sum --check --quiet
  tar -xzf "$t/b.tgz" -C "$t"
  sudo install -m 0755 "$t/bpftool" /usr/local/bin/bpftool.real
  real=/usr/local/bin/bpftool.real
fi
# /usr/local/bin precedes /usr/bin on the runners' PATH, shadowing the wrapper.
sudo ln -sf "$real" /usr/local/bin/bpftool
hash -r
bpftool version
