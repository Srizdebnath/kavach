#!/usr/bin/env bash
# Install clang + bpftool on Ubuntu CI runners (local dev: use your distro's packages).
set -euo pipefail
sudo apt-get update -qq
sudo apt-get install -y -qq clang llvm libelf-dev libbpf-dev linux-tools-common "linux-tools-$(uname -r)" \
  || sudo apt-get install -y -qq clang llvm libelf-dev libbpf-dev linux-tools-common linux-tools-azure
command -v bpftool >/dev/null || sudo ln -sf "$(ls /usr/lib/linux-tools/*/bpftool | head -1)" /usr/local/bin/bpftool
bpftool version
