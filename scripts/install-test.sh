#!/bin/sh
# Install-test a release artifact inside a container.
#   scripts/install-test.sh <debian|ubuntu|fedora|opensuse|arch|alpine> [dist-dir] [image]
# dist-dir must contain the artifacts (build them with .github/workflows/release.yml, or see
# docs/RELEASING.md). The optional third argument overrides the default container image.
set -eu

distro=${1:?usage: $0 <distro> [dist-dir] [image]}
dir=${2:-dist}
[ -d "$dir" ] || { echo "no artifact directory: $dir" >&2; exit 2; }
dir=$(cd "$dir" && pwd)

case "$distro" in
    debian)   default_image=debian:12-slim ;;
    ubuntu)   default_image=ubuntu:24.04 ;;
    fedora)   default_image=fedora:41 ;;
    opensuse) default_image=opensuse/leap:16.0 ;;
    arch)     default_image=archlinux:latest ;;
    alpine)   default_image=alpine:latest ;;
    *) echo "unknown distro: $distro" >&2; exit 2 ;;
esac
image=${3:-$default_image}

root=$(cd "$(dirname "$0")/.." && pwd)
exec docker run --rm \
    -v "$dir:/dist:ro" \
    -v "$root/packaging/install-test/container.sh:/container.sh:ro" \
    -e "KAVACH_VERSION=${KAVACH_VERSION:-0.4.0}" \
    "$image" sh /container.sh "$distro"
