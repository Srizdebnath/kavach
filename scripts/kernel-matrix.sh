#!/usr/bin/env bash
# Run the privileged eBPF suite (crates/kavachd/tests/bpf.rs) on other kernels, under virtme-ng.
#
# Kernels are prebuilt Ubuntu mainline builds (kernel.ubuntu.com/mainline): nothing is compiled.
# The guest boots with the host's root filesystem (read-only + tmpfs overlays), so the test
# binary built here runs unchanged inside it, as root, with BPF-LSM enabled through lsm=.
#
# Usage:
#   scripts/kernel-matrix.sh [KERNEL...]        build the suite once, then boot + test each kernel
#   scripts/kernel-matrix.sh build              build the test binary, print its path
#   scripts/kernel-matrix.sh resolve KERNEL     print the mainline version KERNEL resolves to
#   scripts/kernel-matrix.sh fetch KERNEL       download + unpack into the cache, print the image
#   scripts/kernel-matrix.sh run KERNEL BIN     boot KERNEL and run test binary BIN in it
#
# KERNEL is a series ("6.1": newest point release that has an amd64/arm64 build), an exact
# mainline tag ("v6.1.158"), or "latest" (newest stable series). Default: 6.1 6.6 6.12 latest.
#
# Environment:
#   KAVACH_KERNEL_CACHE  unpacked kernels (default ~/.cache/kavach/kernels)
#   KAVACH_TEST_BIN      skip the build and use this test binary
#   KAVACH_LSM           lsm= list (default yama,bpf; must contain bpf)
#   KAVACH_VM_MEMORY     guest memory (default 2G);  KAVACH_VM_CPUS (default 2)
#   KAVACH_VM_TIMEOUT    seconds before a hung guest is killed (default 1500)
#   KAVACH_TEST_ARGS     extra libtest args, e.g. a test-name filter
#   KAVACH_RESULTS       where per-kernel logs go (default target/kernel-matrix)
#   KAVACH_VNG_ARGS      extra virtme-ng arguments (word-split; default --disable-microvm,
#                        since 6.1 hangs in ACPI init on QEMU's microvm machine)
#   VNG                  virtme-ng command (default vng)
# Requirements: virtme-ng, qemu-system-<arch>, curl, and dpkg-deb or ar+tar(+zstd). KVM is used
# when /dev/kvm is accessible, otherwise the guest runs (much slower) under TCG.
set -euo pipefail

MAINLINE=https://kernel.ubuntu.com/mainline
SELF=$(readlink -f "$0")
ROOT=$(dirname "$(dirname "$SELF")")
CACHE=${KAVACH_KERNEL_CACHE:-$HOME/.cache/kavach/kernels}
LSM=${KAVACH_LSM:-yama,bpf}
VNG=${VNG:-vng}

die() { echo "kernel-matrix: error: $*" >&2; exit 1; }
log() { echo "kernel-matrix: $*" >&2; }

deb_arch() {
  case "$(uname -m)" in
    x86_64) echo amd64 ;;
    aarch64) echo arm64 ;;
    *) die "unsupported architecture $(uname -m)" ;;
  esac
}

# `curl` with retries; the mainline server is occasionally slow.
fetch_url() { curl -fsSL --retry 4 --retry-delay 3 --connect-timeout 20 "$@"; }

# Names of the image + modules .debs for a mainline tag ("" if that build failed for our arch).
debs_for() {
  local v=$1 arch
  arch=$(deb_arch)
  fetch_url "$MAINLINE/$v/$arch/" 2>/dev/null |
    grep -o 'href="linux-\(image-unsigned\|image\|modules\)-[^"]*-generic_[^"]*_'"$arch"'\.deb"' |
    cut -d'"' -f2 | sort -u || true
}

# KERNEL -> exact mainline tag with a usable build for this architecture.
resolve() {
  local want=$1 index series cand
  if [[ $want =~ ^v[0-9]+\.[0-9]+(\.[0-9]+)?(-rc[0-9]+)?$ ]]; then
    if [ -n "$(kimage_in "$CACHE/$want/$(deb_arch)")" ]; then
      echo "$want" # cached: no network needed
      return
    fi
    [ -n "$(debs_for "$want")" ] || die "$MAINLINE/$want has no $(deb_arch) kernel build"
    echo "$want"
    return
  fi
  index=$(fetch_url "$MAINLINE/") || die "cannot list $MAINLINE/"
  if [ "$want" = latest ]; then
    series=$(grep -o 'href="v[0-9]*\.[0-9]*/"' <<<"$index" | cut -d'"' -f2 | tr -d v/ |
      sort -V | tail -1)
    [ -n "$series" ] || die "could not determine the latest stable series"
  elif [[ $want =~ ^[0-9]+\.[0-9]+$ ]]; then
    series=$want
  else
    die "bad kernel '$want' (want 6.1, v6.1.158 or latest)"
  fi
  # Newest first; some point releases fail to build for an arch, so probe a few.
  for cand in $(grep -o "href=\"v${series//./\\.}\(\.[0-9]*\)\?/\"" <<<"$index" |
    cut -d'"' -f2 | tr -d / | sort -Vr | head -8); do
    if [ -n "$(debs_for "$cand")" ]; then
      echo "$cand"
      return
    fi
    log "$cand has no $(deb_arch) build, trying an older one"
  done
  die "no usable $(deb_arch) mainline build found for $series"
}

# Unpack one .deb into a directory without dpkg (works on non-Debian hosts too).
unpack_deb() {
  local deb=$1 dest=$2 tmp
  if command -v dpkg-deb >/dev/null; then
    dpkg-deb -x "$deb" "$dest"
    return
  fi
  tmp=$(mktemp -d)
  (cd "$tmp" && ar x "$deb")
  tar -xf "$tmp"/data.tar* -C "$dest"
  rm -rf "$tmp"
}

kimage_in() { compgen -G "$1/boot/vmlinuz-*" | head -1 || true; }

# Download + unpack a kernel into $CACHE/<tag>/<arch>; print the kernel image path.
fetch() {
  local v dir arch deb img kver moddir tmp
  v=$(resolve "$1")
  arch=$(deb_arch)
  dir=$CACHE/$v/$arch
  img=$(kimage_in "$dir")
  if [ -n "$img" ]; then
    log "$v: cached at $dir"
    echo "$img"
    return
  fi
  log "$v: downloading from $MAINLINE/$v/$arch/"
  tmp=$(mktemp -d)
  rm -rf "$dir"
  mkdir -p "$dir"
  for deb in $(debs_for "$v"); do
    fetch_url -o "$tmp/$deb" "$MAINLINE/$v/$arch/$deb" || die "download of $deb failed"
    unpack_deb "$tmp/$deb" "$dir"
  done
  rm -rf "$tmp"
  img=$(kimage_in "$dir")
  [ -n "$img" ] || die "$v: no boot/vmlinuz-* in the unpacked packages"
  chmod a+r "$img"
  kver=${img##*/vmlinuz-}
  # Drop module trees a headless VM never loads (~500 MB -> ~110 MB cached), then regenerate
  # modules.dep so modprobe works (the .debs leave that to a postinst depmod).
  for moddir in "$dir/lib/modules/$kver" "$dir/usr/lib/modules/$kver"; do
    [ -d "$moddir" ] || continue
    rm -rf "$moddir"/kernel/{sound,drivers/gpu,drivers/media,drivers/infiniband} \
      "$moddir"/kernel/drivers/net/{wireless,ethernet} "$moddir"/kernel/drivers/staging
    if command -v depmod >/dev/null; then
      depmod -b "${moddir%/lib/modules/*}" "$kver" || log "$v: depmod failed (modules may not load)"
    fi
  done
  echo "$img"
}

build() {
  cd "$ROOT"
  cargo test -p kavachd --test bpf --no-run >&2
  local json bin
  json=$(cargo test -p kavachd --test bpf --no-run --message-format=json 2>/dev/null)
  bin=$(grep -o '"executable":"[^"]*/bpf-[0-9a-f]*"' <<<"$json" | tail -1 | cut -d'"' -f4 || true)
  [ -n "$bin" ] || die "could not locate the bpf test binary"
  echo "$bin"
}

# Inside the guest (as root): check the kernel features the suite needs, then run it.
guest() {
  guest_body "$@" 2>&1 | tee "$2/guest.log"
  sync
}

guest_body() {
  local bin=$1 out=$2 lsms rc
  shift 2
  echo "guest kernel: $(uname -r)"
  echo "cmdline: $(cat /proc/cmdline)"
  mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
  mountpoint -q /sys/kernel/security || mount -t securityfs securityfs /sys/kernel/security
  local fail=()
  [ -r /sys/kernel/btf/vmlinux ] || fail+=("no kernel BTF (/sys/kernel/btf/vmlinux)")
  lsms=$(cat /sys/kernel/security/lsm 2>/dev/null || true)
  echo "active LSMs: ${lsms:-<none>}"
  [[ ,$lsms, == *,bpf,* ]] ||
    fail+=("BPF LSM not active (lsm list '$lsms'; kernel needs CONFIG_BPF_LSM=y and lsm=...,bpf)")
  if [ ${#fail[@]} -gt 0 ]; then
    printf 'PRECONDITION FAILED: %s\n' "${fail[@]}"
    echo 97 >"$out/rc"
    return
  fi
  ulimit -l unlimited || true
  # The guest has no network. The LSM tests connect to TEST-NET-1 (192.0.2.0/24) and expect
  # "allowed" sends to succeed and allowed TCP connects to time out, not ENETUNREACH: route
  # everything into a dummy interface, which silently discards it.
  ip link set lo up
  if ! ip route show default | grep -q .; then
    ip link add kvmx0 type dummy && ip addr add 10.254.254.1/24 dev kvmx0 &&
      ip link set kvmx0 up && ip route add default dev kvmx0 ||
      echo "warning: could not set up the dummy default route"
  fi
  # The host tree reaches the guest over virtiofs/9p, which Kavach (rightly) treats as an
  # untrusted filesystem: such an executable is never classified. Run a copy from a tmpfs.
  local run=/run/kavach-matrix
  mkdir -p "$run"
  mountpoint -q "$run" || mount -t tmpfs -o mode=0755 kavach-matrix "$run"
  cp "$bin" "$run/bpf-tests"
  "$run/bpf-tests" --ignored --test-threads=1 --nocapture "$@" && rc=0 || rc=$?
  echo "$rc" >"$out/rc"
}

summarize() {
  local v=$1 out=$2 rc=$3 status
  [ "$rc" = 0 ] && status=passed || status="FAILED (rc=$rc)"
  {
    echo "### kernel $v: $status"
    echo
    echo '```'
    grep -E '^(guest kernel|active LSMs|PRECONDITION)' "$out/guest.log" 2>/dev/null || true
    grep -oE '(tc attach on veth|lsm file_truncate hook|xdp mode on veth): .*' \
      "$out/guest.log" 2>/dev/null | sort -u || true
    grep -E '^test .* \.\.\. (ok|FAILED|ignored)$|^test result:' "$out/guest.log" 2>/dev/null || true
    # --nocapture interleaves output with the status lines: list failures from libtest's tail.
    awk '/^failures:$/ { n++; next } n == 2 && /^    / { print "FAILED:" $0 }' \
      "$out/guest.log" 2>/dev/null || true
    grep -E '^skipping' "$out/guest.log" 2>/dev/null | sort | uniq -c || true
    echo '```'
  } | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
}

run() {
  local want=$1 bin v img out rc kvm=()
  bin=$(readlink -f "$2")
  [ -x "$bin" ] || die "test binary $2 is not executable"
  [[ ,$LSM, == *,bpf,* ]] || die "KAVACH_LSM='$LSM' must include bpf"
  command -v "${VNG%% *}" >/dev/null || die "virtme-ng ('$VNG') not found: pip install virtme-ng"
  v=$(resolve "$want") || return 96
  img=$(fetch "$v") || return 96
  out=$(readlink -f "${KAVACH_RESULTS:-$ROOT/target/kernel-matrix}")/$v
  rm -rf "$out"
  mkdir -p "$out"
  if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
    log "/dev/kvm is not accessible: falling back to TCG emulation (slow)"
    kvm=(--disable-kvm)
  fi
  log "$v: booting $img"
  set +e
  # shellcheck disable=SC2086 # VNG may carry its own arguments
  timeout --foreground -k 30 "${KAVACH_VM_TIMEOUT:-1500}" \
    $VNG --run "$img" --user root --verbose "${kvm[@]}" \
    --memory "${KAVACH_VM_MEMORY:-2G}" --cpus "${KAVACH_VM_CPUS:-2}" \
    --rwdir "$out" --append "lsm=$LSM" ${KAVACH_VNG_ARGS---disable-microvm} \
    --exec "$SELF guest '$bin' '$out' ${KAVACH_TEST_ARGS:-}" </dev/null >"$out/console.log" 2>&1
  local vng_rc=$?
  set -e
  if [ -f "$out/rc" ]; then
    rc=$(cat "$out/rc")
  else
    rc=98
    log "$v: the guest never reported a result (vng exit $vng_rc; 124 = timeout)."
    log "$v: last console lines:"
    tail -n 60 "$out/console.log" >&2 || true
  fi
  if [ "$rc" = 97 ]; then
    log "$v: kernel lacks a feature the suite needs:"
    grep PRECONDITION "$out/guest.log" >&2 || true
  elif [ "$rc" != 0 ] && [ "$rc" != 98 ]; then
    log "$v: test failures (full log: $out/guest.log):"
    # --nocapture: each panic is printed inline, right after the test's name.
    grep -E -A3 "^thread '.*' .*panicked at" "$out/guest.log" | head -n 120 >&2 || true
    if [ -n "${GITHUB_ACTIONS:-}" ]; then
      awk -v v="$v" -F"'" '/^thread .* panicked at/ { t = $2; getline m;
        print "::error title=kernel " v ": " t "::" m }' "$out/guest.log" || true
    fi
  fi
  summarize "$v" "$out" "$rc"
  return "$rc"
}

matrix() {
  local bin failed=() k
  bin=${KAVACH_TEST_BIN:-$(build)}
  [ $# -gt 0 ] || set -- 6.1 6.6 6.12 latest
  for k in "$@"; do
    run "$k" "$bin" || failed+=("$k")
  done
  if [ ${#failed[@]} -gt 0 ]; then
    die "failed on: ${failed[*]}"
  fi
  log "all kernels passed: $*"
}

case "${1:-}" in
  build) build ;;
  resolve) resolve "${2:?kernel}" ;;
  fetch) fetch "${2:?kernel}" ;;
  run) run "${2:?kernel}" "${3:?test binary}" ;;
  guest) shift && guest "$@" ;; # inside the VM: BIN RESULT_DIR [libtest args...]
  -h | --help) sed -n '2,/^set -euo/p' "$SELF" | sed '$d; s/^# \{0,1\}//' ;;
  *) matrix "$@" ;;
esac
