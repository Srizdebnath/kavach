#!/bin/sh
# Install Kavach from the release tarball (static binaries, any distro).
#   sudo ./install.sh            install / upgrade
#   sudo ./install.sh --uninstall
# Never overwrites an existing /etc/kavach/kavachd.toml and never starts enforcement by itself.
set -eu

PREFIX=${PREFIX:-/usr/local}
HERE=$(cd "$(dirname "$0")" && pwd)

die() { echo "error: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "run as root (sudo $0)"

if [ "${1:-}" = "--uninstall" ]; then
    if command -v systemctl >/dev/null 2>&1; then
        systemctl disable --now kavachd.service 2>/dev/null || true
    fi
    # Detach enforcement explicitly (stopping the daemon alone keeps it in the kernel).
    "$PREFIX/bin/kavachctl" kill-switch --yes 2>/dev/null || true
    rm -f "$PREFIX/bin/kavachd" "$PREFIX/bin/kavachctl" "$PREFIX/bin/kavach-gateway" \
        /etc/systemd/system/kavachd.service
    command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload || true
    echo "removed binaries and unit; kept /etc/kavach, /var/lib/kavach and /var/log/kavach"
    exit 0
fi

"$HERE/bin/kavachctl" doctor || die "host does not meet a required check (see above)"

install -d -m 0755 "$PREFIX/bin"
install -m 0755 "$HERE/bin/kavachd" "$HERE/bin/kavachctl" "$HERE/bin/kavach-gateway" "$PREFIX/bin/"
install -d -m 0750 /etc/kavach /etc/kavach/trusted_keys /var/lib/kavach /var/log/kavach
if [ ! -e /etc/kavach/kavachd.toml ]; then
    install -m 0640 "$HERE/etc/kavachd.toml" /etc/kavach/kavachd.toml
    echo "wrote /etc/kavach/kavachd.toml (interfaces = [\"auto\"])"
else
    install -m 0640 "$HERE/etc/kavachd.toml" /etc/kavach/kavachd.toml.new
    echo "kept existing /etc/kavach/kavachd.toml (new default at kavachd.toml.new)"
fi
install -d -m 0755 /usr/local/share/doc/kavach
cp -r "$HERE/doc/." /usr/local/share/doc/kavach/

if command -v systemctl >/dev/null 2>&1; then
    sed "s#/usr/bin/kavachd#$PREFIX/bin/kavachd#" "$HERE/systemd/kavachd.service" \
        > /etc/systemd/system/kavachd.service
    systemctl daemon-reload
    echo "installed kavachd.service (not started)"
fi

cat <<EOF

Kavach installed. Next steps (docs/INSTALL.md has the full guide):
  1. kavachctl keygen ci                         # on your CI / admin machine, keep ci.key secret
  2. cp ci.pub /etc/kavach/trusted_keys/          # on this host
  3. systemctl enable --now kavachd
  4. kavachctl sign kavach.toml --key ci.key -o policy.kvb
     kavachctl apply policy.kvb --dry-run && kavachctl apply policy.kvb
EOF
