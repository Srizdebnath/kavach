#!/bin/sh
# Guest side of scripts/install-test.sh. Installs one artifact, checks the binaries, the
# service definition and the config, then removes the package and checks the binaries are gone.
set -eu

distro=${1:?usage: container.sh <debian|ubuntu|fedora|opensuse|arch|alpine>}
v=${KAVACH_VERSION:-0.4.0}

verify_installed() {
    service=$1
    for bin in kavachd kavachctl kavach-gateway; do
        "$bin" --version | grep -q "^$bin $v$"
    done
    test -f "$service"
    test -f /etc/kavach/kavachd.toml
    echo "$distro: install verified ($(command -v kavachd), $service, /etc/kavach/kavachd.toml)"
}

verify_removed() {
    for bin in kavachd kavachctl kavach-gateway; do
        if command -v "$bin" >/dev/null 2>&1; then
            echo "$distro: $bin still installed" >&2
            exit 1
        fi
    done
    echo "$distro: removal verified"
}

case "$distro" in
    debian|ubuntu)
        dpkg -i --force-depends "/dist/kavach_${v}-1_amd64.deb" >/dev/null
        verify_installed /lib/systemd/system/kavachd.service
        dpkg -r kavach >/dev/null
        verify_removed
        ;;
    fedora|opensuse)
        rpm -ivh --nodeps "/dist/kavach-${v}-1.x86_64.rpm" >/dev/null
        verify_installed /usr/lib/systemd/system/kavachd.service
        rpm -e --nodeps kavach >/dev/null
        verify_removed
        ;;
    arch)
        # systemd, makepkg and zstd are in the base image; only fakeroot is extra.
        pacman -Sy --noconfirm >/dev/null
        pacman -S --noconfirm --needed fakeroot >/dev/null
        useradd -m builder 2>/dev/null || :
        mkdir -p /build
        cp /dist/PKGBUILD /dist/kavach.install /build/
        # The release is not published yet at test time: use the downloaded assets directly.
        cp /dist/kavach-*.tar.gz /dist/SHA256SUMS /build/
        sed -i 's#https://github.com/Srizdebnath/kavach/releases/download/v\$pkgver/##g' \
            /build/PKGBUILD
        chown -R builder /build
        (cd /build && su builder -c 'makepkg --noconfirm --force')
        # Keep the built package so CI can publish it as a release asset (signed via SHA256SUMS).
        mkdir -p /out && cp /build/kavach-*.pkg.tar.zst /out/
        pacman -U --noconfirm --needed /build/kavach-*.pkg.tar.zst >/dev/null
        verify_installed /usr/lib/systemd/system/kavachd.service
        pacman -Rs --noconfirm kavach >/dev/null
        verify_removed
        ;;
    alpine)
        apk update >/dev/null
        apk add --no-cache abuild build-base >/dev/null
        adduser -D builder 2>/dev/null || :
        addgroup builder abuild 2>/dev/null || :
        mkdir -p /build /etc/apk/keys
        cp /dist/APKBUILD /dist/kavachd.initd /build/
        cp /dist/kavach-*.tar.gz /dist/SHA256SUMS /build/
        sed -i 's#https://github.com/Srizdebnath/kavach/releases/download/v\$pkgver/##g' \
            /build/APKBUILD
        # abuild handles plain local filenames; the URL aliases are only needed for downloads.
        sed -i 's/::.*//' /build/APKBUILD
        chown -R builder /build
        # Generate the package-signing key non-interactively (abuild requires one).
        su builder -c 'abuild-keygen -n -a' >/dev/null
        cp /home/builder/.abuild/*.pub /etc/apk/keys/
        (cd /build && su builder -c 'abuild checksum && abuild -r')
        # Keep the built packages (main + doc) so CI can publish them as release assets.
        mkdir -p /out && find /home/builder/packages -name 'kavach*.apk' -exec cp {} /out/ \;
        apk_path=$(find /home/builder/packages -name "kavach-$v-r0.apk" | head -1)
        [ -n "$apk_path" ] || { echo "no built apk found" >&2; exit 1; }
        apk add --allow-untrusted "$apk_path" >/dev/null
        verify_installed /etc/init.d/kavachd
        apk del kavach >/dev/null
        verify_removed
        ;;
    *)
        echo "unknown distro: $distro" >&2
        exit 2
        ;;
esac
