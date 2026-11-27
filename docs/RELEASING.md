# Releasing Kavach

This is the operator's runbook for a Kavach release. Everything published comes from one
tagged commit; no long-lived signing key exists (Sigstore keyless + SLSA provenance instead).
The release workflow is [`.github/workflows/release.yml`](../.github/workflows/release.yml);
version numbers are workspace-wide.

## 1. Version bump

1. Set `version` in `[workspace.package]` **and** the six `kavach-*` versions in
   `[workspace.dependencies]` of the root `Cargo.toml`.
2. Regenerate the workspace crate entries in `Cargo.lock`:
   `cargo check --workspace` (or `cargo generate-lockfile`). Do not hand-edit third-party
   versions.
3. In `CHANGELOG.md`, rename `## [Unreleased]` to `## [version] - YYYY-MM-DD` and add its
   compare link at the bottom. **The workflow extracts release notes with
   `awk '/^## \[/{… index($0,"[" v "]") …}'`, so the heading must match the tag exactly.**
4. Update user-facing filenames in `README.md` and `docs/INSTALL.md` (`0.4.0`, not the
   historical `0.3.1` entries in `CHANGELOG.md` or the golden-bundle notes in
   `docs/ARCHITECTURE.md`).
5. Verify: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
   `cargo test --workspace`.
6. Commit on `main`, then `git tag -s vX.Y.Z -m "Kavach vX.Y.Z" && git push origin vX.Y.Z`.
   The `test` job fails if the tag does not equal the workspace version.

## 2. What is built and where it goes

For each architecture the workflow builds three statically linked musl binaries
(`kavachd`, `kavachctl`, `kavach-gateway`) and packages them five ways. The `publish` job also
uploads the native package manifests so a user can download them from the release.

| Asset | Distros | `x86_64` | `aarch64` | Built by |
|---|---|---|---|---|
| `kavach_<ver>-1_amd64.deb` / `_arm64.deb` | Debian, Ubuntu, Mint, Pop!_OS | ✅ | ✅ | `cargo deb -p kavachd --no-build` |
| `kavach-<ver>-1.x86_64.rpm` / `.aarch64.rpm` | Fedora, RHEL/Rocky/Alma, openSUSE | ✅ | ✅ | `cargo generate-rpm -p crates/kavachd` |
| `kavach-<ver>-<arch>-linux-musl.tar.gz` | any distro (tarball `install.sh`) | ✅ | ✅ | `tar`, static binaries + docs + config + unit |
| `PKGBUILD`, `kavach.install` | Arch, Manjaro, Arch Linux ARM | ✅ | ✅ | `makepkg` from the tarball (no Rust build) |
| `APKBUILD`, `kavachd.initd` | Alpine, postmarketOS | ✅ | ✅ | `abuild` from the tarball (no Rust build) |
| `SHA256SUMS`, `SHA256SUMS.sigstore.json` | all of the above | ✅ | ✅ | `sha256sum` + `cosign sign-blob` |

Every package installs `/usr/bin/kavachd`, `/usr/bin/kavachctl`, `/usr/bin/kavach-gateway`,
`/etc/kavach/kavachd.toml` (a config file: never overwritten on upgrade) and the service
definition: `kavachd.service` on systemd, `/etc/init.d/kavachd` on OpenRC. Services are
installed but **not enabled or started**. Removal runs `kavachctl kill-switch --yes` before
deleting the binaries, because enforcement lives in the kernel.

`kavach.ko` is deliberately **not** in any of these packages: a kernel module is bound to one
kernel version/configuration and would break other kernels. Its source is in
[`kernel/kavach-ko/`](../kernel/kavach-ko/) and
[`.github/workflows/kavach-ko.yml`](../.github/workflows/kavach-ko.yml) builds, BTF-checks and
self-tests it (plus syzkaller) against selected kernels under virtme-ng. Users build it from
source for their own kernel (`make -C kernel/kavach-ko && sudo make -C kernel/kavach-ko
install`); see the module README for toolchain requirements.

## 3. Reproducibility (SRS SR-7)

The build job exports `SOURCE_DATE_EPOCH` from `git log -1 --format=%ct` of the tagged commit
(and `TZ=UTC`) before compiling. `cargo deb`, `cargo generate-rpm` and `tar` all consume that
environment variable: the tarball additionally uses `--sort=name --owner=0 --group=0
--format=gnu --mtime="@$SOURCE_DATE_EPOCH"`, and the binaries are built with `--locked`.
No build step uses the wall clock for asset metadata.

To reproduce one asset locally:

```sh
git checkout v0.4.0
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) TZ=UTC
rustup target add x86_64-unknown-linux-musl && sudo apt-get install -y musl-tools
cargo xtask build-bpf
cargo build --release --locked --target x86_64-unknown-linux-musl \
  -p kavachd -p kavachctl -p kavach-gateway
cargo deb -p kavachd --no-build --target x86_64-unknown-linux-musl -o dist/
# Compare the hash with SHA256SUMS from the release (toolchain versions must match).
```

The Arch `PKGBUILD` pins neither the tarball digest nor the release timestamp: its `build()`
verifies the downloaded tarball against the release's `SHA256SUMS` asset, which is itself
signed. The Alpine `APKBUILD` does the same in `prepare()`; as is usual for Alpine packages,
run `abuild checksum` once after downloading a new `APKBUILD` to fill its `sha512sums`.

## 4. Signing and verification

The workflow computes `SHA256SUMS` over every asset, attaches SLSA build-provenance
attestations and signs the checksum list with a short-lived GitHub OIDC identity:

```sh
cosign sign-blob --yes --bundle dist/SHA256SUMS.sigstore.json dist/SHA256SUMS
cosign verify-blob dist/SHA256SUMS --bundle dist/SHA256SUMS.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/Srizdebnath/kavach/.github/workflows/release.yml@refs/tags/v0.4.0"
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify kavach_0.4.0-1_amd64.deb --repo Srizdebnath/kavach
```

The release notes repeat these commands for users. If verification fails, do not publish;
delete the release and investigate.

## 5. Install-test matrix

The `install-test` job installs each artifact in a container, runs `--version` on all three
binaries (they must report the release version), checks the unit/init script and config exist,
then removes the package and checks the binaries are gone. `scripts/install-test.sh` runs the
same test locally (requires Docker):

| Distro | Image | Artifact / path |
|---|---|---|
| Debian | `debian:12-slim` | `.deb`, `/lib/systemd/system/kavachd.service` |
| Ubuntu | `ubuntu:24.04` | `.deb`, `/lib/systemd/system/kavachd.service` |
| Fedora | `fedora:41` | `.rpm`, `/usr/lib/systemd/system/kavachd.service` |
| openSUSE | `opensuse/leap:16.0` | `.rpm`, `/usr/lib/systemd/system/kavachd.service` |
| Arch | `archlinux:latest` | `PKGBUILD` → `makepkg` → `pacman -U`, systemd unit |
| Alpine | `alpine:latest` | `APKBUILD` → `abuild -r` → `apk add`, `/etc/init.d/kavachd` |

```sh
# after downloading the release assets into ./dist
for d in debian ubuntu fedora opensuse arch alpine; do
    ./scripts/install-test.sh "$d" dist
done
```

The existing in-workflow `.deb` test (on the runner itself) also checks permissions on
`/etc/kavach` and removal; keep it.
