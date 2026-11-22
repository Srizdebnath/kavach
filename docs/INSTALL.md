# Installing and running Kavach

Kavach is a host firewall: one daemon (`kavachd`) loads eBPF programs into the kernel and one
CLI (`kavachctl`) drives it. Enforcement lives in the kernel, so it keeps working while the
daemon restarts or upgrades.

* [1. Requirements](#1-requirements)
* [2. Pick a package](#2-pick-a-package)
* [3. Verify the download](#3-verify-the-download)
* [4. Install](#4-install)
* [5. Enable the BPF LSM (identity egress)](#5-enable-the-bpf-lsm-identity-egress)
* [6. Keys and your first policy](#6-keys-and-your-first-policy)
* [7. Start, observe, enforce](#7-start-observe-enforce)
* [8. Day-2 operations](#8-day-2-operations)
* [9. Upgrade and uninstall](#9-upgrade-and-uninstall)
* [10. Troubleshooting](#10-troubleshooting)
* [11. Build from source](#11-build-from-source)

## 1. Requirements

| Need | Why | Check |
|---|---|---|
| Linux ≥ 6.1, x86_64 or aarch64 | BPF features used (ring buffer, `bpf_find_vma`, LSM hooks) | `uname -r` |
| BTF (`/sys/kernel/btf/vmlinux`) | CO-RE: one binary works on every kernel build | ships with Debian 11+, Ubuntu 20.10+, Fedora 31+, RHEL 8.2+, Arch |
| bpffs at `/sys/fs/bpf` | pinned programs survive daemon restarts | mounted by systemd |
| `bpf` in the active LSM list | identity (per-executable) egress. Without it: XDP + TC still work | `cat /sys/kernel/security/lsm` |
| cgroup v2 | `cgroup = ...` selectors | `ls /sys/fs/cgroup/cgroup.controllers` |
| root (or the capabilities in the unit) | loading BPF | |

The release binaries are statically linked (musl): there are no runtime library dependencies.

After installing, `kavachctl doctor` checks all of this and prints the exact fix for each miss:

```console
$ kavachctl doctor
ok    kernel >= 6.1                        6.12.9-amd64
ok    BTF (CO-RE)                          /sys/kernel/btf/vmlinux
warn  BPF LSM active                       lsm=lockdown,capability,landlock,yama,apparmor
      fix: identity egress needs it: add `lsm=<current list>,bpf` to the kernel command line ...
ok    bpffs mounted                        /sys/fs/bpf
...
```

## 2. Pick a package

Every [release](https://github.com/Srizdebnath/kavach/releases) has these assets:

| Asset | For |
|---|---|
| `kavach_<ver>-1_amd64.deb`, `kavach_<ver>-1_arm64.deb` | Debian, Ubuntu, Mint, Pop!_OS |
| `kavach-<ver>-1.x86_64.rpm`, `kavach-<ver>-1.aarch64.rpm` | Fedora, RHEL/Rocky/Alma, openSUSE |
| `kavach-<ver>-x86_64-linux-musl.tar.gz`, `…-aarch64-linux-musl.tar.gz` | any distro (Arch, Alpine, NixOS, Gentoo, …): static binaries + `install.sh` |
| `SHA256SUMS`, `SHA256SUMS.sigstore.json` | checksums + keyless Sigstore signature |
| `Source code (zip / tar.gz)` | added by GitHub automatically; only needed to build from source |

## 3. Verify the download

Every asset is built by the public [release workflow](../.github/workflows/release.yml) from the
tagged commit. Two independent checks are available:

```sh
# a) GitHub build-provenance attestation (SLSA): proves which workflow + commit built the file
gh attestation verify kavach_0.3.1-1_amd64.deb --repo Srizdebnath/kavach

# b) Sigstore signature over the checksum list, then the checksums
cosign verify-blob SHA256SUMS \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/Srizdebnath/kavach/\.github/workflows/release\.yml@refs/tags/v'
sha256sum --check --ignore-missing SHA256SUMS
```

No long-lived signing key exists: the signature is bound to the workflow identity through
GitHub's OIDC token and recorded in the public Rekor transparency log.

## 4. Install

**Debian / Ubuntu**

```sh
sudo apt install ./kavach_0.3.1-1_amd64.deb
```

**Fedora / RHEL / openSUSE**

```sh
sudo dnf install ./kavach-0.3.1-1.x86_64.rpm      # zypper install ./… on openSUSE
```

**Any distro (tarball)**

```sh
tar xzf kavach-0.3.1-x86_64-linux-musl.tar.gz
cd kavach-0.3.1-x86_64-linux-musl
sudo ./install.sh                 # PREFIX=/usr/local by default
```

All three install `kavachd`, `kavachctl`, the systemd unit `kavachd.service` (installed, **not
enabled or started**), and `/etc/kavach/kavachd.toml`. An existing config is never overwritten.

Layout after install:

| Path | What |
|---|---|
| `/etc/kavach/kavachd.toml` | host config (interfaces, LSM on/off, key dir, rate limit) |
| `/etc/kavach/trusted_keys/*.pub` | public keys allowed to sign policy |
| `/var/lib/kavach/` | last applied bundle (restored at boot), executable hash cache |
| `/var/log/kavach/audit.log` | hash-chained audit log (`kavachctl audit`) |
| `/run/kavach/kavach.sock` | control socket (root, or `control_group`) |
| `/sys/fs/bpf/kavach/` | pinned programs and maps |

## 5. Enable the BPF LSM (identity egress)

Rules with `who = { binary = ... }` need the BPF LSM. Most distro kernels build it
(`CONFIG_BPF_LSM=y`) but leave it out of the default list. Add `bpf` to the **end** of your
current list. Keep every module already there:

```sh
cat /sys/kernel/security/lsm      # e.g. lockdown,capability,landlock,yama,apparmor
```

* **GRUB** (Debian, Ubuntu, Fedora, RHEL): edit `/etc/default/grub` and set
  `GRUB_CMDLINE_LINUX="... lsm=lockdown,capability,landlock,yama,apparmor,bpf"`, then
  `sudo update-grub` (Debian/Ubuntu) or `sudo grub2-mkconfig -o /boot/grub2/grub.cfg`
  (Fedora/RHEL).
* **systemd-boot**: append the same `lsm=...` to `/etc/kernel/cmdline` and run
  `sudo kernel-install add "$(uname -r)" /lib/modules/"$(uname -r)"/vmlinuz` (or `sudo bootctl
  update` / `reinstall-kernels`, depending on the distro).

Reboot, then `kavachctl doctor` should report `ok  BPF LSM active`. Without the LSM, set
`lsm = false` in `kavachd.toml`. XDP and TC enforcement work without it.

## 6. Keys and your first policy

Policy is signed. A host only accepts bundles signed by a key in `trusted_keys_dir`. Keep the
private key on your CI/admin machine, not on the host.

```sh
# on the admin / CI machine
kavachctl keygen ci                      # writes ci.key (secret) and ci.pub
# on each host
sudo install -m 0644 ci.pub /etc/kavach/trusted_keys/
```

Start from the example policy (installed at `/usr/share/doc/kavach/examples/kavach.toml`). A
minimal observe-first policy:

```toml
version = 1

[defaults]
egress  = "allow"     # observe first; switch to "drop" once the counters look right
ingress = "drop"      # new inbound only; replies to our own flows always pass
fail    = "closed"

[sets]
ssh_admins = ["10.0.0.0/8"]

[[rule]]
id        = "ssh-from-admins"
direction = "ingress"
allow     = { from = "@ssh_admins", port = 22, proto = "tcp" }

[[rule]]
id      = "curl-not-to-testnet"
comment = "identity, not IP: only this executable is blocked"
who     = { exe = "/usr/bin/curl" }   # or binary = "sha256:<hex>" to pin exact bytes
deny    = { to = "198.51.100.0/24" }
```

Check it, sign it, and preview it:

```sh
kavachctl compile kavach.toml                       # diagnostics, no key needed
kavachctl explain --policy kavach.toml --to 198.51.100.7 --port 443 --binary /usr/bin/curl
kavachctl sign kavach.toml --key ci.key -o policy.kvb --fleet default
```

## 7. Start, observe, enforce

```sh
sudo systemctl enable --now kavachd
sudo kavachctl status
sudo kavachctl apply policy.kvb --dry-run           # diff against what is running
sudo kavachctl apply policy.kvb                     # atomic swap, reported in µs
sudo kavachctl stats                                # verdict counters
sudo kavachctl events --kind egress                 # live verdicts (sampled 1-in-sample_rate)
```

Recommended rollout:

1. Apply with `egress = "allow"` and watch `stats` and `events` for a day.
2. Use `kavachctl explain` on anything surprising. It runs the same engine (`kavach-core`) as
   the kernel programs.
3. Switch to `egress = "drop"` and add `unclassified = "deny"` for strict identity: a binary's
   egress waits until its hash is known (usually milliseconds after exec).

The last applied bundle is stored in `/var/lib/kavach` and restored at boot before the network
comes up (`Before=network-pre.target`).

## 8. Day-2 operations

```sh
sudo kavachctl block add 203.0.113.7/32 --ttl 1h --reason "scanner"   # XDP drop
sudo kavachctl block list
sudo kavachctl ratelimit 20000 --burst 40000                         # per source; IPv6 per /64
sudo kavachctl metrics                                               # Prometheus text format
sudo kavachctl audit                                                 # verify the audit hash chain
sudo kavachctl diff kavach.toml                                      # what would change
```

To let a group run read/operate commands, set `control_group = "kavach"` in `kavachd.toml`.
`kill-switch` always requires root.

**Emergency off:** `sudo kavachctl kill-switch --yes` detaches every program and removes all
pins. Stopping the daemon does **not** do this (by design: a crash must not open the firewall).

## 9. Upgrade and uninstall

Upgrades install over the old package (`apt install ./new.deb`, `dnf upgrade ./new.rpm`,
`sudo ./install.sh`), then `sudo systemctl restart kavachd`. The new daemon re-attaches to the
pinned programs and maps, so enforcement does not stop during the upgrade. If the
kernel/userspace ABI changed (pins live under `/sys/fs/bpf/kavach/v<ABI>`), the new daemon
loads its own programs, restores the stored bundle, and only then detaches the previous
version's programs, so there is no unprotected window.

Uninstall: `sudo apt remove kavach`, `sudo dnf remove kavach`, or `sudo ./install.sh
--uninstall`. Each one stops the service and runs the kill switch. Config, state and logs under
`/etc/kavach`, `/var/lib/kavach` and `/var/log/kavach` are kept. Delete them by hand if you
want them gone.

## 10. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `doctor`: `FAIL kernel >= 6.1` | upgrade the kernel (6.1 LTS or newer) |
| `doctor`: `warn BPF LSM active` | see [§5](#5-enable-the-bpf-lsm-identity-egress), or set `lsm = false` |
| `apply`: `signing key … is not trusted` / `has been revoked` | the signing key's `.pub` is not in `trusted_keys_dir`, or it is in `revoked_keys` |
| `apply`: `bundle is for fleet …, this host is in fleet …` | sign with `--fleet <name>` that matches `fleet` in `kavachd.toml` |
| XDP attached in `generic` mode | the NIC driver lacks native XDP. Correct, just slower. Force with `xdp_mode = "native"` to fail instead |
| a binary rule does not match | `kavachctl explain --binary /path ...`. A file on FUSE/NFS/overlay-without-backing or a user-writable loop image is never given an identity (by design) |
| `kavachctl: permission denied` | run as root or join `control_group` |
| logs | `journalctl -u kavachd`, raise detail with `Environment=RUST_LOG=kavachd=debug` in a drop-in |

## 11. Build from source

```sh
# toolchain: Rust (stable, see rust-version in Cargo.toml), clang ≥ 14, bpftool
git clone https://github.com/Srizdebnath/kavach && cd kavach
cargo xtask build-bpf            # compiles bpf/*.c to target/bpf/kavach.bpf.o (CO-RE)
cargo build --release -p kavachd -p kavachctl
cargo test --workspace           # unprivileged suite
sudo scripts/priv-test.sh        # verifier + real-kernel suite (needs root)
```

Static release build, the same way the release workflow does it:
`rustup target add x86_64-unknown-linux-musl && cargo build --release --target
x86_64-unknown-linux-musl -p kavachd -p kavachctl`.
