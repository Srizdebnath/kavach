# Security policy

Kavach runs code in the kernel and decides what traffic leaves a host. We would much rather hear
about a problem privately than read about it.

## Reporting a vulnerability
**Use GitHub private vulnerability reporting**: open the repository's **Security** tab and click
**Report a vulnerability** (<https://github.com/Srizdebnath/kavach/security/advisories/new>).
Do not open public issues, discussions or pull requests for security bugs.

Please include the Kavach version (`kavachctl --version`), kernel and distro, the output of
`kavachctl doctor`, a minimal policy or reproducer, and the impact you believe it has.

## Scope
In scope:
- **Kernel programs** (`bpf/`): verifier-accepted programs that can be made to misbehave, crash
  or leak kernel memory; XDP / TC / BPF-LSM enforcement bypasses.
- **Daemon** (`kavachd`, `kavach-gateway`): policy bypasses (executable-identity spoofing,
  unclassified-window abuse, cache staleness after a policy swap), control-socket privilege
  escalation, kill-switch misuse, fail-open conditions.
- **Policy signing** (`kavach-policy`): bundle signature, revocation, rollback (serial) or
  fleet-scope bypasses; trusted-key handling.
- **Parsers** (`kavach-parsers`, `kavach-api`, the policy compiler): panics, hangs or memory
  safety issues on attacker-controlled input (TLS, DNS, policy files, bundles, control requests).
- **Audit log**: forgery or truncation that `kavachctl audit` does not detect.
- Release artifacts and their signatures.

Out of scope: attacks that already require root on the enforcing host (root can unload BPF
programs), configurations the documentation warns against, flooding a link beyond line rate,
and bugs in the Linux kernel itself (report those upstream; we are happy to help coordinate).

## Response targets
| Step | Target |
|---|---|
| Acknowledge the report | 72 hours |
| Initial assessment and severity | 7 days |
| Fix or mitigation released | 30 days for high / critical, next release otherwise |
| Public advisory (GHSA, CVE when warranted) | when the fix ships |

These are targets from a small maintainer team, not guarantees; we keep you updated in the
private advisory thread. Please allow a reasonable window before public disclosure (we aim to
disclose within 90 days of the report).

There is **no bug bounty**. Reporters are credited in the advisory and release notes unless
they prefer otherwise.

## Supported versions
| Version | Supported |
|---|---|
| Latest minor release (currently 0.3.x) | Yes |
| Older releases | No, please upgrade |

Kernels 6.1 LTS and newer are supported.

## Hardening notes
- No network listener; the control socket is 0600 (0660 with `control_group`) and
  `SO_PEERCRED`-checked. The kill-switch is root-only.
- Policy is accepted only as Ed25519-signed bundles from `trusted_keys_dir`, with revocation,
  fleet scoping and monotonic serials. Signing keys belong in CI, never on enforcing hosts.
- Enforcement state is pinned in bpffs: killing `kavachd` does not open the firewall.
