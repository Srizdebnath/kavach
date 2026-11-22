# Security policy

Kavach runs code in the kernel and decides what traffic leaves a host, so we treat these as
security bugs: verifier-accepted programs that can be made to misbehave, policy bypasses
(identity spoofing, unclassified-window abuse, cache staleness after a policy swap), bundle
signature / rollback / fleet-scope bypasses, control-socket privilege escalation, and
audit-log forgery that `kavachctl audit` does not detect.

**Please report privately** through GitHub Security Advisories on this repository
("Report a vulnerability"). Do not open public issues for these. We aim to acknowledge within
72 hours and to ship a fix or mitigation within 30 days.

## Supported versions
The latest minor release receives fixes. Kernels 6.1 LTS and newer are supported.

## Hardening notes
- No network listener; the control socket is 0600 (0660 with `control_group`) and
  `SO_PEERCRED`-checked. The kill-switch is root-only.
- Policy is accepted only as Ed25519-signed bundles from `trusted_keys_dir`, with revocation,
  fleet scoping and monotonic serials. Signing keys belong in CI, never on enforcing hosts.
- Enforcement state is pinned in bpffs: killing `kavachd` does not open the firewall.
