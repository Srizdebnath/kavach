# Kavach diagrams

Hand-written SVGs, drawn from the code in `bpf/` and `crates/` as of v0.3. Each file is
self-contained (no external fonts or images) and follows the viewer's light or dark colour scheme
through an embedded `prefers-color-scheme` style, on a solid background so it reads well on either
GitHub theme.

Colours: orange = kernel (C eBPF), blue = user space (Rust), purple = policy / CI, green = allow /
built / no_std, red = drop / threat, yellow = degraded or partial. Dashed outlines mean planned
(v0.4 / v0.5), not built.

## How Kavach works

| # | Diagram | What it shows |
|---|---------|---------------|
| 01 | [System overview](01-system-overview.svg) | CI, user space and kernel planes; the pinned maps where they meet |
| 02 | [Ingress path](02-ingress-path.svg) | NIC → XDP → TC ingress → socket, every verdict point in order |
| 03 | [Egress path](03-egress-path.svg) | connect()/sendmsg() → BPF-LSM → TC egress, identity mask and re-evaluation |
| 04 | [Identity pipeline](04-identity-pipeline.svg) | exec / iterator / key reports → trust checks → SHA-256 → `exe_class`; taint hooks |
| 05 | [Placeholder protocol](05-taint-race.svg) | sequence diagram: why a write that races the hash can never leave stale trust |
| 06 | [Policy pipeline](06-policy-pipeline.svg) | `kavach.toml` → validate → shadow check → IR → sign → verify → stage → flip → drain |
| 07 | [A/B hot-swap](07-ab-hotswap.svg) | timeline of the two policy slots, `policy_gen` flip and RCU drain |
| 08 | [Bundle format](08-bundle-format.svg) | KVB1 byte layout, signature input and verification order |
| 09 | [Anti-rollback](09-anti-rollback.svg) | serial / fleet / expiry / revocation decisions, worked example |
| 10 | [Audit chain](10-audit-chain.svg) | hash-chained JSONL records and what tampering looks like |
| 11 | [Control plane](11-control-plane.svg) | UDS + `SO_PEERCRED` roles; no network listener |
| 12 | [Failure semantics](12-failure-modes.svg) | daemon crash, restart, punt fail modes, bad bundles, kill-switch |
| 13 | [Upgrade path](13-upgrade-path.svg) | ABI-versioned pins `/sys/fs/bpf/kavach/v<ABI>` and retiring the old version |
| 14 | [Crate graph](14-crate-graph.svg) | Rust crates, the generated C ABI header and planned kernel/BSD consumers |
| 15 | [Roadmap](15-roadmap.svg) | v0.1 – v0.5, built vs partial vs planned |

## Known gaps of modern firewalls (SRS §1.2)

| Gap | Diagram |
|-----|---------|
| G1 | [The firewall itself is the target](gap-g1-attack-surface.svg) |
| G2 | [Encrypted traffic is opaque](gap-g2-encrypted-traffic.svg) |
| G3 | [AI agents speak MCP / A2A](gap-g3-ai-agents.svg) |
| G4 | [East-west traffic is invisible](gap-g4-east-west.svg) |
| G5 | [IP addresses are not identity](gap-g5-identity.svg) |
| G6 | [Rule sprawl and misconfiguration](gap-g6-rule-sprawl.svg) |
| G7 | [Exploited within hours](gap-g7-time-to-exploit.svg) |
| G8 | [Kernel modules can crash the box](gap-g8-kernel-safety.svg) |

Each gap diagram tags every mitigation as **built** (in the data path today), **lib** (built and
tested, not yet wired into the daemon) or **v0.4 / planned**.

## Editing

The files are plain SVG with class-based styles: the palette is defined once in each file's
`<style>` block (light rules, then a `prefers-color-scheme: dark` override). After an edit, check
the file in both schemes, for example with `rsvg-convert -o out.png file.svg` (light) and a
browser in dark mode, and validate it with
`python3 -c "import sys, xml.etree.ElementTree as E; E.parse(sys.argv[1])" file.svg`.
