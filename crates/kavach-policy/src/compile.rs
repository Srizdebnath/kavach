//! parse → validate → lower to IR → compile (FR-POL-2/3/4/8).

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;

use ipnet::IpNet;
use kavach_common::abi::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::schema::*;
use crate::workload::{LabelSelector, SpiffePattern, WorkloadKind, WorkloadSel};

pub const MAX_SET_ENTRIES: usize = 4096;
/// `[gateway.<name>]` policies per kavach.toml.
pub const MAX_GATEWAYS: usize = 256;
/// Patterns/prefixes across all lists of one gateway policy.
pub const MAX_GATEWAY_ENTRIES: usize = 4096;
/// Longest tool pattern or resource prefix.
pub const MAX_GATEWAY_PATTERN_LEN: usize = 1024;

// ---------------------------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub severity: Severity,
    /// Rule id the diagnostic is about, if any.
    pub rule: Option<String>,
    pub message: String,
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sev = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        match &self.rule {
            Some(r) => write!(f, "{sev}[{r}]: {}", self.message),
            None => write!(f, "{sev}: {}", self.message),
        }
    }
}

#[derive(Debug, Default)]
struct Diags(Vec<Diagnostic>);

impl Diags {
    fn err(&mut self, rule: Option<&str>, msg: impl Into<String>) {
        self.0.push(Diagnostic {
            severity: Severity::Error,
            rule: rule.map(str::to_owned),
            message: msg.into(),
        });
    }
    fn warn(&mut self, rule: Option<&str>, msg: impl Into<String>) {
        self.0.push(Diagnostic {
            severity: Severity::Warning,
            rule: rule.map(str::to_owned),
            message: msg.into(),
        });
    }
    fn has_errors(&self) -> bool {
        self.0.iter().any(|d| d.severity == Severity::Error)
    }
}

// ---------------------------------------------------------------------------------------------
// IR
// ---------------------------------------------------------------------------------------------

/// A user in the compiled IR (externally tagged so the binary bundle codec can decode it).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum User {
    Uid(u32),
    Name(String),
}

impl From<UserRef> for User {
    fn from(u: UserRef) -> Self {
        match u {
            UserRef::Uid(n) => Self::Uid(n),
            UserRef::Name(n) => Self::Name(n),
        }
    }
}

/// A compiled identity selector (bit `index` in every mask).
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Selector {
    pub binaries: Vec<[u8; 32]>,
    pub exes: Vec<String>,
    pub users: Vec<User>,
    pub cgroups: Vec<String>,
}

impl Selector {
    pub fn constrains_exe(&self) -> bool {
        !self.binaries.is_empty() || !self.exes.is_empty()
    }
    pub fn constrains_uid(&self) -> bool {
        !self.users.is_empty()
    }
    pub fn constrains_cgroup(&self) -> bool {
        !self.cgroups.is_empty()
    }
    fn is_any(&self) -> bool {
        !self.constrains_exe() && !self.constrains_uid() && !self.constrains_cgroup()
    }
}

/// A compiled address set (id = index + 1).
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AddrSet {
    pub name: String,
    pub cidrs: Vec<IpNet>,
    /// Resolved by kavachd at runtime and refreshed within DNS TTL bounds (FR-EG-3).
    pub fqdns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledRule {
    /// Human id from kavach.toml (several compiled rules may share it, one per port range).
    pub name: String,
    /// Numeric id carried in events (1-based index of the `[[rule]]`).
    pub id: u32,
    pub sel: u64,
    pub dir: u8,
    pub proto: u8,
    pub port_lo: u16,
    pub port_hi: u16,
    pub remote_set: u32,
    pub verdict: u8,
    pub fail: u8,
    /// Unix seconds; 0 = no TTL.
    pub not_after_unix: u64,
    /// `punt` rules: 1-based index into [`CompiledPolicy::gateways`]; 0 = none (bundle format 3+).
    pub gateway: u32,
}

/// Rule layout of bundle formats 1 and 2 (before [`CompiledRule::gateway`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledRuleV2 {
    pub name: String,
    pub id: u32,
    pub sel: u64,
    pub dir: u8,
    pub proto: u8,
    pub port_lo: u16,
    pub port_hi: u16,
    pub remote_set: u32,
    pub verdict: u8,
    pub fail: u8,
    pub not_after_unix: u64,
}

impl From<CompiledRuleV2> for CompiledRule {
    fn from(r: CompiledRuleV2) -> Self {
        Self {
            name: r.name,
            id: r.id,
            sel: r.sel,
            dir: r.dir,
            proto: r.proto,
            port_lo: r.port_lo,
            port_hi: r.port_hi,
            remote_set: r.remote_set,
            verdict: r.verdict,
            fail: r.fail,
            not_after_unix: r.not_after_unix,
            gateway: 0,
        }
    }
}

impl From<&CompiledRule> for CompiledRuleV2 {
    fn from(r: &CompiledRule) -> Self {
        Self {
            name: r.name.clone(),
            id: r.id,
            sel: r.sel,
            dir: r.dir,
            proto: r.proto,
            port_lo: r.port_lo,
            port_hi: r.port_hi,
            remote_set: r.remote_set,
            verdict: r.verdict,
            fail: r.fail,
            not_after_unix: r.not_after_unix,
        }
    }
}

/// A compiled `[gateway.<name>]` L7 policy (bundle format 3+). Lists are validated and
/// de-duplicated; resource prefixes have any trailing `*` removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledGateway {
    pub name: String,
    pub allow_tools: Vec<String>,
    pub deny_tools: Vec<String>,
    pub allow_resources: Vec<String>,
    pub allow_agent_messages: bool,
    pub allow_other: bool,
    pub tls: GatewayTls,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledDefaults {
    pub egress: u8,
    pub ingress: u8,
    pub strict_ingress: bool,
    pub loopback_bypass: bool,
    /// `unclassified = "deny"` (bundle format 2+).
    pub unclassified_deny: bool,
}

/// The portable, host-independent compiled policy carried inside a signed bundle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompiledPolicy {
    pub version: u32,
    pub created_unix: u64,
    pub source_sha256: [u8; 32],
    pub defaults: CompiledDefaults,
    pub selectors: Vec<Selector>,
    pub sets: Vec<AddrSet>,
    pub rules: Vec<CompiledRule>,
    pub agents: Vec<AgentSpec>,
    /// Named L7 gateway policies, sorted by name (bundle format 3+).
    pub gateways: Vec<CompiledGateway>,
    /// k8s / SPIFFE parts of selectors (bundle format 3+); see [`crate::workload`].
    pub workloads: Vec<WorkloadSel>,
}

impl CompiledPolicy {
    /// The gateway policy named `name`.
    pub fn gateway(&self, name: &str) -> Option<&CompiledGateway> {
        self.gateways.iter().find(|g| g.name == name)
    }

    /// The gateway policy a compiled (punt) rule hands its flows to.
    pub fn rule_gateway(&self, rule: &CompiledRule) -> Option<&CompiledGateway> {
        (rule.gateway as usize)
            .checked_sub(1)
            .and_then(|i| self.gateways.get(i))
    }

    /// The gateway policy for the numeric rule id carried in events and flow verdicts.
    pub fn gateway_for_rule_id(&self, id: u32) -> Option<&CompiledGateway> {
        self.rules
            .iter()
            .find(|r| r.id == id)
            .and_then(|r| self.rule_gateway(r))
    }

    /// True when the policy carries gateway policies (a format-3 section).
    pub fn uses_gateways(&self) -> bool {
        !self.gateways.is_empty() || self.rules.iter().any(|r| r.gateway != 0)
    }

    /// True when the policy carries k8s / SPIFFE workload selectors (a format-3 section).
    pub fn uses_workloads(&self) -> bool {
        !self.workloads.is_empty()
    }

    /// True when the policy needs bundle format 3: it carries gateway policies, workload
    /// selectors, or both.
    pub fn needs_format_3(&self) -> bool {
        self.uses_gateways() || self.uses_workloads()
    }

    /// The format-2 payload for this policy, or `None` when it needs format 3.
    pub fn to_v2(&self) -> Option<CompiledPolicyV2> {
        (!self.needs_format_3()).then(|| CompiledPolicyV2 {
            version: self.version,
            created_unix: self.created_unix,
            source_sha256: self.source_sha256,
            defaults: self.defaults.clone(),
            selectors: self.selectors.clone(),
            sets: self.sets.clone(),
            rules: self.rules.iter().map(CompiledRuleV2::from).collect(),
            agents: self.agents.clone(),
        })
    }
}

#[cfg(feature = "gateway")]
impl CompiledGateway {
    /// The gateway crate's decision type for this policy.
    pub fn to_tool_policy(&self) -> kavach_gateway::ToolPolicy {
        kavach_gateway::ToolPolicy {
            allow_tools: self.allow_tools.clone(),
            deny_tools: self.deny_tools.clone(),
            allow_resources: self.allow_resources.clone(),
            allow_agent_messages: self.allow_agent_messages,
            allow_other: self.allow_other,
            tls: match self.tls {
                GatewayTls::Deny => kavach_gateway::TlsMode::Deny,
                GatewayTls::Allow => kavach_gateway::TlsMode::Allow,
            },
        }
    }
}

#[cfg(feature = "gateway")]
impl CompiledPolicy {
    /// Every gateway policy as the proxy consumes it, keyed by name.
    pub fn tool_policies(&self) -> std::collections::HashMap<String, kavach_gateway::ToolPolicy> {
        self.gateways
            .iter()
            .map(|g| (g.name.clone(), g.to_tool_policy()))
            .collect()
    }
}

/// Bundle format 2 payload (before gateway policies and workload selectors); decoded and upgraded
/// on verify.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledPolicyV2 {
    pub version: u32,
    pub created_unix: u64,
    pub source_sha256: [u8; 32],
    pub defaults: CompiledDefaults,
    pub selectors: Vec<Selector>,
    pub sets: Vec<AddrSet>,
    pub rules: Vec<CompiledRuleV2>,
    pub agents: Vec<AgentSpec>,
}

impl From<CompiledPolicyV2> for CompiledPolicy {
    fn from(p: CompiledPolicyV2) -> Self {
        Self {
            version: p.version,
            created_unix: p.created_unix,
            source_sha256: p.source_sha256,
            defaults: p.defaults,
            selectors: p.selectors,
            sets: p.sets,
            rules: p.rules.into_iter().map(CompiledRule::from).collect(),
            agents: p.agents,
            gateways: Vec::new(),
            workloads: Vec::new(),
        }
    }
}

/// Bundle format 1 payload (before `unclassified_deny`); decoded and upgraded on verify.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledPolicyV1 {
    pub version: u32,
    pub created_unix: u64,
    pub source_sha256: [u8; 32],
    pub defaults: CompiledDefaultsV1,
    pub selectors: Vec<Selector>,
    pub sets: Vec<AddrSet>,
    pub rules: Vec<CompiledRuleV2>,
    pub agents: Vec<AgentSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledDefaultsV1 {
    pub egress: u8,
    pub ingress: u8,
    pub strict_ingress: bool,
    pub loopback_bypass: bool,
}

impl From<CompiledPolicyV1> for CompiledPolicy {
    fn from(p: CompiledPolicyV1) -> Self {
        CompiledPolicyV2 {
            version: p.version,
            created_unix: p.created_unix,
            source_sha256: p.source_sha256,
            defaults: CompiledDefaults {
                egress: p.defaults.egress,
                ingress: p.defaults.ingress,
                strict_ingress: p.defaults.strict_ingress,
                loopback_bypass: p.defaults.loopback_bypass,
                unclassified_deny: false,
            },
            selectors: p.selectors,
            sets: p.sets,
            rules: p.rules,
            agents: p.agents,
        }
        .into()
    }
}

#[derive(Debug)]
pub struct CompileOutput {
    pub policy: CompiledPolicy,
    pub warnings: Vec<Diagnostic>,
}

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

pub fn action_verdict(a: Action) -> u8 {
    match a {
        Action::Allow => Verdict::Allow as u8,
        Action::Drop => Verdict::Drop as u8,
        Action::Log => Verdict::Log as u8,
        Action::Punt => Verdict::Punt as u8,
    }
}

/// `"30d" | "12h" | "15m" | "90s"` → seconds.
pub fn parse_duration(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.len() < 2 {
        return Err(format!("invalid duration {s:?}"));
    }
    let (num, unit) = s.split_at(s.len() - 1);
    let n: u64 = num.parse().map_err(|_| format!("invalid duration {s:?}"))?;
    let mul = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        "w" => 7 * 86_400,
        _ => {
            return Err(format!(
                "invalid duration unit in {s:?} (use s, m, h, d, w)"
            ));
        }
    };
    n.checked_mul(mul)
        .filter(|v| *v > 0)
        .ok_or_else(|| format!("duration {s:?} out of range"))
}

fn parse_proto(p: Option<&str>) -> Result<u8, String> {
    Ok(match p.map(str::to_ascii_lowercase).as_deref() {
        None | Some("any") => KV_PROTO_ANY,
        Some("tcp") => KV_PROTO_TCP,
        Some("udp") => KV_PROTO_UDP,
        Some("icmp") => KV_PROTO_ICMP,
        Some("icmpv6") => KV_PROTO_ICMPV6,
        Some(other) => return Err(format!("unknown proto {other:?}")),
    })
}

fn parse_ports(p: &Option<OneOrMany<PortSpec>>) -> Result<Vec<(u16, u16)>, String> {
    let Some(p) = p else {
        return Ok(vec![(0, u16::MAX)]);
    };
    let mut out = Vec::new();
    for spec in p.to_vec() {
        match spec {
            PortSpec::Num(n) => out.push((n, n)),
            PortSpec::Range(r) => {
                let (a, b) = r
                    .split_once('-')
                    .ok_or_else(|| format!("invalid port range {r:?} (use \"lo-hi\")"))?;
                let a: u16 = a
                    .trim()
                    .parse()
                    .map_err(|_| format!("invalid port {a:?}"))?;
                let b: u16 = b
                    .trim()
                    .parse()
                    .map_err(|_| format!("invalid port {b:?}"))?;
                if a > b {
                    return Err(format!("port range {r:?} is reversed"));
                }
                out.push((a, b));
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

fn parse_sha256(s: &str) -> Result<[u8; 32], String> {
    let hexpart = s
        .strip_prefix("sha256:")
        .ok_or_else(|| format!("binary {s:?} must look like \"sha256:<64 hex digits>\""))?;
    let v = hex::decode(hexpart).map_err(|_| format!("binary {s:?}: invalid hex"))?;
    v.try_into()
        .map_err(|_| format!("binary {s:?}: digest must be 32 bytes"))
}

fn is_fqdn(s: &str) -> bool {
    s.len() <= 253
        && s.contains('.')
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
}

enum Remote {
    Any,
    Entries(Vec<IpNet>, Vec<String>),
}

fn parse_remote(
    list: &[String],
    named: &BTreeMap<String, Vec<String>>,
    depth: u8,
) -> Result<Remote, String> {
    let mut cidrs = Vec::new();
    let mut fqdns = Vec::new();
    for item in list {
        let item = item.trim();
        if item == "any" || item == "*" {
            return Ok(Remote::Any);
        }
        if let Some(name) = item.strip_prefix('@') {
            if depth > 4 {
                return Err(format!("set reference cycle at {item:?}"));
            }
            let inner = named
                .get(name)
                .ok_or_else(|| format!("unknown set {item:?}"))?;
            match parse_remote(inner, named, depth + 1)? {
                Remote::Any => return Ok(Remote::Any),
                Remote::Entries(c, f) => {
                    cidrs.extend(c);
                    fqdns.extend(f);
                }
            }
        } else if let Ok(net) = item.parse::<IpNet>() {
            cidrs.push(net.trunc());
        } else if let Ok(ip) = item.parse::<IpAddr>() {
            cidrs.push(IpNet::from(ip));
        } else if is_fqdn(&item.to_ascii_lowercase()) {
            fqdns.push(item.to_ascii_lowercase());
        } else {
            return Err(format!("{item:?} is not a CIDR, IP, FQDN or @set"));
        }
    }
    cidrs.sort();
    cidrs.dedup();
    fqdns.sort();
    fqdns.dedup();
    Ok(Remote::Entries(cidrs, fqdns))
}

fn net_contains(outer: &IpNet, inner: &IpNet) -> bool {
    outer.contains(inner)
}

// ---------------------------------------------------------------------------------------------
// Compile
// ---------------------------------------------------------------------------------------------

/// Compile policy source. `now_unix` anchors TTLs (pass the CI build time).
pub fn compile(src: &str, now_unix: u64) -> Result<CompileOutput, Vec<Diagnostic>> {
    let file = PolicyFile::parse(src).map_err(|e| {
        vec![Diagnostic {
            severity: Severity::Error,
            rule: None,
            message: e.to_string(),
        }]
    })?;
    compile_file(&file, src.as_bytes(), now_unix)
}

pub fn compile_file(
    file: &PolicyFile,
    src: &[u8],
    now_unix: u64,
) -> Result<CompileOutput, Vec<Diagnostic>> {
    let mut d = Diags::default();
    if file.version != 1 {
        d.err(
            None,
            format!("unsupported policy version {} (expected 1)", file.version),
        );
    }

    let mut selectors: BTreeMap<(Selector, Option<WorkloadKind>), usize> = BTreeMap::new();
    let mut workloads: Vec<WorkloadSel> = Vec::new();
    let mut sel_list: Vec<Selector> = Vec::new();
    let mut sets: BTreeMap<(Vec<IpNet>, Vec<String>), usize> = BTreeMap::new();
    let mut set_list: Vec<AddrSet> = Vec::new();
    let mut rules: Vec<CompiledRule> = Vec::new();
    let mut seen_ids: BTreeMap<&str, usize> = BTreeMap::new();
    let gateways = compile_gateways(file, &mut d);
    let mut gateways_used = vec![false; gateways.len()];

    for (idx, r) in file.rules.iter().enumerate() {
        let rid = Some(r.id.as_str());
        if r.id.is_empty() {
            d.err(None, format!("rule #{} has an empty id", idx + 1));
        }
        if seen_ids.insert(&r.id, idx).is_some() {
            d.err(rid, "duplicate rule id");
        }
        let dir = r.direction.unwrap_or_default();

        // Exactly one action.
        let actions: Vec<(Action, &MatchSpec)> = [
            (Action::Allow, r.allow.as_ref()),
            (Action::Drop, r.deny.as_ref()),
            (Action::Log, r.log.as_ref()),
            (Action::Punt, r.punt.as_ref()),
        ]
        .into_iter()
        .filter_map(|(a, m)| m.map(|m| (a, m)))
        .collect();
        if actions.len() != 1 {
            d.err(rid, "exactly one of allow / deny / log / punt is required");
            continue;
        }
        let (action, m) = actions[0];

        // L7 gateway (punt only)
        let gateway = match (&m.gateway, action) {
            (None, Action::Punt) => {
                d.warn(
                    rid,
                    "punt rule has no `gateway`: its flows resolve through the rule's fail mode",
                );
                0
            }
            (None, _) => 0,
            (Some(g), Action::Punt) => match gateways.iter().position(|c| &c.name == g) {
                Some(i) => {
                    gateways_used[i] = true;
                    i as u32 + 1
                }
                None => {
                    d.err(
                        rid,
                        format!("unknown gateway {g:?} (define it as [gateway.{g}])"),
                    );
                    0
                }
            },
            (Some(_), _) => {
                d.err(rid, "`gateway` is only valid on `punt` rules");
                0
            }
        };

        // TTL
        let not_after_unix = match &r.ttl {
            Some(t) => match parse_duration(t) {
                Ok(secs) => now_unix.saturating_add(secs),
                Err(e) => {
                    d.err(rid, e);
                    0
                }
            },
            None => {
                if file.defaults.require_ttl {
                    d.err(rid, "a ttl is required (defaults.require_ttl = true)");
                }
                0
            }
        };

        // Who
        let mut sel = Selector::default();
        let mut workload: Option<WorkloadKind> = None;
        if let Some(w) = &r.who {
            if w.k8s.is_some() || w.spiffe.is_some() {
                let k8s = w.k8s.as_deref().map(LabelSelector::parse).transpose();
                let spiffe = w.spiffe.as_deref().map(SpiffePattern::parse).transpose();
                match (k8s, spiffe) {
                    (Ok(k8s), Ok(spiffe)) => workload = Some(WorkloadKind::Match { k8s, spiffe }),
                    (Err(e), _) | (_, Err(e)) => d.err(rid, e),
                }
                if w.cgroup.is_some() {
                    d.err(
                        rid,
                        "k8s / spiffe selectors already identify the pod's cgroup; they cannot \
                         be combined with `cgroup` in one `who`",
                    );
                }
            }
            for b in w.binary.as_ref().map(OneOrMany::to_vec).unwrap_or_default() {
                match parse_sha256(&b) {
                    Ok(h) => sel.binaries.push(h),
                    Err(e) => d.err(rid, e),
                }
            }
            for e in w.exe.as_ref().map(OneOrMany::to_vec).unwrap_or_default() {
                if !e.starts_with('/') {
                    d.err(rid, format!("exe {e:?} must be an absolute path"));
                }
                if INTERPRETERS.iter().any(|i| e.rsplit('/').next() == Some(i)) {
                    d.warn(
                        rid,
                        format!(
                            "exe {e:?} is an interpreter: every script it runs shares this \
                             identity; prefer user / cgroup selectors"
                        ),
                    );
                }
                sel.exes.push(e);
            }
            sel.users = w
                .user
                .as_ref()
                .map(OneOrMany::to_vec)
                .unwrap_or_default()
                .into_iter()
                .map(User::from)
                .collect();
            for c in w.cgroup.as_ref().map(OneOrMany::to_vec).unwrap_or_default() {
                let c = c.trim_matches('/').to_owned();
                if c.split('/').any(|p| p == ".." || p == ".") {
                    d.err(rid, format!("cgroup {c:?} must not contain . or .."));
                }
                sel.cgroups.push(c);
            }
            sel.binaries.sort();
            sel.binaries.dedup();
            sel.exes.sort();
            sel.exes.dedup();
            sel.users.sort();
            sel.users.dedup();
            sel.cgroups.sort();
            sel.cgroups.dedup();
        }
        let any = sel.is_any() && workload.is_none();
        if dir == Direction::Ingress && !any {
            d.err(
                rid,
                "ingress rules cannot use `who` yet (local service identity lands in v0.4)",
            );
        }
        let mut intern = |sel: &Selector, wl: Option<WorkloadKind>, d: &mut Diags| -> u64 {
            let n = sel_list.len();
            let bit = *selectors
                .entry((sel.clone(), wl.clone()))
                .or_insert_with(|| {
                    sel_list.push(sel.clone());
                    if let Some(kind) = wl {
                        workloads.push(WorkloadSel {
                            sel: n as u32,
                            kind,
                        });
                    }
                    n
                });
            if bit >= KV_MAX_SELECTORS as usize {
                d.err(
                    rid,
                    format!(
                        "more than {KV_MAX_SELECTORS} distinct selectors (each fail-closed k8s / \
                         spiffe selector uses a second one for its unknown-identity twin)"
                    ),
                );
                0
            } else {
                1u64 << bit
            }
        };
        let sel_mask = if any {
            0
        } else {
            intern(&sel, workload.clone(), &mut d)
        };
        // Fail-closed workload rules: a `drop` twin that matches pods whose identity kavachd has
        // not resolved yet (see `crate::workload`). Log rules only observe, so they just skip.
        let fail_mode = r.fail.unwrap_or(file.defaults.fail);
        let unknown_mask = if workload.is_some()
            && sel_mask != 0
            && fail_mode == FailMode::Closed
            && action != Action::Log
        {
            let of = sel_mask.trailing_zeros();
            intern(&sel, Some(WorkloadKind::Unknown { of }), &mut d)
        } else {
            0
        };

        // Remote
        let (remote_list, wrong) = match dir {
            Direction::Egress => (&m.to, m.from.is_some()),
            Direction::Ingress => (&m.from, m.to.is_some()),
        };
        if wrong {
            d.err(
                rid,
                match dir {
                    Direction::Egress => "egress rules use `to`, not `from`",
                    Direction::Ingress => "ingress rules use `from`, not `to`",
                },
            );
        }
        let remote_set = match remote_list.as_ref().map(OneOrMany::to_vec) {
            None => 0,
            Some(list) => match parse_remote(&list, &file.sets, 0) {
                Ok(Remote::Any) => 0,
                Ok(Remote::Entries(c, f)) if c.is_empty() && f.is_empty() => {
                    d.err(rid, "empty destination list");
                    0
                }
                Ok(Remote::Entries(c, f)) => {
                    let n = set_list.len();
                    let name = match list.as_slice() {
                        [one] if one.starts_with('@') => one.clone(),
                        _ => format!("rule:{}", r.id),
                    };
                    let id = *sets.entry((c.clone(), f.clone())).or_insert_with(|| {
                        set_list.push(AddrSet {
                            name,
                            cidrs: c,
                            fqdns: f,
                        });
                        n
                    });
                    if id >= KV_MAX_SETS as usize {
                        d.err(
                            rid,
                            format!("more than {KV_MAX_SETS} distinct address sets"),
                        );
                        0
                    } else {
                        id as u32 + 1
                    }
                }
                Err(e) => {
                    d.err(rid, e);
                    0
                }
            },
        };

        let proto = match parse_proto(m.proto.as_deref()) {
            Ok(p) => p,
            Err(e) => {
                d.err(rid, e);
                0
            }
        };
        let ports = match parse_ports(&m.port) {
            Ok(p) => p,
            Err(e) => {
                d.err(rid, e);
                vec![(0, u16::MAX)]
            }
        };
        if matches!(proto, KV_PROTO_ICMP | KV_PROTO_ICMPV6) && m.port.is_some() {
            d.err(rid, "icmp rules cannot have ports");
        }
        if m.port.is_some() && proto == KV_PROTO_ANY {
            d.warn(rid, "port given without proto: matches both tcp and udp");
        }

        let fail = match fail_mode {
            FailMode::Open => KV_FAIL_OPEN,
            FailMode::Closed => KV_FAIL_CLOSED,
        };
        let mut push = |sel: u64, verdict: u8, gateway: u32| {
            for &(lo, hi) in &ports {
                rules.push(CompiledRule {
                    name: r.id.clone(),
                    id: idx as u32 + 1,
                    sel,
                    dir: match dir {
                        Direction::Egress => KV_DIR_EGRESS,
                        Direction::Ingress => KV_DIR_INGRESS,
                    },
                    proto,
                    port_lo: lo,
                    port_hi: hi,
                    remote_set,
                    verdict,
                    fail,
                    not_after_unix,
                    gateway,
                });
            }
        };
        if unknown_mask != 0 {
            // The unknown-identity twin drops; it never reaches a gateway.
            push(unknown_mask, Verdict::Drop as u8, 0);
        }
        push(sel_mask, action_verdict(action), gateway);
    }
    for (g, used) in gateways.iter().zip(&gateways_used) {
        if !used {
            d.warn(
                Some(&format!("gateway.{}", g.name)),
                "unused: no punt rule references this gateway policy",
            );
        }
    }

    if rules.len() > KV_MAX_RULES as usize {
        d.err(
            None,
            format!(
                "{} compiled rules exceed the limit of {KV_MAX_RULES}",
                rules.len()
            ),
        );
    }
    let entries: usize = set_list.iter().map(|s| s.cidrs.len() + s.fqdns.len()).sum();
    if entries > MAX_SET_ENTRIES {
        d.err(
            None,
            format!("{entries} address-set entries exceed the limit of {MAX_SET_ENTRIES}"),
        );
    }
    if !file.agents.is_empty() {
        d.warn(
            None,
            "[[agent]] policies are carried in the bundle but enforced only by the v0.4 gateway",
        );
    }
    if file.defaults.ingress == Action::Punt || file.defaults.egress == Action::Punt {
        d.err(None, "defaults cannot be `punt`");
    }

    check_shadowing(&rules, &set_list, file.defaults.allow_shadowed, &mut d);

    if d.has_errors() {
        return Err(d.0);
    }
    let policy = CompiledPolicy {
        version: file.version,
        created_unix: now_unix,
        source_sha256: Sha256::digest(src).into(),
        defaults: CompiledDefaults {
            egress: action_verdict(file.defaults.egress),
            ingress: action_verdict(file.defaults.ingress),
            strict_ingress: file.defaults.strict_ingress,
            loopback_bypass: file.defaults.loopback_bypass,
            unclassified_deny: file.defaults.unclassified == crate::schema::Unclassified::Deny,
        },
        selectors: sel_list,
        sets: set_list,
        rules,
        agents: file.agents.clone(),
        gateways,
        workloads,
    };
    Ok(CompileOutput {
        policy,
        warnings: d.0,
    })
}

// ---------------------------------------------------------------------------------------------
// Gateway policies
// ---------------------------------------------------------------------------------------------

fn valid_gateway_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 64
        && n.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// Tool pattern `outer` matches every name tool pattern `inner` matches (`*` only as a suffix,
/// the same semantics as `kavach_gateway::ToolPolicy`).
pub fn tool_pattern_covers(outer: &str, inner: &str) -> bool {
    match outer.strip_suffix('*') {
        Some(prefix) => inner.starts_with(prefix),
        None => outer == inner,
    }
}

/// Syntax-check and de-duplicate one list (`prefixes`: resource URI prefixes, where a trailing
/// `*` is accepted and dropped). Returns the cleaned list in source order.
fn gateway_list(
    gid: &str,
    list: &str,
    items: &[String],
    prefixes: bool,
    d: &mut Diags,
) -> Vec<String> {
    let what = if prefixes {
        "resource prefix"
    } else {
        "tool pattern"
    };
    let mut out: Vec<String> = Vec::new();
    for raw in items {
        if raw.is_empty() {
            d.err(Some(gid), format!("{list}: empty {what}"));
            continue;
        }
        if raw.len() > MAX_GATEWAY_PATTERN_LEN {
            d.err(
                Some(gid),
                format!("{list}: {what} longer than {MAX_GATEWAY_PATTERN_LEN} bytes"),
            );
            continue;
        }
        if raw.chars().any(|c| c.is_whitespace() || c.is_control()) {
            d.err(
                Some(gid),
                format!("{list}: {what} {raw:?} contains whitespace or control characters"),
            );
            continue;
        }
        if raw.strip_suffix('*').unwrap_or(raw).contains('*') {
            d.err(
                Some(gid),
                format!(
                    "{list}: {what} {raw:?}: `*` is only allowed as the last character \
                     (a prefix match)"
                ),
            );
            continue;
        }
        let p = if prefixes {
            raw.strip_suffix('*').unwrap_or(raw).to_owned()
        } else {
            raw.clone()
        };
        if out.contains(&p) {
            d.warn(Some(gid), format!("{list}: duplicate entry {raw:?}"));
            continue;
        }
        out.push(p);
    }
    // Entries another (distinct) entry of the same list already covers.
    for inner in &out {
        let outer = out.iter().find(|outer| {
            *outer != inner
                && if prefixes {
                    inner.starts_with(outer.as_str())
                } else {
                    tool_pattern_covers(outer, inner)
                }
        });
        if let Some(outer) = outer {
            d.warn(
                Some(gid),
                format!("{list}: {inner:?} is redundant, {outer:?} already covers it"),
            );
        }
    }
    out
}

fn compile_gateways(file: &PolicyFile, d: &mut Diags) -> Vec<CompiledGateway> {
    if file.gateways.len() > MAX_GATEWAYS {
        d.err(
            None,
            format!(
                "{} gateway policies exceed the limit of {MAX_GATEWAYS}",
                file.gateways.len()
            ),
        );
    }
    let mut out = Vec::new();
    for (name, g) in &file.gateways {
        let gid = format!("gateway.{name}");
        if !valid_gateway_name(name) {
            d.err(
                Some(&gid),
                "gateway names are 1-64 characters of [A-Za-z0-9._-]",
            );
        }
        let entries = g.allow_tools.len() + g.deny_tools.len() + g.allow_resources.len();
        if entries > MAX_GATEWAY_ENTRIES {
            d.err(
                Some(&gid),
                format!("{entries} entries exceed the limit of {MAX_GATEWAY_ENTRIES}"),
            );
            continue;
        }
        let allow_tools = gateway_list(&gid, "allow_tools", &g.allow_tools, false, d);
        let deny_tools = gateway_list(&gid, "deny_tools", &g.deny_tools, false, d);
        let allow_resources = gateway_list(&gid, "allow_resources", &g.allow_resources, true, d);

        if allow_tools.is_empty() {
            d.warn(
                Some(&gid),
                if deny_tools.is_empty() {
                    "allow_tools is empty: every MCP tool call is denied"
                } else {
                    "allow_tools is empty: every MCP tool call is denied (deny_tools has no effect)"
                },
            );
        }
        // Deny is checked first: an allow pattern a deny pattern covers can never match.
        for a in &allow_tools {
            if let Some(dp) = deny_tools.iter().find(|dp| tool_pattern_covers(dp, a)) {
                let msg = format!(
                    "allow_tools pattern {a:?} can never match: deny_tools pattern {dp:?} covers it"
                );
                if file.defaults.allow_shadowed {
                    d.warn(Some(&gid), msg);
                } else {
                    d.err(Some(&gid), msg);
                }
            }
        }
        out.push(CompiledGateway {
            name: name.clone(),
            allow_tools,
            deny_tools,
            allow_resources,
            allow_agent_messages: g.allow_agent_messages,
            allow_other: g.allow_other,
            tls: g.tls,
        });
    }
    out
}

/// Executables whose identity says nothing about the code they run.
const INTERPRETERS: &[&str] = &[
    "python", "python2", "python3", "node", "nodejs", "ruby", "perl", "php", "bash", "sh", "dash",
    "zsh", "java", "deno", "bun", "lua", "Rscript", "pwsh",
];

fn set_covers(sets: &[AddrSet], outer: u32, inner: u32) -> bool {
    if outer == 0 || outer == inner {
        return true;
    }
    if inner == 0 {
        return false;
    }
    let (o, i) = (&sets[outer as usize - 1], &sets[inner as usize - 1]);
    // FQDNs resolve at runtime, so only CIDR-only sets can be proven to cover each other.
    o.fqdns.is_empty()
        && i.fqdns.is_empty()
        && i.cidrs
            .iter()
            .all(|ic| o.cidrs.iter().any(|oc| net_contains(oc, ic)))
}

/// Rule `outer` matches every flow `inner` matches (so `inner`, if later, never fires).
fn covers(sets: &[AddrSet], outer: &CompiledRule, inner: &CompiledRule) -> bool {
    outer.dir == inner.dir
        && (outer.sel == 0 || outer.sel == inner.sel)
        && (outer.proto == KV_PROTO_ANY || outer.proto == inner.proto)
        && outer.port_lo <= inner.port_lo
        && outer.port_hi >= inner.port_hi
        && set_covers(sets, outer.remote_set, inner.remote_set)
        && (outer.not_after_unix == 0
            || (inner.not_after_unix != 0 && outer.not_after_unix >= inner.not_after_unix))
}

fn check_shadowing(rules: &[CompiledRule], sets: &[AddrSet], allow: bool, d: &mut Diags) {
    let mut reported = std::collections::BTreeSet::new();
    for (j, inner) in rules.iter().enumerate() {
        for outer in &rules[..j] {
            if outer.name == inner.name || !covers(sets, outer, inner) {
                continue;
            }
            if !reported.insert(inner.name.clone()) {
                break;
            }
            if outer.verdict != inner.verdict {
                d.err(
                    Some(&inner.name),
                    format!(
                        "contradicts earlier rule {:?}: it is fully covered by it, so its \
                         verdict can never apply",
                        outer.name
                    ),
                );
            } else if allow {
                d.warn(
                    Some(&inner.name),
                    format!("redundant: shadowed by {:?}", outer.name),
                );
            } else {
                d.err(
                    Some(&inner.name),
                    format!("shadowed by earlier rule {:?} (never matches)", outer.name),
                );
            }
            break;
        }
    }
}
