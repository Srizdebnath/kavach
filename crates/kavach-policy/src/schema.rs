//! `kavach.toml` — the human-authored, git-reviewed policy (FR-POL-1). Unknown keys are errors.
//!
//! ```toml
//! version = 1
//!
//! [defaults]
//! egress  = "allow"     # allow | drop | log
//! ingress = "drop"
//! fail    = "closed"
//!
//! [sets]
//! payments = ["api.stripe.com", "203.0.113.0/24"]
//!
//! [[rule]]
//! id    = "stripe-egress"
//! who   = { binary = "sha256:ab12...", user = "svc-pay" }
//! allow = { to = "@payments", port = 443, proto = "tcp" }
//! ttl   = "30d"
//! fail  = "closed"
//!
//! # L7 gateway policy for MCP / A2A traffic, applied to flows a `punt` rule hands over.
//! [gateway.github-agent]
//! allow_tools     = ["github.*"]
//! deny_tools      = ["github.delete_*"]
//! allow_resources = ["repo://acme/"]
//! tls             = "deny"
//!
//! [[rule]]
//! id   = "agent-to-mcp"
//! who  = { user = "agent" }
//! punt = { to = "mcp.internal.example", port = 443, proto = "tcp", gateway = "github-agent" }
//! ```

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyFile {
    pub version: u32,
    #[serde(default)]
    pub defaults: Defaults,
    /// Named address sets: CIDRs, IPs or FQDNs. Referenced as `"@name"`.
    #[serde(default)]
    pub sets: BTreeMap<String, Vec<String>>,
    #[serde(default, rename = "rule")]
    pub rules: Vec<RuleSpec>,
    /// v0.4 agent policies (parsed and carried, enforced by the gateway).
    #[serde(default, rename = "agent")]
    pub agents: Vec<AgentSpec>,
    /// Named L7 gateway policies (`[gateway.<name>]`), referenced by `punt` rules.
    #[serde(default, rename = "gateway")]
    pub gateways: BTreeMap<String, GatewaySpec>,
}

/// `[gateway.<name>]`: what an agent may do over a punted MCP / A2A connection.
///
/// Tool patterns are exact names or a prefix ending in `*` (`"github.*"`, `"*"`). A tool call
/// is allowed when no `deny_tools` pattern and at least one `allow_tools` pattern matches.
/// Handshake/discovery traffic (`initialize`, `ping`, `*/list`, notifications) always passes.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GatewaySpec {
    /// MCP tool name patterns that may be called.
    #[serde(default)]
    pub allow_tools: Vec<String>,
    /// MCP tool name patterns that are refused (checked before `allow_tools`).
    #[serde(default)]
    pub deny_tools: Vec<String>,
    /// URI prefixes `resources/read` may read (plain prefixes, no `*`).
    #[serde(default)]
    pub allow_resources: Vec<String>,
    /// A2A `message/send` / `message/stream` (delegating to another agent).
    #[serde(default)]
    pub allow_agent_messages: bool,
    /// Any other JSON-RPC method.
    #[serde(default)]
    pub allow_other: bool,
    /// TLS the gateway does not terminate (no frame visible): `deny` (default) or `allow`.
    #[serde(default)]
    pub tls: GatewayTls,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum GatewayTls {
    /// Refuse opaque TLS streams (fail closed).
    #[default]
    Deny,
    /// Pass them through uninspected; only the punting L3/L4 rule applies.
    Allow,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    #[serde(default = "Defaults::egress")]
    pub egress: Action,
    #[serde(default = "Defaults::ingress")]
    pub ingress: Action,
    #[serde(default)]
    pub fail: FailMode,
    /// Every rule must carry a `ttl` (FR-POL-2).
    #[serde(default)]
    pub require_ttl: bool,
    /// Drop mid-stream TCP packets that have no flow state.
    #[serde(default)]
    pub strict_ingress: bool,
    /// Exempt 127.0.0.0/8 and ::1 from egress/ingress policy.
    #[serde(default = "yes")]
    pub loopback_bypass: bool,
    /// Report shadowed rules as warnings instead of errors.
    #[serde(default)]
    pub allow_shadowed: bool,
    /// Egress from an executable whose hash is not known yet (its first moments after exec):
    /// `allow` (default) or `deny` (strict; the program may see one EPERM while kavachd hashes).
    #[serde(default)]
    pub unclassified: Unclassified,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Unclassified {
    #[default]
    Allow,
    Deny,
}

fn yes() -> bool {
    true
}

impl Defaults {
    fn egress() -> Action {
        Action::Allow
    }
    fn ingress() -> Action {
        Action::Drop
    }
}

impl Default for Defaults {
    fn default() -> Self {
        Self {
            egress: Self::egress(),
            ingress: Self::ingress(),
            fail: FailMode::default(),
            require_ttl: false,
            strict_ingress: false,
            loopback_bypass: true,
            allow_shadowed: false,
            unclassified: Unclassified::Allow,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    #[serde(alias = "deny")]
    Drop,
    Log,
    Punt,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum FailMode {
    Open,
    #[default]
    Closed,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    #[default]
    Egress,
    Ingress,
}

/// One-or-many helper: `x = "a"` or `x = ["a", "b"]`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

impl<T: Clone> OneOrMany<T> {
    pub fn to_vec(&self) -> Vec<T> {
        match self {
            Self::One(v) => vec![v.clone()],
            Self::Many(v) => v.clone(),
        }
    }
}

/// A user given by name (resolved on the host) or numeric uid.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(untagged)]
pub enum UserRef {
    Uid(u32),
    Name(String),
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WhoSpec {
    /// `"sha256:<64 hex>"` digests of the executable.
    pub binary: Option<OneOrMany<String>>,
    /// Absolute executable paths (weaker than `binary`; resolved per exec).
    pub exe: Option<OneOrMany<String>>,
    pub user: Option<OneOrMany<UserRef>>,
    /// cgroup v2 paths relative to /sys/fs/cgroup; matches the whole subtree.
    pub cgroup: Option<OneOrMany<String>>,
    /// Kubernetes label selector (v0.4, needs the node agent).
    pub k8s: Option<String>,
    /// SPIFFE ID (v0.4).
    pub spiffe: Option<String>,
}

/// A port: `443` or `"8000-8999"`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum PortSpec {
    Num(u16),
    Range(String),
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MatchSpec {
    /// Egress destination(s): CIDR, IP, FQDN or `@set`.
    pub to: Option<OneOrMany<String>>,
    /// Ingress source(s): CIDR, IP, FQDN or `@set`.
    pub from: Option<OneOrMany<String>>,
    pub port: Option<OneOrMany<PortSpec>>,
    /// `tcp`, `udp`, `icmp`, `icmpv6` or `any`.
    pub proto: Option<String>,
    /// `punt` only: the `[gateway.<name>]` policy that decides the punted flow at L7.
    pub gateway: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuleSpec {
    pub id: String,
    #[serde(default)]
    pub direction: Option<Direction>,
    #[serde(default)]
    pub who: Option<WhoSpec>,
    pub allow: Option<MatchSpec>,
    #[serde(alias = "drop")]
    pub deny: Option<MatchSpec>,
    pub log: Option<MatchSpec>,
    pub punt: Option<MatchSpec>,
    /// `"30d"`, `"12h"`, `"15m"`, `"90s"`.
    pub ttl: Option<String>,
    pub fail: Option<FailMode>,
    /// Free-form note kept in the audit log.
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AgentSpec {
    pub id: String,
    #[serde(default)]
    pub mcp: Option<McpSpec>,
    #[serde(default)]
    pub budget: Option<BudgetSpec>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpSpec {
    pub tools: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BudgetSpec {
    pub calls_per_min: Option<u32>,
    pub usd_per_day: Option<f64>,
}

impl PolicyFile {
    pub fn parse(src: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(src)
    }
}
