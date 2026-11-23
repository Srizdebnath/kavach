//! Workload identity selectors (v0.4 node agent): `who = { k8s = "app=db,ns=prod" }` and
//! `who = { spiffe = "spiffe://example.org/ns/prod/sa/*" }`.
//!
//! These constrain the **cgroup dimension** of a selector: kavachd maps each pod's cgroup to
//! the pod's labels / namespace / service account / SPIFFE ID and publishes, per cgroup, the
//! bits of the workload selectors that pod satisfies (`wl_class`). The kernel ORs the class of
//! the *nearest* classified cgroup on the task's path into the cgroup mask.
//!
//! When kavachd knows a cgroup is a pod but not (yet) who the pod is, it publishes the
//! **unknown-identity** bits instead. Every workload rule with `fail = "closed"` (and a verdict
//! other than `log`) is compiled with a `drop` twin in front of it that matches exactly those
//! bits: an unresolved pod is refused by fail-closed rules and skips fail-open ones.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Pseudo-label that matches the pod's namespace.
pub const NS_KEY: &str = "ns";

// ---------------------------------------------------------------------------------------------
// Label selectors
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LabelOp {
    Eq(String),
    NotEq(String),
    In(Vec<String>),
    NotIn(Vec<String>),
    Exists,
    NotExists,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct LabelReq {
    /// A label key, or [`NS_KEY`] for the namespace.
    pub key: String,
    pub op: LabelOp,
}

/// Conjunction of requirements (the Kubernetes label-selector subset: `k=v`, `k==v`, `k!=v`,
/// `k in (a,b)`, `k notin (a,b)`, `k`, `!k`; `ns` is the namespace).
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct LabelSelector {
    pub reqs: Vec<LabelReq>,
}

/// What kavachd knows about the pod that owns a cgroup.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PodIdentity {
    pub uid: String,
    pub namespace: String,
    pub name: String,
    pub service_account: String,
    pub labels: BTreeMap<String, String>,
    /// Derived from the configured template (or the Workload API).
    pub spiffe_id: Option<String>,
}

fn valid_name(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.as_bytes()[s.len() - 1].is_ascii_alphanumeric()
}

fn valid_dns_subdomain(s: &str) -> bool {
    s.len() <= 253
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
}

/// `[prefix/]name`, as Kubernetes validates label keys.
pub fn valid_label_key(k: &str) -> bool {
    match k.split_once('/') {
        Some((prefix, name)) => valid_dns_subdomain(prefix) && valid_name(name, 63),
        None => valid_name(k, 63),
    }
}

/// Empty, or ≤ 63 chars of `[A-Za-z0-9_.-]` starting and ending alphanumeric.
pub fn valid_label_value(v: &str) -> bool {
    v.is_empty() || valid_name(v, 63)
}

/// Split on commas that are not inside parentheses.
fn split_top(s: &str) -> Result<Vec<&str>, String> {
    let (mut depth, mut start, mut out) = (0i32, 0usize, Vec::new());
    for (i, c) in s.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth < 0 {
                    return Err(format!("unbalanced ')' in {s:?}"));
                }
            }
            ',' if depth == 0 => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err(format!("unbalanced '(' in {s:?}"));
    }
    out.push(&s[start..]);
    Ok(out)
}

fn parse_set(rest: &str, key: &str) -> Result<Vec<String>, String> {
    let inner = rest
        .trim()
        .strip_prefix('(')
        .and_then(|r| r.strip_suffix(')'))
        .ok_or_else(|| format!("{key}: expected a parenthesised value list"))?;
    let mut vals: Vec<String> = inner.split(',').map(|v| v.trim().to_owned()).collect();
    if vals.iter().all(String::is_empty) {
        return Err(format!("{key}: empty value list"));
    }
    for v in &vals {
        check_value(key, v)?;
    }
    vals.sort();
    vals.dedup();
    Ok(vals)
}

fn check_key(k: &str) -> Result<(), String> {
    if valid_label_key(k) {
        Ok(())
    } else {
        Err(format!("invalid label key {k:?}"))
    }
}

fn check_value(key: &str, v: &str) -> Result<(), String> {
    let ok = if key == NS_KEY {
        // namespaces are DNS labels
        !v.is_empty() && v.len() <= 63 && valid_dns_subdomain(v) && !v.contains('.')
    } else {
        valid_label_value(v)
    };
    if ok {
        Ok(())
    } else {
        Err(format!("invalid value {v:?} for {key:?}"))
    }
}

/// Split `"key<ws>in<ws>(...)"`: returns (key, rest) when the word `op` follows the key.
fn split_word_op<'a>(r: &'a str, op: &str) -> Option<(&'a str, &'a str)> {
    let (k, rest) = r.split_once(char::is_whitespace)?;
    let rest = rest.trim_start();
    let tail = rest.strip_prefix(op)?;
    (tail.starts_with('(') || tail.starts_with(char::is_whitespace)).then_some((k, tail))
}

impl LabelSelector {
    pub fn parse(src: &str) -> Result<Self, String> {
        if src.trim().is_empty() {
            return Err(
                "empty k8s selector (it would match every pod; use `ns=...` or a label)".into(),
            );
        }
        let mut reqs = Vec::new();
        for raw in split_top(src)? {
            let r = raw.trim();
            if r.is_empty() {
                return Err(format!("empty requirement in {src:?}"));
            }
            let req = if let Some((k, rest)) = split_word_op(r, "notin") {
                LabelReq {
                    key: k.to_owned(),
                    op: LabelOp::NotIn(parse_set(rest, k)?),
                }
            } else if let Some((k, rest)) = split_word_op(r, "in") {
                LabelReq {
                    key: k.to_owned(),
                    op: LabelOp::In(parse_set(rest, k)?),
                }
            } else if let Some((k, v)) = r.split_once("!=") {
                let (k, v) = (k.trim(), v.trim());
                check_value(k, v)?;
                LabelReq {
                    key: k.to_owned(),
                    op: LabelOp::NotEq(v.to_owned()),
                }
            } else if let Some((k, v)) = r.split_once("==").or_else(|| r.split_once('=')) {
                let (k, v) = (k.trim(), v.trim());
                check_value(k, v)?;
                LabelReq {
                    key: k.to_owned(),
                    op: LabelOp::Eq(v.to_owned()),
                }
            } else if let Some(k) = r.strip_prefix('!') {
                LabelReq {
                    key: k.trim().to_owned(),
                    op: LabelOp::NotExists,
                }
            } else {
                LabelReq {
                    key: r.to_owned(),
                    op: LabelOp::Exists,
                }
            };
            check_key(&req.key)?;
            if req.key == NS_KEY && matches!(req.op, LabelOp::Exists | LabelOp::NotExists) {
                return Err("`ns` needs a value (every pod has a namespace)".into());
            }
            reqs.push(req);
        }
        reqs.sort();
        reqs.dedup();
        Ok(Self { reqs })
    }

    pub fn matches(&self, pod: &PodIdentity) -> bool {
        self.reqs.iter().all(|r| {
            let got = if r.key == NS_KEY {
                Some(pod.namespace.as_str())
            } else {
                pod.labels.get(&r.key).map(String::as_str)
            };
            match &r.op {
                LabelOp::Eq(v) => got == Some(v.as_str()),
                LabelOp::NotEq(v) => got != Some(v.as_str()),
                LabelOp::In(vs) => got.is_some_and(|g| vs.iter().any(|v| v == g)),
                LabelOp::NotIn(vs) => !got.is_some_and(|g| vs.iter().any(|v| v == g)),
                LabelOp::Exists => got.is_some(),
                LabelOp::NotExists => got.is_none(),
            }
        })
    }
}

impl fmt::Display for LabelSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let parts: Vec<String> = self
            .reqs
            .iter()
            .map(|r| match &r.op {
                LabelOp::Eq(v) => format!("{}={v}", r.key),
                LabelOp::NotEq(v) => format!("{}!={v}", r.key),
                LabelOp::In(vs) => format!("{} in ({})", r.key, vs.join(",")),
                LabelOp::NotIn(vs) => format!("{} notin ({})", r.key, vs.join(",")),
                LabelOp::Exists => r.key.clone(),
                LabelOp::NotExists => format!("!{}", r.key),
            })
            .collect();
        f.write_str(&parts.join(","))
    }
}

// ---------------------------------------------------------------------------------------------
// SPIFFE IDs
// ---------------------------------------------------------------------------------------------

/// `spiffe://td/a/b` (exact) or `spiffe://td/a/*` (everything strictly below `/a/`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SpiffePattern {
    Exact(String),
    /// Stored with its trailing `/`.
    Prefix(String),
}

/// Validate a SPIFFE ID (spiffe-id spec: lowercase trust domain, non-empty path segments of
/// `[A-Za-z0-9._-]`, no `.`/`..` segments, no query/fragment/port/userinfo).
pub fn validate_spiffe_id(id: &str) -> Result<(), String> {
    let rest = id
        .strip_prefix("spiffe://")
        .ok_or_else(|| format!("SPIFFE ID {id:?} must start with spiffe://"))?;
    let (td, path) = rest.split_once('/').unwrap_or((rest, ""));
    if td.is_empty()
        || td.len() > 255
        || !td.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_')
        })
    {
        return Err(format!("SPIFFE ID {id:?}: invalid trust domain {td:?}"));
    }
    if id.len() > 2048 {
        return Err(format!("SPIFFE ID {id:?} is longer than 2048 bytes"));
    }
    if path.is_empty() {
        return Ok(());
    }
    for seg in path.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            return Err(format!("SPIFFE ID {id:?}: empty, . or .. path segment"));
        }
        if !seg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        {
            return Err(format!("SPIFFE ID {id:?}: invalid character in {seg:?}"));
        }
    }
    Ok(())
}

impl SpiffePattern {
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if let Some(base) = s.strip_suffix("/*") {
            validate_spiffe_id(base)?;
            if base.contains('*') {
                return Err(format!(
                    "{s:?}: `*` is only allowed as the last path segment"
                ));
            }
            return Ok(Self::Prefix(format!("{base}/")));
        }
        if s.contains('*') {
            return Err(format!("{s:?}: `*` is only allowed as a trailing `/*`"));
        }
        validate_spiffe_id(s)?;
        Ok(Self::Exact(s.to_owned()))
    }

    pub fn matches(&self, id: &str) -> bool {
        match self {
            Self::Exact(e) => id == e,
            Self::Prefix(p) => id.len() > p.len() && id.starts_with(p.as_str()),
        }
    }
}

impl fmt::Display for SpiffePattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact(e) => f.write_str(e),
            Self::Prefix(p) => write!(f, "{p}*"),
        }
    }
}

/// Render a SPIFFE ID template. Placeholders: `{trust_domain}`, `{namespace}`,
/// `{service_account}`, `{pod}`, `{uid}`, and `{label:<key>}`. `None` when a placeholder has
/// no value or the result is not a valid SPIFFE ID (the pod then has no SPIFFE identity).
pub fn render_spiffe(template: &str, trust_domain: &str, pod: &PodIdentity) -> Option<String> {
    let mut out = String::with_capacity(template.len() + 32);
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let close = rest[open..].find('}')? + open;
        let name = &rest[open + 1..close];
        let val = match name {
            "trust_domain" => trust_domain,
            "namespace" => pod.namespace.as_str(),
            "service_account" => pod.service_account.as_str(),
            "pod" => pod.name.as_str(),
            "uid" => pod.uid.as_str(),
            _ => pod.labels.get(name.strip_prefix("label:")?)?.as_str(),
        };
        if val.is_empty() {
            return None;
        }
        out.push_str(val);
        rest = &rest[close + 1..];
    }
    out.push_str(rest);
    validate_spiffe_id(&out).ok().map(|()| out)
}

/// The Kubernetes default (SPIRE's k8s workload registrar layout).
pub const DEFAULT_SPIFFE_TEMPLATE: &str =
    "spiffe://{trust_domain}/ns/{namespace}/sa/{service_account}";

// ---------------------------------------------------------------------------------------------
// Compiled workload selectors
// ---------------------------------------------------------------------------------------------

/// The workload part of selector `sel` (bit index). Carried in [`crate::CompiledPolicy`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct WorkloadSel {
    pub sel: u32,
    pub kind: WorkloadKind,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum WorkloadKind {
    /// Pod satisfies the label selector AND (if given) its SPIFFE ID matches.
    Match {
        k8s: Option<LabelSelector>,
        spiffe: Option<SpiffePattern>,
    },
    /// Set for tasks in a pod whose identity is not resolved; `of` is the selector it shadows.
    Unknown { of: u32 },
}

/// A cgroup's workload state, as kavachd resolved it.
#[derive(Debug, Clone, Copy)]
pub enum WorkloadState<'a> {
    Resolved(&'a PodIdentity),
    Unknown,
}

impl WorkloadKind {
    pub fn matches(&self, st: WorkloadState<'_>) -> bool {
        match (self, st) {
            (Self::Match { k8s, spiffe }, WorkloadState::Resolved(p)) => {
                k8s.as_ref().is_none_or(|l| l.matches(p))
                    && spiffe
                        .as_ref()
                        .is_none_or(|s| p.spiffe_id.as_deref().is_some_and(|id| s.matches(id)))
            }
            (Self::Unknown { .. }, WorkloadState::Unknown) => true,
            _ => false,
        }
    }
}

impl fmt::Display for WorkloadKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Match { k8s, spiffe } => {
                let mut parts = Vec::new();
                if let Some(k) = k8s {
                    parts.push(format!("k8s({k})"));
                }
                if let Some(s) = spiffe {
                    parts.push(format!("spiffe({s})"));
                }
                f.write_str(&parts.join("&"))
            }
            Self::Unknown { of } => write!(f, "unknown-identity(of selector {of})"),
        }
    }
}

impl crate::CompiledPolicy {
    /// Selector bits a cgroup in workload state `st` satisfies (its `wl_class` value).
    pub fn workload_mask(&self, st: WorkloadState<'_>) -> u64 {
        self.workloads
            .iter()
            .filter(|w| w.sel < 64 && w.kind.matches(st))
            .fold(0, |m, w| m | (1 << w.sel))
    }

    /// Bits of selectors that constrain the workload (excluded from `wild_cgroup`).
    pub fn workload_bits(&self) -> u64 {
        self.workloads
            .iter()
            .filter(|w| w.sel < 64)
            .fold(0, |m, w| m | (1 << w.sel))
    }

    pub fn workload_of(&self, bit: usize) -> Option<&WorkloadKind> {
        self.workloads
            .iter()
            .find(|w| w.sel as usize == bit)
            .map(|w| &w.kind)
    }
}

#[cfg(test)]
mod tests {
    use kavach_common::abi::*;

    use super::*;
    use crate::compile::compile;

    fn pod(ns: &str, labels: &[(&str, &str)]) -> PodIdentity {
        PodIdentity {
            uid: "u1".into(),
            namespace: ns.into(),
            name: "p".into(),
            service_account: "default".into(),
            labels: labels
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            spiffe_id: None,
        }
    }

    fn m(sel: &str, p: &PodIdentity) -> bool {
        LabelSelector::parse(sel).unwrap().matches(p)
    }

    #[test]
    fn label_selector_parsing() {
        let s = LabelSelector::parse(" app = db , tier in (a, b),ns=prod, !legacy, team").unwrap();
        assert_eq!(s.reqs.len(), 5);
        assert_eq!(s.to_string(), "app=db,!legacy,ns=prod,team,tier in (a,b)");
        assert_eq!(
            LabelSelector::parse("app==db").unwrap(),
            LabelSelector::parse("app=db").unwrap()
        );
        assert!(LabelSelector::parse("app.kubernetes.io/name=web").is_ok());
        assert!(LabelSelector::parse("env notin (dev,test)").is_ok());
        assert!(
            LabelSelector::parse("app=").is_ok(),
            "empty value is a valid label value"
        );
        let long = format!("app={}", "x".repeat(64));
        for bad in [
            "",
            "app=db,",
            "app=d b",
            "-app=db",
            "app in (a,b",
            "app in a,b)",
            "app in ()",
            "Bad_Prefix.COM/x=y",
            "ns",
            "!ns",
            "ns=Prod",
            "ns=a.b",
            "app=-x",
            long.as_str(),
        ] {
            assert!(
                LabelSelector::parse(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn label_selector_matching() {
        let p = pod("prod", &[("app", "db"), ("tier", "b")]);
        assert!(m("app=db", &p));
        assert!(!m("app=web", &p));
        assert!(m("app!=web", &p));
        assert!(m("missing!=x", &p), "!= matches when the label is absent");
        assert!(m("tier in (a,b)", &p));
        assert!(!m("tier notin (a,b)", &p));
        assert!(m("missing notin (a)", &p));
        assert!(!m("missing in (a)", &p));
        assert!(m("app", &p));
        assert!(m("!missing", &p));
        assert!(!m("!app", &p));
        assert!(m("ns=prod,app=db", &p));
        assert!(!m("ns=dev,app=db", &p));
        assert!(m("ns in (dev,prod)", &p));
        assert!(m("ns!=dev", &p));
    }

    #[test]
    fn spiffe_patterns() {
        let e = SpiffePattern::parse("spiffe://example.org/ns/prod/sa/db").unwrap();
        assert!(e.matches("spiffe://example.org/ns/prod/sa/db"));
        assert!(!e.matches("spiffe://example.org/ns/prod/sa/dbx"));
        let p = SpiffePattern::parse("spiffe://example.org/ns/prod/*").unwrap();
        assert!(p.matches("spiffe://example.org/ns/prod/sa/db"));
        assert!(!p.matches("spiffe://example.org/ns/prod"));
        assert!(!p.matches("spiffe://example.org/ns/prod/"));
        assert!(
            !p.matches("spiffe://example.org/ns/production/sa/x"),
            "segment boundary"
        );
        assert_eq!(p.to_string(), "spiffe://example.org/ns/prod/*");
        assert!(SpiffePattern::parse("spiffe://example.org/*").is_ok());
        for bad in [
            "https://example.org/x",
            "spiffe://Example.org/x",
            "spiffe:///x",
            "spiffe://example.org/a//b",
            "spiffe://example.org/a/../b",
            "spiffe://example.org/a/*/b",
            "spiffe://example.org/a*",
            "spiffe://example.org/a?b",
            "spiffe://example.org:8080/a",
        ] {
            assert!(
                SpiffePattern::parse(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn spiffe_templates() {
        let mut p = pod("prod", &[("app", "db")]);
        p.service_account = "db-sa".into();
        assert_eq!(
            render_spiffe(DEFAULT_SPIFFE_TEMPLATE, "cluster.local", &p).as_deref(),
            Some("spiffe://cluster.local/ns/prod/sa/db-sa")
        );
        assert_eq!(
            render_spiffe("spiffe://{trust_domain}/app/{label:app}", "td", &p).as_deref(),
            Some("spiffe://td/app/db")
        );
        assert_eq!(render_spiffe("spiffe://td/{label:nope}", "td", &p), None);
        assert_eq!(render_spiffe("spiffe://td/{bogus", "td", &p), None);
        p.service_account.clear();
        assert_eq!(render_spiffe(DEFAULT_SPIFFE_TEMPLATE, "td", &p), None);
    }

    const POLICY: &str = r#"
version = 1
[defaults]
egress = "allow"
fail = "closed"
[[rule]]
id = "db-to-backup"
who = { k8s = "app=db,ns=prod" }
allow = { to = "10.0.0.0/8", port = [5432, "6000-6010"], proto = "tcp" }
[[rule]]
id = "db-rest"
who = { k8s = "app=db,ns=prod" }
deny = { to = "any" }
[[rule]]
id = "spiffe-observe"
who = { spiffe = "spiffe://td/ns/prod/*", user = 1000 }
log = { to = "192.0.2.0/24" }
[[rule]]
id = "open-one"
who = { k8s = "app=web" }
fail = "open"
deny = { to = "198.51.100.1" }
"#;

    #[test]
    fn compile_interns_workload_selectors_and_adds_fail_closed_twins() {
        let p = compile(POLICY, 0).unwrap().policy;
        // db (0), db-unknown (1), spiffe+uid (2), web (3)
        assert_eq!(p.selectors.len(), 4);
        assert_eq!(p.workloads.len(), 4);
        assert_eq!(p.workload_bits(), 0b1111);
        assert!(matches!(
            p.workload_of(1),
            Some(WorkloadKind::Unknown { of: 0 })
        ));
        assert!(p.selectors[2].constrains_uid());
        let got: Vec<(&str, u64, u8)> = p
            .rules
            .iter()
            .map(|r| (r.name.as_str(), r.sel, r.verdict))
            .collect();
        let (d, a, l) = (
            Verdict::Drop as u8,
            Verdict::Allow as u8,
            Verdict::Log as u8,
        );
        assert_eq!(
            got,
            [
                // twin first, per port range, then the rule itself
                ("db-to-backup", 0b10, d),
                ("db-to-backup", 0b10, d),
                ("db-to-backup", 0b01, a),
                ("db-to-backup", 0b01, a),
                ("db-rest", 0b10, d),
                ("db-rest", 0b01, d),
                ("spiffe-observe", 0b100, l), // log rules get no twin
                ("open-one", 0b1000, d),      // fail-open: no twin
            ]
        );
        let k = p.to_kernel(
            1,
            1,
            crate::kernel::Clocks {
                unix_ns: 0,
                boot_ns: 0,
            },
        );
        assert!(k.hdr.flags & KV_POL_F_WORKLOAD != 0);
        assert_eq!(
            k.hdr.wild_cgroup & 0b1111,
            0,
            "workload selectors constrain cgroups"
        );
        assert_eq!(k.hdr.wild_uid & 0b1111, 0b1011);

        let mut db = pod("prod", &[("app", "db")]);
        assert_eq!(p.workload_mask(WorkloadState::Resolved(&db)), 0b0001);
        db.spiffe_id = Some("spiffe://td/ns/prod/sa/default".into());
        assert_eq!(p.workload_mask(WorkloadState::Resolved(&db)), 0b0101);
        let web = pod("dev", &[("app", "web")]);
        assert_eq!(p.workload_mask(WorkloadState::Resolved(&web)), 0b1000);
        assert_eq!(p.workload_mask(WorkloadState::Unknown), 0b0010);

        // host-side reference mask: the spiffe selector also needs its uid
        let facts = crate::kernel::Facts {
            uid: Some(1000),
            ..Default::default()
        };
        assert_eq!(
            p.selector_mask(&facts),
            0,
            "not a pod: no workload selector matches"
        );
        assert_eq!(
            p.selector_mask_in(&facts, Some(WorkloadState::Resolved(&db))),
            0b0101
        );
        assert_eq!(
            p.selector_mask_in(
                &crate::kernel::Facts::default(),
                Some(WorkloadState::Resolved(&db))
            ),
            0b0001
        );
    }

    #[test]
    fn compile_rejects_bad_workload_selectors() {
        let err = |who: &str| {
            let src = format!("version=1\n[[rule]]\nid='r'\nwho={who}\ndeny={{}}\n");
            compile(&src, 0)
                .unwrap_err()
                .into_iter()
                .map(|d| d.message)
                .collect::<Vec<_>>()
                .join("; ")
        };
        assert!(err("{k8s='app in (a'}").contains("unbalanced"));
        assert!(err("{spiffe='http://x/y'}").contains("spiffe://"));
        assert!(err("{k8s='app=db', cgroup='/kubepods.slice'}").contains("cannot be combined"));
        assert!(err("{k8s=''}").contains("empty"));
    }

    #[test]
    fn workload_selectors_are_distinct_from_plain_ones() {
        // Same uid part, different k8s part: three selectors, not one.
        let src = r#"
version = 1
[[rule]]
id = "a"
who = { user = 1, k8s = "app=a" }
fail = "open"
deny = { to = "192.0.2.1" }
[[rule]]
id = "b"
who = { user = 1, k8s = "app=b" }
fail = "open"
deny = { to = "192.0.2.2" }
[[rule]]
id = "c"
who = { user = 1 }
deny = { to = "192.0.2.3" }
"#;
        let p = compile(src, 0).unwrap().policy;
        assert_eq!(p.selectors.len(), 3);
        assert_eq!(p.workload_bits(), 0b011);
        let q = compile(&src.replace("app=b", "app=z"), 0).unwrap().policy;
        let diff = crate::diff::diff(&p, &q);
        assert_eq!(
            diff.len(),
            1,
            "a changed label selector is a rule change: {diff:?}"
        );
    }

    #[test]
    fn format_2_bundles_still_verify() {
        use crate::bundle;
        let p = compile(
            "version=1\n[[rule]]\nid='r'\nwho={user=0}\ndeny={to='192.0.2.1'}\n",
            5,
        )
        .unwrap()
        .policy;
        let v2 = crate::compile::CompiledPolicyV2 {
            version: p.version,
            created_unix: p.created_unix,
            source_sha256: p.source_sha256,
            defaults: p.defaults.clone(),
            selectors: p.selectors.clone(),
            sets: p.sets.clone(),
            rules: p.rules.clone(),
            agents: p.agents.clone(),
        };
        let sk = bundle::generate_key();
        let trust = bundle::TrustPolicy {
            trusted: vec![sk.verifying_key()],
            fleet: "f".into(),
            now_unix: 10,
            ..Default::default()
        };
        let b = bundle::sign_v2(&v2, &sk, 2, 0, "f").unwrap();
        assert_eq!(bundle::verify(&b, &trust, true).unwrap().policy, p);
        // and a format-3 bundle with workloads round-trips
        let w = compile(POLICY, 5).unwrap().policy;
        let b = bundle::sign(&w, &sk, 3, 0, "f").unwrap();
        assert_eq!(bundle::verify(&b, &trust, true).unwrap().policy, w);
    }
}
