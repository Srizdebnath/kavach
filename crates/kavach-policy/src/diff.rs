//! Human-readable policy diff for `kavachctl diff` / `apply --dry-run` (FR-CLI-2).

use std::collections::BTreeMap;
use std::fmt;

use crate::compile::{CompiledPolicy, CompiledRule};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    Added(String),
    Removed(String),
    Modified(String),
    Moved {
        name: String,
        from: usize,
        to: usize,
    },
    Defaults,
    GatewayAdded(String),
    GatewayRemoved(String),
    GatewayModified(String),
}

impl fmt::Display for Change {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Added(n) => write!(f, "+ rule {n}"),
            Self::Removed(n) => write!(f, "- rule {n}"),
            Self::Modified(n) => write!(f, "~ rule {n}"),
            Self::Moved { name, from, to } => write!(f, "↕ rule {name} (position {from} → {to})"),
            Self::Defaults => write!(f, "~ defaults"),
            Self::GatewayAdded(n) => write!(f, "+ gateway {n}"),
            Self::GatewayRemoved(n) => write!(f, "- gateway {n}"),
            Self::GatewayModified(n) => write!(f, "~ gateway {n}"),
        }
    }
}

/// Rules grouped by name, preserving first position, with selectors/sets resolved so that
/// renumbering alone does not show up as a change.
fn by_name(p: &CompiledPolicy) -> BTreeMap<String, (usize, Vec<String>)> {
    let mut m: BTreeMap<String, (usize, Vec<String>)> = BTreeMap::new();
    for (i, r) in p.rules.iter().enumerate() {
        let e = m.entry(r.name.clone()).or_insert((i, Vec::new()));
        e.1.push(describe(p, r));
    }
    m
}

fn describe(p: &CompiledPolicy, r: &CompiledRule) -> String {
    let sel = (0..64)
        .filter(|b| r.sel & (1 << b) != 0)
        .filter_map(|b| p.selectors.get(b))
        .map(|s| format!("{s:?}"))
        .collect::<Vec<_>>()
        .join("|");
    let set = match r.remote_set {
        0 => "any".to_owned(),
        n => p
            .sets
            .get(n as usize - 1)
            .map_or("?".into(), |s| format!("{:?}{:?}", s.cidrs, s.fqdns)),
    };
    let gateway = p.rule_gateway(r).map_or("-", |g| g.name.as_str());
    format!(
        "dir={} sel={sel} proto={} ports={}-{} remote={set} verdict={} fail={} ttl={} \
         gateway={gateway}",
        r.dir, r.proto, r.port_lo, r.port_hi, r.verdict, r.fail, r.not_after_unix
    )
}

pub fn diff(old: &CompiledPolicy, new: &CompiledPolicy) -> Vec<Change> {
    let mut out = Vec::new();
    if old.defaults != new.defaults {
        out.push(Change::Defaults);
    }
    for g in &old.gateways {
        match new.gateway(&g.name) {
            None => out.push(Change::GatewayRemoved(g.name.clone())),
            Some(n) if n != g => out.push(Change::GatewayModified(g.name.clone())),
            _ => {}
        }
    }
    for g in &new.gateways {
        if old.gateway(&g.name).is_none() {
            out.push(Change::GatewayAdded(g.name.clone()));
        }
    }
    let (a, b) = (by_name(old), by_name(new));
    let order_a: Vec<&String> = {
        let mut v: Vec<_> = a.iter().collect();
        v.sort_by_key(|(_, (i, _))| *i);
        v.into_iter()
            .map(|(n, _)| n)
            .filter(|n| b.contains_key(*n))
            .collect()
    };
    let order_b: Vec<&String> = {
        let mut v: Vec<_> = b.iter().collect();
        v.sort_by_key(|(_, (i, _))| *i);
        v.into_iter()
            .map(|(n, _)| n)
            .filter(|n| a.contains_key(*n))
            .collect()
    };
    for (name, (_, desc)) in &a {
        match b.get(name) {
            None => out.push(Change::Removed(name.clone())),
            Some((_, d2)) if d2 != desc => out.push(Change::Modified(name.clone())),
            _ => {}
        }
    }
    for name in b.keys() {
        if !a.contains_key(name) {
            out.push(Change::Added(name.clone()));
        }
    }
    // Order matters (first match wins): report relative moves among surviving rules.
    for (to, name) in order_b.iter().enumerate() {
        if let Some(from) = order_a.iter().position(|n| n == name)
            && from != to
        {
            out.push(Change::Moved {
                name: (*name).clone(),
                from,
                to,
            });
        }
    }
    out
}
