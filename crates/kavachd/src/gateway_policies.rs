//! The L7 gateway policies of the active bundle, shared with the gateway proxy.
//!
//! [`GatewayPolicies`] is a cheap-to-clone handle. kavachd [`publish`](GatewayPolicies::publish)es
//! each bundle it applies or restores; the proxy takes a [`snapshot`](GatewayPolicies::snapshot)
//! per connection (or per frame) and decides with the `kavach_gateway::ToolPolicy` it finds.
//! A snapshot is immutable: a policy swap never changes a decision half-way through a lookup.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, PoisonError, RwLock};

use kavach_gateway::{AgentPolicy, ToolPolicy};
use kavach_policy::compile::CompiledPolicy;

/// One applied bundle's gateway policies.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct GatewaySnapshot {
    /// Bundle serial these policies came from (0 before the first apply).
    pub serial: u64,
    /// Gateway policies by `[gateway.<name>]` name.
    pub policies: HashMap<String, ToolPolicy>,
    /// Numeric rule id (as carried in events and flow verdicts) → gateway name, for every
    /// `punt` rule that names a gateway.
    pub rules: HashMap<u32, String>,
    /// Agent identities and budgets from `[[agent]]` in the signed policy.
    pub agents: HashMap<String, AgentPolicy>,
}

impl GatewaySnapshot {
    /// Build from a verified, compiled policy.
    pub fn from_policy(policy: &CompiledPolicy, serial: u64) -> Self {
        let rules = policy
            .rules
            .iter()
            .filter_map(|r| Some((r.id, policy.rule_gateway(r)?.name.clone())))
            .collect();
        Self {
            serial,
            policies: policy.tool_policies(),
            rules,
            agents: policy.agent_policies(),
        }
    }

    /// The policy named `name`.
    pub fn policy(&self, name: &str) -> Option<&ToolPolicy> {
        self.policies.get(name)
    }

    /// The policy for a flow punted by rule `rule_id`; `None` = no gateway, fail mode decides.
    pub fn policy_for_rule(&self, rule_id: u32) -> Option<&ToolPolicy> {
        self.rules.get(&rule_id).and_then(|n| self.policies.get(n))
    }
}

/// Shared handle on the active gateway policies. The disabled-agent set is deliberately kept
/// outside the immutable snapshot: a kill-switch takes effect on the next frame, and a policy
/// reload must not re-enable an agent.
#[derive(Debug, Default, Clone)]
pub struct GatewayPolicies {
    policies: Arc<RwLock<Arc<GatewaySnapshot>>>,
    disabled: Arc<RwLock<HashSet<String>>>,
}

impl GatewayPolicies {
    pub fn new() -> Self {
        Self::default()
    }

    /// The current policies. Holds no lock after returning.
    pub fn snapshot(&self) -> Arc<GatewaySnapshot> {
        self.policies
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Replace the policies with those of a newly active bundle; returns how many there are.
    pub fn publish(&self, policy: &CompiledPolicy, serial: u64) -> usize {
        let snap = Arc::new(GatewaySnapshot::from_policy(policy, serial));
        let n = snap.policies.len();
        *self
            .policies
            .write()
            .unwrap_or_else(PoisonError::into_inner) = snap;
        n
    }

    /// Enable or disable one agent immediately (FR-GW-4). Does not touch BPF programs.
    pub fn set_agent_disabled(&self, id: &str, disabled: bool) {
        let mut set = self
            .disabled
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        if disabled {
            set.insert(id.to_owned());
        } else {
            set.remove(id);
        }
    }

    /// Whether `id` is currently disabled.
    pub fn agent_disabled(&self, id: &str) -> bool {
        self.disabled
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(id)
    }

    /// All disabled agent ids, sorted.
    pub fn disabled_agents(&self) -> Vec<String> {
        let mut v: Vec<_> = self
            .disabled
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .cloned()
            .collect();
        v.sort();
        v
    }
}

#[cfg(test)]
mod tests {
    use kavach_gateway::{Action, Decision};

    use super::*;

    const SRC: &str = r#"
version = 1
[gateway.github-agent]
allow_tools = ["github.*"]
deny_tools  = ["github.delete_*"]
[[rule]]
id   = "dns"
allow = { to = "1.1.1.1", port = 53, proto = "udp" }
[[rule]]
id   = "mcp"
punt = { to = "203.0.113.0/24", port = [443, 8443], proto = "tcp", gateway = "github-agent" }
"#;

    #[test]
    fn publish_swaps_the_snapshot_seen_by_every_clone() {
        let h = GatewayPolicies::new();
        let proxy_side = h.clone();
        assert_eq!(proxy_side.snapshot().serial, 0);
        assert!(proxy_side.snapshot().policies.is_empty());

        let p = kavach_policy::compile(SRC, 0).unwrap().policy;
        let before = proxy_side.snapshot();
        assert_eq!(h.publish(&p, 7), 1);
        let s = proxy_side.snapshot();
        assert_eq!(s.serial, 7);
        assert!(before.policies.is_empty(), "old snapshots are immutable");
        assert!(s.policy_for_rule(1).is_none(), "dns is not punted");
        let gp = s.policy_for_rule(2).expect("rule 2 punts to github-agent");
        assert_eq!(Some(gp), s.policy("github-agent"));
        let call = |t: &str| Action::ToolCall { tool: t.into() };
        assert_eq!(gp.decide(&call("github.get_issue")), Decision::Allow);
        assert_eq!(gp.decide(&call("github.delete_repo")), Decision::Deny);

        let empty = kavach_policy::compile("version = 1\n", 0).unwrap().policy;
        assert_eq!(h.publish(&empty, 8), 0);
        assert!(proxy_side.snapshot().policy_for_rule(2).is_none());
    }

    #[test]
    fn agents_are_published_and_kill_switch_survives_reload() {
        let src = r#"
version = 1
[gateway.dev]
allow_tools = ["search"]
[[rule]]
id = "mcp"
punt = { to = "203.0.113.0/24", port = 443, proto = "tcp", gateway = "dev" }
[[agent]]
id = "bot"
require_auth = true
gateway = "dev"
token_sha256 = "0000000000000000000000000000000000000000000000000000000000000001"
budget = { calls_per_min = 2, usd_per_day = 1.0, usd_per_call = 0.5 }
"#;
        let h = GatewayPolicies::new();
        let p = kavach_policy::compile(src, 0).unwrap().policy;
        h.publish(&p, 1);
        let snap = h.snapshot();
        let a = snap.agents.get("bot").expect("agent published");
        assert!(a.require_auth);
        assert_eq!(a.calls_per_min, Some(2));
        assert_eq!(a.usd_per_day_micros, Some(1_000_000));
        assert_eq!(a.usd_per_call_micros, 500_000);
        h.set_agent_disabled("bot", true);
        assert!(h.agent_disabled("bot"));
        h.publish(&p, 2);
        assert!(
            h.agent_disabled("bot"),
            "reload must not re-enable an agent"
        );
        h.set_agent_disabled("bot", false);
        assert!(!h.agent_disabled("bot"));
    }
}
