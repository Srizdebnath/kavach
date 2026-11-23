//! The L7 gateway policies of the active bundle, shared with the gateway proxy.
//!
//! [`GatewayPolicies`] is a cheap-to-clone handle. kavachd [`publish`](GatewayPolicies::publish)es
//! each bundle it applies or restores; the proxy takes a [`snapshot`](GatewayPolicies::snapshot)
//! per connection (or per frame) and decides with the `kavach_gateway::ToolPolicy` it finds.
//! A snapshot is immutable: a policy swap never changes a decision half-way through a lookup.

use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock};

use kavach_gateway::ToolPolicy;
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

/// Shared handle on the active gateway policies.
#[derive(Debug, Default, Clone)]
pub struct GatewayPolicies(Arc<RwLock<Arc<GatewaySnapshot>>>);

impl GatewayPolicies {
    pub fn new() -> Self {
        Self::default()
    }

    /// The current policies. Holds no lock after returning.
    pub fn snapshot(&self) -> Arc<GatewaySnapshot> {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Replace the policies with those of a newly active bundle; returns how many there are.
    pub fn publish(&self, policy: &CompiledPolicy, serial: u64) -> usize {
        let snap = Arc::new(GatewaySnapshot::from_policy(policy, serial));
        let n = snap.policies.len();
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = snap;
        n
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
}
