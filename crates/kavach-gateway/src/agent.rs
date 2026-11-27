//! Per-agent identity (FR-GW-1) and runtime kill-switch (FR-GW-4) primitives.
//!
//! Credentials are resolved once per request: a bearer token is hashed with SHA-256 and matched
//! against the configured digests in constant time; a SPIFFE ID comes from a pluggable resolver
//! (kavachd supplies one backed by its workload node agent; a standalone proxy has none). When
//! no agent policy requires authentication, resolution is a no-op and the proxy behaves exactly
//! as it did before v0.4.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::proxy::PolicySource;

/// One agent's compiled identity and budget requirements.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentPolicy {
    /// SHA-256 digests of accepted bearer tokens (normally one).
    #[serde(default)]
    pub token_sha256: Vec<[u8; 32]>,
    /// Accepted SPIFFE IDs or `spiffe://.../*` prefixes.
    #[serde(default)]
    pub spiffe_id: Vec<String>,
    /// Refuse all frames unless a credential identifies this agent.
    #[serde(default)]
    pub require_auth: bool,
    /// Bind this agent to one named gateway policy.
    #[serde(default)]
    pub gateway: Option<String>,
    /// Sliding-window call limit.
    #[serde(default)]
    pub calls_per_min: Option<u32>,
    /// UTC-day spend limit, in micro-USD.
    #[serde(default)]
    pub usd_per_day_micros: Option<u64>,
    /// Price charged per tool call, in micro-USD.
    #[serde(default)]
    pub usd_per_call_micros: u64,
}

impl AgentPolicy {
    /// Whether any frame from this agent needs a credential before it can be attributed.
    pub fn needs_credential(&self) -> bool {
        self.require_auth
    }
}

/// Credentials presented on (or derived from) one connection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Credentials {
    /// Raw `Authorization: Bearer <token>` value (never logged).
    pub bearer: Option<String>,
    /// SPIFFE ID resolved from the connection's cgroup, if a resolver is configured.
    pub spiffe_id: Option<String>,
}

impl Credentials {
    /// Build credentials from an HTTP `Authorization` header and an optional SPIFFE ID.
    pub fn new(authorization: Option<&[u8]>, spiffe_id: Option<String>) -> Self {
        let bearer = authorization
            .and_then(Self::bearer_token)
            .map(str::to_owned);
        Self { bearer, spiffe_id }
    }

    /// Parse a strict `Bearer <token>` header. A token is visible ASCII without whitespace;
    /// anything else is ignored (fail closed when a policy requires authentication).
    pub fn bearer_token(header: &[u8]) -> Option<&str> {
        if !header
            .get(..7)
            .is_some_and(|p| p.eq_ignore_ascii_case(b"Bearer "))
        {
            return None;
        }
        let token = &header[7..];
        if token.is_empty()
            || token.len() > 512
            || !token
                .iter()
                .all(|b| (0x21..=0x7e).contains(b) && *b != b',')
        {
            return None;
        }
        // The header bytes were checked to be ASCII above.
        std::str::from_utf8(token).ok()
    }

    /// Attach a bearer token to existing credentials.
    pub fn with_bearer(mut self, authorization: Option<&[u8]>) -> Self {
        self.bearer = authorization
            .and_then(Self::bearer_token)
            .map(str::to_owned);
        self
    }
}

/// Resolves a SPIFFE ID from the process/cgroup that opened a punted connection.
pub trait AgentResolver: Send + Sync {
    /// The SPIFFE ID of the workload in `cgroup_id`, if known.
    fn spiffe_id(&self, cgroup_id: u64, pid: u32) -> Option<String>;
}

/// Adapts a closure into an [`AgentResolver`].
pub struct FnAgentResolver<F>(pub F);

impl<F: Fn(u64, u32) -> Option<String> + Send + Sync> AgentResolver for FnAgentResolver<F> {
    fn spiffe_id(&self, cgroup_id: u64, pid: u32) -> Option<String> {
        (self.0)(cgroup_id, pid)
    }
}

impl<F> std::fmt::Debug for FnAgentResolver<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FnAgentResolver")
    }
}

/// Why a flow with a credential requirement was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFailure {
    /// No credential was presented, or none matched an agent allowed on this gateway.
    Unauthenticated,
    /// A matching agent was disabled with the per-agent kill-switch.
    Disabled,
}

/// Constant-time equality of two 32-byte digests (no early exit on a mismatch).
fn digest_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// SPIFFE IDs match exactly or by a single trailing `/*` path prefix.
fn spiffe_matches(pattern: &str, id: &str) -> bool {
    match pattern.strip_suffix("/*") {
        Some(prefix) => id.strip_prefix(prefix).is_some_and(|rest| !rest.is_empty()),
        None => pattern == id,
    }
}

/// Resolve the agent a request belongs to.
///
/// `Ok(None)` means no agent was identified and no agent policy on this gateway requires one:
/// that is the pre-v0.4 default and every frame keeps its existing decision path. `Ok(Some(id))`
/// attributes the frame (and its budgets) to that agent. `Err` fails the frame closed.
pub fn resolve_agent(
    policies: &dyn PolicySource,
    gateway: &str,
    creds: &Credentials,
) -> Result<Option<String>, AuthFailure> {
    let agents = policies.agents();
    let required = agents
        .iter()
        .any(|(_, p)| p.needs_credential() && p.gateway.as_deref().is_none_or(|g| g == gateway));
    let digest: Option<[u8; 32]> = creds
        .bearer
        .as_deref()
        .map(|t| Sha256::digest(t.as_bytes()).into());
    let mut matched = None;
    for (id, p) in &agents {
        if p.gateway.as_deref().is_some_and(|g| g != gateway) {
            continue;
        }
        let token_ok = match (&digest, p.token_sha256.first()) {
            (Some(h), Some(expected)) => digest_eq(h, expected),
            _ => false,
        };
        let spiffe_ok = match (&creds.spiffe_id, p.spiffe_id.first()) {
            (Some(id), Some(pattern)) => spiffe_matches(pattern, id),
            _ => false,
        };
        if token_ok || spiffe_ok {
            matched = Some(id.clone());
            break;
        }
    }
    let Some(id) = matched else {
        return if required {
            Err(AuthFailure::Unauthenticated)
        } else {
            Ok(None)
        };
    };
    if policies.agent_disabled(&id) {
        return Err(AuthFailure::Disabled);
    }
    Ok(Some(id))
}

/// Convenience: look up one agent's policy by id through a [`PolicySource`].
pub fn policy_for(policies: &dyn PolicySource, id: &str) -> Option<Arc<AgentPolicy>> {
    policies
        .agents()
        .into_iter()
        .find(|(name, _)| name == id)
        .map(|(_, p)| p)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Source {
        agents: Vec<(String, Arc<AgentPolicy>)>,
        disabled: Vec<String>,
    }

    impl PolicySource for Source {
        fn policy_for(
            &self,
            _: &crate::proxy::OrigInfo,
        ) -> Option<std::sync::Arc<crate::ToolPolicy>> {
            None
        }
        fn agents(&self) -> Vec<(String, Arc<AgentPolicy>)> {
            self.agents.clone()
        }
        fn agent_disabled(&self, id: &str) -> bool {
            self.disabled.iter().any(|x| x == id)
        }
    }

    fn policy(require: bool) -> AgentPolicy {
        AgentPolicy {
            token_sha256: vec![Sha256::digest(b"secret").into()],
            spiffe_id: vec!["spiffe://td/ns/prod/*".into()],
            require_auth: require,
            gateway: Some("dev".into()),
            ..Default::default()
        }
    }

    #[test]
    fn resolution_is_opt_in_and_fails_closed_when_required() {
        let c = Credentials::new(Some(b"Bearer secret"), None);
        let src = |require: bool, disabled: bool| Source {
            agents: vec![("bot".into(), Arc::new(policy(require)))],
            disabled: if disabled { vec!["bot".into()] } else { vec![] },
        };
        assert_eq!(
            resolve_agent(&src(false, false), "dev", &Credentials::default()),
            Ok(None)
        );
        assert_eq!(
            resolve_agent(&src(true, false), "dev", &Credentials::default()),
            Err(AuthFailure::Unauthenticated)
        );
        assert_eq!(
            resolve_agent(&src(true, false), "dev", &c),
            Ok(Some("bot".into()))
        );
        assert_eq!(
            resolve_agent(&src(true, true), "dev", &c),
            Err(AuthFailure::Disabled)
        );
        // An agent bound to another gateway does not lock down this one.
        let mut other = policy(true);
        other.gateway = Some("other".into());
        let s = Source {
            agents: vec![("bot".into(), Arc::new(other))],
            disabled: vec![],
        };
        assert_eq!(resolve_agent(&s, "dev", &Credentials::default()), Ok(None));
    }

    #[test]
    fn bearer_parsing_is_strict() {
        assert_eq!(Credentials::bearer_token(b"Bearer abc"), Some("abc"));
        assert_eq!(Credentials::bearer_token(b"bearer abc"), Some("abc"));
        assert_eq!(Credentials::bearer_token(b"Basic abc"), None);
        assert_eq!(Credentials::bearer_token(b"Bearer  abc"), None);
        assert_eq!(Credentials::bearer_token(b"Bearer "), None);
        assert_eq!(Credentials::bearer_token(b"Bearer a b"), None);
    }

    #[test]
    fn spiffe_patterns() {
        assert!(spiffe_matches(
            "spiffe://td/ns/prod/*",
            "spiffe://td/ns/prod/sa/db"
        ));
        assert!(!spiffe_matches(
            "spiffe://td/ns/prod/*",
            "spiffe://td/ns/prod"
        ));
        assert!(spiffe_matches(
            "spiffe://td/ns/prod/db",
            "spiffe://td/ns/prod/db"
        ));
    }
}
