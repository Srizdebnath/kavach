//! # kavach-gateway (v0.4 preview)
//!
//! When an egress rule's verdict is `punt`, the flow needs a decision only L7 can make. For AI
//! agents, the questions are "which MCP tool is being called?" and "which A2A task is being
//! sent?" This crate holds that decision logic. It is deliberately transport-free, so the
//! v0.4 proxy (which terminates the agent's HTTP/WebSocket/stdio stream) and the tests share it.
//!
//! The data path (`[gateway] enabled = true` in kavachd.toml):
//! 1. The LSM punts the TCP connect (rule verdict `punt`, gateway alive).
//! 2. A `cgroup/connect4|6` program rewrites its destination to the gateway listener; sockops
//!    records the original destination under the client's 4-tuple (`orig_dst`).
//! 3. The proxy accepts, resolves the original destination with an [`OrigDst`], parses
//!    each JSON-RPC frame with [`classify`] and decides with [`ToolPolicy::decide`].
//! 4. The proxy enforces its decision in-path; kavachd may record a connection-level verdict
//!    in the `orig_dst` entry (informational, see docs/ARCHITECTURE.md).
//!
//! [`proxy`] is that transport: a TCP listener that relays redirected flows (HTTP/1.1, SSE,
//! WebSocket, raw NDJSON) and enforces the decision per frame. With the gateway off or dead
//! (liveness deadline lapsed), punted flows resolve through the rule's fail mode.
//!
//! [`afxdp`] is an optional, opt-in RX backend: the XDP program redirects frames for
//! gateway-selected ports straight to per-queue AF_XDP sockets, guarded by a watchdog. It is
//! not part of the punt path (that is socket-level, above).
//!
//! `unsafe` is denied crate-wide; only `afxdp::sys` (raw syscalls, mmap) and `afxdp::ring`
//! (shared-memory ring indices) opt out, each block with a `SAFETY:` justification.
#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod afxdp;
pub mod agent;
pub mod budget;
pub mod proxy;

pub use agent::{
    AgentPolicy, AgentResolver, AuthFailure, Credentials, FnAgentResolver, resolve_agent,
};
pub use budget::{BudgetClock, Budgets, ManualClock, SystemClock};
pub use proxy::{
    DecisionEvent, EventSink, Gateway, OrigDst, OrigInfo, PolicySource, PolicyStore, ProxyConfig,
    run,
};

use serde::{Deserialize, Serialize};

/// What a single JSON-RPC message from the agent is trying to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// MCP `tools/call` with the tool name.
    ToolCall {
        /// The `params.name` of the call.
        tool: String,
    },
    /// MCP `resources/read` with the URI.
    ResourceRead {
        /// The `params.uri` being read.
        uri: String,
    },
    /// A2A `message/send` / `message/stream` (task delegation to another agent).
    AgentMessage,
    /// Handshake / discovery traffic (`initialize`, `*/list`, notifications, pings).
    Control,
    /// Any other method.
    Other {
        /// The JSON-RPC method name.
        method: String,
    },
}

/// Why a frame could not be classified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Not JSON, or not a JSON-RPC 2.0 request/notification.
    NotJsonRpc,
    /// Batches are refused: one frame, one decision (no smuggling a call inside a batch).
    Batch,
    /// Frame exceeds [`MAX_FRAME`].
    TooLarge,
}

/// Largest JSON-RPC frame the gateway will parse.
pub const MAX_FRAME: usize = 1 << 20;

#[derive(Deserialize)]
struct Frame {
    jsonrpc: String,
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

/// Classify one JSON-RPC frame sent by an agent.
pub fn classify(frame: &[u8]) -> Result<Action, ParseError> {
    if frame.len() > MAX_FRAME {
        return Err(ParseError::TooLarge);
    }
    let trimmed = frame
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .map(|i| &frame[i..])
        .unwrap_or(&[]);
    if trimmed.first() == Some(&b'[') {
        return Err(ParseError::Batch);
    }
    let f: Frame = serde_json::from_slice(frame).map_err(|_| ParseError::NotJsonRpc)?;
    if f.jsonrpc != "2.0" {
        return Err(ParseError::NotJsonRpc);
    }
    let s = |k: &str| f.params.get(k).and_then(|v| v.as_str()).map(str::to_owned);
    Ok(match f.method.as_str() {
        "tools/call" => Action::ToolCall {
            tool: s("name").ok_or(ParseError::NotJsonRpc)?,
        },
        "resources/read" => Action::ResourceRead {
            uri: s("uri").ok_or(ParseError::NotJsonRpc)?,
        },
        "message/send" | "message/stream" => Action::AgentMessage,
        m if m == "initialize"
            || m == "ping"
            || m.ends_with("/list")
            || m.starts_with("notifications/") =>
        {
            Action::Control
        }
        m => Action::Other {
            method: m.to_owned(),
        },
    })
}

/// Gateway verdict for one frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    /// Forward the frame.
    Allow,
    /// Answer with a JSON-RPC error and do not forward.
    Deny,
}

/// What the gateway does with a punted stream it cannot read because it is TLS it does not
/// terminate (no JSON-RPC frame is visible, so no tool decision can be made).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    /// Refuse the stream (fail closed). The default.
    #[default]
    Deny,
    /// Pass it through uninspected: only the L3/L4 rule that punted it applies.
    Allow,
}

/// Per-agent tool policy: first matching pattern wins; `*` suffix is a prefix match.
///
/// Named gateway policies in `kavach.toml` (`[gateway.<name>]`) compile into these; kavachd
/// hands them to the proxy keyed by name.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolPolicy {
    /// Tool name patterns that are allowed.
    #[serde(default)]
    pub allow_tools: Vec<String>,
    /// Tool name patterns that are denied (checked first).
    #[serde(default)]
    pub deny_tools: Vec<String>,
    /// Resource URI prefixes that may be read.
    #[serde(default)]
    pub allow_resources: Vec<String>,
    /// Whether the agent may delegate to other agents (A2A).
    #[serde(default)]
    pub allow_agent_messages: bool,
    /// Verdict for methods not covered above.
    #[serde(default)]
    pub allow_other: bool,
    /// Opaque (non-terminated) TLS streams.
    #[serde(default)]
    pub tls: TlsMode,
}

fn matches(pat: &str, s: &str) -> bool {
    match pat.strip_suffix('*') {
        Some(prefix) => s.starts_with(prefix),
        None => pat == s,
    }
}

impl ToolPolicy {
    /// Decide one classified action. Control traffic is always allowed so sessions can start.
    pub fn decide(&self, a: &Action) -> Decision {
        let ok = match a {
            Action::Control => true,
            Action::ToolCall { tool } => {
                !self.deny_tools.iter().any(|p| matches(p, tool))
                    && self.allow_tools.iter().any(|p| matches(p, tool))
            }
            Action::ResourceRead { uri } => self
                .allow_resources
                .iter()
                .any(|p| uri.starts_with(p.as_str())),
            Action::AgentMessage => self.allow_agent_messages,
            Action::Other { .. } => self.allow_other,
        };
        if ok { Decision::Allow } else { Decision::Deny }
    }

    /// Classify and decide; unparseable frames are denied (fail closed at L7).
    pub fn decide_frame(&self, frame: &[u8]) -> Decision {
        classify(frame).map_or(Decision::Deny, |a| self.decide(&a))
    }

    /// [`ToolPolicy::decide`] plus the reason, naming the pattern that decided (for
    /// `kavachctl explain`). Always returns the same decision as `decide`.
    pub fn explain(&self, a: &Action) -> (Decision, String) {
        let first = |pats: &[String], s: &str| pats.iter().find(|p| matches(p, s)).cloned();
        let flag = |ok: bool, name: &str| {
            let d = if ok { Decision::Allow } else { Decision::Deny };
            (d, format!("{name} = {ok}"))
        };
        match a {
            Action::Control => (
                Decision::Allow,
                "control traffic (initialize, ping, */list, notifications) is always allowed"
                    .into(),
            ),
            Action::ToolCall { tool } => {
                if let Some(p) = first(&self.deny_tools, tool) {
                    (Decision::Deny, format!("deny_tools pattern {p:?}"))
                } else if let Some(p) = first(&self.allow_tools, tool) {
                    (Decision::Allow, format!("allow_tools pattern {p:?}"))
                } else {
                    (Decision::Deny, "no allow_tools pattern matches".into())
                }
            }
            Action::ResourceRead { uri } => {
                match self
                    .allow_resources
                    .iter()
                    .find(|p| uri.starts_with(p.as_str()))
                {
                    Some(p) => (Decision::Allow, format!("allow_resources prefix {p:?}")),
                    None => (Decision::Deny, "no allow_resources prefix matches".into()),
                }
            }
            Action::AgentMessage => flag(self.allow_agent_messages, "allow_agent_messages"),
            Action::Other { .. } => flag(self.allow_other, "allow_other"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> ToolPolicy {
        ToolPolicy {
            allow_tools: vec!["github.*".into(), "search".into()],
            deny_tools: vec!["github.delete_repo".into()],
            allow_resources: vec!["file:///workspace/".into()],
            ..Default::default()
        }
    }

    #[test]
    fn classifies_mcp_and_a2a() {
        let call = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","arguments":{}}}"#;
        assert_eq!(
            classify(call),
            Ok(Action::ToolCall {
                tool: "search".into()
            })
        );
        assert_eq!(
            classify(br#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#),
            Ok(Action::Control)
        );
        assert_eq!(
            classify(br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#),
            Ok(Action::Control)
        );
        assert_eq!(
            classify(br#"{"jsonrpc":"2.0","id":3,"method":"message/send","params":{}}"#),
            Ok(Action::AgentMessage)
        );
        assert_eq!(
            classify(br#" [{"jsonrpc":"2.0","method":"tools/call"}]"#),
            Err(ParseError::Batch)
        );
        assert_eq!(
            classify(br#"{"jsonrpc":"1.0","method":"x"}"#),
            Err(ParseError::NotJsonRpc)
        );
        assert_eq!(classify(b"\x00garbage"), Err(ParseError::NotJsonRpc));
    }

    #[test]
    fn deny_beats_allow_and_unknown_fails_closed() {
        let p = policy();
        let d = |f: &str| p.decide_frame(f.as_bytes());
        assert_eq!(
            d(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"github.create_issue"}}"#
            ),
            Decision::Allow
        );
        assert_eq!(
            d(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"github.delete_repo"}}"#
            ),
            Decision::Deny
        );
        assert_eq!(
            d(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"shell.exec"}}"#),
            Decision::Deny
        );
        assert_eq!(
            d(
                r#"{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///workspace/a.rs"}}"#
            ),
            Decision::Allow
        );
        assert_eq!(
            d(
                r#"{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///etc/shadow"}}"#
            ),
            Decision::Deny
        );
        assert_eq!(
            d(r#"{"jsonrpc":"2.0","id":1,"method":"message/send","params":{}}"#),
            Decision::Deny
        );
        assert_eq!(
            d(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#),
            Decision::Allow
        );
        assert_eq!(d("not json"), Decision::Deny);
    }

    #[test]
    fn explain_agrees_with_decide_and_names_the_pattern() {
        let mut p = policy();
        p.deny_tools.push("shell.*".into());
        let actions = [
            Action::Control,
            Action::ToolCall {
                tool: "github.create_issue".into(),
            },
            Action::ToolCall {
                tool: "github.delete_repo".into(),
            },
            Action::ToolCall {
                tool: "shell.exec".into(),
            },
            Action::ToolCall { tool: "x".into() },
            Action::ResourceRead {
                uri: "file:///workspace/a".into(),
            },
            Action::ResourceRead {
                uri: "file:///etc/passwd".into(),
            },
            Action::AgentMessage,
            Action::Other {
                method: "sampling/createMessage".into(),
            },
        ];
        for allow in [false, true] {
            p.allow_agent_messages = allow;
            p.allow_other = allow;
            for a in &actions {
                assert_eq!(p.explain(a).0, p.decide(a), "{a:?}");
            }
        }
        let why = |t: &str| p.explain(&Action::ToolCall { tool: t.into() }).1;
        assert_eq!(
            why("github.delete_repo"),
            r#"deny_tools pattern "github.delete_repo""#
        );
        assert_eq!(why("github.list"), r#"allow_tools pattern "github.*""#);
        assert_eq!(why("shell.exec"), r#"deny_tools pattern "shell.*""#);
    }

    #[test]
    fn tool_policy_tls_defaults_to_deny_and_rejects_unknown_keys() {
        let p: ToolPolicy = toml::from_str("allow_tools = [\"a\"]").unwrap();
        assert_eq!(p.tls, TlsMode::Deny);
        let p: ToolPolicy = toml::from_str("tls = \"allow\"").unwrap();
        assert_eq!(p.tls, TlsMode::Allow);
        assert!(toml::from_str::<ToolPolicy>("bogus = 1").is_err());
    }
}
