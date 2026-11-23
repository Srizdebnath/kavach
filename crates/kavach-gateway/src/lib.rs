//! # kavach-gateway (v0.4 preview)
//!
//! When an egress rule's verdict is `punt`, the flow needs a decision only L7 can make. For AI
//! agents, the questions are "which MCP tool is being called?" and "which A2A task is being
//! sent?" This crate holds that decision logic. It is deliberately transport-free, so the
//! v0.4 proxy (which terminates the agent's HTTP/WebSocket/stdio stream) and the tests share it.
//!
//! The planned data path:
//! 1. The LSM punts the connect.
//! 2. kavachd redirects the flow to the gateway via `sk_assign`/TPROXY.
//! 3. The gateway parses each JSON-RPC frame with [`classify`] and decides with
//!    [`ToolPolicy::decide`].
//! 4. The verdict is written back to `flow_cache` for the connection.
//!
//! Until v0.4 ships, punted flows resolve through the rule's fail mode.
//!
//! [`afxdp`] is an optional, opt-in RX backend: the XDP program redirects frames for
//! gateway-selected ports straight to per-queue AF_XDP sockets, guarded by a watchdog.
//!
//! `unsafe` is denied crate-wide; only `afxdp::sys` (raw syscalls, mmap) and `afxdp::ring`
//! (shared-memory ring indices) opt out, each block with a `SAFETY:` justification.
#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod afxdp;

use serde::Deserialize;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Forward the frame.
    Allow,
    /// Answer with a JSON-RPC error and do not forward.
    Deny,
}

/// Per-agent tool policy: first matching pattern wins; `*` suffix is a prefix match.
#[derive(Debug, Clone, Default, Deserialize)]
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
}
