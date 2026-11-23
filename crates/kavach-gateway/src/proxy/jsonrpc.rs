//! Per-frame inspection and the JSON-RPC errors the gateway answers with.

use std::collections::HashSet;
use std::fmt;

use serde::Serialize;
use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Value, json};

use crate::{Action, Decision, ParseError, ToolPolicy, classify};

/// JSON-RPC error code for a policy denial.
pub const DENIED: i64 = -32001;
/// JSON-RPC parse error.
pub const PARSE_ERROR: i64 = -32700;
/// JSON-RPC invalid request.
pub const INVALID_REQUEST: i64 = -32600;

/// Why a frame got its decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// The gateway policy decided.
    Policy,
    /// A JSON-RPC response from the agent to a server-initiated request (sampling,
    /// elicitation, roots); allowed: it is an answer, not an action.
    Response,
    /// An HTTP request without a body (SSE stream open, session delete).
    NoFrame,
    /// The flow's gateway has no policy loaded (fail closed).
    NoPolicy,
    /// The original destination of the flow is unknown (fail closed).
    NoOrigDst,
    /// Not a JSON-RPC 2.0 message, or a key appears twice in an object.
    Malformed,
    /// JSON-RPC batch (one frame, one decision).
    Batch,
    /// Frame exceeds the size limit.
    TooLarge,
    /// HTTP framing violation (smuggling shapes, bad chunking, pipelining).
    Framing,
    /// A WebSocket binary message (no JSON-RPC to inspect).
    Binary,
    /// The flow is TLS and the policy has `tls = "deny"`.
    Tls,
    /// The flow is TLS and the policy has `tls = "allow"` (relayed, not inspected).
    TlsPassthrough,
    /// The first bytes are no protocol the gateway speaks.
    UnknownProtocol,
}

impl Reason {
    /// Whether the frame was refused for being malformed rather than by policy. These
    /// close the connection; a policy denial does not.
    pub fn is_malformed(self) -> bool {
        matches!(
            self,
            Reason::Malformed | Reason::Batch | Reason::TooLarge | Reason::Framing | Reason::Binary
        )
    }
}

/// The outcome of inspecting one frame.
#[derive(Debug, Clone, PartialEq)]
pub struct Inspection {
    /// Allow or deny.
    pub decision: Decision,
    /// Why.
    pub reason: Reason,
    /// JSON-RPC method, if one was parsed.
    pub method: Option<String>,
    /// Tool name or resource URI, when the method has one.
    pub target: Option<String>,
    /// The request id; `None` for notifications and unparseable frames.
    pub id: Option<Value>,
}

impl Inspection {
    fn deny(reason: Reason) -> Self {
        Self {
            decision: Decision::Deny,
            reason,
            method: None,
            target: None,
            id: None,
        }
    }
}

/// Inspect one client→server frame. `policy` is `None` when the gateway has none loaded.
pub fn inspect(policy: Option<&ToolPolicy>, frame: &[u8], max: usize) -> Inspection {
    if frame.len() > max.min(crate::MAX_FRAME) {
        return Inspection::deny(Reason::TooLarge);
    }
    let first = frame.iter().find(|b| !b.is_ascii_whitespace());
    if first == Some(&b'[') {
        return Inspection::deny(Reason::Batch);
    }
    let Some(Value::Object(obj)) = parse_unique(frame) else {
        return Inspection::deny(Reason::Malformed);
    };
    let id = obj.get("id").cloned();
    if id
        .as_ref()
        .is_some_and(|v| !(v.is_string() || v.is_number()))
    {
        return Inspection::deny(Reason::Malformed);
    }
    let method = obj.get("method").and_then(Value::as_str).map(str::to_owned);

    // A response from the agent: {"jsonrpc":"2.0","id":..,"result"|"error":..}, no method.
    if !obj.contains_key("method") {
        let ok = obj.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
            && id.is_some()
            && (obj.contains_key("result") ^ obj.contains_key("error"))
            && obj.len() == 3;
        let mut i = Inspection::deny(if ok {
            Reason::Response
        } else {
            Reason::Malformed
        });
        if ok {
            i.decision = Decision::Allow;
        }
        return i;
    }

    let action = match classify(frame) {
        Ok(a) => a,
        Err(e) => {
            let mut i = Inspection::deny(match e {
                ParseError::Batch => Reason::Batch,
                ParseError::TooLarge => Reason::TooLarge,
                ParseError::NotJsonRpc => Reason::Malformed,
            });
            // A well-formed request whose params are wrong still gets its id back.
            i.method = method;
            i.id = id;
            return i;
        }
    };
    let target = match &action {
        Action::ToolCall { tool } => Some(tool.clone()),
        Action::ResourceRead { uri } => Some(uri.clone()),
        _ => None,
    };
    let (decision, reason) = match policy {
        Some(p) => (p.decide(&action), Reason::Policy),
        None => (Decision::Deny, Reason::NoPolicy),
    };
    Inspection {
        decision,
        reason,
        method,
        target,
        id,
    }
}

/// The JSON-RPC error the gateway sends for a denied or malformed frame, or `None` when no
/// reply is due (a denied notification).
pub fn error_reply(i: &Inspection, gateway: &str, rule_id: u32) -> Option<Vec<u8>> {
    if i.id.is_none() && !i.reason.is_malformed() {
        return None;
    }
    Some(error_body(i, gateway, rule_id))
}

/// The JSON-RPC error object for `i` (id `null` when the frame had none).
pub fn error_body(i: &Inspection, gateway: &str, rule_id: u32) -> Vec<u8> {
    let (code, message) = if i.reason.is_malformed() {
        let code = if i.reason == Reason::Malformed && i.id.is_none() {
            PARSE_ERROR
        } else {
            INVALID_REQUEST
        };
        (code, format!("kavach: frame refused ({:?})", i.reason))
    } else {
        (DENIED, format!("denied by kavach policy {gateway}"))
    };
    let v = json!({
        "jsonrpc": "2.0",
        "id": i.id.clone().unwrap_or(Value::Null),
        "error": {
            "code": code,
            "message": message,
            "data": {
                "gateway": gateway,
                "rule_id": rule_id,
                "reason": i.reason,
                "method": i.method,
                "target": i.target,
            },
        },
    });
    // Serializing a Value built from strings and numbers cannot fail.
    serde_json::to_vec(&v).unwrap_or_default()
}

/// Parse JSON into a [`Value`], refusing any object with a repeated key. serde_json keeps the
/// last duplicate; an upstream parser that keeps the first would see a different tool name.
pub fn parse_unique(frame: &[u8]) -> Option<Value> {
    let mut de = serde_json::Deserializer::from_slice(frame);
    let v = UniqueValue.deserialize(&mut de).ok()?;
    de.end().ok()?;
    Some(v)
}

struct UniqueValue;

impl<'de> DeserializeSeed<'de> for UniqueValue {
    type Value = Value;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for UniqueValue {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JSON")
    }
    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_f64<E>(self, v: f64) -> Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }
    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(v) = seq.next_element_seed(UniqueValue)? {
            out.push(v);
        }
        Ok(Value::Array(out))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut seen = HashSet::new();
        let mut out = serde_json::Map::new();
        while let Some(k) = map.next_key::<String>()? {
            if !seen.insert(k.clone()) {
                return Err(de::Error::custom("duplicate key"));
            }
            let v = map.next_value_seed(UniqueValue)?;
            out.insert(k, v);
        }
        Ok(Value::Object(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> ToolPolicy {
        ToolPolicy {
            allow_tools: vec!["search".into()],
            ..Default::default()
        }
    }

    fn i(frame: &str) -> Inspection {
        inspect(Some(&policy()), frame.as_bytes(), crate::MAX_FRAME)
    }

    #[test]
    fn decides_and_keeps_id() {
        let a = i(r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"search"}}"#);
        assert_eq!(a.decision, Decision::Allow);
        assert_eq!(a.target.as_deref(), Some("search"));
        let d = i(r#"{"jsonrpc":"2.0","id":"x","method":"tools/call","params":{"name":"rm"}}"#);
        assert_eq!((d.decision, d.reason), (Decision::Deny, Reason::Policy));
        assert_eq!(d.id, Some(json!("x")));
        let e: Value = serde_json::from_slice(&error_reply(&d, "dev", 4).unwrap()).unwrap();
        assert_eq!(e["id"], json!("x"));
        assert_eq!(e["error"]["code"], json!(DENIED));
        assert_eq!(e["error"]["message"], json!("denied by kavach policy dev"));
        assert_eq!(e["error"]["data"]["rule_id"], json!(4));
    }

    #[test]
    fn duplicate_keys_fail_closed() {
        let d = i(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"rm","name":"search"}}"#,
        );
        assert_eq!((d.decision, d.reason), (Decision::Deny, Reason::Malformed));
        let d = i(r#"{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}"#);
        assert_eq!(d.reason, Reason::Malformed);
        assert!(parse_unique(br#"{"a":[{"b":1,"b":2}]}"#).is_none());
        assert!(parse_unique(br#"{"a":[{"b":1},{"b":2}]}"#).is_some());
    }

    #[test]
    fn responses_notifications_and_junk() {
        let r = i(r#"{"jsonrpc":"2.0","id":3,"result":{}}"#);
        assert_eq!((r.decision, r.reason), (Decision::Allow, Reason::Response));
        let r = i(r#"{"jsonrpc":"2.0","id":3,"result":{},"error":{}}"#);
        assert_eq!(r.decision, Decision::Deny);
        let n = i(r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"rm"}}"#);
        assert_eq!((n.decision, n.reason), (Decision::Deny, Reason::Policy));
        assert!(error_reply(&n, "dev", 0).is_none());
        assert_eq!(i("[]").reason, Reason::Batch);
        assert_eq!(i("nope").reason, Reason::Malformed);
        assert_eq!(
            i(r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#).reason,
            Reason::Malformed
        );
        assert_eq!(
            i(r#"{"jsonrpc":"2.0","id":1,"method":"ping"} x"#).reason,
            Reason::Malformed
        );
        let junk = i("nope");
        let e: Value = serde_json::from_slice(&error_reply(&junk, "dev", 0).unwrap()).unwrap();
        assert_eq!(e["error"]["code"], json!(PARSE_ERROR));
        assert_eq!(e["id"], Value::Null);
        let p = inspect(None, br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#, 100);
        assert_eq!((p.decision, p.reason), (Decision::Deny, Reason::NoPolicy));
        let big = inspect(Some(&policy()), &[b' '; 101], 100);
        assert_eq!(big.reason, Reason::TooLarge);
        // tools/call without a name: malformed, but the id comes back
        let m = i(r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{}}"#);
        assert_eq!(
            (m.reason, m.id.clone()),
            (Reason::Malformed, Some(json!(9)))
        );
        let e: Value = serde_json::from_slice(&error_reply(&m, "dev", 0).unwrap()).unwrap();
        assert_eq!(e["error"]["code"], json!(INVALID_REQUEST));
    }
}
