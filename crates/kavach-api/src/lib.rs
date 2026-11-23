//! # kavach-api
//!
//! The local control protocol between `kavachctl` and `kavachd`: one JSON object per line over
//! the Unix socket `/run/kavach/kavach.sock` (0600, `SO_PEERCRED`-checked). There is no network
//! listener (SR-1).
#![forbid(unsafe_code)]

pub mod audit;

use serde::{Deserialize, Serialize};

pub const DEFAULT_SOCKET: &str = "/run/kavach/kavach.sock";
/// Hard cap on one request line (bundles are sent base64-free as byte arrays, so allow headroom).
pub const MAX_LINE: usize = 16 << 20;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Status,
    Stats,
    Metrics,
    BlockAdd {
        cidr: String,
        ttl_secs: Option<u64>,
        reason: Option<u32>,
    },
    BlockDel {
        cidr: String,
    },
    BlockList,
    RateLimit {
        pps: u64,
        burst: u64,
    },
    RateLimitOff,
    /// Apply a signed bundle (raw `.kvb` bytes).
    Apply {
        bundle: Vec<u8>,
        dry_run: bool,
    },
    /// Return the active compiled policy (postcard bytes) for local explain/diff.
    ActivePolicy,
    /// Stream events until the client disconnects.
    Events,
    /// Detach every program and remove all pins (root only).
    KillSwitch,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Ok,
    Error {
        message: String,
    },
    Status(Status),
    Stats {
        counters: Vec<(String, u64)>,
    },
    Metrics {
        text: String,
    },
    BlockList {
        entries: Vec<BlockEntry>,
    },
    Applied(ApplyReport),
    ActivePolicy {
        policy: Option<Vec<u8>>,
        serial: u64,
        generation: u32,
    },
    Event(EventRecord),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Status {
    pub version: String,
    pub kernel: String,
    pub generation: u32,
    pub serial: u64,
    pub policy_expired: bool,
    pub rules: u32,
    pub xdp: Vec<(String, String)>,
    pub tc: Vec<String>,
    pub lsm: bool,
    pub features: Vec<(String, bool)>,
    pub uptime_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockEntry {
    pub cidr: String,
    pub reason: u32,
    /// Seconds remaining, `None` = permanent.
    pub expires_in: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ApplyReport {
    pub dry_run: bool,
    pub serial: u64,
    pub generation: u32,
    pub rules: u32,
    pub changes: Vec<String>,
    pub warnings: Vec<String>,
    pub swap_micros: u64,
}

/// A kernel event rendered for humans and SIEMs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct EventRecord {
    pub ts_ns: u64,
    pub kind: String,
    pub verdict: String,
    pub reason: String,
    pub proto: u8,
    pub src: Option<String>,
    pub dst: Option<String>,
    pub sport: u16,
    pub dport: u16,
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    pub cgroup_id: u64,
    pub identity: u64,
    pub rule_id: u32,
    pub rule: Option<String>,
    pub generation: u32,
    pub ifindex: u32,
    /// Free-form detail (e.g. the metric and baseline of an `anomaly` event).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Encode one protocol line (JSON + `\n`).
pub fn encode<T: Serialize>(msg: &T) -> Vec<u8> {
    let mut v = serde_json::to_vec(msg).expect("protocol types always serialise");
    v.push(b'\n');
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_wire_format_is_stable() {
        let r = Request::BlockAdd {
            cidr: "10.0.0.0/8".into(),
            ttl_secs: Some(60),
            reason: None,
        };
        let s = String::from_utf8(encode(&r)).unwrap();
        assert_eq!(
            s,
            "{\"op\":\"block_add\",\"cidr\":\"10.0.0.0/8\",\"ttl_secs\":60,\"reason\":null}\n"
        );
        let back: Request = serde_json::from_str(s.trim()).unwrap();
        assert_eq!(back, r);
    }

    /// Regression: the response tag must not collide with payload fields (EventRecord.kind).
    #[test]
    fn every_response_roundtrips() {
        let ev = Response::Event(EventRecord {
            kind: "egress".into(),
            verdict: "drop".into(),
            ..Default::default()
        });
        let st = Response::Status(Status::default());
        for r in [
            ev,
            st,
            Response::Ok,
            Response::Error {
                message: "x".into(),
            },
        ] {
            let line = encode(&r);
            let back: Response = serde_json::from_slice(&line).unwrap();
            assert_eq!(back, r);
        }
    }
}
