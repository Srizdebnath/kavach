//! Ring-buffer reader: decodes kernel events, feeds the identity broker, fans out to
//! `kavachctl events` subscribers and samples verdicts into the audit log.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::Result;
use aya::maps::{MapData, RingBuf};
use kavach_api::EventRecord;
use kavach_common::abi::*;
use kavach_common::addr::{from_mapped, from_words};
use tokio::io::unix::AsyncFd;
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, warn};

use crate::daemon::{self, Daemon};

/// Work for the identity broker.
#[derive(Debug, Clone, Copy)]
pub enum IdentityJob {
    Exec { pid: u32, key: ExeKey },
    Tainted { key: ExeKey },
}

pub fn decode(bytes: &[u8]) -> Option<Event> {
    (bytes.len() >= std::mem::size_of::<Event>())
        .then(|| bytemuck::pod_read_unaligned(&bytes[..std::mem::size_of::<Event>()]))
}

fn verdict_name(v: u8) -> &'static str {
    match Verdict::from_u8(v) {
        Some(Verdict::Allow) => "allow",
        Some(Verdict::Drop) => "drop",
        Some(Verdict::Log) => "log",
        Some(Verdict::Punt) => "punt",
        None => "?",
    }
}

fn reason_name(r: u8) -> &'static str {
    match r as u32 {
        x if x == StatReason::XdpDropBlocklist as u32 => "blocklist",
        x if x == StatReason::XdpDropRate as u32 => "rate_limit",
        x if x == StatReason::EgressDrop as u32 => "egress_policy",
        x if x == StatReason::EgressLog as u32 => "egress_log",
        x if x == StatReason::IngressDrop as u32 => "ingress_policy",
        x if x == StatReason::IngressAllow as u32 => "ingress_log",
        _ => "",
    }
}

pub fn render(e: &Event, rule_name: Option<String>) -> EventRecord {
    let kind = match e.kind {
        k if k == EventKind::XdpDrop as u8 => "xdp_drop",
        k if k == EventKind::EgressVerdict as u8 => "egress",
        k if k == EventKind::IngressVerdict as u8 => "ingress",
        k if k == EventKind::Exec as u8 => "exec",
        k if k == EventKind::ExeTainted as u8 => "exe_tainted",
        _ => "unknown",
    };
    let is_flow = matches!(kind, "xdp_drop" | "egress" | "ingress");
    let addr = |w: [u32; 4]| {
        let a = from_words(w);
        (a != [0; 16]).then(|| from_mapped(a).to_string())
    };
    let comm_end = e.comm.iter().position(|b| *b == 0).unwrap_or(16);
    EventRecord {
        ts_ns: e.ts_ns,
        kind: kind.into(),
        verdict: if is_flow { verdict_name(e.verdict).into() } else { String::new() },
        reason: reason_name(e.reason).into(),
        proto: e.key.proto,
        src: if is_flow { addr(e.key.src) } else { None },
        dst: if is_flow { addr(e.key.dst) } else { None },
        sport: u16::from_be(e.key.sport),
        dport: u16::from_be(e.key.dport),
        pid: e.pid,
        uid: e.uid,
        comm: String::from_utf8_lossy(&e.comm[..comm_end]).into_owned(),
        cgroup_id: e.cgroup_id,
        identity: e.identity,
        rule_id: if is_flow { e.rule_id } else { 0 },
        rule: rule_name,
        generation: if is_flow { e.generation } else { 0 },
        ifindex: e.ifindex,
    }
}

/// Drain the ring buffer forever.
pub async fn reader(
    rb: RingBuf<MapData>,
    state: Arc<Mutex<Daemon>>,
    tx: broadcast::Sender<EventRecord>,
    jobs: mpsc::Sender<IdentityJob>,
) -> Result<()> {
    // RingBuf owns its fd for the lifetime of the AsyncFd, which is the safety condition.
    #[allow(deprecated)]
    let mut fd = AsyncFd::new(rb)?;
    let mut audit_window = (Instant::now(), 0u32);
    loop {
        let mut guard = fd.readable_mut().await?;
        let rb = guard.get_inner_mut();
        while let Some(item) = rb.next() {
            let Some(e) = decode(&item) else { continue };
            drop(item);
            if e.kind == EventKind::Exec as u8 || e.kind == EventKind::ExeTainted as u8 {
                let key = ExeKey { dev: e.rule_id, generation: e.generation, ino: e.identity };
                let job = if e.kind == EventKind::Exec as u8 {
                    IdentityJob::Exec { pid: e.pid, key }
                } else {
                    IdentityJob::Tainted { key }
                };
                if jobs.try_send(job).is_err() {
                    debug!("identity queue full; executable will be classified on its next exec");
                }
            }
            let rule_name = (e.rule_id != 0 && e.kind != EventKind::Exec as u8)
                .then(|| {
                    let st = state.lock().ok()?;
                    let p = st.active()?;
                    p.rules.iter().find(|r| r.id == e.rule_id).map(|r| r.name.clone())
                })
                .flatten();
            let rec = render(&e, rule_name);
            // Sampled verdicts into the audit log: at most 10 per second (FR-AUD-1).
            if e.kind == EventKind::EgressVerdict as u8 && e.verdict == Verdict::Drop as u8 {
                if audit_window.0.elapsed().as_secs() >= 1 {
                    audit_window = (Instant::now(), 0);
                }
                if audit_window.1 < 10 {
                    audit_window.1 += 1;
                    if let Ok(mut st) = state.lock() {
                        st.audit.record("verdict", serde_json::to_value(&rec).unwrap_or_default());
                    }
                }
            }
            let _ = tx.send(rec);
        }
        guard.clear_ready();
    }
}

/// Classify executables reported by the kernel. Hashing happens outside the state lock.
pub async fn identity_broker(state: Arc<Mutex<Daemon>>, mut jobs: mpsc::Receiver<IdentityJob>) {
    while let Some(job) = jobs.recv().await {
        match job {
            IdentityJob::Tainted { key } => {
                if let Ok(mut st) = state.lock() {
                    st.exe_cache.remove(&key);
                    st.audit.record("exe_tainted", serde_json::json!({ "ino": key.ino, "dev": key.dev }));
                }
            }
            IdentityJob::Exec { pid, key } => {
                // Read the modification sequence BEFORE hashing (seq-pair protocol).
                let cached = {
                    let Ok(mut st) = state.lock() else { continue };
                    let seq = match st.k().and_then(|k| k.exe_dirty(&key)) {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    (seq, st.exe_cache.get(&key).cloned())
                };
                let (seq, info) = match cached {
                    (seq, Some(info)) => (seq, Ok(info)),
                    (seq, None) => {
                        let r = tokio::task::spawn_blocking(move || daemon::hash_exe(pid, key.ino)).await;
                        (seq, r.unwrap_or_else(|e| Err(anyhow::anyhow!(e))))
                    }
                };
                match info {
                    Ok(info) => {
                        if let Ok(mut st) = state.lock() {
                            if let Err(e) = st.write_classification(key, info, seq) {
                                warn!(pid, error = %e, "writing exe classification failed");
                            }
                        }
                    }
                    Err(e) => debug!(pid, error = %e, "could not hash executable (process exited?)"),
                }
            }
        }
    }
}
