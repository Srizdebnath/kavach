//! Ring-buffer reader: decodes kernel events, feeds the identity broker, fans out to
//! `kavachctl events` subscribers and samples verdicts into the audit log.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
#[derive(Debug, Clone)]
pub enum IdentityJob {
    /// An unclassified executable started running.
    Exec { pid: u32, key: ExeKey },
    /// The LSM revoked a classification.
    Tainted { key: ExeKey },
    /// Pre-classify an executable the policy names by path.
    Path { path: String },
}

/// How long the broker waits for the LSM's `KeyReport` after its read-open.
const REPORT_TIMEOUT: Duration = Duration::from_secs(1);
/// How long a read-open may take before the broker moves on (the thread is left behind).
const OPEN_TIMEOUT: Duration = Duration::from_secs(2);
/// Concurrent classifications (hashing) in the broker.
const HASHERS: usize = 4;
/// Blocking threads currently inside a key-request open (stuck ones included).
static STUCK_OPENERS: AtomicUsize = AtomicUsize::new(0);
const MAX_STUCK_OPENERS: usize = 8;

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
        verdict: if is_flow {
            verdict_name(e.verdict).into()
        } else {
            String::new()
        },
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
/// The ring buffer wrapped for async readiness. Shared so a restarted reader resumes on it.
pub type EventFd = Arc<tokio::sync::Mutex<AsyncFd<RingBuf<MapData>>>>;

/// Wrap the events ring buffer for [`reader`].
pub fn event_fd(rb: RingBuf<MapData>) -> Result<EventFd> {
    // RingBuf owns its fd for the lifetime of the AsyncFd, which is the safety condition.
    #[allow(deprecated)]
    let fd = AsyncFd::new(rb)?;
    Ok(Arc::new(tokio::sync::Mutex::new(fd)))
}

pub async fn reader(
    fd: EventFd,
    state: Arc<Mutex<Daemon>>,
    tx: broadcast::Sender<EventRecord>,
    jobs: mpsc::Sender<IdentityJob>,
) -> Result<()> {
    let mut fd = fd.lock().await;
    let mut audit_window = (Instant::now(), 0u32);
    loop {
        let mut guard = fd.readable_mut().await?;
        let rb = guard.get_inner_mut();
        while let Some(item) = rb.next() {
            let Some(e) = decode(&item) else { continue };
            drop(item);
            if let Some(rep) = daemon::KeyReport::from_event(&e) {
                if let Ok(mut st) = state.lock() {
                    match st.key_waiters.remove(&rep.nonce) {
                        Some(w) => {
                            if let Err(rep) = w.send(rep) {
                                st.abandon_classification(rep.key, rep.nonce);
                            }
                        }
                        // The broker timed out: nobody will commit this placeholder.
                        None => st.abandon_classification(rep.key, rep.nonce),
                    }
                }
                continue; // internal bookkeeping, not an operator-facing event
            }
            if e.kind == EventKind::Exec as u8 || e.kind == EventKind::ExeTainted as u8 {
                let key = e.exe_key();
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
                    p.rules
                        .iter()
                        .find(|r| r.id == e.rule_id)
                        .map(|r| r.name.clone())
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
                        st.audit
                            .record("verdict", serde_json::to_value(&rec).unwrap_or_default());
                    }
                }
            }
            let _ = tx.send(rec);
        }
        guard.clear_ready();
    }
}

/// Classify executables reported by the kernel. Hashing happens outside the state lock.
/// Shared job queue so a restarted broker keeps draining the same channel.
pub type JobRx = Arc<tokio::sync::Mutex<mpsc::Receiver<IdentityJob>>>;

/// `prewarm` carries `Path` jobs from `apply` and is always drained first: they must not wait
/// behind a backlog of exec events (e.g. the startup task scan), or `apply` would return before
/// the binaries it names are classified.
pub async fn identity_broker(state: Arc<Mutex<Daemon>>, jobs: JobRx, prewarm: JobRx) {
    let mut jobs = jobs.lock().await;
    let mut prewarm = prewarm.lock().await;
    // Hashing runs concurrently (one huge binary must not delay every other exec); only the
    // short arm/open/disarm step is serialised, because `key_req` is a single slot.
    let hashers = Arc::new(tokio::sync::Semaphore::new(HASHERS));
    let gate = Arc::new(tokio::sync::Mutex::new(()));
    loop {
        let job = tokio::select! {
            biased;
            Some(j) = prewarm.recv() => j,
            Some(j) = jobs.recv() => j,
            else => break,
        };
        match job {
            IdentityJob::Tainted { key } => {
                if let Ok(mut st) = state.lock() {
                    st.exe_cache.remove(&key);
                    st.save_exe_cache();
                    st.audit
                        .record("exe_tainted", serde_json::json!({ "ino": key.ino }));
                }
            }
            IdentityJob::Path { path } => {
                let Ok(permit) = hashers.clone().acquire_owned().await else {
                    break;
                };
                let (st, gate) = (state.clone(), gate.clone());
                tokio::spawn(async move {
                    if let Err(e) = classify(&st, &gate, &path, None).await {
                        debug!(path, error = %e, "could not pre-classify");
                    }
                    if let Ok(mut s) = st.lock() {
                        s.prewarm_pending = s.prewarm_pending.saturating_sub(1);
                    }
                    drop(permit);
                });
            }
            IdentityJob::Exec { pid, key } => {
                // Always re-hash: a cached hash is only as good as the class it produced, and
                // an Exec event means that class is gone.
                let Ok(permit) = hashers.clone().acquire_owned().await else {
                    break;
                };
                let (st, gate) = (state.clone(), gate.clone());
                tokio::spawn(async move {
                    let path = format!("/proc/{pid}/exe");
                    if let Err(e) = classify(&st, &gate, &path, Some(key)).await {
                        debug!(pid, error = %e, "could not classify executable");
                    }
                    drop(permit);
                });
            }
        }
    }
}

/// The classification protocol (see `ExeClass`): report, refuse open writers, hash the kept
/// fd outside the state lock, commit with `BPF_EXIST`.
async fn classify(
    state: &Arc<Mutex<Daemon>>,
    gate: &tokio::sync::Mutex<()>,
    path: &str,
    expect: Option<ExeKey>,
) -> Result<()> {
    // Register the waiter, then arm + open + disarm on a blocking thread WITHOUT the state
    // lock: an open can block (e.g. a hung filesystem) and must not stall the whole daemon.
    let (nonce, rx) = {
        let mut st = state
            .lock()
            .map_err(|_| anyhow::anyhow!("state poisoned"))?;
        let nonce = st.take_nonce();
        let (tx, rx) = tokio::sync::oneshot::channel();
        st.key_waiters.insert(nonce, tx);
        (nonce, rx)
    };
    let give_up = |why: String| {
        if let Ok(mut st) = state.lock() {
            st.key_waiters.remove(&nonce);
            if let Ok(k) = st.k() {
                let _ = k.disarm_key_req(nonce);
            }
            if let Some(key) = expect {
                st.abandon_classification(key, nonce);
            }
        }
        anyhow::anyhow!("{path}: {why}")
    };
    let opened = {
        // Spawned under the gate: spawn_blocking starts running immediately.
        let _one_request_at_a_time = gate.lock().await;
        // A timed-out opener stays stuck in its blocking thread; cap them so a hung filesystem
        // cannot exhaust the blocking pool.
        if STUCK_OPENERS.load(Ordering::Relaxed) >= MAX_STUCK_OPENERS {
            drop(_one_request_at_a_time);
            return Err(give_up("too many hung opens; not classifying".into()));
        }
        let opener = {
            let (st, path) = (state.clone(), path.to_owned());
            STUCK_OPENERS.fetch_add(1, Ordering::Relaxed);
            tokio::task::spawn_blocking(move || -> Result<std::fs::File> {
                struct Done;
                impl Drop for Done {
                    fn drop(&mut self) {
                        STUCK_OPENERS.fetch_sub(1, Ordering::Relaxed);
                    }
                }
                let _done = Done;
                let tid = nix::unistd::gettid().as_raw() as u32;
                st.lock()
                    .map_err(|_| anyhow::anyhow!("state poisoned"))?
                    .k()?
                    .set_key_req(nonce, tid)?;
                let f = std::fs::File::open(&path);
                if let Ok(mut s) = st.lock()
                    && let Ok(k) = s.k()
                {
                    let _ = k.disarm_key_req(nonce);
                }
                Ok(f?)
            })
        };
        tokio::time::timeout(OPEN_TIMEOUT, opener).await
    };
    let file = match opened {
        Ok(Ok(Ok(f))) => f,
        Ok(Ok(Err(e))) => return Err(give_up(format!("{e:#}"))),
        Ok(Err(e)) => return Err(give_up(e.to_string())),
        Err(_) => return Err(give_up("open timed out".into())),
    };
    let rep = match tokio::time::timeout(REPORT_TIMEOUT, rx).await {
        Ok(Ok(rep)) => rep,
        _ => return Err(give_up("no key report (LSM not attached?)".into())),
    };
    let abandon = |why: &str| {
        if let Ok(mut st) = state.lock() {
            st.abandon_classification(rep.key, rep.nonce);
        }
        anyhow::anyhow!("{path}: {why}")
    };
    if expect.is_some_and(|k| k != rep.key) {
        return Err(abandon("now a different inode than the one that ran"));
    }
    if rep.untrusted_fs {
        return Err(abandon(
            "filesystem cannot be vouched for (memfd, FUSE, network, overlay); left unclassified",
        ));
    }
    if rep.writers {
        return Err(abandon(
            "open for write by another process; left unclassified",
        ));
    }
    let hashed = tokio::task::spawn_blocking(move || {
        let mut file = file;
        daemon::hash_file(&mut file).map(|info| (info, file))
    })
    .await
    .map_err(anyhow::Error::from)
    .and_then(|r| r);
    let (info, file) = match hashed {
        Ok(x) => x,
        Err(e) => return Err(abandon(&e.to_string())),
    };
    let exe = info.path.clone();
    let mut st = state
        .lock()
        .map_err(|_| anyhow::anyhow!("state poisoned"))?;
    if st.commit_classification(rep.key, info, rep.nonce)? {
        debug!(exe, ino = rep.key.ino, "classified");
        if expect.is_none() {
            st.pinned.insert(path.to_owned(), file); // policy-named: keep the inode alive
        }
    } else {
        warn!(exe, "modified while being hashed; left unclassified");
    }
    Ok(())
}
