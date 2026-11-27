//! L7 gateway redirect, user-space half (kernel half: `bpf/gw_redirect.c` + `kv_gw_take` in
//! `bpf/lsm_egress.c`).
//!
//! * [`kernel_cfg`] turns `[gateway]` into the `gw_cfg` map value (listeners, exemptions).
//! * [`Heartbeat`] renews the `gw_cfg` liveness deadline while something listens on the
//!   configured address. A dead or absent gateway lets the deadline lapse within
//!   [`HORIZON`], after which punts resolve through their fail mode again (as before v0.4), so
//!   a fail-open rule never turns into "connection refused" because the proxy is down.
//! * [`PinnedOrigDst`] implements [`kavach_gateway::OrigDst`] over the pinned `orig_dst`
//!   map, and records the gateway's connection-level verdict ([`PinnedOrigDst::record_verdict`]).
//!
//! # Verdict write-back semantics
//! Every JSON-RPC frame is enforced in-path by the proxy (forward, refuse, close). Its decision
//! is also written back to the kernel `flow_cache` (FR-GW-5):
//! [`PinnedOrigDst`] recovers the punting record from `orig_dst`, and
//! [`write_decision_verdict`] calls [`crate::kernel::Kernel::write_flow_verdict`] from the
//! daemon's decision task. Both the forward and reply 5-tuples of the original (pre-redirect)
//! connection are seeded with `l7_verdict`, `l7_generation` and `l7_rule_id`, so TC egress and
//! TC ingress can drop a denied flow in O(1) without asking user space again. TC honours the
//! L7 verdict only while its generation matches the active policy (FR-HS-4); a swap makes
//! stale entries misses and they are re-judged at L3/L4.
//!
//! The client leg still runs over loopback and the upstream leg still belongs to the gateway's
//! exempt identity: the write-back is what makes the L7 decision visible to TC on the original
//! client flow, which is the flow the agent's packets actually use. `record_verdict` keeps its
//! informational `KV_PUNT_F_DECIDED` update of `orig_dst` for observability; it lives only as
//! long as that connection.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use aya::maps::{Array, HashMap, MapData, MapError};
use kavach_common::abi::*;
use kavach_common::addr::{from_mapped, from_words, to_mapped, to_words};
use kavach_gateway::{
    Decision, DecisionEvent, EventSink, OrigDst, OrigInfo, PolicySource, ToolPolicy,
};
use tracing::{info, warn};

use crate::config::GatewayConfig;
use crate::gateway_policies::{GatewayPolicies, GatewaySnapshot};
use crate::kernel::Kernel;

/// How often the heartbeat checks the listener and renews the deadline.
pub const TICK: Duration = Duration::from_secs(1);
/// How far ahead each renewal pushes the deadline (three missed ticks = gateway dead).
pub const HORIZON: Duration = Duration::from_secs(3);

/// Pinned `orig_dst` + `gw_cfg` handles (independent of the daemon lock).
pub struct GatewayMaps {
    pub(crate) orig: HashMap<MapData, OrigKey, PuntRecord>,
    pub(crate) cfg: Array<MapData, GatewayCfg>,
}

impl GatewayMaps {
    /// The `orig_dst` handle alone (for a [`PinnedOrigDst`] without a heartbeat).
    pub fn into_orig(self) -> HashMap<MapData, OrigKey, PuntRecord> {
        self.orig
    }
}

impl std::fmt::Debug for GatewayMaps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GatewayMaps")
    }
}

// ---------------------------------------------------------------------------------------------
// Pure helpers (unit-tested)
// ---------------------------------------------------------------------------------------------

/// `orig_dst` key for an accepted connection (`peer` = client, `local` = the gateway's side).
pub fn orig_key(peer: SocketAddr, local: SocketAddr) -> OrigKey {
    OrigKey {
        client: to_words(to_mapped(peer.ip())),
        gateway: to_words(to_mapped(local.ip())),
        client_port: peer.port().to_be(),
        gateway_port: local.port().to_be(),
    }
}

/// Decode an `orig_dst` record. The gateway name comes from the active bundle's gateway
/// policies (rule id -> `[gateway.<name>]`); empty when that rule names none in the active
/// policy (e.g. the policy changed since the connect): the proxy must then refuse the flow.
pub fn orig_info(r: &PuntRecord, gateways: &GatewaySnapshot) -> OrigInfo {
    OrigInfo {
        dst: SocketAddr::new(from_mapped(from_words(r.dst)), u16::from_be(r.dport)),
        rule_id: r.rule_id,
        gateway: gateways.rules.get(&r.rule_id).cloned().unwrap_or_default(),
        cgroup_id: r.cgroup_id,
        pid: r.pid,
    }
}

/// The `gw_cfg` value for `[gateway]`, with no liveness yet (`alive_until_ns = 0`, no flags:
/// the heartbeat sets both once a listener is up).
pub fn kernel_cfg(g: &GatewayConfig, exempt_tgid: u32, exempt_cgroup: u64) -> GatewayCfg {
    let mut c = GatewayCfg {
        exempt_tgid,
        exempt_cgroup,
        ..Default::default()
    };
    if let SocketAddr::V4(a) = g.listen {
        c.listen4 = u32::from_ne_bytes(a.ip().octets());
        c.listen4_port = a.port().to_be();
    }
    if let Some(SocketAddr::V6(a)) = g.listen6 {
        c.listen6 = to_words(a.ip().octets());
        c.listen6_port = a.port().to_be();
    }
    c
}

/// cgroup v2 id of a cgroup directory (the kernfs inode number, as `bpf_get_current_cgroup_id`
/// reports it).
pub fn cgroup_id(dir: &Path) -> io::Result<u64> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(dir)?;
    if !m.is_dir() {
        return Err(io::Error::other(format!(
            "{} is not a directory",
            dir.display()
        )));
    }
    Ok(m.ino())
}

/// Mount point of the unified (cgroup2) hierarchy in `/proc/self/mounts` text.
pub fn cgroup2_root(mounts: &str) -> Option<PathBuf> {
    mounts.lines().find_map(|l| {
        let mut f = l.split_whitespace();
        let (_, dir, fstype) = (f.next()?, f.next()?, f.next()?);
        (fstype == "cgroup2").then(|| PathBuf::from(dir))
    })
}

fn proc_hex_v4(ip: Ipv4Addr) -> String {
    format!("{:08X}", u32::from_ne_bytes(ip.octets()))
}

fn proc_hex_v6(ip: Ipv6Addr) -> String {
    to_words(ip.octets())
        .iter()
        .map(|w| format!("{w:08X}"))
        .collect()
}

/// Is a TCP socket listening on `addr` (or the wildcard of its family, or the dual-stack `::`)
/// according to `/proc/net/tcp` (`tcp`) and `/proc/net/tcp6` (`tcp6`) text?
pub fn listener_present(addr: SocketAddr, tcp: &str, tcp6: &str) -> bool {
    let port = format!("{:04X}", addr.port());
    let listening = |text: &str, ips: &[String]| {
        text.lines().skip(1).any(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            f.len() > 3
                && f[3] == "0A"
                && f[1]
                    .rsplit_once(':')
                    .is_some_and(|(ip, p)| p == port && ips.iter().any(|i| i == ip))
        })
    };
    let any6 = proc_hex_v6(Ipv6Addr::UNSPECIFIED);
    match addr.ip() {
        IpAddr::V4(ip) => {
            listening(tcp, &[proc_hex_v4(ip), proc_hex_v4(Ipv4Addr::UNSPECIFIED)])
                || listening(tcp6, &[proc_hex_v6(ip.to_ipv6_mapped()), any6.clone()])
        }
        IpAddr::V6(ip) => listening(tcp6, &[proc_hex_v6(ip), any6]),
    }
}

fn listening_now(addr: SocketAddr) -> bool {
    let tcp = std::fs::read_to_string("/proc/net/tcp").unwrap_or_default();
    let tcp6 = std::fs::read_to_string("/proc/net/tcp6").unwrap_or_default();
    listener_present(addr, &tcp, &tcp6)
}

/// Listener flags (`KV_GW_F_*`) given which configured listeners are up.
pub fn live_flags(v4_up: bool, v6_configured: bool, v6_up: bool) -> u32 {
    let mut f = 0;
    if v4_up {
        f |= KV_GW_F_V4;
    }
    if v6_configured && v6_up {
        f |= KV_GW_F_V6;
    }
    f
}

// ---------------------------------------------------------------------------------------------
// OrigDst over the pinned map
// ---------------------------------------------------------------------------------------------

/// [`OrigDst`] backed by the pinned `orig_dst` map. Gateway names come from the
/// [`GatewayPolicies`] handle kavachd publishes every applied bundle to.
pub struct PinnedOrigDst {
    orig: Mutex<HashMap<MapData, OrigKey, PuntRecord>>,
    gateways: GatewayPolicies,
}

impl std::fmt::Debug for PinnedOrigDst {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PinnedOrigDst")
    }
}

impl PinnedOrigDst {
    pub fn new(orig: HashMap<MapData, OrigKey, PuntRecord>, gateways: GatewayPolicies) -> Self {
        Self {
            orig: Mutex::new(orig),
            gateways,
        }
    }

    /// The raw record for an accepted connection.
    pub fn record(&self, peer: SocketAddr, local: SocketAddr) -> Option<PuntRecord> {
        let m = self.orig.lock().ok()?;
        m.get(&orig_key(peer, local), 0).ok()
    }

    /// Find the `orig_dst` record from what a [`DecisionEvent`] carries: the client address
    /// (`peer`) and the original destination (`dst`). The gateway listener address is not part
    /// of the event, so the client side and the original destination identify the connection.
    pub fn record_for_peer(
        &self,
        peer: SocketAddr,
        dst: SocketAddr,
    ) -> Option<(OrigKey, PuntRecord)> {
        let m = self.orig.lock().ok()?;
        let client = to_words(to_mapped(peer.ip()));
        let client_port = peer.port().to_be();
        let want_dst = to_words(to_mapped(dst.ip()));
        let want_dport = dst.port().to_be();
        m.iter().find_map(|item| {
            let Ok((k, r)) = item else { return None };
            (k.client == client
                && k.client_port == client_port
                && r.dst == want_dst
                && r.dport == want_dport)
                .then_some((k, r))
        })
    }

    /// Record the gateway's connection-level verdict in `orig_dst` for observability. The
    /// kernel-enforced write-back is [`write_decision_verdict`]; this flag never changes what
    /// TC lets through. `Ok(false)` when the connection's entry is gone (closed).
    pub fn record_verdict(
        &self,
        peer: SocketAddr,
        local: SocketAddr,
        verdict: Verdict,
    ) -> io::Result<bool> {
        const BPF_EXIST: u64 = 2;
        let k = orig_key(peer, local);
        let mut m = self
            .orig
            .lock()
            .map_err(|_| io::Error::other("orig_dst lock poisoned"))?;
        let Ok(mut r) = m.get(&k, 0) else {
            return Ok(false);
        };
        r.flags |= KV_PUNT_F_DECIDED;
        r.verdict = verdict as u8;
        match m.insert(&k, &r, BPF_EXIST) {
            Ok(()) => Ok(true),
            Err(MapError::SyscallError(e)) if e.io_error.raw_os_error() == Some(libc_enoent()) => {
                Ok(false)
            }
            Err(MapError::SyscallError(e)) => Err(e.io_error),
            Err(e) => Err(io::Error::other(e.to_string())),
        }
    }
}

fn libc_enoent() -> i32 {
    nix::libc::ENOENT
}

impl OrigDst for PinnedOrigDst {
    fn lookup(&self, peer: SocketAddr, local: SocketAddr) -> Option<OrigInfo> {
        let r = self.record(peer, local)?;
        Some(orig_info(&r, &self.gateways.snapshot()))
    }
}

// ---------------------------------------------------------------------------------------------
// Liveness heartbeat
// ---------------------------------------------------------------------------------------------

/// Renews `gw_cfg.alive_until_ns` every [`TICK`] while the configured listener is up; on stop
/// (or drop) it zeroes the deadline so punts fall back to their fail mode at once.
#[derive(Debug)]
pub struct Heartbeat {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Heartbeat {
    pub fn start(
        mut cfg_map: Array<MapData, GatewayCfg>,
        base: GatewayCfg,
        listen: SocketAddr,
        listen6: Option<SocketAddr>,
    ) -> io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let s = stop.clone();
        let thread = std::thread::Builder::new()
            .name("kv-gw-heartbeat".into())
            .spawn(move || {
                let mut was_live = None;
                while !s.load(Ordering::Relaxed) {
                    let v4 = listening_now(listen);
                    let v6 = listen6.is_some_and(listening_now);
                    let flags = live_flags(v4, listen6.is_some(), v6);
                    let mut c = base;
                    c.flags = flags;
                    c.alive_until_ns = if flags != 0 {
                        crate::kernel::boot_ns() + HORIZON.as_nanos() as u64
                    } else {
                        0
                    };
                    if let Err(e) = cfg_map.set(0, &c, 0) {
                        // A failed renew lets the deadline lapse: the safe direction.
                        warn!(error = %e, "gateway heartbeat: gw_cfg update failed");
                    }
                    let live = flags != 0;
                    if was_live != Some(live) {
                        if live {
                            info!(%listen, ?listen6, "L7 gateway listener up: punted TCP connects are redirected");
                        } else {
                            warn!(%listen, "L7 gateway listener not up: punts use their rule's fail mode");
                        }
                        was_live = Some(live);
                    }
                    std::thread::sleep(TICK);
                }
                let mut c = base;
                c.alive_until_ns = 0;
                c.flags = 0;
                let _ = cfg_map.set(0, &c, 0);
            })?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }

    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for Heartbeat {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// A running gateway redirect: hand [`Gateway::orig`] to the proxy.
#[derive(Debug)]
pub struct Gateway {
    pub orig: Arc<PinnedOrigDst>,
    pub heartbeat: Heartbeat,
}

/// Bring the redirect up for `[gateway] enabled = true`. Order: `gw_cfg` with no liveness
/// (punts keep using their fail mode), then the cgroup programs, then the heartbeat, which
/// turns redirection on only once the listener is up. Nothing is left attached on failure.
/// `exempt_tgid` is the process hosting the proxy (kavachd itself).
pub fn start(
    k: &mut crate::kernel::Kernel,
    g: &GatewayConfig,
    exempt_tgid: u32,
    gateways: GatewayPolicies,
) -> anyhow::Result<Gateway> {
    use anyhow::{Context, bail};
    g.validate().map_err(anyhow::Error::msg)?;
    if !k.lsm {
        bail!("the gateway redirect needs the BPF-LSM egress hooks (they make the punt decision)");
    }
    let mounts = std::fs::read_to_string("/proc/self/mounts").unwrap_or_default();
    let root = cgroup2_root(&mounts).context("no cgroup v2 (unified) hierarchy mounted")?;
    let exempt_cgroup = match &g.exempt_cgroup {
        Some(p) => {
            cgroup_id(p).with_context(|| format!("gateway.exempt_cgroup {}", p.display()))?
        }
        None => 0,
    };
    let base = kernel_cfg(g, exempt_tgid, exempt_cgroup);
    let up = (|| -> anyhow::Result<Gateway> {
        k.set_gateway_cfg(base)?;
        k.attach_gateway(&root)?;
        let maps = k.gateway_maps()?;
        let heartbeat = Heartbeat::start(maps.cfg, base, g.listen, g.listen6)
            .context("spawning the gateway heartbeat")?;
        Ok(Gateway {
            orig: Arc::new(PinnedOrigDst::new(maps.orig, gateways)),
            heartbeat,
        })
    })();
    if up.is_err() {
        disable(k);
    }
    up
}

/// `[gateway] enabled = false` (or a failed start): no liveness, no redirect programs, so a
/// previous run leaves nothing behind and punts resolve through their fail mode.
pub fn disable(k: &mut crate::kernel::Kernel) {
    if let Err(e) = k.set_gateway_cfg(GatewayCfg::default()) {
        warn!(error = %format!("{e:#}"), "could not clear gw_cfg");
    }
    let n = k.detach_gateway();
    if n > 0 {
        info!(links = n, "gateway redirect programs detached");
    }
}

// ---------------------------------------------------------------------------------------------
// The in-process proxy
// ---------------------------------------------------------------------------------------------

/// [`PolicySource`] over the active bundle's gateway policies. A flow gets a policy only while
/// the rule that punted it still punts to that same gateway in the active bundle; otherwise
/// `None`, and the proxy denies every frame (fail closed at L7).
#[derive(Debug, Clone)]
pub struct BundlePolicies(pub GatewayPolicies);

impl PolicySource for BundlePolicies {
    fn policy_for(&self, info: &OrigInfo) -> Option<Arc<ToolPolicy>> {
        let snap = self.0.snapshot();
        if snap.rules.get(&info.rule_id) != Some(&info.gateway) {
            return None;
        }
        snap.policy(&info.gateway).cloned().map(Arc::new)
    }
}

/// Run the L7 proxy on `[gateway] listen` (and `listen6`, when set) until `shutdown`. The
/// heartbeat notices each listener once it is bound, and redirecting starts then (not before).
/// A `listen6` that cannot be bound (e.g. IPv6 disabled on `lo`) is logged and skipped: the
/// heartbeat then never reports it, and IPv6 sockets go to the IPv4-mapped `listen`.
pub async fn serve_proxy(
    g: &GatewayConfig,
    orig: Arc<PinnedOrigDst>,
    policies: GatewayPolicies,
    events: Arc<dyn EventSink>,
    shutdown: impl std::future::Future<Output = ()>,
) -> io::Result<()> {
    let policies: Arc<dyn PolicySource> = Arc::new(BundlePolicies(policies));
    let bind = |listen: SocketAddr| {
        let mut cfg = g.proxy.clone();
        cfg.listen = listen;
        kavach_gateway::Gateway::bind(cfg, orig.clone(), policies.clone(), events.clone())
    };
    let proxy = bind(g.listen).await?;
    info!(listen = %g.listen, "L7 gateway proxy listening");
    let proxy6 = match g.listen6 {
        Some(l6) => match bind(l6).await {
            Ok(p) => {
                info!(listen6 = %l6, "L7 gateway proxy listening (IPv6)");
                Some(p)
            }
            Err(e) => {
                warn!(listen6 = %l6, error = %e, "L7 gateway: cannot bind listen6; IPv6 sockets \
                      use the IPv4-mapped listen (IPV6_V6ONLY ones their fail mode)");
                None
            }
        },
        None => None,
    };
    // Dropping the accept loops on shutdown stops accepting; open connections finish on their
    // own (they run in tasks of their own), as with `serve_until`.
    let serve = async move {
        match proxy6 {
            Some(p6) => tokio::try_join!(proxy.serve(), p6.serve()).map(|_| ()),
            None => proxy.serve().await,
        }
    };
    tokio::select! {
        r = serve => r,
        _ = shutdown => Ok(()),
    }
}

/// Write one proxy decision to the kernel flow verdict cache (FR-GW-5). Called from the
/// daemon's decision task, which already holds the state lock, so the write cannot race with
/// policy swaps and the in-process proxy never takes that lock on its data path (it emits
/// into a channel). Returns `false` when the connection's `orig_dst` entry is already gone.
pub fn write_decision_verdict(
    kernel: &mut Kernel,
    orig: &PinnedOrigDst,
    ev: &DecisionEvent,
) -> bool {
    let Some((k, r)) = orig.record_for_peer(ev.peer, ev.dst) else {
        return false;
    };
    let verdict = decision_verdict(ev.decision);
    // Keep the informational, connection-scoped update too (nothing regresses).
    let local = SocketAddr::new(
        from_mapped(from_words(r.target)),
        u16::from_be(r.target_port),
    );
    if let Err(e) = orig.record_verdict(ev.peer, local, verdict) {
        warn!(error = %e, "could not record L7 verdict in orig_dst");
    }
    if let Err(e) = kernel.write_flow_verdict(&r, &k, verdict) {
        warn!(
            error = %format!("{e:#}"),
            "could not write L7 verdict to flow_cache"
        );
    }
    true
}

fn decision_verdict(decision: Decision) -> Verdict {
    match decision {
        Decision::Allow => Verdict::Allow,
        Decision::Deny => Verdict::Drop,
    }
}

/// Which gateway decisions go to the audit log: every deny, and allows up to `allows_per_sec`
/// per second (the rest are counted).
#[derive(Debug)]
pub struct AuditThrottle {
    window: std::time::Instant,
    allows: u32,
    allows_per_sec: u32,
    pub skipped: u64,
}

impl AuditThrottle {
    pub fn new(allows_per_sec: u32) -> Self {
        Self {
            window: std::time::Instant::now(),
            allows: 0,
            allows_per_sec,
            skipped: 0,
        }
    }

    pub fn admit(&mut self, ev: &DecisionEvent) -> bool {
        if ev.decision == Decision::Deny {
            return true;
        }
        if self.window.elapsed() >= Duration::from_secs(1) {
            self.window = std::time::Instant::now();
            self.allows = 0;
        }
        if self.allows < self.allows_per_sec {
            self.allows += 1;
            true
        } else {
            self.skipped += 1;
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orig_key_is_the_kernel_layout() {
        let k = orig_key(
            "127.0.0.1:40000".parse().unwrap(),
            "127.0.0.1:15001".parse().unwrap(),
        );
        let b = from_words(k.client);
        assert_eq!(&b[..12], &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]);
        assert_eq!(&b[12..], &[127, 0, 0, 1]);
        // network order in memory
        assert_eq!(k.client_port.to_ne_bytes(), 40000u16.to_be_bytes());
        assert_eq!(k.gateway_port.to_ne_bytes(), 15001u16.to_be_bytes());
        // a dual-stack gateway socket reports mapped peers: same key
        let k6 = orig_key(
            "[::ffff:127.0.0.1]:40000".parse().unwrap(),
            "[::ffff:127.0.0.1]:15001".parse().unwrap(),
        );
        assert_eq!(k, k6);
    }

    #[test]
    fn records_decode_and_gateways_resolve_by_rule() {
        let src = r#"
version = 1
[gateway.mcp]
allow_tools = ["search"]
[[rule]]
id = "mcp"
punt = { to = "93.184.216.0/24", port = 443, proto = "tcp", gateway = "mcp" }
"#;
        let p = kavach_policy::compile(src, 0).unwrap().policy;
        let h = GatewayPolicies::new();
        h.publish(&p, 1);
        let snap = h.snapshot();
        let r = PuntRecord {
            cgroup_id: 77,
            dst: to_words(to_mapped("93.184.216.34".parse().unwrap())),
            dport: 443u16.to_be(),
            rule_id: 1,
            pid: 1234,
            gateway: 1,
            ..Default::default()
        };
        let i = orig_info(&r, &snap);
        assert_eq!(i.dst, "93.184.216.34:443".parse().unwrap());
        assert_eq!((i.rule_id, i.cgroup_id, i.pid), (1, 77, 1234));
        assert_eq!(i.gateway, "mcp");
        // a rule the active policy does not punt to a gateway: no name, the proxy refuses
        let stale = PuntRecord { rule_id: 9, ..r };
        assert_eq!(orig_info(&stale, &snap).gateway, "");
        let v6 = PuntRecord {
            dst: to_words("2001:db8::1".parse::<Ipv6Addr>().unwrap().octets()),
            dport: 8443u16.to_be(),
            ..Default::default()
        };
        assert_eq!(
            orig_info(&v6, &GatewaySnapshot::default()).dst,
            "[2001:db8::1]:8443".parse().unwrap()
        );
    }

    #[test]
    fn bundle_policies_follow_the_active_bundle() {
        let src = r#"
version = 1
[gateway.mcp]
allow_tools = ["search"]
[gateway.other]
allow_tools = ["*"]
[[rule]]
id = "mcp"
punt = { to = "198.51.100.0/24", port = 443, proto = "tcp", gateway = "mcp" }
[[rule]]
id = "other"
punt = { to = "203.0.113.0/24", port = 443, proto = "tcp", gateway = "other" }
"#;
        let h = GatewayPolicies::new();
        let src_ = BundlePolicies(h.clone());
        let info = |rule_id: u32, gw: &str| OrigInfo {
            dst: "198.51.100.1:443".parse().unwrap(),
            rule_id,
            gateway: gw.into(),
            cgroup_id: 1,
            pid: 1,
        };
        assert!(src_.policy_for(&info(1, "mcp")).is_none(), "no bundle yet");
        h.publish(&kavach_policy::compile(src, 0).unwrap().policy, 1);
        let p = src_
            .policy_for(&info(1, "mcp"))
            .expect("rule 1 punts to mcp");
        assert_eq!(p.allow_tools, ["search"]);
        assert!(
            src_.policy_for(&info(1, "other")).is_none(),
            "a record naming another gateway than its rule gets nothing"
        );
        assert!(src_.policy_for(&info(1, "")).is_none());
        assert!(src_.policy_for(&info(7, "mcp")).is_none());
    }

    #[test]
    fn decisions_map_to_kernel_verdicts() {
        assert_eq!(decision_verdict(Decision::Allow), Verdict::Allow);
        assert_eq!(decision_verdict(Decision::Deny), Verdict::Drop);
    }

    #[test]
    fn audit_keeps_every_deny_and_samples_allows() {
        let ev = |decision| DecisionEvent {
            gateway: "mcp".into(),
            rule_id: 1,
            pid: 1,
            cgroup_id: 1,
            peer: "127.0.0.1:1".parse().unwrap(),
            dst: "198.51.100.1:443".parse().unwrap(),
            protocol: kavach_gateway::proxy::Protocol::Http,
            method: None,
            target: None,
            decision,
            reason: kavach_gateway::proxy::Reason::Policy,
        };
        let mut t = AuditThrottle::new(2);
        let allows = (0..5).filter(|_| t.admit(&ev(Decision::Allow))).count();
        assert_eq!((allows, t.skipped), (2, 3));
        assert!((0..100).all(|_| t.admit(&ev(Decision::Deny))));
    }

    #[test]
    fn kernel_cfg_encodes_listeners() {
        let g = GatewayConfig {
            enabled: true,
            listen6: Some("[::1]:15002".parse().unwrap()),
            ..Default::default()
        };
        let c = kernel_cfg(&g, 42, 7);
        assert_eq!(c.listen4.to_ne_bytes(), [127, 0, 0, 1]);
        assert_eq!(c.listen4_port, 15001u16.to_be());
        assert_eq!(from_words(c.listen6), Ipv6Addr::LOCALHOST.octets());
        assert_eq!(c.listen6_port, 15002u16.to_be());
        assert_eq!((c.exempt_tgid, c.exempt_cgroup), (42, 7));
        assert_eq!(
            (c.alive_until_ns, c.flags),
            (0, 0),
            "liveness is the heartbeat's job"
        );
        assert_eq!(live_flags(true, false, false), KV_GW_F_V4);
        assert_eq!(live_flags(true, true, false), KV_GW_F_V4);
        assert_eq!(live_flags(false, true, true), KV_GW_F_V6);
        assert_eq!(live_flags(false, false, true), 0);
    }

    #[test]
    fn finds_listeners_in_proc_net_tcp() {
        let tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100007F:3A99 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0 10 0\n\
   1: 0100007F:3A9A 0100007F:9C40 01 00000000:00000000 00:00000000 00000000     0        0 2 1 0 10 0\n";
        let tcp6 = "  sl  local_address                         remote_address                        st\n\
   0: 00000000000000000000000001000000:3A9B 00000000000000000000000000000000:0000 0A 0\n\
   1: 00000000000000000000000000000000:3A9C 00000000000000000000000000000000:0000 0A 0\n";
        let a = |s: &str| s.parse::<SocketAddr>().unwrap();
        assert!(listener_present(a("127.0.0.1:15001"), tcp, tcp6));
        assert!(
            !listener_present(a("127.0.0.1:15002"), tcp, tcp6),
            "established, not listening"
        );
        assert!(listener_present(a("[::1]:15003"), tcp, tcp6));
        assert!(!listener_present(a("[::1]:15001"), tcp, tcp6));
        // [::]:15004 is dual-stack: serves 127.0.0.1 and ::1
        assert!(listener_present(a("127.0.0.1:15004"), tcp, tcp6));
        assert!(listener_present(a("[::1]:15004"), tcp, tcp6));
        assert!(!listener_present(a("127.0.0.1:15001"), "", ""));
    }

    #[test]
    fn sees_a_real_listener() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        assert!(listening_now(addr));
        drop(l);
        assert!(!listening_now(addr));
    }

    #[test]
    fn finds_the_cgroup2_mount() {
        let m = "sysfs /sys sysfs rw 0 0\ncgroup2 /sys/fs/cgroup cgroup2 rw,nosuid 0 0\n";
        assert_eq!(cgroup2_root(m), Some(PathBuf::from("/sys/fs/cgroup")));
        assert_eq!(cgroup2_root("tmpfs /run tmpfs rw 0 0\n"), None);
    }
}
