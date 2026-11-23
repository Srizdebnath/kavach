//! Optional AF_XDP RX backend: the XDP fast path redirects frames of gateway-selected
//! `(proto, port)` pairs straight to a user-space socket per RX queue, skipping the kernel stack.
//!
//! **Never the default.** A redirected queue depends on this process: if the consumer stops
//! returning buffers, the queue's selected flows stall. So:
//! * only frames matching `xsk_ports` are redirected; everything else (SSH included) passes;
//! * the [`Watchdog`] unsets the queue's `xsk_sockets` entry when the fill ring has not advanced
//!   for `watchdog_ms` while frames wait on the RX ring, and re-arms it once the consumer
//!   shows progress again;
//! * the watchdog also renews a per-queue `xsk_alive` deadline in BPF; if this whole process
//!   freezes, the XDP program stops redirecting by itself within one period;
//! * a closed socket (crash, exit) is removed from `xsk_sockets` by the kernel.
//!
//! Bind modes are negotiated per queue, best first: [`BindMode::ZeroCopy`] (driver support:
//! ice, i40e, ixgbe, igc, mlx5, ...), then [`BindMode::Copy`], and [`BindMode::Skb`] when the
//! XDP program itself runs in generic (SKB) mode. See [`negotiate`].

mod ring;
mod socket;
mod sys;

use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use kavach_common::abi::{KV_PROTO_TCP, KV_PROTO_UDP, KV_XSK_MAX_PORTS, KV_XSK_MAX_QUEUES};
use serde::Deserialize;
use tracing::{error, info, warn};

pub use ring::{ConsRing, ProdRing, RingProbe};
pub use socket::{
    FrameHandler, ProbeSample, QueueProbe, RxAction, SockFd, SocketParams, SocketStats, XskSocket,
};
pub use sys::{
    LinuxSys, MmapOffsets, Region, RingOffset, SockaddrXdp, Sys, Umem, UmemReg, XDP_COPY,
    XDP_USE_NEED_WAKEUP, XDP_ZEROCOPY, XdpDesc, XdpStatistics,
};

// ---------------------------------------------------------------------------------------------
// Configuration: `[gateway.afxdp]`
// ---------------------------------------------------------------------------------------------

/// `[gateway.afxdp]` in kavachd.toml.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AfXdpConfig {
    /// Off unless explicitly enabled.
    pub enabled: bool,
    /// Interface whose RX queues are served (must have the Kavach XDP program attached).
    pub iface: String,
    /// RX queue ids to bind (opt-in per queue).
    pub queues: Vec<u32>,
    /// Destination ports to redirect: `8443` (TCP), `"8443/tcp"` or `"443/udp"`.
    pub ports: Vec<PortSpec>,
    /// Detach a queue whose fill ring has not advanced for this long while work is pending.
    pub watchdog_ms: u64,
    /// Entries per ring (power of two, 64..=16384). The UMEM holds twice as many frames.
    pub ring_size: u32,
    /// UMEM frame size: 2048 or 4096.
    pub frame_size: u32,
}

impl Default for AfXdpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            iface: String::new(),
            queues: Vec::new(),
            ports: Vec::new(),
            watchdog_ms: 250,
            ring_size: 2048,
            frame_size: 4096,
        }
    }
}

/// One redirected `(proto, destination port)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "RawPort")]
pub struct PortSpec {
    /// `KV_PROTO_TCP` or `KV_PROTO_UDP`.
    pub proto: u8,
    /// Host byte order.
    pub port: u16,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawPort {
    Num(u16),
    Str(String),
}

impl TryFrom<RawPort> for PortSpec {
    type Error = String;
    fn try_from(r: RawPort) -> Result<Self, String> {
        match r {
            RawPort::Num(port) => Ok(Self {
                proto: KV_PROTO_TCP,
                port,
            }),
            RawPort::Str(s) => s.parse(),
        }
    }
}

impl std::str::FromStr for PortSpec {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let (p, proto) = match s.split_once('/') {
            Some((p, "tcp")) => (p, KV_PROTO_TCP),
            Some((p, "udp")) => (p, KV_PROTO_UDP),
            Some((_, other)) => return Err(format!("unknown protocol {other:?} in {s:?}")),
            None => (s, KV_PROTO_TCP),
        };
        let port = p
            .parse::<u16>()
            .map_err(|_| format!("bad port {p:?} in {s:?}"))?;
        Ok(Self { proto, port })
    }
}

impl fmt::Display for PortSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let p = if self.proto == KV_PROTO_UDP {
            "udp"
        } else {
            "tcp"
        };
        write!(f, "{}/{p}", self.port)
    }
}

impl PortSpec {
    /// The `xsk_ports` map key.
    pub fn key(&self) -> u32 {
        kavach_common::abi::xsk_port_key(self.proto, self.port)
    }
}

impl AfXdpConfig {
    /// Check an enabled configuration (a disabled one is always valid).
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self.iface.is_empty() {
            return Err("gateway.afxdp.iface is required".into());
        }
        if self.queues.is_empty() {
            return Err("gateway.afxdp.queues must list at least one RX queue".into());
        }
        let mut seen = BTreeSet::new();
        for q in &self.queues {
            if *q >= KV_XSK_MAX_QUEUES {
                return Err(format!(
                    "gateway.afxdp.queues: {q} is >= {KV_XSK_MAX_QUEUES}"
                ));
            }
            if !seen.insert(*q) {
                return Err(format!("gateway.afxdp.queues: {q} listed twice"));
            }
        }
        if self.ports.is_empty() {
            return Err("gateway.afxdp.ports must list at least one port".into());
        }
        if self.ports.len() > KV_XSK_MAX_PORTS as usize {
            return Err(format!(
                "gateway.afxdp.ports: at most {KV_XSK_MAX_PORTS} entries"
            ));
        }
        for p in &self.ports {
            if p.port == 0 {
                return Err("gateway.afxdp.ports: port 0".into());
            }
            if p.proto == KV_PROTO_TCP && p.port == 22 {
                return Err(
                    "gateway.afxdp.ports: refusing to redirect 22/tcp (SSH must stay on the \
                     kernel stack)"
                        .into(),
                );
            }
        }
        if !(10..=10_000).contains(&self.watchdog_ms) {
            return Err("gateway.afxdp.watchdog_ms must be within 10..=10000".into());
        }
        if !self.ring_size.is_power_of_two() || !(64..=16384).contains(&self.ring_size) {
            return Err("gateway.afxdp.ring_size must be a power of two in 64..=16384".into());
        }
        if self.frame_size != 2048 && self.frame_size != 4096 {
            return Err("gateway.afxdp.frame_size must be 2048 or 4096".into());
        }
        Ok(())
    }

    /// `xsk_ports` keys for [`Self::ports`].
    pub fn port_keys(&self) -> Vec<u32> {
        let mut v: Vec<u32> = self.ports.iter().map(PortSpec::key).collect();
        v.sort_unstable();
        v.dedup();
        v
    }
}

// ---------------------------------------------------------------------------------------------
// Bind-mode negotiation
// ---------------------------------------------------------------------------------------------

/// How the Kavach XDP program is attached to the interface (decides which bind modes exist).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpAttach {
    /// Driver (native) XDP: zero-copy is possible if the driver supports it.
    Native,
    /// Generic (SKB) XDP: frames are already `sk_buff`s; only copy mode makes sense.
    Generic,
    /// Not known (e.g. the program was replaced in place on an existing link): try everything.
    Unknown,
}

impl XdpAttach {
    /// From the label `Kernel::attach_xdp` returns (`native`, `generic`, `replaced`).
    pub fn from_label(s: &str) -> Self {
        match s {
            "native" => Self::Native,
            "generic" => Self::Generic,
            _ => Self::Unknown,
        }
    }
}

/// The mode an AF_XDP socket ended up in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindMode {
    /// `XDP_ZEROCOPY`: the NIC DMAs straight into the UMEM.
    ZeroCopy,
    /// `XDP_COPY` with driver XDP: one copy into the UMEM.
    Copy,
    /// `XDP_COPY` behind generic (SKB) XDP: works on any interface, slowest.
    Skb,
}

impl BindMode {
    /// `sxdp_flags` for this mode.
    pub fn bind_flags(self) -> u16 {
        match self {
            Self::ZeroCopy => XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP,
            Self::Copy | Self::Skb => XDP_COPY | XDP_USE_NEED_WAKEUP,
        }
    }
}

impl fmt::Display for BindMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ZeroCopy => "zerocopy",
            Self::Copy => "copy",
            Self::Skb => "skb",
        })
    }
}

/// Modes to try, best first.
pub fn ladder(attach: XdpAttach) -> &'static [BindMode] {
    match attach {
        XdpAttach::Native | XdpAttach::Unknown => &[BindMode::ZeroCopy, BindMode::Copy],
        XdpAttach::Generic => &[BindMode::Skb],
    }
}

/// Errors that mean "this mode is not available here, try the next one". Anything else (queue
/// busy, no such device, no permission) would fail the same way in every mode.
pub fn is_fallback_error(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::EOPNOTSUPP | libc::EINVAL | libc::EPROTONOSUPPORT | libc::EAFNOSUPPORT)
    )
}

/// Every bind attempt failed.
#[derive(Debug)]
pub struct NegotiateError {
    /// Interface name.
    pub iface: String,
    /// Queue id.
    pub queue: u32,
    /// Each attempted mode and its error, in order.
    pub attempts: Vec<(BindMode, io::Error)>,
    /// How the XDP program was attached.
    pub attach: XdpAttach,
}

impl fmt::Display for NegotiateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AF_XDP bind on {} queue {} failed:",
            self.iface, self.queue
        )?;
        for (m, e) in &self.attempts {
            write!(f, " {m}: {e};")?;
        }
        match self.attempts.last() {
            Some((_, e)) if !is_fallback_error(e) => {
                write!(f, " (not a mode problem: no further modes tried)")
            }
            _ if self.attach != XdpAttach::Generic => write!(
                f,
                " (set xdp_mode = \"skb\" to attach XDP in generic mode for an SKB-mode socket)"
            ),
            _ => Ok(()),
        }
    }
}

impl std::error::Error for NegotiateError {}

/// Walk the [`ladder`] for `attach`, calling `try_bind` for each mode until one succeeds.
/// Falls back only on [`is_fallback_error`]; logs every step.
pub fn negotiate<T>(
    iface: &str,
    queue: u32,
    attach: XdpAttach,
    mut try_bind: impl FnMut(BindMode) -> io::Result<T>,
) -> Result<(BindMode, T), NegotiateError> {
    let mut attempts = Vec::new();
    for &mode in ladder(attach) {
        match try_bind(mode) {
            Ok(t) => {
                if attempts.is_empty() {
                    info!(iface, queue, %mode, "AF_XDP socket bound");
                } else {
                    info!(iface, queue, %mode, after = attempts.len(), "AF_XDP socket bound after fallback");
                }
                return Ok((mode, t));
            }
            Err(e) => {
                let fall = is_fallback_error(&e);
                warn!(iface, queue, %mode, error = %e, fallback = fall, "AF_XDP bind failed");
                attempts.push((mode, e));
                if !fall {
                    break;
                }
            }
        }
    }
    Err(NegotiateError {
        iface: iface.to_owned(),
        queue,
        attempts,
        attach,
    })
}

// ---------------------------------------------------------------------------------------------
// Watchdog
// ---------------------------------------------------------------------------------------------

/// What the watchdog wants done for one queue after a sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogAction {
    /// Healthy: extend the `xsk_alive` deadline.
    Renew,
    /// Stalled: unset the queue's `xsk_sockets` entry and expire its deadline.
    Detach,
    /// Recovered: set the socket again and renew.
    Reattach,
    /// Still detached; nothing to do.
    Hold,
}

/// Per-queue stall detector. "Progress" is the consumer moving the fill producer (returning
/// buffers) or the RX consumer (reading frames). An idle queue is not stalled: the timer only
/// runs while the RX ring holds unread frames. (An empty fill ring alone is not a stall:
/// zero-copy drivers move every fill buffer into their hardware ring while idle.)
#[derive(Debug, Clone)]
pub struct Watchdog {
    stall_ns: u64,
    last_fill_prod: u32,
    last_rx_cons: u32,
    last_ok_ns: u64,
    detached: bool,
}

impl Watchdog {
    /// Start watching from `sample` at `now_ns`.
    pub fn new(stall_ms: u64, now_ns: u64, sample: ProbeSample) -> Self {
        Self {
            stall_ns: stall_ms.saturating_mul(1_000_000),
            last_fill_prod: sample.fill_prod,
            last_rx_cons: sample.rx_cons,
            last_ok_ns: now_ns,
            detached: false,
        }
    }

    /// True while the queue is detached.
    pub fn detached(&self) -> bool {
        self.detached
    }

    /// Feed one sample.
    pub fn observe(&mut self, now_ns: u64, s: ProbeSample) -> WatchdogAction {
        let advanced = s.fill_prod != self.last_fill_prod || s.rx_cons != self.last_rx_cons;
        self.last_fill_prod = s.fill_prod;
        self.last_rx_cons = s.rx_cons;
        let pending = s.rx_prod != s.rx_cons;
        if self.detached {
            // Only proof of life re-arms: a hung consumer would otherwise flap.
            if advanced {
                self.detached = false;
                self.last_ok_ns = now_ns;
                return WatchdogAction::Reattach;
            }
            return WatchdogAction::Hold;
        }
        if advanced || !pending {
            self.last_ok_ns = now_ns;
            return WatchdogAction::Renew;
        }
        if now_ns.saturating_sub(self.last_ok_ns) >= self.stall_ns {
            self.detached = true;
            return WatchdogAction::Detach;
        }
        WatchdogAction::Renew
    }

    /// Re-arming failed: stay detached until the next proof of life.
    pub fn mark_detached(&mut self) {
        self.detached = true;
    }
}

/// The kernel maps the backend drives (`xsk_sockets`, `xsk_alive`). kavachd implements this
/// with aya over the pinned maps; tests use a recorder.
pub trait RedirectMaps: Send + 'static {
    /// `xsk_sockets[queue] = fd`.
    fn set_socket(&mut self, queue: u32, fd: std::os::fd::RawFd) -> io::Result<()>;
    /// Remove `xsk_sockets[queue]` (absent is fine).
    fn clear_socket(&mut self, queue: u32) -> io::Result<()>;
    /// `xsk_alive[queue] = until_ns` (`CLOCK_BOOTTIME`; 0 stops redirecting).
    fn set_alive_until(&mut self, queue: u32, until_ns: u64) -> io::Result<()>;
}

// ---------------------------------------------------------------------------------------------
// Backend: one consumer thread per queue + one watchdog thread
// ---------------------------------------------------------------------------------------------

/// Starting the backend failed.
#[derive(Debug)]
pub enum BackendError {
    /// Configuration rejected by [`AfXdpConfig::validate`].
    Config(String),
    /// Interface lookup, map update or thread spawn failed.
    Io(String, io::Error),
    /// No bind mode worked for a queue.
    Bind(NegotiateError),
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(s) => f.write_str(s),
            Self::Io(what, e) => write!(f, "{what}: {e}"),
            Self::Bind(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for BackendError {}

/// A running backend. Dropping it (or [`Backend::stop`]) unsets every redirect first, then
/// stops the consumers.
#[derive(Debug)]
pub struct Backend {
    stop: Arc<AtomicBool>,
    watchdog: Option<JoinHandle<()>>,
    consumers: Vec<JoinHandle<()>>,
    modes: Vec<(u32, BindMode)>,
}

const RX_BUDGET: u32 = 64;
const POLL_MS: i32 = 50;

impl Backend {
    /// Bind every configured queue (negotiating the mode), publish the redirects and start the
    /// consumers and the watchdog. Nothing is published unless every queue bound.
    pub fn start<S: Sys, M: RedirectMaps, H: FrameHandler>(
        sys: Arc<S>,
        cfg: &AfXdpConfig,
        attach: XdpAttach,
        mut maps: M,
        mut make_handler: impl FnMut(u32) -> H,
    ) -> Result<Self, BackendError> {
        if !cfg.enabled {
            return Err(BackendError::Config("gateway.afxdp is disabled".into()));
        }
        cfg.validate().map_err(BackendError::Config)?;
        let ifindex = sys
            .ifindex(&cfg.iface)
            .map_err(|e| BackendError::Io(format!("interface {}", cfg.iface), e))?;
        let mut socks = Vec::with_capacity(cfg.queues.len());
        for &queue in &cfg.queues {
            let p = SocketParams {
                ifindex,
                queue,
                ring_size: cfg.ring_size,
                frame_size: cfg.frame_size,
            };
            let (_, s) = negotiate(&cfg.iface, queue, attach, |m| {
                XskSocket::open(sys.clone(), &p, m)
            })
            .map_err(BackendError::Bind)?;
            socks.push(s);
        }
        let stall_ms = cfg.watchdog_ms;
        let tick = Duration::from_millis((stall_ms / 4).max(1));
        // The deadline covers a full stall period plus one tick of watchdog scheduling slack.
        let horizon_ns = stall_ms * 1_000_000 + tick.as_nanos() as u64;
        let now = sys.now_boot_ns();
        let mut watched = Vec::with_capacity(socks.len());
        let publish = |maps: &mut M, s: &XskSocket<S>| -> io::Result<()> {
            maps.set_socket(s.queue(), s.fd().raw())?;
            maps.set_alive_until(s.queue(), now + horizon_ns)
        };
        for s in &socks {
            if let Err(e) = publish(&mut maps, s) {
                for s in &socks {
                    let _ = maps.set_alive_until(s.queue(), 0);
                    let _ = maps.clear_socket(s.queue());
                }
                return Err(BackendError::Io(
                    format!("publishing queue {}", s.queue()),
                    e,
                ));
            }
            let probe = s.probe();
            let wd = Watchdog::new(stall_ms, now, probe.sample());
            watched.push((s.queue(), s.fd(), probe, wd));
        }
        let modes: Vec<(u32, BindMode)> = socks.iter().map(|s| (s.queue(), s.mode())).collect();
        let stop = Arc::new(AtomicBool::new(false));

        let mut consumers = Vec::with_capacity(socks.len());
        for mut s in socks {
            let mut h = make_handler(s.queue());
            let stop_c = stop.clone();
            let name = format!("kv-xsk-q{}", s.queue());
            let spawned = std::thread::Builder::new().name(name).spawn(move || {
                while !stop_c.load(Ordering::Relaxed) {
                    match s.wait(POLL_MS) {
                        Ok(_) => {
                            s.process_rx(RX_BUDGET, &mut h);
                        }
                        Err(e) => {
                            error!(queue = s.queue(), error = %e, "AF_XDP poll failed; consumer exits");
                            break;
                        }
                    }
                }
            });
            match spawned {
                Ok(j) => consumers.push(j),
                Err(e) => {
                    stop.store(true, Ordering::Relaxed);
                    for (q, ..) in &watched {
                        let _ = maps.set_alive_until(*q, 0);
                        let _ = maps.clear_socket(*q);
                    }
                    return Err(BackendError::Io("spawning consumer".into(), e));
                }
            }
        }

        let wd_stop = stop.clone();
        let wd_sys = sys.clone();
        let watchdog = std::thread::Builder::new()
            .name("kv-xsk-watchdog".into())
            .spawn(move || {
                while !wd_stop.load(Ordering::Relaxed) {
                    std::thread::sleep(tick);
                    let now = wd_sys.now_boot_ns();
                    for (q, fd, probe, wd) in watched.iter_mut() {
                        watchdog_step(&mut maps, *q, fd.raw(), now, horizon_ns, wd, probe.sample());
                    }
                }
                // Unset every redirect before the consumers (and their sockets) go away.
                for (q, ..) in &watched {
                    let _ = maps.set_alive_until(*q, 0);
                    let _ = maps.clear_socket(*q);
                }
            })
            .map_err(|e| BackendError::Io("spawning watchdog".into(), e))?;

        Ok(Self {
            stop,
            watchdog: Some(watchdog),
            consumers,
            modes,
        })
    }

    /// `(queue, mode)` for every bound queue.
    pub fn modes(&self) -> &[(u32, BindMode)] {
        &self.modes
    }

    /// Unset the redirects and stop. Consumers stuck in a handler are left behind (their queue
    /// no longer receives anything) rather than blocking shutdown.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(w) = self.watchdog.take() {
            let _ = w.join();
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        for c in self.consumers.drain(..) {
            while !c.is_finished() && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            if c.is_finished() {
                let _ = c.join();
            } else {
                warn!("AF_XDP consumer did not stop; leaving it detached");
            }
        }
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// The backend's consumer: counts redirected frames and consumes (drops) them. Frames
/// delivered to it do **not** reach the kernel stack.
///
/// Dropping is deliberate. AF_XDP has no way to re-inject a received frame into the local
/// stack (`Transmit` sends it out of the NIC), and re-injecting through a TAP device would
/// re-enter the stack *after* XDP/TC, with a different ifindex and without the flow state TC
/// keeps, i.e. bypass policy. Consuming fails closed for exactly the ports the operator
/// selected, and nothing else. Punted L7 flows do not use this path: they are redirected at
/// `connect()` to the gateway listener (cgroup connect hooks), where the kernel stack still
/// terminates TCP.
#[derive(Debug, Clone, Default)]
pub struct CountingSink {
    /// Shared counters: `(frames, bytes)`.
    pub counts: Arc<(std::sync::atomic::AtomicU64, std::sync::atomic::AtomicU64)>,
}

impl FrameHandler for CountingSink {
    fn on_frame(&mut self, _queue: u32, frame: &mut [u8]) -> RxAction {
        self.counts.0.fetch_add(1, Ordering::Relaxed);
        self.counts
            .1
            .fetch_add(frame.len() as u64, Ordering::Relaxed);
        RxAction::Consume
    }
}

/// Apply one watchdog decision to the maps.
fn watchdog_step<M: RedirectMaps>(
    maps: &mut M,
    queue: u32,
    fd: std::os::fd::RawFd,
    now: u64,
    horizon_ns: u64,
    wd: &mut Watchdog,
    sample: ProbeSample,
) {
    let res = match wd.observe(now, sample) {
        WatchdogAction::Renew => maps.set_alive_until(queue, now + horizon_ns),
        WatchdogAction::Hold => Ok(()),
        WatchdogAction::Detach => {
            warn!(
                queue,
                fill_prod = sample.fill_prod,
                rx_pending = sample.rx_prod.wrapping_sub(sample.rx_cons),
                "AF_XDP consumer stalled: detaching queue (its flows pass to the kernel stack)"
            );
            let a = maps.set_alive_until(queue, 0);
            let b = maps.clear_socket(queue);
            a.and(b)
        }
        WatchdogAction::Reattach => {
            info!(queue, "AF_XDP consumer recovered: re-attaching queue");
            let r = maps
                .set_socket(queue, fd)
                .and_then(|()| maps.set_alive_until(queue, now + horizon_ns));
            if r.is_err() {
                wd.mark_detached();
                let _ = maps.clear_socket(queue);
            }
            r
        }
    };
    if let Err(e) = res {
        // A failed renew lets the BPF deadline lapse, which is the safe direction.
        warn!(queue, error = %e, "AF_XDP watchdog map update failed");
    }
}

#[cfg(test)]
mod tests;
