//! The v0.4 agent-gateway proxy.
//!
//! The kernel redirects a punted flow to [`ProxyConfig::listen`]. For each accepted
//! connection the proxy:
//! 1. recovers the original destination and the matching rule through [`OrigDst`] (fail closed
//!    when it is unknown);
//! 2. sniffs the first bytes: a TLS ClientHello (the policy's
//!    [`TlsMode`](crate::TlsMode): `allow` relays it uninspected), an HTTP/1.1 request, or a
//!    newline-delimited JSON-RPC stream (anything else is closed);
//! 3. connects to the original destination and relays, inspecting every client→server
//!    JSON-RPC frame with [`classify`](crate::classify) and the gateway's
//!    [`ToolPolicy`]: MCP Streamable HTTP (POST, JSON or SSE responses), legacy HTTP+SSE MCP,
//!    A2A JSON-RPC over HTTP, WebSocket text messages, and raw NDJSON over TCP;
//! 4. answers a denied request itself with a JSON-RPC error (same id, code
//!    [`jsonrpc::DENIED`]) in the protocol's framing, without forwarding it;
//! 5. reports a [`DecisionEvent`] per frame to an [`EventSink`].
//!
//! Policies are looked up per frame through a [`PolicySource`], so a reload ([`PolicyStore`])
//! takes effect on open connections at their next frame.
//!
//! Resource bounds: [`ProxyConfig::max_connections`] (excess connections wait in the listen
//! backlog), header / idle / connect timeouts, and [`ProxyConfig::max_frame`] for every
//! buffered frame. Response bodies (SSE included) are streamed, never buffered, and each
//! direction reads only as fast as the other side accepts writes.

mod conn;
pub mod http;
pub mod jsonrpc;
pub mod ws;

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::{Decision, ToolPolicy};
pub use jsonrpc::Reason;

/// Where a redirected flow was going, and which rule sent it here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrigInfo {
    /// The original destination.
    pub dst: SocketAddr,
    /// Id of the egress rule that punted the flow.
    pub rule_id: u32,
    /// Name of the gateway policy that applies.
    pub gateway: String,
    /// cgroup of the connecting process.
    pub cgroup_id: u64,
    /// pid of the connecting process.
    pub pid: u32,
}

/// Recovers the original destination of a redirected connection.
pub trait OrigDst: Send + Sync {
    /// Look up the flow by the accepted socket's `peer` and `local` addresses.
    fn lookup(&self, peer: SocketAddr, local: SocketAddr) -> Option<OrigInfo>;
}

/// An [`OrigDst`] that maps every connection to the same destination (explicit-proxy mode
/// and tests).
#[derive(Debug, Clone)]
pub struct StaticOrigDst(pub OrigInfo);

impl OrigDst for StaticOrigDst {
    fn lookup(&self, _peer: SocketAddr, _local: SocketAddr) -> Option<OrigInfo> {
        Some(self.0.clone())
    }
}

/// An [`OrigDst`] keyed by the client's address (tests, or a resolver fed from elsewhere).
#[derive(Debug, Default)]
pub struct MapOrigDst(RwLock<HashMap<SocketAddr, OrigInfo>>);

impl MapOrigDst {
    /// Record where the flow from `peer` was going.
    pub fn insert(&self, peer: SocketAddr, info: OrigInfo) {
        self.0
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(peer, info);
    }
}

impl OrigDst for MapOrigDst {
    fn lookup(&self, peer: SocketAddr, _local: SocketAddr) -> Option<OrigInfo> {
        self.0
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&peer)
            .cloned()
    }
}

/// Supplies the policy for a flow; consulted for every frame, so a swap behind it applies to
/// open connections at their next frame. kavachd backs it with its gateway snapshot
/// (`policy_for_rule(info.rule_id)`); [`PolicyStore`] keys by [`OrigInfo::gateway`].
pub trait PolicySource: Send + Sync {
    /// The policy for the flow described by `info`, or `None` (every frame is then denied).
    fn policy_for(&self, info: &OrigInfo) -> Option<Arc<ToolPolicy>>;
}

/// Policies keyed by gateway name, replaced atomically as a whole.
#[derive(Debug, Default)]
pub struct PolicyStore(RwLock<Arc<HashMap<String, Arc<ToolPolicy>>>>);

impl PolicyStore {
    /// A store holding `policies`.
    pub fn new(policies: HashMap<String, ToolPolicy>) -> Self {
        let s = Self::default();
        s.replace(policies);
        s
    }

    /// Swap in a new set of policies. Frames inspected after this see only the new set.
    pub fn replace(&self, policies: HashMap<String, ToolPolicy>) {
        let map = policies
            .into_iter()
            .map(|(k, v)| (k, Arc::new(v)))
            .collect();
        *self.0.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(map);
    }

    /// The names currently loaded.
    pub fn names(&self) -> Vec<String> {
        let mut v: Vec<_> = self
            .0
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .cloned()
            .collect();
        v.sort();
        v
    }
}

impl PolicyStore {
    /// The policy named `gateway`.
    pub fn get(&self, gateway: &str) -> Option<Arc<ToolPolicy>> {
        self.0
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(gateway)
            .cloned()
    }
}

impl PolicySource for PolicyStore {
    fn policy_for(&self, info: &OrigInfo) -> Option<Arc<ToolPolicy>> {
        self.get(&info.gateway)
    }
}

/// The wire protocol a decision was made on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    /// JSON-RPC over HTTP/1.1 (MCP Streamable HTTP, legacy HTTP+SSE, A2A).
    Http,
    /// JSON-RPC in WebSocket text messages.
    WebSocket,
    /// Newline-delimited JSON-RPC over raw TCP.
    RawJsonRpc,
    /// TLS (not terminated).
    Tls,
    /// Not identified.
    Unknown,
}

/// One gateway decision, for the audit log.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DecisionEvent {
    /// Gateway policy name (empty when the flow was unknown).
    pub gateway: String,
    /// Egress rule that punted the flow.
    pub rule_id: u32,
    /// Process id of the agent.
    pub pid: u32,
    /// cgroup of the agent.
    pub cgroup_id: u64,
    /// The agent's socket address.
    pub peer: SocketAddr,
    /// The original destination (the listener address when unknown).
    pub dst: SocketAddr,
    /// Protocol.
    pub protocol: Protocol,
    /// JSON-RPC method (or HTTP method for body-less requests, `"tls"` for TLS).
    pub method: Option<String>,
    /// Tool name, resource URI, or TLS SNI.
    pub target: Option<String>,
    /// The verdict.
    pub decision: Decision,
    /// Why.
    pub reason: Reason,
}

/// Receives decision events. Must not block: it runs on the data path.
pub trait EventSink: Send + Sync {
    /// Handle one event.
    fn emit(&self, ev: DecisionEvent);
}

/// Discards events.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullSink;

impl EventSink for NullSink {
    fn emit(&self, _ev: DecisionEvent) {}
}

/// Forwards events to a bounded channel, dropping (and counting) them when it is full so a
/// slow auditor cannot stall the data path.
#[derive(Debug)]
pub struct ChannelSink {
    tx: tokio::sync::mpsc::Sender<DecisionEvent>,
    dropped: AtomicU64,
}

impl ChannelSink {
    /// Wrap a sender.
    pub fn new(tx: tokio::sync::mpsc::Sender<DecisionEvent>) -> Self {
        Self {
            tx,
            dropped: AtomicU64::new(0),
        }
    }

    /// Events dropped because the channel was full or closed.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl EventSink for ChannelSink {
    fn emit(&self, ev: DecisionEvent) {
        if self.tx.try_send(ev).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Adapts a closure into an [`EventSink`].
pub struct FnSink<F>(pub F);

impl<F> std::fmt::Debug for FnSink<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FnSink")
    }
}

impl<F: Fn(DecisionEvent) + Send + Sync> EventSink for FnSink<F> {
    fn emit(&self, ev: DecisionEvent) {
        (self.0)(ev)
    }
}

/// `[gateway.proxy]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ProxyConfig {
    /// Listen address (default `127.0.0.1:15001`).
    pub listen: SocketAddr,
    /// Concurrent connections; more wait in the listen backlog.
    pub max_connections: usize,
    /// Largest JSON-RPC frame / HTTP request body (capped at [`crate::MAX_FRAME`]).
    pub max_frame: usize,
    /// Largest HTTP head.
    pub max_header_bytes: usize,
    /// Most HTTP header fields.
    pub max_headers: usize,
    /// Time allowed for the first bytes and for each HTTP head, in ms.
    pub header_timeout_ms: u64,
    /// A connection direction with no traffic for this long is closed, in ms.
    pub idle_timeout_ms: u64,
    /// Upstream connect timeout, in ms.
    pub connect_timeout_ms: u64,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 15001)),
            max_connections: 1024,
            max_frame: crate::MAX_FRAME,
            max_header_bytes: 16 * 1024,
            max_headers: 64,
            header_timeout_ms: 10_000,
            idle_timeout_ms: 300_000,
            connect_timeout_ms: 5_000,
        }
    }
}

impl ProxyConfig {
    fn max_frame(&self) -> usize {
        self.max_frame.clamp(1, crate::MAX_FRAME)
    }
    fn limits(&self) -> http::Limits {
        http::Limits {
            max_head: self.max_header_bytes.max(256),
            max_headers: self.max_headers.max(1),
            max_body: self.max_frame(),
        }
    }
    fn header_timeout(&self) -> Duration {
        Duration::from_millis(self.header_timeout_ms.max(1))
    }
    fn idle_timeout(&self) -> Duration {
        Duration::from_millis(self.idle_timeout_ms.max(1))
    }
    fn connect_timeout(&self) -> Duration {
        Duration::from_millis(self.connect_timeout_ms.max(1))
    }
}

/// Gateway counters.
#[derive(Debug, Default)]
pub struct Stats {
    /// Connections accepted.
    pub connections: AtomicU64,
    /// Connections open now.
    pub active: AtomicU64,
    /// Frames allowed.
    pub allowed: AtomicU64,
    /// Frames denied (policy or malformed).
    pub denied: AtomicU64,
}

pub(crate) struct Shared {
    cfg: ProxyConfig,
    listen: SocketAddr,
    resolver: Arc<dyn OrigDst>,
    policies: Arc<dyn PolicySource>,
    events: Arc<dyn EventSink>,
    stats: Arc<Stats>,
}

/// A bound gateway listener.
pub struct Gateway {
    listener: TcpListener,
    shared: Arc<Shared>,
}

impl std::fmt::Debug for Gateway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gateway")
            .field("listen", &self.shared.listen)
            .finish_non_exhaustive()
    }
}

impl Gateway {
    /// Bind the listener.
    pub async fn bind(
        cfg: ProxyConfig,
        resolver: Arc<dyn OrigDst>,
        policies: Arc<dyn PolicySource>,
        events: Arc<dyn EventSink>,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(cfg.listen).await?;
        let listen = listener.local_addr()?;
        Ok(Self {
            listener,
            shared: Arc::new(Shared {
                cfg,
                listen,
                resolver,
                policies,
                events,
                stats: Arc::default(),
            }),
        })
    }

    /// The bound address.
    pub fn local_addr(&self) -> SocketAddr {
        self.shared.listen
    }

    /// Counters.
    pub fn stats(&self) -> Arc<Stats> {
        self.shared.stats.clone()
    }

    /// Accept connections forever.
    pub async fn serve(self) -> io::Result<()> {
        self.serve_until(std::future::pending()).await
    }

    /// Accept connections until `shutdown` resolves. Open connections finish on their own
    /// (bounded by the idle timeout).
    pub async fn serve_until(self, shutdown: impl Future<Output = ()>) -> io::Result<()> {
        let permits = Arc::new(Semaphore::new(self.shared.cfg.max_connections.max(1)));
        tokio::pin!(shutdown);
        loop {
            let permit = tokio::select! {
                _ = &mut shutdown => return Ok(()),
                p = permits.clone().acquire_owned() => p.map_err(io::Error::other)?,
            };
            let (stream, peer) = tokio::select! {
                _ = &mut shutdown => return Ok(()),
                r = self.listener.accept() => match r {
                    Ok(x) => x,
                    Err(e) => {
                        // EMFILE and friends: back off instead of spinning.
                        tracing::warn!(error = %e, "gateway accept failed");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                },
            };
            let shared = self.shared.clone();
            shared.stats.connections.fetch_add(1, Ordering::Relaxed);
            shared.stats.active.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(async move {
                conn::handle(shared.clone(), stream, peer).await;
                shared.stats.active.fetch_sub(1, Ordering::Relaxed);
                drop(permit);
            });
        }
    }
}

/// Bind `config.listen` and serve until the task is dropped.
pub async fn run(
    config: ProxyConfig,
    resolver: Arc<dyn OrigDst>,
    policies: Arc<dyn PolicySource>,
    events: Arc<dyn EventSink>,
) -> io::Result<()> {
    Gateway::bind(config, resolver, policies, events)
        .await?
        .serve()
        .await
}
