//! Per-connection relay: protocol sniffing, HTTP / WebSocket / NDJSON / TLS paths.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use kavach_parsers::tls::ClientHello;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc;
use tokio::time::timeout;

use super::http::{self, ChunkedDecoder, Framing, HttpError, RequestHead};
use super::jsonrpc::{self, Inspection, Reason};
use super::ws::{self, Assembler, FrameTracker, Step};
use super::{DecisionEvent, OrigInfo, Protocol, Shared};
use crate::{Decision, TlsMode, ToolPolicy};

const READ_CHUNK: usize = 16 * 1024;
/// A ClientHello fits one TLS record (≤ 16 KiB + header) in practice.
const MAX_CLIENT_HELLO: usize = 16 * 1024 + 5;
/// Bytes to look at before giving up on identifying the protocol.
const SNIFF_MAX: usize = 64;

struct Ctx {
    shared: Arc<Shared>,
    peer: SocketAddr,
    info: OrigInfo,
}

impl Ctx {
    fn idle(&self) -> Duration {
        self.shared.cfg.idle_timeout()
    }

    fn policy(&self) -> Option<Arc<ToolPolicy>> {
        self.shared.policies.policy_for(&self.info)
    }

    fn emit(
        &self,
        protocol: Protocol,
        method: Option<String>,
        target: Option<String>,
        decision: Decision,
        reason: Reason,
    ) {
        let s = &self.shared.stats;
        match decision {
            Decision::Allow => s.allowed.fetch_add(1, Ordering::Relaxed),
            Decision::Deny => s.denied.fetch_add(1, Ordering::Relaxed),
        };
        tracing::debug!(
            peer = %self.peer, dst = %self.info.dst, gateway = %self.info.gateway,
            ?protocol, ?method, ?target, ?decision, ?reason, "gateway decision"
        );
        self.shared.events.emit(DecisionEvent {
            gateway: self.info.gateway.clone(),
            rule_id: self.info.rule_id,
            pid: self.info.pid,
            cgroup_id: self.info.cgroup_id,
            peer: self.peer,
            dst: self.info.dst,
            protocol,
            method,
            target,
            decision,
            reason,
        });
    }

    fn deny(&self, protocol: Protocol, reason: Reason) {
        self.emit(protocol, None, None, Decision::Deny, reason);
    }

    /// Inspect one frame and record the decision.
    fn inspect(&self, protocol: Protocol, frame: &[u8]) -> Inspection {
        let policy = self.policy();
        let i = jsonrpc::inspect(policy.as_deref(), frame, self.shared.cfg.max_frame());
        self.emit(
            protocol,
            i.method.clone(),
            i.target.clone(),
            i.decision,
            i.reason,
        );
        i
    }

    fn reply(&self, i: &Inspection) -> Option<Vec<u8>> {
        jsonrpc::error_reply(i, &self.info.gateway, self.info.rule_id)
    }

    async fn connect(&self) -> io::Result<TcpStream> {
        let s = timeout(
            self.shared.cfg.connect_timeout(),
            TcpStream::connect(self.info.dst),
        )
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        let _ = s.set_nodelay(true);
        Ok(s)
    }
}

/// Read more bytes into `buf` (appending). `Ok(0)` is EOF; a timeout is an error.
async fn fill<R: AsyncRead + Unpin>(
    r: &mut R,
    buf: &mut Vec<u8>,
    dur: Duration,
) -> io::Result<usize> {
    buf.reserve(READ_CHUNK);
    timeout(dur, r.read_buf(buf))
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}

async fn send<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8], dur: Duration) -> io::Result<()> {
    timeout(dur, w.write_all(data))
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}

pub(super) async fn handle(shared: Arc<Shared>, mut client: TcpStream, peer: SocketAddr) {
    let _ = client.set_nodelay(true);
    let Ok(local) = client.local_addr() else {
        return;
    };
    let listen = shared.listen;
    let info = shared.resolver.lookup(peer, local);
    let is_self = |d: SocketAddr| {
        d.port() == listen.port() && (listen.ip().is_unspecified() || d.ip() == listen.ip())
    };
    let Some(info) = info.filter(|i| !is_self(i.dst)) else {
        let ctx = Ctx {
            shared,
            peer,
            info: OrigInfo {
                dst: listen,
                rule_id: 0,
                gateway: String::new(),
                cgroup_id: 0,
                pid: 0,
            },
        };
        ctx.deny(Protocol::Unknown, Reason::NoOrigDst);
        return;
    };
    let ctx = Ctx { shared, peer, info };
    let mut buf = Vec::new();
    let Some(kind) = sniff(&mut client, &mut buf, ctx.shared.cfg.header_timeout()).await else {
        return;
    };
    match kind {
        Kind::Tls => tls(&ctx, client, buf).await,
        Kind::Http => http_session(&ctx, client, buf).await,
        Kind::Json => ndjson_session(&ctx, client, buf).await,
        Kind::Unknown => ctx.deny(Protocol::Unknown, Reason::UnknownProtocol),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Tls,
    Http,
    Json,
    Unknown,
}

fn sniff_kind(buf: &[u8]) -> Option<Kind> {
    let first = *buf.first()?;
    if first == 0x16 {
        return Some(Kind::Tls);
    }
    let Some(start) = buf.iter().position(|b| !b.is_ascii_whitespace()) else {
        return (buf.len() >= SNIFF_MAX).then_some(Kind::Unknown);
    };
    match buf[start] {
        b'{' | b'[' => Some(Kind::Json),
        b'A'..=b'Z' if start == 0 => {
            let n = buf.len().min(9);
            match buf[..n].iter().position(|&b| b == b' ') {
                Some(i) if buf[..i].iter().all(u8::is_ascii_uppercase) => Some(Kind::Http),
                Some(_) => Some(Kind::Unknown),
                None if n == 9 || !buf.iter().all(u8::is_ascii_uppercase) => Some(Kind::Unknown),
                None => None,
            }
        }
        _ => Some(Kind::Unknown),
    }
}

async fn sniff(client: &mut TcpStream, buf: &mut Vec<u8>, dur: Duration) -> Option<Kind> {
    loop {
        if let Some(k) = sniff_kind(buf) {
            return Some(k);
        }
        match fill(client, buf, dur).await {
            Ok(0) | Err(_) => return None,
            Ok(_) => {}
        }
    }
}

// --- TLS -----------------------------------------------------------------------------------

async fn tls(ctx: &Ctx, mut client: TcpStream, mut buf: Vec<u8>) {
    let sni = loop {
        match ClientHello::parse(&buf) {
            Err(kavach_parsers::Error::Truncated) if buf.len() < MAX_CLIENT_HELLO => {
                match fill(&mut client, &mut buf, ctx.shared.cfg.header_timeout()).await {
                    Ok(0) | Err(_) => break None,
                    Ok(_) => {}
                }
            }
            Ok(h) => break h.server_name().map(str::to_owned),
            Err(_) => break None,
        }
    };
    let policy = ctx.policy();
    let mode = policy.as_ref().map(|p| p.tls);
    tracing::info!(peer = %ctx.peer, dst = %ctx.info.dst, sni = ?sni, ?mode, "TLS flow at gateway");
    let pass = mode == Some(TlsMode::Allow);
    let (decision, reason) = if pass {
        (Decision::Allow, Reason::TlsPassthrough)
    } else if policy.is_none() {
        (Decision::Deny, Reason::NoPolicy)
    } else {
        (Decision::Deny, Reason::Tls)
    };
    ctx.emit(Protocol::Tls, Some("tls".into()), sni, decision, reason);
    if !pass {
        return;
    }
    let Ok(mut up) = ctx.connect().await else {
        return;
    };
    if send(&mut up, &buf, ctx.idle()).await.is_err() {
        return;
    }
    pump(client, up, ctx.idle()).await;
}

/// Relay both directions unmodified until both close (or one fails / idles out).
async fn pump(client: TcpStream, up: TcpStream, idle: Duration) {
    let (mut cr, mut cw) = client.into_split();
    let (mut ur, mut uw) = up.into_split();
    let c2u = copy_idle(&mut cr, &mut uw, idle);
    let u2c = copy_idle(&mut ur, &mut cw, idle);
    tokio::pin!(c2u, u2c);
    tokio::select! {
        r = &mut c2u => if r.is_ok() { let _ = u2c.await; },
        r = &mut u2c => if r.is_ok() { let _ = c2u.await; },
    }
}

async fn copy_idle<R, W>(r: &mut R, w: &mut W, idle: Duration) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = Vec::with_capacity(READ_CHUNK);
    loop {
        buf.clear();
        if fill(r, &mut buf, idle).await? == 0 {
            let _ = w.shutdown().await;
            return Ok(());
        }
        send(w, &buf, idle).await?;
    }
}

// --- HTTP ----------------------------------------------------------------------------------

async fn respond(client: &mut TcpStream, ctx: &Ctx, bytes: &[u8]) {
    let _ = send(client, bytes, ctx.idle()).await;
}

async fn http_error(ctx: &Ctx, client: &mut TcpStream, e: HttpError) {
    ctx.deny(
        Protocol::Http,
        if e == HttpError::BodyTooLarge {
            Reason::TooLarge
        } else {
            Reason::Framing
        },
    );
    let (status, reason) = e.status();
    let body = format!("kavach gateway: {e}\n");
    respond(
        client,
        ctx,
        &http::simple_response(status, reason, "text/plain", body.as_bytes(), true),
    )
    .await;
}

enum BodyError {
    Http(HttpError),
    Io,
}

async fn read_body(
    ctx: &Ctx,
    client: &mut TcpStream,
    cbuf: &mut Vec<u8>,
    framing: Framing,
) -> Result<Vec<u8>, BodyError> {
    let idle = ctx.idle();
    match framing {
        Framing::None | Framing::CloseDelimited => Ok(Vec::new()),
        Framing::Length(n) => {
            // n ≤ max_body was checked by the head parser.
            let n = usize::try_from(n).map_err(|_| BodyError::Http(HttpError::BodyTooLarge))?;
            while cbuf.len() < n {
                match fill(client, cbuf, idle).await {
                    Ok(0) | Err(_) => return Err(BodyError::Io),
                    Ok(_) => {}
                }
            }
            Ok(cbuf.drain(..n).collect())
        }
        Framing::Chunked => {
            let mut dec = ChunkedDecoder::strict(ctx.shared.cfg.max_frame());
            let mut body = Vec::new();
            loop {
                let used = dec.decode(cbuf, &mut body).map_err(BodyError::Http)?;
                cbuf.drain(..used);
                if dec.is_done() {
                    return Ok(body);
                }
                match fill(client, cbuf, idle).await {
                    Ok(0) | Err(_) => return Err(BodyError::Io),
                    Ok(_) => {}
                }
            }
        }
    }
}

async fn http_session(ctx: &Ctx, mut client: TcpStream, mut cbuf: Vec<u8>) {
    let cfg = &ctx.shared.cfg;
    let limits = cfg.limits();
    let mut upstream: Option<(TcpStream, Vec<u8>)> = None;
    loop {
        let head = loop {
            match http::parse_request_head(&cbuf, &limits) {
                Ok(h) => break h,
                Err(HttpError::Incomplete) => {
                    // Between requests the connection may idle; inside a head it may not dawdle.
                    let t = if cbuf.is_empty() {
                        ctx.idle()
                    } else {
                        cfg.header_timeout()
                    };
                    match fill(&mut client, &mut cbuf, t).await {
                        Ok(0) | Err(_) => return,
                        Ok(_) => {}
                    }
                }
                Err(e) => return http_error(ctx, &mut client, e).await,
            }
        };
        cbuf.drain(..head.head_len);
        if head.expect_continue
            && head.framing != Framing::None
            && send(&mut client, b"HTTP/1.1 100 Continue\r\n\r\n", ctx.idle())
                .await
                .is_err()
        {
            return;
        }
        let body = match read_body(ctx, &mut client, &mut cbuf, head.framing).await {
            Ok(b) => b,
            Err(BodyError::Http(e)) => return http_error(ctx, &mut client, e).await,
            Err(BodyError::Io) => return,
        };
        // Bytes after a complete request, sent before its response: pipelining. Refused, so
        // no second request can ride along in a buffer the upstream might frame differently.
        if !cbuf.is_empty() && !head.websocket {
            ctx.deny(Protocol::Http, Reason::Framing);
            let msg = b"kavach gateway: pipelined requests are not accepted\n";
            respond(
                &mut client,
                ctx,
                &http::simple_response(400, "Bad Request", "text/plain", msg, true),
            )
            .await;
            return;
        }

        if !body.is_empty() {
            let i = ctx.inspect(Protocol::Http, &body);
            if i.decision == Decision::Deny {
                let close = i.reason.is_malformed() || head.close;
                let json = jsonrpc::error_body(&i, &ctx.info.gateway, ctx.info.rule_id);
                let (status, reason) = if i.reason.is_malformed() {
                    (400, "Bad Request")
                } else if i.id.is_none() {
                    (403, "Forbidden")
                } else {
                    // A JSON-RPC error is a successful HTTP exchange (MCP, A2A).
                    (200, "OK")
                };
                let r = http::simple_response(status, reason, "application/json", &json, close);
                if send(&mut client, &r, ctx.idle()).await.is_err() || close {
                    return;
                }
                continue;
            }
        } else if matches!(head.method.as_str(), "POST" | "PUT" | "PATCH") {
            let i = ctx.inspect(Protocol::Http, b"");
            let json = jsonrpc::error_body(&i, &ctx.info.gateway, ctx.info.rule_id);
            let r = http::simple_response(400, "Bad Request", "application/json", &json, true);
            return respond(&mut client, ctx, &r).await;
        } else if ctx.policy().is_none() {
            ctx.deny(Protocol::Http, Reason::NoPolicy);
            let r = http::simple_response(403, "Forbidden", "text/plain", b"", true);
            return respond(&mut client, ctx, &r).await;
        } else {
            ctx.emit(
                if head.websocket {
                    Protocol::WebSocket
                } else {
                    Protocol::Http
                },
                Some(head.method.clone()),
                Some(head.target.clone()),
                Decision::Allow,
                Reason::NoFrame,
            );
        }

        let (mut up, mut ubuf) = match upstream.take() {
            Some(u) => u,
            None => match ctx.connect().await {
                Ok(s) => (s, Vec::new()),
                Err(e) => {
                    tracing::debug!(dst = %ctx.info.dst, error = %e, "gateway upstream connect failed");
                    let r = http::simple_response(502, "Bad Gateway", "text/plain", b"", true);
                    return respond(&mut client, ctx, &r).await;
                }
            },
        };
        let mut req = head.forward(body.len());
        req.extend_from_slice(&body);
        if send(&mut up, &req, ctx.idle()).await.is_err() {
            let r = http::simple_response(502, "Bad Gateway", "text/plain", b"", true);
            return respond(&mut client, ctx, &r).await;
        }
        match relay_response(ctx, &mut up, &mut ubuf, &mut client, &head).await {
            Ok(Outcome::Done { close }) => {
                if close || head.close {
                    let _ = client.shutdown().await;
                    return;
                }
                upstream = Some((up, ubuf));
            }
            Ok(Outcome::Upgraded) => return ws_session(ctx, client, cbuf, up, ubuf).await,
            Err(RelayError::BeforeHead) => {
                let r = http::simple_response(502, "Bad Gateway", "text/plain", b"", true);
                return respond(&mut client, ctx, &r).await;
            }
            Err(RelayError::AfterHead) => return,
        }
    }
}

enum Outcome {
    Done { close: bool },
    Upgraded,
}

enum RelayError {
    /// Nothing was sent to the client yet; it can still get a 502.
    BeforeHead,
    /// The response was cut off mid-way; close.
    AfterHead,
}

async fn relay_response(
    ctx: &Ctx,
    up: &mut TcpStream,
    ubuf: &mut Vec<u8>,
    client: &mut TcpStream,
    req: &RequestHead,
) -> Result<Outcome, RelayError> {
    let idle = ctx.idle();
    let limits = ctx.shared.cfg.limits();
    let mut sent_any = false;
    let fail = |sent: bool| {
        if sent {
            RelayError::AfterHead
        } else {
            RelayError::BeforeHead
        }
    };
    loop {
        let head = loop {
            match http::parse_response_head(ubuf, &limits, req.method == "HEAD") {
                Ok(h) => break h,
                Err(HttpError::Incomplete) => match fill(up, ubuf, idle).await {
                    Ok(0) | Err(_) => return Err(fail(sent_any)),
                    Ok(_) => {}
                },
                Err(e) => {
                    tracing::debug!(dst = %ctx.info.dst, error = %e, "bad upstream response");
                    return Err(fail(sent_any));
                }
            }
        };
        ubuf.drain(..head.head_len);
        if head.status == 101 {
            if !req.websocket || head.header("sec-websocket-extensions").is_some() {
                return Err(fail(sent_any));
            }
            send(client, &head.forward(), idle)
                .await
                .map_err(|_| RelayError::AfterHead)?;
            return Ok(Outcome::Upgraded);
        }
        send(client, &head.forward(), idle)
            .await
            .map_err(|_| RelayError::AfterHead)?;
        sent_any = true;
        if (100..200).contains(&head.status) {
            continue;
        }
        match head.framing {
            Framing::None => {}
            Framing::Length(mut rem) => loop {
                let take = usize::try_from(rem).unwrap_or(usize::MAX).min(ubuf.len());
                if take > 0 {
                    send(client, &ubuf[..take], idle)
                        .await
                        .map_err(|_| RelayError::AfterHead)?;
                    ubuf.drain(..take);
                    rem -= take as u64;
                }
                if rem == 0 {
                    break;
                }
                match fill(up, ubuf, idle).await {
                    Ok(0) | Err(_) => return Err(RelayError::AfterHead),
                    Ok(_) => {}
                }
            },
            Framing::Chunked => {
                let mut dec = ChunkedDecoder::lenient();
                let mut data = Vec::new();
                let mut wire = Vec::new();
                loop {
                    let used = dec
                        .decode(ubuf, &mut data)
                        .map_err(|_| RelayError::AfterHead)?;
                    ubuf.drain(..used);
                    if !data.is_empty() {
                        wire.clear();
                        http::encode_chunk(&data, &mut wire);
                        data.clear();
                        send(client, &wire, idle)
                            .await
                            .map_err(|_| RelayError::AfterHead)?;
                    }
                    if dec.is_done() {
                        send(client, http::LAST_CHUNK, idle)
                            .await
                            .map_err(|_| RelayError::AfterHead)?;
                        break;
                    }
                    match fill(up, ubuf, idle).await {
                        Ok(0) | Err(_) => return Err(RelayError::AfterHead),
                        Ok(_) => {}
                    }
                }
            }
            Framing::CloseDelimited => {
                loop {
                    if !ubuf.is_empty() {
                        send(client, ubuf, idle)
                            .await
                            .map_err(|_| RelayError::AfterHead)?;
                        ubuf.clear();
                    }
                    match fill(up, ubuf, idle).await {
                        Ok(0) => break,
                        Err(_) => return Err(RelayError::AfterHead),
                        Ok(_) => {}
                    }
                }
                return Ok(Outcome::Done { close: true });
            }
        }
        // Bytes the upstream sent beyond the response it owed: never relay them as the next one.
        return Ok(Outcome::Done {
            close: head.close || !ubuf.is_empty(),
        });
    }
}

// --- framed sessions (WebSocket, NDJSON) ---------------------------------------------------

/// A frame the gateway itself sends to the client, spliced in at a message boundary.
struct Inject {
    bytes: Vec<u8>,
    close: bool,
}

enum Boundary {
    Ws(FrameTracker),
    Lines(bool),
}

impl Boundary {
    fn observe(&mut self, data: &[u8]) {
        match self {
            Boundary::Ws(t) => t.observe(data),
            Boundary::Lines(at) => {
                if let Some(&b) = data.last() {
                    *at = b == b'\n';
                }
            }
        }
    }
    fn at(&self) -> bool {
        match self {
            Boundary::Ws(t) => t.at_boundary(),
            Boundary::Lines(at) => *at,
        }
    }
}

/// Server→client: forward unmodified, splicing in injected frames only at boundaries.
async fn server_to_client(
    mut ur: OwnedReadHalf,
    pending: Vec<u8>,
    mut cw: OwnedWriteHalf,
    mut rx: mpsc::Receiver<Inject>,
    idle: Duration,
    mut boundary: Boundary,
) {
    if !pending.is_empty() {
        boundary.observe(&pending);
        if send(&mut cw, &pending, idle).await.is_err() {
            return;
        }
    }
    let mut buf = Vec::with_capacity(READ_CHUNK);
    let mut rx_open = true;
    loop {
        let at = boundary.at();
        tokio::select! {
            biased;
            inj = rx.recv(), if at && rx_open => match inj {
                Some(i) => {
                    if send(&mut cw, &i.bytes, idle).await.is_err() {
                        return;
                    }
                    if i.close {
                        let _ = cw.shutdown().await;
                        return;
                    }
                }
                None => rx_open = false,
            },
            r = fill(&mut ur, &mut buf, idle) => match r {
                Ok(n) if n > 0 => {
                    boundary.observe(&buf);
                    if send(&mut cw, &buf, idle).await.is_err() {
                        return;
                    }
                    buf.clear();
                }
                _ => break,
            },
        }
    }
    if boundary.at() {
        while let Ok(i) = rx.try_recv() {
            if send(&mut cw, &i.bytes, idle).await.is_err() {
                break;
            }
        }
    }
    let _ = cw.shutdown().await;
}

/// Run a framed session: `client_loop` reads and inspects client frames, writing allowed
/// ones upstream; the server direction runs as its own task.
async fn framed<F, Fut>(
    ctx: &Ctx,
    client: TcpStream,
    up: TcpStream,
    ubuf: Vec<u8>,
    boundary: Boundary,
    client_loop: F,
) where
    F: FnOnce(OwnedReadHalf, OwnedWriteHalf, mpsc::Sender<Inject>) -> Fut,
    Fut: std::future::Future<Output = OwnedWriteHalf>,
{
    let idle = ctx.idle();
    let (cr, cw) = client.into_split();
    let (ur, uw) = up.into_split();
    let (tx, rx) = mpsc::channel(4);
    let mut server = tokio::spawn(server_to_client(ur, ubuf, cw, rx, idle, boundary));
    let fut = client_loop(cr, uw, tx);
    tokio::select! {
        mut uw = fut => {
            let _ = uw.shutdown().await;
            if timeout(idle, &mut server).await.is_err() {
                server.abort();
            }
        }
        _ = &mut server => {}
    }
}

async fn ws_session(ctx: &Ctx, client: TcpStream, cbuf: Vec<u8>, up: TcpStream, ubuf: Vec<u8>) {
    let boundary = Boundary::Ws(FrameTracker::default());
    framed(ctx, client, up, ubuf, boundary, |cr, uw, tx| {
        ws_client_loop(ctx, cr, cbuf, uw, tx)
    })
    .await;
}

async fn ws_client_loop(
    ctx: &Ctx,
    mut cr: OwnedReadHalf,
    mut cbuf: Vec<u8>,
    mut uw: OwnedWriteHalf,
    tx: mpsc::Sender<Inject>,
) -> OwnedWriteHalf {
    let idle = ctx.idle();
    let mut asm = Assembler::new(ctx.shared.cfg.max_frame());
    let fatal = |code: u16, reason: &str| Inject {
        bytes: ws::close_frame(code, reason),
        close: true,
    };
    loop {
        let h = loop {
            if let Some(h) = ws::parse_frame_header(&cbuf) {
                break h;
            }
            match fill(&mut cr, &mut cbuf, idle).await {
                Ok(0) | Err(_) => return uw,
                Ok(_) => {}
            }
        };
        if let Err(e) = ws::validate_client(&h).and_then(|()| asm.admit(&h)) {
            ctx.deny(
                Protocol::WebSocket,
                if e == ws::WsError::TooLarge {
                    Reason::TooLarge
                } else {
                    Reason::Framing
                },
            );
            let _ = tx
                .send(fatal(e.close_code(), "kavach: frame refused"))
                .await;
            return uw;
        }
        // admit() bounded data frames by max_frame and control frames by 125 bytes.
        let total = h.header_len + h.len as usize;
        while cbuf.len() < total {
            match fill(&mut cr, &mut cbuf, idle).await {
                Ok(0) | Err(_) => return uw,
                Ok(_) => {}
            }
        }
        let raw: Vec<u8> = cbuf.drain(..total).collect();
        match asm.push(&h, raw) {
            Err(e) => {
                ctx.deny(Protocol::WebSocket, Reason::Framing);
                let _ = tx
                    .send(fatal(e.close_code(), "kavach: frame refused"))
                    .await;
                return uw;
            }
            Ok(Step::Pending) => {}
            Ok(Step::Control { raw, .. }) => {
                if send(&mut uw, &raw, idle).await.is_err() {
                    return uw;
                }
            }
            Ok(Step::Binary) => {
                ctx.deny(Protocol::WebSocket, Reason::Binary);
                let _ = tx
                    .send(fatal(1003, "kavach: binary messages are not inspected"))
                    .await;
                return uw;
            }
            Ok(Step::Text { text, raw }) => {
                let i = ctx.inspect(Protocol::WebSocket, &text);
                if i.decision == Decision::Allow {
                    if send(&mut uw, &raw, idle).await.is_err() {
                        return uw;
                    }
                    continue;
                }
                if let Some(r) = ctx.reply(&i) {
                    let inj = Inject {
                        bytes: ws::encode_frame(ws::OP_TEXT, &r),
                        close: false,
                    };
                    if tx.send(inj).await.is_err() {
                        return uw;
                    }
                }
                if i.reason.is_malformed() {
                    let _ = tx.send(fatal(1008, "kavach: frame refused")).await;
                    return uw;
                }
            }
        }
    }
}

async fn ndjson_session(ctx: &Ctx, client: TcpStream, cbuf: Vec<u8>) {
    if ctx.policy().is_none() {
        return ctx.deny(Protocol::RawJsonRpc, Reason::NoPolicy);
    }
    let Ok(up) = ctx.connect().await else {
        return;
    };
    framed(
        ctx,
        client,
        up,
        Vec::new(),
        Boundary::Lines(true),
        |cr, uw, tx| ndjson_client_loop(ctx, cr, cbuf, uw, tx),
    )
    .await;
}

async fn ndjson_client_loop(
    ctx: &Ctx,
    mut cr: OwnedReadHalf,
    mut cbuf: Vec<u8>,
    mut uw: OwnedWriteHalf,
    tx: mpsc::Sender<Inject>,
) -> OwnedWriteHalf {
    let idle = ctx.idle();
    let max = ctx.shared.cfg.max_frame();
    let mut scanned = 0;
    loop {
        let Some(p) = cbuf[scanned..].iter().position(|&b| b == b'\n') else {
            scanned = cbuf.len();
            if cbuf.len() > max {
                let i = ctx.inspect(Protocol::RawJsonRpc, &cbuf);
                let mut r = jsonrpc::error_body(&i, &ctx.info.gateway, ctx.info.rule_id);
                r.push(b'\n');
                let _ = tx
                    .send(Inject {
                        bytes: r,
                        close: true,
                    })
                    .await;
                return uw;
            }
            match fill(&mut cr, &mut cbuf, idle).await {
                // A final line without '\n' is incomplete and never forwarded.
                Ok(0) | Err(_) => return uw,
                Ok(_) => continue,
            }
        };
        let end = scanned + p + 1;
        scanned = 0;
        let line: Vec<u8> = cbuf.drain(..end).collect();
        let frame = &line[..line.len() - 1];
        if frame.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let i = ctx.inspect(Protocol::RawJsonRpc, frame);
        if i.decision == Decision::Allow {
            if send(&mut uw, &line, idle).await.is_err() {
                return uw;
            }
            continue;
        }
        let close = i.reason.is_malformed();
        if let Some(mut r) = ctx.reply(&i) {
            r.push(b'\n');
            if tx.send(Inject { bytes: r, close }).await.is_err() {
                return uw;
            }
        }
        if close {
            return uw;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffing() {
        assert_eq!(sniff_kind(b""), None);
        assert_eq!(sniff_kind(b"\x16\x03\x01"), Some(Kind::Tls));
        assert_eq!(sniff_kind(b"  {\"a\""), Some(Kind::Json));
        assert_eq!(sniff_kind(b"["), Some(Kind::Json));
        assert_eq!(sniff_kind(b"   "), None);
        assert_eq!(sniff_kind(b"PO"), None);
        assert_eq!(sniff_kind(b"POST /"), Some(Kind::Http));
        assert_eq!(sniff_kind(b"OPTIONS *"), Some(Kind::Http));
        assert_eq!(sniff_kind(b"Post /"), Some(Kind::Unknown));
        assert_eq!(sniff_kind(b"ABCDEFGHIJ"), Some(Kind::Unknown));
        assert_eq!(sniff_kind(b" GET /"), Some(Kind::Unknown));
        assert_eq!(sniff_kind(b"\x00\x01"), Some(Kind::Unknown));
        assert_eq!(sniff_kind(b"SSH-2.0"), Some(Kind::Unknown));
    }
}
