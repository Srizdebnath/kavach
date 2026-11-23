//! End-to-end gateway tests over loopback: a fake upstream MCP / A2A / WebSocket / NDJSON
//! server, the gateway in front of it, and a hand-rolled client so every byte is controlled.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kavach_gateway::proxy::{
    DecisionEvent, FnSink, Gateway, MapOrigDst, OrigDst, OrigInfo, PolicyStore, Protocol,
    ProxyConfig, Reason, StaticOrigDst, TlsMode, ws,
};
use kavach_gateway::{Decision, ToolPolicy};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const T: Duration = Duration::from_secs(5);

// --- fake upstream ---------------------------------------------------------------------------

/// Everything the upstream received, as complete requests / lines / messages.
type Seen = Arc<Mutex<Vec<String>>>;

async fn read_head(s: &mut TcpStream, buf: &mut Vec<u8>) -> Option<String> {
    loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..p + 4]).into_owned();
            buf.drain(..p + 4);
            return Some(head);
        }
        let mut tmp = [0u8; 4096];
        let n = s.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

async fn read_exact_buf(s: &mut TcpStream, buf: &mut Vec<u8>, n: usize) -> Option<Vec<u8>> {
    while buf.len() < n {
        let mut tmp = [0u8; 4096];
        let k = s.read(&mut tmp).await.ok()?;
        if k == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..k]);
    }
    Some(buf.drain(..n).collect())
}

/// An HTTP/1.1 upstream speaking MCP Streamable HTTP (`/mcp`), legacy HTTP+SSE (`/sse`,
/// `/messages`), A2A (`/a2a`) and WebSocket (`/ws`, echo).
async fn http_upstream(seen: Seen) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                while let Some(head) = read_head(&mut s, &mut buf).await {
                    if header(&head, "transfer-encoding").is_some() {
                        seen.lock()
                            .unwrap()
                            .push("UPSTREAM SAW TRANSFER-ENCODING".into());
                        return;
                    }
                    let n: usize =
                        header(&head, "content-length").map_or(0, |v| v.parse().unwrap());
                    let body = read_exact_buf(&mut s, &mut buf, n).await.unwrap();
                    let body = String::from_utf8(body).unwrap();
                    let line = head.lines().next().unwrap().to_owned();
                    seen.lock().unwrap().push(format!("{line} {body}"));
                    let path = line.split(' ').nth(1).unwrap().to_owned();
                    if path == "/ws" {
                        let resp = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: x\r\n\r\n";
                        s.write_all(resp.as_bytes()).await.unwrap();
                        ws_echo(s, buf, seen).await;
                        return;
                    }
                    if path == "/sse" {
                        let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\nevent: endpoint\ndata: /messages?sessionId=1\n\n";
                        s.write_all(resp.as_bytes()).await.unwrap();
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        s.write_all(b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n")
                            .await
                            .unwrap();
                        return; // close-delimited
                    }
                    if path.starts_with("/messages") {
                        s.write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n")
                            .await
                            .unwrap();
                        continue;
                    }
                    if head.starts_with("GET") || head.starts_with("DELETE") {
                        s.write_all(
                            b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n",
                        )
                        .await
                        .unwrap();
                        continue;
                    }
                    let req: Value = serde_json::from_str(&body).unwrap();
                    let id = req["id"].clone();
                    if req["params"]["name"] == "stream" {
                        // SSE response, chunked, with a pause between events.
                        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n").await.unwrap();
                        for k in 0..3 {
                            let ev = format!(
                                "event: message\ndata: {}\n\n",
                                json!({"jsonrpc":"2.0","method":"notifications/progress","params":{"k":k}})
                            );
                            s.write_all(format!("{:x}\r\n{ev}\r\n", ev.len()).as_bytes())
                                .await
                                .unwrap();
                            tokio::time::sleep(Duration::from_millis(20)).await;
                        }
                        let last = format!(
                            "event: message\ndata: {}\n\n",
                            json!({"jsonrpc":"2.0","id":id,"result":{"done":true}})
                        );
                        s.write_all(
                            format!(
                                "{:x};ext=1\r\n{last}\r\n0\r\nX-Trailer: t\r\n\r\n",
                                last.len()
                            )
                            .as_bytes(),
                        )
                        .await
                        .unwrap();
                        continue;
                    }
                    let out = json!({"jsonrpc":"2.0","id":id,"result":{"echo":req["method"]}})
                        .to_string();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nMcp-Session-Id: abc\r\nContent-Length: {}\r\n\r\n{out}",
                        out.len()
                    );
                    s.write_all(resp.as_bytes()).await.unwrap();
                }
            });
        }
    });
    addr
}

/// Echo WebSocket text messages back (unmasked), recording them.
async fn ws_echo(mut s: TcpStream, mut buf: Vec<u8>, seen: Seen) {
    let mut msg = Vec::new();
    loop {
        let h = loop {
            if let Some(h) = ws::parse_frame_header(&buf) {
                break h;
            }
            let mut tmp = [0u8; 4096];
            match s.read(&mut tmp).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
            }
        };
        let total = h.header_len + h.len as usize;
        let Some(raw) = read_exact_buf(&mut s, &mut buf, total).await else {
            return;
        };
        let mut p = raw[h.header_len..].to_vec();
        ws::unmask(&mut p, h.mask.unwrap(), 0);
        match h.opcode {
            ws::OP_TEXT | ws::OP_CONT => {
                msg.extend_from_slice(&p);
                if h.fin {
                    let t = String::from_utf8(std::mem::take(&mut msg)).unwrap();
                    s.write_all(&ws::encode_frame(ws::OP_TEXT, t.as_bytes()))
                        .await
                        .unwrap();
                    seen.lock().unwrap().push(format!("WS {t}"));
                }
            }
            ws::OP_CLOSE => {
                let _ = s.write_all(&ws::encode_frame(ws::OP_CLOSE, &p)).await;
                return;
            }
            _ => seen.lock().unwrap().push(format!("WS op {}", h.opcode)),
        }
    }
}

/// Newline-delimited JSON-RPC upstream: answers every line.
async fn ndjson_upstream(seen: Seen) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            let seen = seen.clone();
            tokio::spawn(async move {
                let (r, mut w) = s.into_split();
                let mut lines = tokio::io::AsyncBufReadExt::lines(tokio::io::BufReader::new(r));
                while let Ok(Some(line)) = lines.next_line().await {
                    seen.lock().unwrap().push(line.clone());
                    let v: Value = serde_json::from_str(&line).unwrap();
                    let out = json!({"jsonrpc":"2.0","id":v["id"],"result":"ok"});
                    w.write_all(format!("{out}\n").as_bytes()).await.unwrap();
                }
            });
        }
    });
    addr
}

// --- harness ----------------------------------------------------------------------------------

struct Harness {
    addr: SocketAddr,
    seen: Seen,
    events: Arc<Mutex<Vec<DecisionEvent>>>,
    policies: Arc<PolicyStore>,
}

fn policy() -> HashMap<String, ToolPolicy> {
    HashMap::from([(
        "dev".to_owned(),
        ToolPolicy {
            allow_tools: vec!["search".into(), "stream".into(), "github.*".into()],
            deny_tools: vec!["github.delete_repo".into()],
            ..Default::default()
        },
    )])
}

fn info(dst: SocketAddr) -> OrigInfo {
    OrigInfo {
        dst,
        rule_id: 42,
        gateway: "dev".into(),
        cgroup_id: 7,
        pid: 1234,
    }
}

async fn start_with(
    cfg: ProxyConfig,
    dst: SocketAddr,
    seen: Seen,
    resolver: Option<Arc<dyn OrigDst>>,
) -> Harness {
    let events: Arc<Mutex<Vec<DecisionEvent>>> = Arc::default();
    let sink = {
        let events = events.clone();
        FnSink(move |e| events.lock().unwrap().push(e))
    };
    let policies = Arc::new(PolicyStore::new(policy()));
    let resolver = resolver.unwrap_or_else(|| Arc::new(StaticOrigDst(info(dst))));
    let gw = Gateway::bind(
        ProxyConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            ..cfg
        },
        resolver,
        policies.clone(),
        Arc::new(sink),
    )
    .await
    .unwrap();
    let addr = gw.local_addr();
    tokio::spawn(gw.serve());
    Harness {
        addr,
        seen,
        events,
        policies,
    }
}

async fn http_with(cfg: ProxyConfig) -> Harness {
    let seen: Seen = Arc::default();
    let dst = http_upstream(seen.clone()).await;
    start_with(cfg, dst, seen, None).await
}

async fn start_http() -> Harness {
    http_with(ProxyConfig::default()).await
}

async fn ndjson_with(cfg: ProxyConfig) -> Harness {
    let seen: Seen = Arc::default();
    let dst = ndjson_upstream(seen.clone()).await;
    start_with(cfg, dst, seen, None).await
}

impl Harness {
    async fn connect(&self) -> TcpStream {
        TcpStream::connect(self.addr).await.unwrap()
    }
    fn seen(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
    fn events(&self) -> Vec<DecisionEvent> {
        self.events.lock().unwrap().clone()
    }
}

struct Response {
    status: u16,
    head: String,
    body: Vec<u8>,
}

impl Response {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}

/// Read one response from the gateway, decoding Content-Length, chunked or close framing.
async fn read_response(s: &mut TcpStream, buf: &mut Vec<u8>) -> Response {
    let head = timeout(T, read_head(s, buf))
        .await
        .unwrap()
        .expect("response head");
    let status = head[9..12].parse().unwrap();
    let body = if let Some(n) = header(&head, "content-length") {
        read_exact_buf(s, buf, n.parse().unwrap()).await.unwrap()
    } else if header(&head, "transfer-encoding") == Some("chunked") {
        let mut body = Vec::new();
        loop {
            let line = loop {
                if let Some(p) = buf.windows(2).position(|w| w == b"\r\n") {
                    let l = String::from_utf8(buf[..p].to_vec()).unwrap();
                    buf.drain(..p + 2);
                    break l;
                }
                let mut tmp = [0u8; 4096];
                let n = timeout(T, s.read(&mut tmp)).await.unwrap().unwrap();
                assert!(n > 0, "eof inside chunked body");
                buf.extend_from_slice(&tmp[..n]);
            };
            assert!(!line.contains(';'), "gateway must normalise chunk lines");
            let n = usize::from_str_radix(&line, 16).unwrap();
            let chunk = read_exact_buf(s, buf, n + 2).await.unwrap();
            if n == 0 {
                assert_eq!(chunk, b"\r\n", "no trailers forwarded");
                break;
            }
            body.extend_from_slice(&chunk[..n]);
        }
        body
    } else if status == 101 || status == 100 {
        Vec::new()
    } else {
        let mut rest = std::mem::take(buf);
        timeout(T, s.read_to_end(&mut rest)).await.unwrap().unwrap();
        rest
    };
    Response { status, head, body }
}

async fn post(s: &mut TcpStream, path: &str, body: &str) {
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: mcp.example\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).await.unwrap();
}

fn call(id: u64, tool: &str) -> String {
    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":tool,"arguments":{}}})
        .to_string()
}

/// The gateway closes the connection without answering.
async fn assert_closed(s: &mut TcpStream) {
    let mut rest = Vec::new();
    if let Ok(()) = timeout(T, s.read_to_end(&mut rest))
        .await
        .expect("gateway must close")
        .map(drop)
    {
        assert!(rest.is_empty(), "unexpected reply {rest:?}");
    }
}

// --- MCP Streamable HTTP -------------------------------------------------------------------------

#[tokio::test]
async fn allowed_call_is_forwarded_and_denied_call_answered_locally() {
    let h = start_http().await;
    let mut s = h.connect().await;
    let mut buf = Vec::new();

    post(&mut s, "/mcp", &call(1, "search")).await;
    let r = read_response(&mut s, &mut buf).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["result"]["echo"], "tools/call");
    assert_eq!(header(&r.head, "mcp-session-id"), Some("abc"));

    // Same connection (keep-alive): denied tool never reaches the upstream.
    post(&mut s, "/mcp", &call(2, "github.delete_repo")).await;
    let r = read_response(&mut s, &mut buf).await;
    assert_eq!(r.status, 200);
    let e = r.json();
    assert_eq!(e["id"], 2);
    assert_eq!(e["error"]["code"], -32001);
    assert_eq!(e["error"]["message"], "denied by kavach policy dev");
    assert_eq!(e["error"]["data"]["rule_id"], 42);

    // And the connection still works afterwards.
    post(&mut s, "/mcp", &call(3, "github.create_issue")).await;
    assert_eq!(read_response(&mut s, &mut buf).await.status, 200);

    let seen = h.seen();
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert!(seen.iter().all(|l| !l.contains("delete_repo")));

    let ev = h.events();
    assert_eq!(ev.len(), 3);
    let d = &ev[1];
    assert_eq!(
        (d.decision, d.reason, d.protocol),
        (Decision::Deny, Reason::Policy, Protocol::Http)
    );
    assert_eq!(d.target.as_deref(), Some("github.delete_repo"));
    assert_eq!(d.method.as_deref(), Some("tools/call"));
    assert_eq!((d.pid, d.cgroup_id, d.rule_id), (1234, 7, 42));
    assert_eq!(d.gateway, "dev");
    assert_eq!(ev[0].decision, Decision::Allow);
}

#[tokio::test]
async fn sse_response_is_streamed_and_rechunked() {
    let h = start_http().await;
    let mut s = h.connect().await;
    let mut buf = Vec::new();
    post(&mut s, "/mcp", &call(9, "stream")).await;
    let r = read_response(&mut s, &mut buf).await;
    assert_eq!(r.status, 200);
    assert_eq!(header(&r.head, "content-type"), Some("text/event-stream"));
    let body = String::from_utf8(r.body).unwrap();
    assert_eq!(body.matches("event: message").count(), 4);
    assert!(body.contains(r#""done":true"#));
    // keep-alive survives a streamed response
    post(&mut s, "/mcp", &call(10, "search")).await;
    assert_eq!(read_response(&mut s, &mut buf).await.status, 200);
}

#[tokio::test]
async fn first_sse_event_arrives_before_the_stream_ends() {
    let h = start_http().await;
    let mut s = h.connect().await;
    post(&mut s, "/mcp", &call(9, "stream")).await;
    let mut got = Vec::new();
    // The upstream pauses between events; the first must be relayed without waiting.
    while !String::from_utf8_lossy(&got).contains("\"k\":0") {
        let mut tmp = [0u8; 1024];
        let n = timeout(Duration::from_millis(500), s.read(&mut tmp))
            .await
            .unwrap()
            .unwrap();
        assert!(n > 0);
        got.extend_from_slice(&tmp[..n]);
    }
    assert!(!String::from_utf8_lossy(&got).contains("\"done\""));
}

#[tokio::test]
async fn notifications_responses_and_get_streams() {
    let h = start_http().await;
    let mut s = h.connect().await;
    let mut buf = Vec::new();
    // A denied notification: no id to answer, so 403 with a null-id error.
    let n = json!({"jsonrpc":"2.0","method":"tools/call","params":{"name":"rm"}}).to_string();
    post(&mut s, "/mcp", &n).await;
    let r = read_response(&mut s, &mut buf).await;
    assert_eq!(r.status, 403);
    assert_eq!(r.json()["id"], Value::Null);
    // A response to a server-initiated request (sampling) is allowed through.
    let resp = json!({"jsonrpc":"2.0","id":"srv-1","result":{"content":[]}}).to_string();
    post(&mut s, "/mcp", &resp).await;
    assert_eq!(read_response(&mut s, &mut buf).await.status, 200);
    // GET (SSE stream open) carries no frame and is forwarded.
    s.write_all(b"GET /mcp HTTP/1.1\r\nHost: x\r\nAccept: text/event-stream\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(read_response(&mut s, &mut buf).await.status, 405);
    let ev = h.events();
    assert_eq!(ev[1].reason, Reason::Response);
    assert_eq!(ev[2].reason, Reason::NoFrame);
    assert_eq!(ev[2].method.as_deref(), Some("GET"));
}

// --- legacy HTTP+SSE and A2A ---------------------------------------------------------------------

#[tokio::test]
async fn legacy_http_sse_transport() {
    let h = start_http().await;
    let mut sse = h.connect().await;
    sse.write_all(b"GET /sse HTTP/1.1\r\nHost: x\r\nAccept: text/event-stream\r\n\r\n")
        .await
        .unwrap();
    let r = read_response(&mut sse, &mut Vec::new()).await;
    assert_eq!(r.status, 200);
    assert!(header(&r.head, "connection").unwrap().contains("close"));
    let body = String::from_utf8(r.body).unwrap();
    assert!(body.contains("data: /messages?sessionId=1"));
    assert!(body.contains("event: message"));

    let mut s = h.connect().await;
    let mut buf = Vec::new();
    post(&mut s, "/messages?sessionId=1", &call(1, "search")).await;
    assert_eq!(read_response(&mut s, &mut buf).await.status, 202);
    post(&mut s, "/messages?sessionId=1", &call(2, "shell.exec")).await;
    let r = read_response(&mut s, &mut buf).await;
    assert_eq!(r.json()["error"]["code"], -32001);
    assert_eq!(
        h.seen().iter().filter(|l| l.contains("/messages")).count(),
        1
    );
}

#[tokio::test]
async fn a2a_message_send_and_policy_hot_reload() {
    let h = start_http().await;
    let mut s = h.connect().await;
    let mut buf = Vec::new();
    let msg = json!({"jsonrpc":"2.0","id":"t1","method":"message/send","params":{"message":{"role":"user","parts":[]}}}).to_string();
    post(&mut s, "/a2a", &msg).await;
    let r = read_response(&mut s, &mut buf).await;
    assert_eq!(r.json()["error"]["code"], -32001);
    assert_eq!(r.json()["id"], "t1");

    // Reload: the same open connection sees the new policy at its next frame.
    let mut p = policy();
    p.get_mut("dev").unwrap().allow_agent_messages = true;
    h.policies.replace(p);
    post(&mut s, "/a2a", &msg).await;
    let r = read_response(&mut s, &mut buf).await;
    assert_eq!(r.json()["result"]["echo"], "message/send");

    // Removing the gateway's policy fails closed.
    h.policies.replace(HashMap::new());
    post(&mut s, "/a2a", &msg).await;
    let r = read_response(&mut s, &mut buf).await;
    assert_eq!(r.json()["error"]["code"], -32001);
    assert_eq!(h.events().last().unwrap().reason, Reason::NoPolicy);
}

// --- smuggling and framing -------------------------------------------------------------------------

async fn raw_exchange(h: &Harness, req: &[u8]) -> Response {
    let mut s = h.connect().await;
    s.write_all(req).await.unwrap();
    read_response(&mut s, &mut Vec::new()).await
}

#[tokio::test]
async fn smuggling_attempts_are_rejected_before_the_upstream() {
    let h = start_http().await;
    let smuggled = call(1, "shell.exec");
    let cases: Vec<(String, u16)> = vec![
        // CL.TE
        (
            format!(
                "POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nPOST /mcp HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{smuggled}",
                smuggled.len()
            ),
            400,
        ),
        // duplicate CL
        (
            format!(
                "POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nContent-Length: {}\r\n\r\n{smuggled}",
                smuggled.len()
            ),
            400,
        ),
        // TE obfuscation
        (
            "POST /mcp HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nTransfer-encoding: x\r\n\r\n0\r\n\r\n".into(),
            501,
        ),
        // bare LF line endings
        ("POST /mcp HTTP/1.1\nHost: x\nContent-Length: 2\n\n{}".into(), 400),
        // obs-fold
        ("POST /mcp HTTP/1.1\r\nHost: x\r\nX: a\r\n Content-Length: 2\r\n\r\n{}".into(), 400),
        // chunk extension (strict for requests)
        ("POST /mcp HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n2;x=y\r\n{}\r\n0\r\n\r\n".into(), 400),
        // oversized Content-Length
        ("POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Length: 99999999\r\n\r\n".into(), 413),
        // CONNECT tunnel
        ("CONNECT evil:443 HTTP/1.1\r\nHost: evil:443\r\n\r\n".into(), 405),
        // HTTP/1.0
        ("POST /mcp HTTP/1.0\r\nContent-Length: 2\r\n\r\n{}".into(), 400),
        // pipelining: a second request rides behind the first
        (
            format!(
                "POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{}POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{smuggled}",
                call(1, "search").len(),
                call(1, "search"),
                smuggled.len()
            ),
            400,
        ),
        // batch
        (
            format!(
                "POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n[{smuggled}]",
                smuggled.len() + 2
            ),
            400,
        ),
        // empty POST
        ("POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n".into(), 400),
        // duplicate key in the JSON-RPC object
        (
            {
                let b = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"shell.exec","name":"search"}}"#;
                format!("POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{b}", b.len())
            },
            400,
        ),
    ];
    for (req, want) in &cases {
        let r = raw_exchange(&h, req.as_bytes()).await;
        assert_eq!(r.status, *want, "{req:?}");
        assert!(
            header(&r.head, "connection").is_some_and(|c| c.contains("close")),
            "{req:?}"
        );
    }
    assert!(h.seen().is_empty(), "upstream saw {:?}", h.seen());
    assert!(h.events().iter().all(|e| e.decision == Decision::Deny));
}

#[tokio::test]
async fn chunked_requests_are_decoded_and_reframed() {
    let h = start_http().await;
    let body = call(5, "search");
    let (a, b) = body.split_at(10);
    let req = format!(
        "POST /mcp HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nExpect: 100-continue\r\n\r\n{:x}\r\n{a}\r\n{:X}\r\n{b}\r\n0\r\n\r\n",
        a.len(),
        b.len()
    );
    let mut s = h.connect().await;
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let cont = read_response(&mut s, &mut buf).await;
    assert_eq!(cont.status, 100);
    let r = read_response(&mut s, &mut buf).await;
    assert_eq!(r.status, 200);
    let seen = h.seen();
    assert_eq!(seen.len(), 1);
    assert!(seen[0].ends_with(&body), "{seen:?}");

    // A chunked body that grows past max_frame is refused once the limit is crossed.
    let mut s = h.connect().await;
    s.write_all(b"POST /mcp HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n")
        .await
        .unwrap();
    let chunk = vec![b' '; 64 * 1024];
    let mut status = None;
    for _ in 0..20 {
        let mut c = format!("{:x}\r\n", chunk.len()).into_bytes();
        c.extend_from_slice(&chunk);
        c.extend_from_slice(b"\r\n");
        if s.write_all(&c).await.is_err() {
            break;
        }
    }
    let mut buf = Vec::new();
    if let Ok(Some(head)) = timeout(T, read_head(&mut s, &mut buf)).await {
        status = Some(head[9..12].to_owned());
    }
    assert_eq!(status.as_deref(), Some("413"));
    assert_eq!(h.seen().len(), 1);
}

#[tokio::test]
async fn unknown_flows_and_protocols_fail_closed() {
    let seen: Seen = Arc::default();
    let dst = http_upstream(seen.clone()).await;
    let h = start_with(
        ProxyConfig::default(),
        dst,
        seen.clone(),
        Some(Arc::new(MapOrigDst::default())),
    )
    .await;
    let mut s = h.connect().await;
    post(&mut s, "/mcp", &call(1, "search")).await;
    assert_closed(&mut s).await;
    assert_eq!(h.events()[0].reason, Reason::NoOrigDst);
    assert!(seen.lock().unwrap().is_empty());

    let h = start_http().await;
    let mut s = h.connect().await;
    s.write_all(b"SSH-2.0-OpenSSH_9.6\r\n").await.unwrap();
    assert_closed(&mut s).await;
    assert_eq!(h.events()[0].reason, Reason::UnknownProtocol);
}

#[tokio::test]
async fn orig_dst_by_peer_address() {
    let seen: Seen = Arc::default();
    let dst = http_upstream(seen.clone()).await;
    let map = Arc::new(MapOrigDst::default());
    let h = start_with(ProxyConfig::default(), dst, seen, Some(map.clone())).await;
    let sock = tokio::net::TcpSocket::new_v4().unwrap();
    sock.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    map.insert(sock.local_addr().unwrap(), info(dst));
    let mut s = sock.connect(h.addr).await.unwrap();
    post(&mut s, "/mcp", &call(1, "search")).await;
    assert_eq!(read_response(&mut s, &mut Vec::new()).await.status, 200);
    assert_eq!(h.events()[0].peer, s.local_addr().unwrap());
}

#[tokio::test]
async fn max_connections_applies_backpressure() {
    let h = http_with(ProxyConfig {
        max_connections: 1,
        ..ProxyConfig::default()
    })
    .await;
    let mut a = h.connect().await;
    post(&mut a, "/mcp", &call(1, "search")).await;
    let mut abuf = Vec::new();
    assert_eq!(read_response(&mut a, &mut abuf).await.status, 200);
    let mut b = h.connect().await;
    post(&mut b, "/mcp", &call(2, "search")).await;
    let mut tmp = [0u8; 16];
    assert!(
        timeout(Duration::from_millis(300), b.read(&mut tmp))
            .await
            .is_err(),
        "second connection must wait"
    );
    drop(a);
    assert_eq!(read_response(&mut b, &mut Vec::new()).await.status, 200);
}

#[tokio::test]
async fn idle_connections_are_closed() {
    let h = http_with(ProxyConfig {
        header_timeout_ms: 200,
        idle_timeout_ms: 200,
        ..ProxyConfig::default()
    })
    .await;
    let mut s = h.connect().await;
    // A slowloris head is cut off by the header timeout.
    s.write_all(b"POST /mcp HTTP/1.1\r\nHost: x\r\n")
        .await
        .unwrap();
    let mut rest = Vec::new();
    let r = timeout(Duration::from_secs(2), s.read_to_end(&mut rest)).await;
    assert!(r.is_ok(), "gateway must drop a stalled head");
}

// --- WebSocket ---------------------------------------------------------------------------------------

fn masked(opcode: u8, fin: bool, payload: &[u8]) -> Vec<u8> {
    let mask = [0x37, 0xfa, 0x21, 0x3d];
    let mut f = vec![(u8::from(fin) << 7) | opcode];
    match payload.len() {
        n if n < 126 => f.push(0x80 | n as u8),
        n => {
            f.push(0x80 | 126);
            f.extend_from_slice(&(n as u16).to_be_bytes());
        }
    }
    f.extend_from_slice(&mask);
    let mut p = payload.to_vec();
    ws::unmask(&mut p, mask, 0);
    f.extend_from_slice(&p);
    f
}

async fn read_frame(s: &mut TcpStream, buf: &mut Vec<u8>) -> (u8, Vec<u8>) {
    let h = loop {
        if let Some(h) = ws::parse_frame_header(buf) {
            break h;
        }
        let mut tmp = [0u8; 4096];
        let n = timeout(T, s.read(&mut tmp)).await.unwrap().unwrap();
        assert!(n > 0, "eof waiting for a frame");
        buf.extend_from_slice(&tmp[..n]);
    };
    assert!(h.mask.is_none());
    let raw = read_exact_buf(s, buf, h.header_len + h.len as usize)
        .await
        .unwrap();
    (h.opcode, raw[h.header_len..].to_vec())
}

async fn ws_connect(h: &Harness) -> (TcpStream, Vec<u8>) {
    let mut s = h.connect().await;
    s.write_all(b"GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n").await.unwrap();
    let mut buf = Vec::new();
    let r = read_response(&mut s, &mut buf).await;
    assert_eq!(r.status, 101);
    assert_eq!(header(&r.head, "upgrade"), Some("websocket"));
    (s, buf)
}

#[tokio::test]
async fn websocket_messages_are_inspected() {
    let h = start_http().await;
    let (mut s, mut buf) = ws_connect(&h).await;
    assert!(
        h.seen()[0].contains("GET /ws"),
        "handshake forwarded: {:?}",
        h.seen()
    );

    // Allowed, fragmented across two frames with a ping in between.
    let msg = call(1, "search");
    let (a, b) = msg.as_bytes().split_at(7);
    let mut out = masked(ws::OP_TEXT, false, a);
    out.extend(masked(ws::OP_PING, true, b"p"));
    out.extend(masked(ws::OP_CONT, true, b));
    s.write_all(&out).await.unwrap();
    let (op, p) = read_frame(&mut s, &mut buf).await;
    assert_eq!(op, ws::OP_TEXT);
    assert_eq!(p, msg.as_bytes());

    // Denied: answered by the gateway with the same id.
    s.write_all(&masked(
        ws::OP_TEXT,
        true,
        call(2, "github.delete_repo").as_bytes(),
    ))
    .await
    .unwrap();
    let (op, p) = read_frame(&mut s, &mut buf).await;
    assert_eq!(op, ws::OP_TEXT);
    let e: Value = serde_json::from_slice(&p).unwrap();
    assert_eq!(
        (e["id"].clone(), e["error"]["code"].clone()),
        (json!(2), json!(-32001))
    );

    // Still open: another allowed call goes through.
    s.write_all(&masked(ws::OP_TEXT, true, call(3, "search").as_bytes()))
        .await
        .unwrap();
    let (_, p) = read_frame(&mut s, &mut buf).await;
    assert_eq!(serde_json::from_slice::<Value>(&p).unwrap()["id"], 3);

    // Binary is refused with a close frame.
    s.write_all(&masked(ws::OP_BINARY, true, b"\x00\x01"))
        .await
        .unwrap();
    let (op, p) = read_frame(&mut s, &mut buf).await;
    assert_eq!(op, ws::OP_CLOSE);
    assert_eq!(u16::from_be_bytes([p[0], p[1]]), 1003);

    let seen = h.seen();
    assert!(!seen.iter().any(|l| l.contains("delete_repo")), "{seen:?}");
    assert_eq!(seen.iter().filter(|l| l.starts_with("WS ")).count(), 3); // 2 texts + ping
    let ev: Vec<_> = h
        .events()
        .into_iter()
        .filter(|e| e.protocol == Protocol::WebSocket)
        .collect();
    assert_eq!(ev.last().unwrap().reason, Reason::Binary);
}

#[tokio::test]
async fn websocket_protocol_violations_close() {
    let h = start_http().await;
    for bad in [
        // unmasked client frame
        ws::encode_frame(ws::OP_TEXT, b"{}"),
        // RSV1 (compression was never negotiated)
        {
            let mut f = masked(ws::OP_TEXT, true, b"{}");
            f[0] |= 0x40;
            f
        },
        // continuation without a message
        masked(ws::OP_CONT, true, b"{}"),
        // malformed JSON
        masked(ws::OP_TEXT, true, b"{not json"),
    ] {
        let (mut s, mut buf) = ws_connect(&h).await;
        s.write_all(&bad).await.unwrap();
        loop {
            let (op, _) = read_frame(&mut s, &mut buf).await;
            if op == ws::OP_CLOSE {
                break;
            }
        }
    }
    assert!(!h.seen().iter().any(|l| l.starts_with("WS ")));
}

#[tokio::test]
async fn websocket_oversized_message_is_refused() {
    let h = http_with(ProxyConfig {
        max_frame: 1000,
        ..ProxyConfig::default()
    })
    .await;
    let (mut s, mut buf) = ws_connect(&h).await;
    s.write_all(&masked(ws::OP_TEXT, false, &[b' '; 800]))
        .await
        .unwrap();
    s.write_all(&masked(ws::OP_CONT, true, &[b' '; 800]))
        .await
        .unwrap();
    let (op, p) = read_frame(&mut s, &mut buf).await;
    assert_eq!(op, ws::OP_CLOSE);
    assert_eq!(u16::from_be_bytes([p[0], p[1]]), 1009);
    assert_eq!(h.events().last().unwrap().reason, Reason::TooLarge);
}

// --- raw NDJSON over TCP ---------------------------------------------------------------------------------

async fn next_json(
    lines: &mut tokio::io::Lines<tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>>,
) -> Value {
    let l = timeout(T, lines.next_line())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    serde_json::from_str(&l).unwrap()
}

#[tokio::test]
async fn ndjson_stream() {
    let h = ndjson_with(ProxyConfig::default()).await;
    let s = h.connect().await;
    let (r, mut w) = s.into_split();
    let mut lines = tokio::io::AsyncBufReadExt::lines(tokio::io::BufReader::new(r));
    w.write_all(format!("{}\n", call(1, "search")).as_bytes())
        .await
        .unwrap();
    assert_eq!(next_json(&mut lines).await["result"], "ok");
    w.write_all(format!("{}\r\n\n", call(2, "rm")).as_bytes())
        .await
        .unwrap();
    let e = next_json(&mut lines).await;
    assert_eq!(
        (e["id"].clone(), e["error"]["code"].clone()),
        (json!(2), json!(-32001))
    );
    // a denied notification gets no reply; the next request still works
    let n = json!({"jsonrpc":"2.0","method":"tools/call","params":{"name":"rm"}});
    w.write_all(format!("{n}\n{}\n", call(3, "search")).as_bytes())
        .await
        .unwrap();
    assert_eq!(next_json(&mut lines).await["id"], 3);
    // malformed: parse error, then the gateway closes
    w.write_all(b"{oops\n").await.unwrap();
    let e = next_json(&mut lines).await;
    assert_eq!(e["error"]["code"], -32700);
    assert!(
        timeout(T, lines.next_line())
            .await
            .unwrap()
            .unwrap()
            .is_none()
    );
    let seen = h.seen();
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert!(!seen.iter().any(|l| l.contains("\"rm\"")));
}

#[tokio::test]
async fn ndjson_batch_and_oversize_fail_closed() {
    let h = ndjson_with(ProxyConfig {
        max_frame: 256,
        ..ProxyConfig::default()
    })
    .await;
    let mut s = h.connect().await;
    s.write_all(format!("[{}]\n", call(1, "search")).as_bytes())
        .await
        .unwrap();
    let mut out = String::new();
    timeout(T, s.read_to_string(&mut out))
        .await
        .unwrap()
        .unwrap();
    assert!(out.contains("-32600"), "{out}");

    let mut s = h.connect().await;
    s.write_all(&[b'{'; 1024]).await.unwrap();
    let mut out = String::new();
    timeout(T, s.read_to_string(&mut out))
        .await
        .unwrap()
        .unwrap();
    assert!(out.contains("TooLarge"), "{out}");
    assert!(h.seen().is_empty());
}

// --- TLS ---------------------------------------------------------------------------------------------------

fn client_hello(host: &str) -> Vec<u8> {
    let mut sni = Vec::new();
    sni.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
    sni.push(0);
    sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
    sni.extend_from_slice(host.as_bytes());
    let mut ext = vec![0, 0];
    ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    ext.extend_from_slice(&sni);
    let mut body = vec![3, 3];
    body.extend_from_slice(&[0x11; 32]);
    body.push(0); // session id
    body.extend_from_slice(&[0, 2, 0x13, 0x01]); // one cipher
    body.extend_from_slice(&[1, 0]); // null compression
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);
    let mut hs = vec![1, 0];
    hs.extend_from_slice(&(body.len() as u16).to_be_bytes());
    hs.extend_from_slice(&body);
    let mut rec = vec![0x16, 3, 1];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

#[tokio::test]
async fn tls_deny_logs_sni() {
    let h = start_http().await;
    let mut s = h.connect().await;
    let hello = client_hello("api.example.com");
    // split across two writes: the gateway must buffer the whole ClientHello
    s.write_all(&hello[..10]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    s.write_all(&hello[10..]).await.unwrap();
    assert_closed(&mut s).await;
    let ev = &h.events()[0];
    assert_eq!(
        (ev.protocol, ev.decision, ev.reason),
        (Protocol::Tls, Decision::Deny, Reason::Tls)
    );
    assert_eq!(ev.target.as_deref(), Some("api.example.com"));
    assert!(h.seen().is_empty());
}

#[tokio::test]
async fn tls_passthrough_relays_bytes() {
    // An upstream that echoes raw bytes.
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dst = l.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let (mut r, mut w) = s.split();
        let _ = tokio::io::copy(&mut r, &mut w).await;
    });
    let h = start_with(
        ProxyConfig {
            tls: TlsMode::Passthrough,
            ..ProxyConfig::default()
        },
        dst,
        Seen::default(),
        None,
    )
    .await;
    let mut s = h.connect().await;
    let hello = client_hello("passthrough.example");
    s.write_all(&hello).await.unwrap();
    let mut back = vec![0u8; hello.len()];
    timeout(T, s.read_exact(&mut back)).await.unwrap().unwrap();
    assert_eq!(back, hello);
    let ev = &h.events()[0];
    assert_eq!(
        (ev.decision, ev.reason),
        (Decision::Allow, Reason::TlsPassthrough)
    );
    assert_eq!(ev.target.as_deref(), Some("passthrough.example"));
}

// --- hostile upstream ------------------------------------------------------------------------------------

/// An upstream that answers every request with the same raw bytes and then closes.
async fn raw_upstream(resp: &'static [u8]) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                if read_head(&mut s, &mut buf).await.is_some() {
                    let _ = s.write_all(resp).await;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            });
        }
    });
    addr
}

#[tokio::test]
async fn hostile_upstream_responses() {
    // Ambiguous framing from upstream: the client gets a 502, not the upstream's bytes.
    let dst = raw_upstream(
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    )
    .await;
    let h = start_with(ProxyConfig::default(), dst, Seen::default(), None).await;
    let mut s = h.connect().await;
    post(&mut s, "/mcp", &call(1, "search")).await;
    assert_eq!(read_response(&mut s, &mut Vec::new()).await.status, 502);

    // Extra bytes after a response (an unsolicited second response) are never relayed:
    // the gateway closes the client connection after the first.
    let dst = raw_upstream(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n[]").await;
    let h = start_with(ProxyConfig::default(), dst, Seen::default(), None).await;
    let mut s = h.connect().await;
    post(&mut s, "/mcp", &call(1, "search")).await;
    let mut buf = Vec::new();
    let r = read_response(&mut s, &mut buf).await;
    assert_eq!((r.status, r.body.as_slice()), (200, &b"{}"[..]));
    let mut rest = Vec::new();
    timeout(T, s.read_to_end(&mut rest)).await.unwrap().unwrap();
    assert!(buf.is_empty() && rest.is_empty(), "{rest:?}");

    // A 101 nobody asked for is refused.
    let dst = raw_upstream(
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
    )
    .await;
    let h = start_with(ProxyConfig::default(), dst, Seen::default(), None).await;
    let mut s = h.connect().await;
    post(&mut s, "/mcp", &call(1, "search")).await;
    assert_eq!(read_response(&mut s, &mut Vec::new()).await.status, 502);
}
