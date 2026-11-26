//! Privileged end-to-end test of the v0.4 punt flow through a real `kavachd` process.
//!
//! ```text
//!  netns kvec<pid> (kavachd and the agent; host mount/PID/cgroup namespaces)
//!  test cgroup: curl ──connect(10.203.42.2:P)──► LSM punt ─► cgroup/connect4 rewrite
//!        │                                                         │
//!        └──────────────── 127.0.0.1:<listen> ◄────────────────────┘
//!                     kavachd (in-process L7 proxy, exempt tgid)
//!                          │ orig_dst → 10.203.42.2:P, [gateway.mcp-e2e] per frame
//!                          ▼
//!  netns kves<pid>: MCP-over-HTTP server on 10.203.42.2 / 2001:db8:203:42::2 (veth)
//! ```
//!
//! The daemon gets a private pin directory, control socket, state and audit log, a freshly
//! generated trusted key and a bundle signed with it. Punt rules only match processes in a
//! private cgroup and only the namespace's addresses, so nothing else on the host is touched.
//! Run with `scripts/priv-test.sh` (root + BPF LSM); without them the test skips.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aya::maps::{Array, MapData, PerCpuArray};
use kavach_api::{Request, Response};
use kavach_common::abi::*;
use serde_json::{Value, json};

const GW: &str = "mcp-e2e";
const TAG: u32 = 42;
const SRV4: Ipv4Addr = Ipv4Addr::new(10, 203, 42, 2);
const HOST4: Ipv4Addr = Ipv4Addr::new(10, 203, 42, 1);
const SRV6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0x203, 0x42, 0, 0, 0, 2);
const HOST6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0x203, 0x42, 0, 0, 0, 1);
/// Server ports, one per kind of rule.
const P_CLOSED: u16 = 18081; // punt → gateway, fail closed
const P_OPEN: u16 = 18082; // punt → gateway, fail open
const P_LOG: u16 = 18083; // ordinary `log` rule (not punted)
const P_DENY: u16 = 18084; // ordinary `deny` rule

fn skip_reason() -> Option<&'static str> {
    if !nix::unistd::geteuid().is_root() {
        return Some("needs root");
    }
    let lsms = std::fs::read_to_string("/sys/kernel/security/lsm").unwrap_or_default();
    if !lsms.split(',').any(|l| l.trim() == "bpf") {
        return Some("BPF LSM not active");
    }
    let mounts = std::fs::read_to_string("/proc/self/mounts").unwrap_or_default();
    if kavachd::gateway::cgroup2_root(&mounts).as_deref() != Some(Path::new("/sys/fs/cgroup")) {
        return Some("cgroup v2 is not mounted at /sys/fs/cgroup");
    }
    if Command::new("curl").arg("--version").output().is_err() {
        return Some("curl not installed");
    }
    if Command::new("nsenter").arg("--version").output().is_err() {
        return Some("nsenter (util-linux) not installed");
    }
    None
}

fn sh(cmd: &str) {
    let ok = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .status()
        .unwrap()
        .success();
    assert!(ok, "setup failed: {cmd}");
}

// ---------------------------------------------------------------------------------------------
// Network namespaces: kavachd and its clients in one, the MCP server in another
// ---------------------------------------------------------------------------------------------

/// `client` (kavachd, the gateway listeners, the agent) ──veth── `server` (the MCP server).
/// Only `nsenter --net` is used to enter `client`, so the processes keep the host's mount,
/// PID and cgroup namespaces (bpffs, `/sys/fs/cgroup`, the host PID view kavachd requires).
/// The host's own interfaces and sysctls are never touched.
struct Netns {
    client: String,
    server: String,
}

impl Netns {
    fn new() -> Self {
        let id = std::process::id() % 100000;
        let n = Self {
            client: format!("kvec{id}"),
            server: format!("kves{id}"),
        };
        sh(&format!("ip netns add {}", n.client));
        sh(&format!("ip netns add {}", n.server));
        sh(&format!(
            "ip link add kvec{TAG} netns {c} type veth peer name kves{TAG} netns {s} && \
             ip -n {c} addr add {HOST4}/24 dev kvec{TAG} && \
             ip -n {c} -6 addr add {HOST6}/64 dev kvec{TAG} nodad && \
             ip -n {c} link set kvec{TAG} up && ip -n {c} link set lo up && \
             ip -n {s} addr add {SRV4}/24 dev kves{TAG} && \
             ip -n {s} -6 addr add {SRV6}/64 dev kves{TAG} nodad && \
             ip -n {s} link set kves{TAG} up && ip -n {s} link set lo up",
            c = n.client,
            s = n.server,
        ));
        n
    }

    fn path(ns: &str) -> String {
        format!("/run/netns/{ns}")
    }

    /// Run `f` on a thread that has joined `ns` (network namespaces are per thread).
    fn within<T: Send + 'static>(ns: &str, f: impl FnOnce() -> T + Send + 'static) -> T {
        let path = Self::path(ns);
        std::thread::spawn(move || {
            let fd = std::fs::File::open(path).unwrap();
            nix::sched::setns(fd, nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
            f()
        })
        .join()
        .unwrap()
    }
}

impl Drop for Netns {
    fn drop(&mut self) {
        for ns in [&self.client, &self.server] {
            let _ = Command::new("ip").args(["netns", "del", ns]).status();
        }
    }
}

/// One request the MCP server received.
#[derive(Debug, Clone)]
struct Seen {
    /// The server port it arrived on.
    port: u16,
    /// The connecting socket as the server sees it.
    peer: SocketAddr,
    /// pid owning the client end of that connection (in the host namespace).
    owner: Option<u32>,
    method: String,
    tool: Option<String>,
}

type Log = Arc<Mutex<Vec<Seen>>>;

/// A tiny MCP Streamable-HTTP server (`POST`, JSON response) on `ports`, in the server
/// namespace. Network namespaces are per thread: the listeners are created after `setns` on a
/// thread of their own, then served from threads it spawns (which inherit the namespace).
fn serve_mcp(ns: &Netns, ports: &[u16]) -> Log {
    let log: Log = Arc::default();
    let (tx, rx) = std::sync::mpsc::channel();
    let (path, ports, l) = (Netns::path(&ns.server), ports.to_vec(), log.clone());
    let client = ns.client.clone();
    std::thread::spawn(move || {
        let f = std::fs::File::open(path).unwrap();
        nix::sched::setns(f, nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
        for port in ports {
            // [::] is dual-stack (bindv6only = 0 in a fresh namespace): v4 and v6 clients.
            let lst = TcpListener::bind(("::", port)).unwrap();
            let (l, client) = (l.clone(), client.clone());
            std::thread::spawn(move || {
                for s in lst.incoming().flatten() {
                    let (l, client) = (l.clone(), client.clone());
                    std::thread::spawn(move || handle_mcp(s, port, &client, &l));
                }
            });
        }
        tx.send(()).unwrap();
    });
    rx.recv_timeout(Duration::from_secs(5))
        .expect("server listening");
    log
}

fn handle_mcp(mut s: TcpStream, port: u16, client_ns: &str, log: &Log) {
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    let peer = s.peer_addr().unwrap();
    let peer = SocketAddr::new(peer.ip().to_canonical(), peer.port());
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        // one request per connection: head, then a Content-Length body
        let head_end = buf.windows(4).position(|w| w == b"\r\n\r\n");
        if let Some(h) = head_end {
            let head = String::from_utf8_lossy(&buf[..h]).to_ascii_lowercase();
            let len = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if buf.len() >= h + 4 + len {
                let body = buf[h + 4..h + 4 + len].to_vec();
                let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                let tool = v["params"]["name"].as_str().map(str::to_owned);
                // Who is on the other end, while the connection is still open.
                let owner = Netns::within(client_ns, move || socket_owner(peer));
                log.lock().unwrap().push(Seen {
                    port,
                    peer,
                    owner,
                    method: v["method"].as_str().unwrap_or("").to_owned(),
                    tool: tool.clone(),
                });
                let out = json!({
                    "jsonrpc": "2.0",
                    "id": v["id"],
                    "result": {"content": [{"type": "text",
                        "text": format!("ok:{}:{port}", tool.unwrap_or_default())}]},
                });
                let out = serde_json::to_vec(&out).unwrap();
                let _ = s.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n",
                        out.len()
                    )
                    .as_bytes(),
                );
                let _ = s.write_all(&out);
                return;
            }
        }
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

/// `/proc/net/tcp{,6}` spelling of a socket address (words in host order, like the kernel).
fn proc_hex(a: SocketAddr) -> Vec<String> {
    let port = format!("{:04X}", a.port());
    match a.ip().to_canonical() {
        IpAddr::V4(ip) => {
            let mapped: String = ip
                .to_ipv6_mapped()
                .octets()
                .chunks(4)
                .map(|w| format!("{:08X}", u32::from_ne_bytes(w.try_into().unwrap())))
                .collect();
            vec![
                format!("{:08X}:{port}", u32::from_ne_bytes(ip.octets())),
                format!("{mapped}:{port}"),
            ]
        }
        IpAddr::V6(ip) => vec![format!(
            "{}:{port}",
            ip.octets()
                .chunks(4)
                .map(|w| format!("{:08X}", u32::from_ne_bytes(w.try_into().unwrap())))
                .collect::<String>()
        )],
    }
}

/// The process holding the TCP socket bound to `local` in the calling thread's namespace.
fn socket_owner(local: SocketAddr) -> Option<u32> {
    let want = proc_hex(local);
    let mut inode = None;
    for f in ["/proc/thread-self/net/tcp", "/proc/thread-self/net/tcp6"] {
        let text = std::fs::read_to_string(f).unwrap_or_default();
        for l in text.lines().skip(1) {
            let c: Vec<&str> = l.split_whitespace().collect();
            if c.len() > 9 && want.iter().any(|w| w == c[1]) {
                inode = Some(c[9].to_owned());
            }
        }
    }
    let link = format!("socket:[{}]", inode?);
    for p in std::fs::read_dir("/proc").ok()?.flatten() {
        let Ok(pid) = p.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(p.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            if std::fs::read_link(fd.path()).is_ok_and(|t| t.as_os_str() == link.as_str()) {
                return Some(pid);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------------------------
// The enforced cgroup and its clients
// ---------------------------------------------------------------------------------------------

/// The agent's cgroup; its processes run in the client network namespace.
struct TestCgroup {
    dir: PathBuf,
    net: String,
}

impl TestCgroup {
    fn new(ns: &Netns) -> Self {
        let dir = PathBuf::from(format!(
            "/sys/fs/cgroup/kavach-e2e-gw-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self {
            dir,
            net: Netns::path(&ns.client),
        }
    }

    /// The path policy selectors use (relative to /sys/fs/cgroup).
    fn rel(&self) -> String {
        self.dir
            .strip_prefix("/sys/fs/cgroup")
            .unwrap()
            .display()
            .to_string()
    }

    fn id(&self) -> u64 {
        kavachd::gateway::cgroup_id(&self.dir).unwrap()
    }

    /// Run `argv` inside the cgroup and the client namespace (bash moves itself in, then
    /// execs nsenter, which execs `argv`: the child's pid is the client's pid).
    fn run(&self, argv: &[&str]) -> Ran {
        let child = Command::new("bash")
            .arg("-c")
            .arg("echo $$ > \"$0\" && exec nsenter --net=\"$1\" \"${@:2}\"")
            .arg(self.dir.join("cgroup.procs"))
            .arg(&self.net)
            .args(argv)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let pid = child.id();
        let out = child.wait_with_output().unwrap();
        Ran {
            pid,
            ok: out.status.success(),
            code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    /// An MCP `tools/call` with curl to `host:port` (an address literal: no proxy settings,
    /// the kernel does the redirect).
    fn call(&self, url_host: &str, port: u16, id: u64, tool: &str) -> Ran {
        let body = tools_call(id, tool);
        let url = format!("http://{url_host}:{port}/mcp");
        self.run(&[
            "curl",
            "-sS",
            "--noproxy",
            "*",
            "--max-time",
            "5",
            "-H",
            "Content-Type: application/json",
            "-H",
            "Accept: application/json, text/event-stream",
            "--data-binary",
            &body,
            &url,
        ])
    }
}

impl Drop for TestCgroup {
    fn drop(&mut self) {
        for _ in 0..50 {
            if std::fs::remove_dir(&self.dir).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

#[derive(Debug)]
struct Ran {
    pid: u32,
    ok: bool,
    code: Option<i32>,
    stdout: String,
    #[allow(dead_code)] // shown in failure messages (Debug)
    stderr: String,
}

impl Ran {
    fn json(&self) -> Value {
        serde_json::from_str(&self.stdout).unwrap_or_else(|e| panic!("not JSON ({e}): {self:?}"))
    }
}

fn tools_call(id: u64, tool: &str) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
           "params": {"name": tool, "arguments": {"q": "x"}}})
    .to_string()
}

/// A raw `IPV6_V6ONLY` client (curl cannot set it): the same request, printed response.
const V6ONLY_CLIENT: &str = r#"
import socket, sys
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
s.settimeout(5)
s.connect((sys.argv[1], int(sys.argv[2])))
body = sys.argv[3].encode()
s.sendall(b"POST /mcp HTTP/1.1\r\nHost: mcp\r\nContent-Type: application/json\r\n"
          b"Accept: application/json, text/event-stream\r\nConnection: close\r\n"
          b"Content-Length: %d\r\n\r\n" % len(body) + body)
data = b""
while True:
    c = s.recv(65536)
    if not c:
        break
    data += c
sys.stdout.write(data.split(b"\r\n\r\n", 1)[1].decode())
"#;

// ---------------------------------------------------------------------------------------------
// The daemon
// ---------------------------------------------------------------------------------------------

struct Kavachd {
    child: Option<Child>,
    pin_root: PathBuf,
    pin: PathBuf,
    socket: PathBuf,
    audit: PathBuf,
    conf: PathBuf,
    stderr_log: PathBuf,
}

impl Kavachd {
    fn paths(tmp: &Path) -> Self {
        let pin_root = PathBuf::from(format!("/sys/fs/bpf/kavach-e2e-{}", std::process::id()));
        Self {
            child: None,
            pin: pin_root.join(format!("v{}", kavachd::kernel::ABI_VERSION)),
            pin_root,
            socket: tmp.join("kavach.sock"),
            audit: tmp.join("audit.log"),
            conf: tmp.join("kavachd.toml"),
            stderr_log: tmp.join("kavachd.log"),
        }
    }

    fn write_config(&self, tmp: &Path, listen: SocketAddr, listen6: Option<SocketAddr>) {
        let l6 = listen6
            .map(|a| format!("listen6 = \"{a}\"\n"))
            .unwrap_or_default();
        let conf = format!(
            r#"interfaces = []
tc = false
lsm = true
pin_dir = "{pin}"
socket = "{sock}"
state_dir = "{state}"
audit_log = "{audit}"
trusted_keys_dir = "{keys}"
hash_scan_dirs = []
sample_rate = 0
[anomaly]
enabled = false
[gateway]
enabled = true
listen = "{listen}"
{l6}[gateway.proxy]
idle_timeout_ms = 10000
"#,
            pin = self.pin.display(),
            sock = self.socket.display(),
            state = tmp.join("state").display(),
            audit = self.audit.display(),
            keys = tmp.join("keys").display(),
        );
        std::fs::write(&self.conf, conf).unwrap();
    }

    fn start(&mut self, net: &str) {
        assert!(self.child.is_none());
        let _ = std::fs::remove_file(&self.socket);
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.stderr_log)
            .unwrap();
        let child = Command::new("nsenter")
            .arg(format!("--net={}", Netns::path(net)))
            .arg(env!("CARGO_BIN_EXE_kavachd"))
            .arg("--config")
            .arg(&self.conf)
            .env("RUST_LOG", "info")
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .expect("spawn kavachd");
        self.child = Some(child);
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if matches!(self.try_call(&Request::Status), Ok(Response::Status(_))) {
                return;
            }
            if let Some(st) = self.child.as_mut().unwrap().try_wait().unwrap() {
                panic!("kavachd exited ({st}): {}", self.log());
            }
            assert!(Instant::now() < deadline, "kavachd API never came up");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn pid(&self) -> u32 {
        self.child.as_ref().expect("running").id()
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.stderr_log).unwrap_or_default()
    }

    fn try_call(&self, req: &Request) -> std::io::Result<Response> {
        let s = UnixStream::connect(&self.socket)?;
        s.set_read_timeout(Some(Duration::from_secs(10)))?;
        (&s).write_all(&kavach_api::encode(req))?;
        let mut line = String::new();
        BufReader::new(&s).read_line(&mut line)?;
        serde_json::from_str(&line).map_err(std::io::Error::other)
    }

    /// Signal and reap.
    fn kill(&mut self, sig: &str) {
        let mut c = self.child.take().expect("running");
        let ok = Command::new("kill")
            .args([format!("-{sig}"), c.id().to_string()])
            .status()
            .unwrap()
            .success();
        assert!(ok, "kill -{sig}");
        let deadline = Instant::now() + Duration::from_secs(10);
        while c.try_wait().unwrap().is_none() {
            if Instant::now() > deadline {
                let _ = c.kill();
                let _ = c.wait();
                panic!("kavachd did not exit on {sig}");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn map(&self, name: &str) -> MapData {
        MapData::from_pin(self.pin.join(name)).unwrap_or_else(|e| panic!("pinned {name}: {e}"))
    }

    fn gw_cfg(&self) -> GatewayCfg {
        let a: Array<_, GatewayCfg> =
            Array::try_from(aya::maps::Map::Array(self.map("gw_cfg"))).expect("gw_cfg");
        a.get(&0, 0).unwrap()
    }

    fn alive(&self) -> bool {
        let c = self.gw_cfg();
        c.flags != 0 && c.alive_until_ns > kavachd::kernel::boot_ns()
    }

    fn wait_alive(&self, want: bool, within: Duration) {
        let deadline = Instant::now() + within;
        while self.alive() != want {
            assert!(
                Instant::now() < deadline,
                "gateway liveness never became {want}: {}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn gw_stat(&self, i: u32) -> u64 {
        let a: PerCpuArray<_, u64> =
            PerCpuArray::try_from(aya::maps::Map::PerCpuArray(self.map("gw_stats")))
                .expect("gw_stats");
        a.get(&i, 0).unwrap().iter().sum()
    }

    /// Every `gateway_decision` the daemon audited so far (the chain must verify).
    fn decisions(&self) -> Vec<Value> {
        let f = std::fs::File::open(&self.audit).unwrap();
        kavach_api::audit::verify(BufReader::new(f)).expect("audit chain intact");
        std::fs::read_to_string(&self.audit)
            .unwrap()
            .lines()
            .filter_map(|l| serde_json::from_str::<kavach_api::audit::Record>(l).ok())
            .filter(|r| r.kind == "gateway_decision")
            .map(|r| r.data)
            .collect()
    }

    /// Wait for the audited decision on `tool` (the audit writer runs after the reply).
    fn decision_for(&self, tool: &str, pid: u32) -> Value {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(d) = self
                .decisions()
                .into_iter()
                .find(|d| d["target"] == tool && d["pid"] == pid)
            {
                return d;
            }
            assert!(
                Instant::now() < deadline,
                "no audited decision for {tool} (pid {pid}): {:#?}",
                self.decisions()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Kavachd {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        // Offline kill-switch: unpinning every link detaches every program.
        let _ = std::fs::remove_dir_all(&self.pin_root);
    }
}

fn policy(cgroup: &str) -> String {
    format!(
        r#"
version = 1
[defaults]
egress = "allow"
ingress = "allow"

[gateway.{GW}]
allow_tools = ["search", "github.*"]
deny_tools  = ["github.delete_*"]

[[rule]]
# Every process reaching the MCP server on this port is punted, kavachd's upstream leg
# included: that one is exempted at the LSM (no redirect loop).
id   = "mcp-punt-closed"
punt = {{ to = ["{SRV4}", "{SRV6}"], port = {P_CLOSED}, proto = "tcp", gateway = "{GW}" }}
fail = "closed"

[[rule]]
id   = "mcp-punt-open"
who  = {{ cgroup = "{cgroup}" }}
punt = {{ to = "{SRV4}", port = {P_OPEN}, proto = "tcp", gateway = "{GW}" }}
fail = "open"

[[rule]]
id  = "plain-log"
who = {{ cgroup = "{cgroup}" }}
log = {{ to = "{SRV4}", port = {P_LOG}, proto = "tcp" }}

[[rule]]
id   = "plain-deny"
who  = {{ cgroup = "{cgroup}" }}
deny = {{ to = "{SRV4}", port = {P_DENY}, proto = "tcp" }}
"#
    )
}

/// Sign `src` with a fresh key, trust that key, and apply the bundle.
fn apply(d: &Kavachd, tmp: &Path, src: &str) {
    use kavach_policy::bundle;
    let sk = bundle::generate_key();
    let keys = tmp.join("keys");
    std::fs::create_dir_all(&keys).unwrap();
    std::fs::write(
        keys.join("e2e.pub"),
        hex::encode(sk.verifying_key().as_bytes()),
    )
    .unwrap();
    let now = kavachd::kernel::unix_ns() / 1_000_000_000;
    let p = kavach_policy::compile(src, now).expect("policy").policy;
    let kvb = bundle::sign(&p, &sk, 1, now + 3600, "default").unwrap();
    match d.try_call(&Request::Apply {
        bundle: kvb,
        dry_run: false,
    }) {
        Ok(Response::Applied(r)) => assert!(r.rules >= 4, "{r:?}"),
        other => panic!("apply failed: {other:?}"),
    }
}

fn seen(log: &Log) -> Vec<Seen> {
    log.lock().unwrap().clone()
}

fn assert_allowed(r: &Ran, tool: &str, port: u16) {
    assert!(r.ok, "{tool} call failed: {r:?}");
    let v = r.json();
    assert_eq!(
        v["result"]["content"][0]["text"],
        format!("ok:{tool}:{port}"),
        "{v}"
    );
}

fn assert_denied(r: &Ran, id: u64, tool: &str) {
    assert!(r.ok, "a denied call is still an HTTP 200 exchange: {r:?}");
    let v = r.json();
    assert_eq!(v["id"], id, "{v}");
    assert_eq!(v["error"]["code"], -32001, "{v}");
    assert_eq!(v["error"]["data"]["gateway"], GW, "{v}");
    assert_eq!(v["error"]["data"]["target"], tool, "{v}");
}

/// curl could not connect (exit 7), and nothing reached the server.
fn assert_refused(r: &Ran) {
    assert!(!r.ok, "expected the connect to be refused: {r:?}");
    assert_eq!(r.code, Some(7), "curl: couldn't connect: {r:?}");
}

#[test]
#[ignore = "needs root + BPF LSM: scripts/priv-test.sh"]
fn gateway_e2e_mcp_through_kavachd() {
    if let Some(why) = skip_reason() {
        eprintln!("skipping: {why}");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let ns = Netns::new();
    let server = serve_mcp(&ns, &[P_CLOSED, P_OPEN, P_LOG, P_DENY]);
    let cg = TestCgroup::new(&ns);
    let me = std::process::id();

    // ---- run 1: IPv4 listener only (IPv6 sockets go to ::ffff:<listen>) ----
    let listen: SocketAddr = (Ipv4Addr::LOCALHOST, 15001).into();
    let mut d = Kavachd::paths(tmp.path());
    d.write_config(tmp.path(), listen, None);
    d.start(&ns.client);
    apply(&d, tmp.path(), &policy(&cg.rel()));
    d.wait_alive(true, Duration::from_secs(5));
    let kpid = d.pid();
    let (redirects0, exempt0) = (d.gw_stat(KV_GW_STAT_REDIRECT), d.gw_stat(KV_GW_STAT_EXEMPT));

    // Tool A over IPv4: redirected to the gateway, allowed, forwarded to the REAL server
    // (orig_dst recovered the address and port), by kavachd's own exempt upstream connection.
    let a = cg.call(&SRV4.to_string(), P_CLOSED, 1, "search");
    assert_allowed(&a, "search", P_CLOSED);
    let s = seen(&server);
    assert_eq!(s.len(), 1, "{s:?}");
    assert_eq!((s[0].port, s[0].method.as_str()), (P_CLOSED, "tools/call"));
    assert_eq!(s[0].tool.as_deref(), Some("search"));
    assert_eq!(s[0].peer.ip(), IpAddr::V4(HOST4));
    assert_eq!(
        s[0].owner,
        Some(kpid),
        "the upstream leg is kavachd's (curl is {}), not a loop back into the proxy",
        a.pid
    );
    assert!(d.gw_stat(KV_GW_STAT_REDIRECT) > redirects0);
    assert!(
        d.gw_stat(KV_GW_STAT_EXEMPT) > exempt0,
        "the proxy's upstream punt was exempted"
    );
    let ev = d.decision_for("search", a.pid);
    assert_eq!(ev["decision"], "allow");
    assert_eq!(ev["gateway"], GW);
    assert_eq!(ev["method"], "tools/call");
    assert_eq!(
        ev["dst"],
        format!("{SRV4}:{P_CLOSED}"),
        "original destination"
    );
    assert_eq!(ev["rule_id"], 1);
    assert_eq!(ev["cgroup_id"], cg.id());
    assert_eq!(ev["protocol"], "http");

    // Tool B: a JSON-RPC error from the gateway; the server never sees it.
    let b = cg.call(&SRV4.to_string(), P_CLOSED, 2, "github.delete_repo");
    assert_denied(&b, 2, "github.delete_repo");
    let ev = d.decision_for("github.delete_repo", b.pid);
    assert_eq!(ev["decision"], "deny");
    assert_eq!(ev["reason"], "policy");
    assert_eq!(ev["dst"], format!("{SRV4}:{P_CLOSED}"));
    // the fail-open punt rule is redirected too while the gateway is alive
    let c = cg.call(&SRV4.to_string(), P_OPEN, 3, "github.delete_repo");
    assert_denied(&c, 3, "github.delete_repo");
    assert_eq!(
        d.decision_for("github.delete_repo", c.pid)["dst"],
        format!("{SRV4}:{P_OPEN}")
    );
    assert_eq!(
        seen(&server).len(),
        1,
        "denied calls never reach the server"
    );

    // IPv6 (dual-stack curl socket → ::ffff:127.0.0.1): same decisions, v6 upstream.
    let a6 = cg.call(&format!("[{SRV6}]"), P_CLOSED, 4, "github.get_issue");
    assert_allowed(&a6, "github.get_issue", P_CLOSED);
    let s = seen(&server);
    assert_eq!(s.len(), 2);
    assert_eq!(s[1].peer.ip(), IpAddr::V6(HOST6));
    assert_eq!(s[1].owner, Some(kpid));
    let ev = d.decision_for("github.get_issue", a6.pid);
    assert_eq!(ev["dst"], format!("[{SRV6}]:{P_CLOSED}"));
    assert_eq!(
        ev["peer"].as_str().unwrap().split(':').next(),
        Some("127.0.0.1")
    );
    let b6 = cg.call(&format!("[{SRV6}]"), P_CLOSED, 5, "github.delete_repo");
    assert_denied(&b6, 5, "github.delete_repo");
    assert_eq!(
        d.decision_for("github.delete_repo", b6.pid)["dst"],
        format!("[{SRV6}]:{P_CLOSED}")
    );
    assert_eq!(seen(&server).len(), 2);

    // Non-punt rules are unaffected: `log` connects straight to the server (no gateway in the
    // path, so no L7 filtering), `deny` is refused by the LSM.
    let redirects = d.gw_stat(KV_GW_STAT_REDIRECT);
    let n_decisions = d.decisions().len();
    let l = cg.call(&SRV4.to_string(), P_LOG, 6, "github.delete_repo");
    assert_allowed(&l, "github.delete_repo", P_LOG);
    let s = seen(&server);
    assert_eq!(s.len(), 3);
    assert_eq!(
        s[2].owner,
        Some(l.pid),
        "direct connection from curl itself"
    );
    assert_refused(&cg.call(&SRV4.to_string(), P_DENY, 7, "search"));
    assert_eq!(d.gw_stat(KV_GW_STAT_REDIRECT), redirects);
    // Outside the cgroup the (cgroup-scoped) fail-open punt rule does not match: this process
    // connects directly.
    let resp = Netns::within(&ns.client, || {
        let mut direct = TcpStream::connect((SRV4, P_OPEN)).unwrap();
        let body = tools_call(8, "github.delete_repo");
        write!(
            direct,
            "POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        let mut resp = String::new();
        direct.read_to_string(&mut resp).unwrap();
        resp
    });
    assert!(resp.contains("ok:github.delete_repo"), "{resp}");
    let s = seen(&server);
    assert_eq!((s.len(), s[3].owner), (4, Some(me)));
    assert_eq!(d.gw_stat(KV_GW_STAT_REDIRECT), redirects);
    assert_eq!(d.decisions().len(), n_decisions, "no gateway decisions");

    // A connection made straight to the gateway listener has no orig_dst entry: refused.
    let sink = Netns::within(&ns.client, move || {
        let mut raw = TcpStream::connect(listen).unwrap();
        raw.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let _ = raw.write_all(tools_call(9, "search").as_bytes());
        let mut sink = Vec::new();
        let _ = raw.read_to_end(&mut sink);
        sink
    });
    assert!(sink.is_empty(), "unknown flow gets nothing: {sink:?}");
    assert_eq!(seen(&server).len(), 4);

    // ---- the gateway dies (SIGKILL: no clean shutdown) ----
    // The pinned programs keep enforcing; the liveness deadline lapses within the horizon,
    // after which punts resolve through their fail mode (docs/ARCHITECTURE.md §9c, §10).
    d.kill("KILL");
    let t0 = Instant::now();
    d.wait_alive(false, kavachd::gateway::HORIZON + Duration::from_secs(1));
    eprintln!("liveness lapsed {:?} after SIGKILL", t0.elapsed());
    assert_refused(&cg.call(&SRV4.to_string(), P_CLOSED, 10, "search"));
    assert_refused(&cg.call(&format!("[{SRV6}]"), P_CLOSED, 11, "search"));
    assert!(d.gw_stat(KV_GW_STAT_DEAD) >= 2);
    // fail open: the call goes straight to the server, unfiltered (documented fail-open)
    let o = cg.call(&SRV4.to_string(), P_OPEN, 12, "github.delete_repo");
    assert_allowed(&o, "github.delete_repo", P_OPEN);
    assert_eq!(seen(&server).last().unwrap().owner, Some(o.pid));
    // ordinary rules are still enforced by the pinned programs
    assert_allowed(
        &cg.call(&SRV4.to_string(), P_LOG, 13, "search"),
        "search",
        P_LOG,
    );
    assert_refused(&cg.call(&SRV4.to_string(), P_DENY, 14, "search"));

    // ---- run 2: restart with an IPv6 listener too ----
    // kavachd re-adopts the pins, restores the persisted bundle, and serves both listeners.
    let listen6: SocketAddr = (Ipv6Addr::LOCALHOST, 15001).into();
    d.write_config(tmp.path(), listen, Some(listen6));
    d.start(&ns.client);
    d.wait_alive(true, Duration::from_secs(5));
    assert_ne!(
        d.gw_cfg().flags & KV_GW_F_V6,
        0,
        "listen6 is served: {}",
        d.log()
    );
    let kpid = d.pid();
    let n = seen(&server).len();
    let a6 = cg.call(&format!("[{SRV6}]"), P_CLOSED, 20, "search");
    assert_allowed(&a6, "search", P_CLOSED);
    assert_eq!(seen(&server)[n].owner, Some(kpid));
    let ev = d.decision_for("search", a6.pid);
    assert_eq!(ev["dst"], format!("[{SRV6}]:{P_CLOSED}"));
    assert!(
        ev["peer"].as_str().unwrap().starts_with("[::1]"),
        "dual-stack v6 socket redirected to listen6: {ev}"
    );
    // IPV6_V6ONLY sockets can only be redirected to listen6.
    if Command::new("python3").arg("-V").output().is_ok() {
        for (id, tool, allowed) in [
            (21, "github.create_issue", true),
            (22, "github.delete_x", false),
        ] {
            let r = cg.run(&[
                "python3",
                "-c",
                V6ONLY_CLIENT,
                &SRV6.to_string(),
                &P_CLOSED.to_string(),
                &tools_call(id, tool),
            ]);
            if allowed {
                assert_allowed(&r, tool, P_CLOSED);
                assert_eq!(seen(&server).last().unwrap().owner, Some(kpid));
            } else {
                assert_denied(&r, id, tool);
            }
            let ev = d.decision_for(tool, r.pid);
            assert_eq!(ev["decision"], if allowed { "allow" } else { "deny" });
            assert_eq!(ev["dst"], format!("[{SRV6}]:{P_CLOSED}"));
        }
    } else {
        eprintln!("python3 missing: IPV6_V6ONLY client not exercised");
    }
    assert!(
        !seen(&server)
            .iter()
            .any(|s| s.tool.as_deref() == Some("github.delete_x")),
        "denied call reached the server"
    );

    // ---- clean stop (SIGTERM): the deadline is zeroed at once ----
    d.kill("TERM");
    assert!(!d.alive(), "clean exit stops redirecting immediately");
    assert_refused(&cg.call(&SRV4.to_string(), P_CLOSED, 30, "search"));
    let o = cg.call(&SRV4.to_string(), P_OPEN, 31, "search");
    assert_allowed(&o, "search", P_OPEN);
    assert_eq!(seen(&server).last().unwrap().owner, Some(o.pid));
    let log = d.log();
    assert!(!log.contains("panicked"), "{log}");
    drop(d); // kill-switch (unpin everything)
    assert!(!Path::new(&format!("/sys/fs/bpf/kavach-e2e-{me}")).exists());
}

/// The shipped gateway example (examples/gateway/) is valid and means what it says (no root).
#[test]
fn gateway_example_configs_are_valid() {
    use kavach_gateway::{Action, Decision};
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/gateway");
    let cfg = kavachd::config::Config::load(&root.join("kavachd.toml")).expect("kavachd.toml");
    assert!(cfg.gateway.enabled);
    cfg.gateway.validate().expect("valid [gateway]");
    assert_eq!(cfg.gateway.listen6, Some("[::1]:15001".parse().unwrap()));

    let src = std::fs::read_to_string(root.join("kavach.toml")).unwrap();
    let p = kavach_policy::compile(&src, 0).expect("kavach.toml").policy;
    let snap = kavachd::gateway_policies::GatewaySnapshot::from_policy(&p, 1);
    let gp = snap.policy_for_rule(1).expect("rule 1 punts to mcp-tools");
    let call = |t: &str| gp.decide(&Action::ToolCall { tool: t.into() });
    assert_eq!(call("search"), Decision::Allow);
    assert_eq!(call("github.get_issue"), Decision::Allow);
    assert_eq!(call("github.delete_repo"), Decision::Deny);
    assert_eq!(call("shell.exec"), Decision::Deny);
    assert!(
        snap.policy_for_rule(2).is_none(),
        "the deny rule is not punted"
    );
}
