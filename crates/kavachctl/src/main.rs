//! kavachctl — the Kavach operator CLI. Talks to kavachd over the local Unix socket only.
#![forbid(unsafe_code)]

mod doctor;
mod top;

use std::io::{BufRead, BufReader, Write};
use std::net::IpAddr;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use kavach_api::{Request, Response, encode};
use kavach_common::abi::*;
use kavach_common::addr::to_mapped;
use kavach_core::{FlowQuery, Miss, Snapshot};
use kavach_policy::bundle;
use kavach_policy::compile::{CompiledGateway, CompiledPolicy, Severity};
use kavach_policy::kernel::{Clocks, Facts, OfflineTables};
use kavach_policy::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

#[derive(Parser)]
#[command(version, about = "Kavach kernel-native firewall control")]
struct Cli {
    /// kavachd control socket.
    #[arg(long, global = true, default_value = kavach_api::DEFAULT_SOCKET)]
    socket: PathBuf,
    /// Print raw JSON responses.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Check this host against Kavach's requirements (kernel, BTF, BPF LSM, bpffs, cgroup v2).
    Doctor,
    /// Daemon, kernel and policy status.
    Status,
    /// Verdict counters.
    Stats,
    /// Prometheus metrics.
    Metrics,
    /// Manage the XDP blocklist.
    #[command(subcommand)]
    Block(BlockCmd),
    /// Per-source XDP rate limiting (GCRA; IPv6 per /64).
    Ratelimit {
        /// Packets per second per source; `off` disables.
        pps: String,
        #[arg(long, default_value_t = 100)]
        burst: u64,
    },
    /// Stream kernel events.
    Events {
        /// Only show these kinds (xdp_drop, egress, ingress, exec, exe_tainted, anomaly).
        #[arg(long)]
        kind: Vec<String>,
    },
    /// Live dashboard: verdict rates, top denied identities, rules hit, recent events.
    Top {
        /// Refresh interval (e.g. 1s, 500ms, 2).
        #[arg(long, default_value = "1s", value_parser = top::parse_interval)]
        interval: std::time::Duration,
    },
    /// Validate kavach.toml and print diagnostics (no key needed).
    Compile { policy: PathBuf },
    /// Generate an ed25519 signing key pair (`<out>.key` stays with CI; `<out>.pub` goes to hosts).
    Keygen { out: PathBuf },
    /// Compile and sign kavach.toml into a bundle.
    Sign(SignArgs),
    /// Verify a bundle against a public key.
    Verify {
        bundle: PathBuf,
        #[arg(long)]
        pubkey: PathBuf,
        #[arg(long, default_value = "default")]
        fleet: String,
    },
    /// Apply a signed bundle to the running daemon.
    Apply {
        bundle: PathBuf,
        /// Show what would change without applying.
        #[arg(long)]
        dry_run: bool,
    },
    /// Diff a kavach.toml against the active policy.
    Diff { policy: PathBuf },
    /// Explain the verdict for a flow (same engine as the kernel: kavach-core).
    ///
    /// When the flow is punted to a gateway policy, `--tool` / `--jsonrpc` also evaluate an
    /// MCP / A2A call against it (same engine as the gateway: kavach-gateway).
    Explain(ExplainArgs),
    /// L7 gateway policies (`[gateway.<name>]` in kavach.toml).
    #[command(subcommand)]
    Gateway(GatewayCmd),
    /// Per-agent gateway kill-switch (root only; does not detach BPF programs).
    #[command(subcommand)]
    Agent(AgentCmd),
    /// Verify the hash-chained audit log.
    Audit {
        #[arg(default_value = "/var/log/kavach/audit.log")]
        log: PathBuf,
    },
    /// Detach every program and remove all pins (root only).
    ///
    /// Goes through kavachd when it is running. If the daemon is not reachable (stopped,
    /// crashed, being uninstalled), removes every Kavach pin under `--pin-root` directly:
    /// pinned links detach once their last pin is gone.
    KillSwitch {
        #[arg(long)]
        yes: bool,
        /// Root of all Kavach pins (every ABI version lives below it).
        #[arg(long, default_value = "/sys/fs/bpf/kavach")]
        pin_root: PathBuf,
    },
}

#[derive(Subcommand)]
enum GatewayCmd {
    /// List gateway policies and the punt rules that use them.
    List {
        /// Read a local kavach.toml instead of the daemon's active policy.
        #[arg(long)]
        policy: Option<PathBuf>,
    },
    /// Decide every JSON-RPC frame in a file (one per line; `-` = stdin) with one policy.
    Test {
        /// Gateway policy name.
        name: String,
        /// File of JSON-RPC frames, one per line (blank lines and `#` comments are skipped).
        frames: PathBuf,
        /// Read a local kavach.toml instead of the daemon's active policy.
        #[arg(long)]
        policy: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum AgentCmd {
    /// Disable one agent at the gateway (takes effect on the next frame).
    Kill {
        /// Agent id from `[[agent]]` in the active policy.
        id: String,
    },
    /// Re-enable one agent at the gateway.
    Enable {
        /// Agent id from `[[agent]]` in the active policy.
        id: String,
    },
    /// Show disabled agents and the ids known from the active policy.
    Status,
}

#[derive(Subcommand)]
enum BlockCmd {
    Add {
        cidr: String,
        /// Expire after this long (e.g. 30m, 12h, 7d).
        #[arg(long)]
        ttl: Option<String>,
        #[arg(long)]
        reason: Option<u32>,
    },
    Del {
        cidr: String,
    },
    List,
}

#[derive(Args)]
struct SignArgs {
    policy: PathBuf,
    #[arg(long)]
    key: PathBuf,
    #[arg(short, long)]
    out: PathBuf,
    /// Monotonic serial (default: current unix time).
    #[arg(long)]
    serial: Option<u64>,
    #[arg(long, default_value = "default")]
    fleet: String,
    /// Bundle validity (e.g. 90d). Past expiry hosts keep enforcing and alert.
    #[arg(long)]
    valid_for: Option<String>,
}

#[derive(Args)]
struct ExplainArgs {
    /// Remote address (egress destination / ingress source).
    #[arg(long)]
    to: IpAddr,
    #[arg(long)]
    port: u16,
    #[arg(long, default_value = "tcp")]
    proto: String,
    #[arg(long)]
    ingress: bool,
    /// Executable path (hashed locally) or `sha256:<hex>`.
    #[arg(long)]
    binary: Option<String>,
    #[arg(long)]
    uid: Option<u32>,
    #[arg(long)]
    user: Option<String>,
    /// cgroup v2 path relative to /sys/fs/cgroup.
    #[arg(long)]
    cgroup: Option<String>,
    /// Explain against a local kavach.toml instead of the daemon's active policy.
    #[arg(long)]
    policy: Option<PathBuf>,
    /// L7: an MCP `tools/call` of this tool, decided by the punt rule's gateway policy.
    #[arg(long, conflicts_with = "jsonrpc")]
    tool: Option<String>,
    /// L7: one JSON-RPC frame (or `@file`), decided by the punt rule's gateway policy.
    #[arg(long)]
    jsonrpc: Option<String>,
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

struct Conn {
    rd: BufReader<UnixStream>,
    wr: UnixStream,
}

impl Conn {
    fn open(path: &Path) -> Result<Self> {
        let s = UnixStream::connect(path)
            .with_context(|| format!("connecting to kavachd at {}", path.display()))?;
        Ok(Self {
            rd: BufReader::new(s.try_clone()?),
            wr: s,
        })
    }
    fn send(&mut self, r: &Request) -> Result<()> {
        self.wr.write_all(&encode(r))?;
        Ok(())
    }
    fn recv(&mut self) -> Result<Response> {
        let mut line = String::new();
        if self.rd.read_line(&mut line)? == 0 {
            bail!("kavachd closed the connection (permission denied?)");
        }
        Ok(serde_json::from_str(&line)?)
    }
    fn call(&mut self, r: &Request) -> Result<Response> {
        self.send(r)?;
        match self.recv()? {
            Response::Error { message } => Err(anyhow!(message)),
            other => Ok(other),
        }
    }
}

fn print_json(r: &Response) {
    println!("{}", serde_json::to_string_pretty(r).unwrap_or_default());
}

fn load_policy_file(path: &Path) -> Result<CompiledPolicy> {
    let src =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    match kavach_policy::compile(&src, now_unix()) {
        Ok(out) => {
            for w in &out.warnings {
                eprintln!("{w}");
            }
            Ok(out.policy)
        }
        Err(diags) => {
            for d in &diags {
                eprintln!("{d}");
            }
            let n = diags
                .iter()
                .filter(|d| d.severity == Severity::Error)
                .count();
            bail!("{} has {n} error(s)", path.display())
        }
    }
}

fn active_policy(socket: &Path) -> Result<Option<(CompiledPolicy, u32)>> {
    match Conn::open(socket)?.call(&Request::ActivePolicy)? {
        Response::ActivePolicy {
            policy: Some(bytes),
            generation,
            ..
        } => Ok(Some((postcard::from_bytes(&bytes)?, generation))),
        Response::ActivePolicy { policy: None, .. } => Ok(None),
        other => bail!("unexpected response {other:?}"),
    }
}

fn read_key(path: &Path) -> Result<SigningKey> {
    let s = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let b: [u8; 32] = hex::decode(s.trim())?
        .try_into()
        .map_err(|_| anyhow!("signing key must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&b))
}

fn read_pub(path: &Path) -> Result<VerifyingKey> {
    let s = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let b: [u8; 32] = hex::decode(s.trim())?
        .try_into()
        .map_err(|_| anyhow!("public key must be 32 bytes"))?;
    Ok(VerifyingKey::from_bytes(&b)?)
}

fn run(cli: Cli) -> Result<()> {
    let sock = cli.socket.as_path();
    match cli.cmd {
        Cmd::Status => {
            let r = Conn::open(sock)?.call(&Request::Status)?;
            if cli.json {
                print_json(&r);
            } else if let Response::Status(s) = r {
                println!(
                    "kavachd {}   kernel {}   up {}s",
                    s.version, s.kernel, s.uptime_secs
                );
                println!(
                    "policy    serial {}  generation {}  rules {}{}",
                    s.serial,
                    s.generation,
                    s.rules,
                    if s.policy_expired {
                        "  (EXPIRED — replace it)"
                    } else {
                        ""
                    }
                );
                for (i, m) in &s.xdp {
                    println!("xdp       {i} ({m})");
                }
                println!(
                    "tc        {}",
                    if s.tc.is_empty() {
                        "-".into()
                    } else {
                        s.tc.join(", ")
                    }
                );
                println!(
                    "lsm       {}",
                    if s.lsm {
                        "attached (identity egress on)"
                    } else {
                        "off"
                    }
                );
            }
        }
        Cmd::Stats => {
            let r = Conn::open(sock)?.call(&Request::Stats)?;
            if cli.json {
                print_json(&r);
            } else if let Response::Stats { counters } = r {
                for (n, c) in counters {
                    println!("{n:<20} {c}");
                }
            }
        }
        Cmd::Metrics => {
            if let Response::Metrics { text } = Conn::open(sock)?.call(&Request::Metrics)? {
                print!("{text}");
            }
        }
        Cmd::Block(b) => {
            let req = match b {
                BlockCmd::Add { cidr, ttl, reason } => Request::BlockAdd {
                    cidr,
                    ttl_secs: ttl
                        .map(|t| kavach_policy::compile::parse_duration(&t))
                        .transpose()
                        .map_err(|e| anyhow!(e))?,
                    reason,
                },
                BlockCmd::Del { cidr } => Request::BlockDel { cidr },
                BlockCmd::List => Request::BlockList,
            };
            let r = Conn::open(sock)?.call(&req)?;
            match r {
                Response::BlockList { entries } if !cli.json => {
                    for e in entries {
                        let exp = e
                            .expires_in
                            .map_or("permanent".into(), |s| format!("{s}s left"));
                        println!("{:<44} reason={:<6} {exp}", e.cidr, e.reason);
                    }
                }
                Response::Ok if !cli.json => println!("ok"),
                other => print_json(&other),
            }
        }
        Cmd::Ratelimit { pps, burst } => {
            let req = if pps == "off" {
                Request::RateLimitOff
            } else {
                Request::RateLimit {
                    pps: pps.parse().context("pps must be a number or `off`")?,
                    burst,
                }
            };
            Conn::open(sock)?.call(&req)?;
            println!("ok");
        }
        Cmd::Events { kind } => {
            let mut c = Conn::open(sock)?;
            c.send(&Request::Events)?;
            loop {
                match c.recv()? {
                    Response::Event(e) => {
                        if !kind.is_empty() && !kind.contains(&e.kind) {
                            continue;
                        }
                        if cli.json {
                            println!("{}", serde_json::to_string(&e)?);
                        } else {
                            let flow = top::format_flow(&e);
                            let rule = e.rule.clone().unwrap_or_else(|| {
                                if e.rule_id == 0 {
                                    "default".into()
                                } else {
                                    e.rule_id.to_string()
                                }
                            });
                            if e.kind == "anomaly" {
                                println!(
                                    "{:<11} {:<5} {:<48} pid={} uid={} comm={} cgroup={}",
                                    e.kind,
                                    "",
                                    e.detail.as_deref().unwrap_or(&e.reason),
                                    e.pid,
                                    e.uid,
                                    e.comm,
                                    e.cgroup_id
                                );
                                continue;
                            }
                            println!(
                                "{:<11} {:<5} {flow:<48} pid={} uid={} comm={} rule={rule} {}",
                                e.kind, e.verdict, e.pid, e.uid, e.comm, e.reason
                            );
                        }
                    }
                    Response::Error { message } => eprintln!("warning: {message}"),
                    _ => {}
                }
            }
        }
        Cmd::Top { interval } => top::run(sock, interval)?,
        Cmd::Doctor => {
            if !doctor::run() {
                bail!("a required check failed");
            }
        }
        Cmd::Compile { policy } => {
            let p = load_policy_file(&policy)?;
            println!(
                "ok: {} rules, {} selectors, {} address sets, {} gateway policies, source sha256 {}",
                p.rules.len(),
                p.selectors.len(),
                p.sets.len(),
                p.gateways.len(),
                hex::encode(p.source_sha256)
            );
        }
        Cmd::Keygen { out } => {
            let sk = bundle::generate_key();
            let key_path = out.with_extension("key");
            let pub_path = out.with_extension("pub");
            if key_path.exists() {
                bail!("{} already exists", key_path.display());
            }
            write_secret(&key_path, &hex::encode(sk.to_bytes()))?;
            std::fs::write(&pub_path, hex::encode(sk.verifying_key().to_bytes()) + "\n")?;
            println!(
                "private key  {}  (keep in CI / a vault, never on enforcing hosts)",
                key_path.display()
            );
            println!(
                "public key   {}  (copy to /etc/kavach/trusted_keys/)",
                pub_path.display()
            );
            println!("key id       {}", bundle::key_id_hex(&sk.verifying_key()));
        }
        Cmd::Sign(a) => {
            let p = load_policy_file(&a.policy)?;
            let sk = read_key(&a.key)?;
            let serial = a.serial.unwrap_or_else(now_unix);
            let not_after = a
                .valid_for
                .map(|v| kavach_policy::compile::parse_duration(&v).map(|s| now_unix() + s))
                .transpose()
                .map_err(|e| anyhow!(e))?
                .unwrap_or(0);
            let b = bundle::sign(&p, &sk, serial, not_after, &a.fleet)?;
            std::fs::write(&a.out, &b)?;
            println!(
                "signed {} → {} (serial {serial}, fleet {}, key {}, {} bytes)",
                a.policy.display(),
                a.out.display(),
                a.fleet,
                bundle::key_id_hex(&sk.verifying_key()),
                b.len()
            );
        }
        Cmd::Verify {
            bundle: path,
            pubkey,
            fleet,
        } => {
            let bytes = std::fs::read(&path)?;
            let vk = read_pub(&pubkey)?;
            let trust = bundle::TrustPolicy {
                trusted: vec![vk],
                revoked: vec![],
                fleet,
                active_serial: 0,
                now_unix: now_unix(),
            };
            let v = bundle::verify(&bytes, &trust, false)?;
            println!(
                "valid: serial {}  fleet {}  key {}  created {}  rules {}{}",
                v.header.serial,
                v.header.fleet,
                hex::encode(v.header.key_id),
                v.header.created_unix,
                v.policy.rules.len(),
                if v.expired { "  (EXPIRED)" } else { "" }
            );
        }
        Cmd::Apply {
            bundle: path,
            dry_run,
        } => {
            let bytes =
                std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            let r = Conn::open(sock)?.call(&Request::Apply {
                bundle: bytes,
                dry_run,
            })?;
            if cli.json {
                print_json(&r);
            } else if let Response::Applied(rep) = r {
                for c in &rep.changes {
                    println!("  {c}");
                }
                if rep.dry_run {
                    println!(
                        "dry run: serial {} would replace the active policy ({} rules)",
                        rep.serial, rep.rules
                    );
                } else {
                    println!(
                        "applied serial {} as generation {} ({} rules, atomic swap {} µs)",
                        rep.serial, rep.generation, rep.rules, rep.swap_micros
                    );
                }
                for w in &rep.warnings {
                    eprintln!("warning: {w}");
                }
            }
        }
        Cmd::Diff { policy } => {
            let new = load_policy_file(&policy)?;
            match active_policy(sock)? {
                None => println!("no active policy: everything is new"),
                Some((old, _)) => {
                    let d = kavach_policy::diff::diff(&old, &new);
                    if d.is_empty() {
                        println!("no changes");
                    }
                    for c in d {
                        println!("{c}");
                    }
                }
            }
        }
        Cmd::Explain(a) => explain(sock, a)?,
        Cmd::Gateway(GatewayCmd::List { policy }) => {
            let p = policy_source(sock, policy.as_deref())?.0;
            for l in gateway_list_lines(&p) {
                println!("{l}");
            }
        }
        Cmd::Gateway(GatewayCmd::Test {
            name,
            frames,
            policy,
        }) => {
            let p = policy_source(sock, policy.as_deref())?.0;
            let g = p
                .gateway(&name)
                .ok_or_else(|| anyhow!("no gateway policy {name:?}"))?;
            let text = if frames.as_os_str() == "-" {
                std::io::read_to_string(std::io::stdin())?
            } else {
                std::fs::read_to_string(&frames)
                    .with_context(|| format!("reading {}", frames.display()))?
            };
            for l in gateway_test_lines(g, &text, cli.json) {
                println!("{l}");
            }
        }
        Cmd::Agent(cmd) => {
            let (id, disabled) = match cmd {
                AgentCmd::Kill { id } => (id, true),
                AgentCmd::Enable { id } => (id, false),
                AgentCmd::Status => {
                    match Conn::open(sock)?.call(&Request::AgentStatus)? {
                        Response::AgentStatus { disabled, known } if !cli.json => {
                            println!(
                                "agents:    {}",
                                if known.is_empty() {
                                    "-".into()
                                } else {
                                    known.join(", ")
                                }
                            );
                            println!(
                                "disabled:  {}",
                                if disabled.is_empty() {
                                    "-".into()
                                } else {
                                    disabled.join(", ")
                                }
                            );
                        }
                        other => print_json(&other),
                    }
                    return Ok(());
                }
            };
            Conn::open(sock)?.call(&Request::AgentKillSwitch {
                id: id.clone(),
                disabled,
            })?;
            if !cli.json {
                println!(
                    "agent {id}: {}",
                    if disabled { "disabled" } else { "enabled" }
                );
            }
        }
        Cmd::Audit { log } => {
            let f =
                std::fs::File::open(&log).with_context(|| format!("opening {}", log.display()))?;
            let chain = kavach_api::audit::verify(BufReader::new(f))?;
            println!(
                "audit log intact: {} records, head {}",
                chain.next_seq,
                hex::encode(chain.last)
            );
        }
        Cmd::KillSwitch { yes, pin_root } => {
            if !yes {
                bail!("this detaches ALL Kavach enforcement on this host; re-run with --yes");
            }
            match Conn::open(sock) {
                Ok(mut c) => {
                    c.call(&Request::KillSwitch)?;
                    println!("kill-switch engaged: all Kavach programs detached");
                }
                Err(e) => {
                    eprintln!("kavachd not reachable ({e:#}); removing pins directly");
                    kill_switch_offline(&pin_root)?;
                }
            }
        }
    }
    Ok(())
}

/// Daemon-less kill-switch: remove the whole pin tree. Programs whose links were pinned
/// detach as soon as the last reference (the pin) disappears.
fn kill_switch_offline(root: &Path) -> Result<()> {
    if !root.exists() {
        println!("kill-switch: nothing pinned under {}", root.display());
        return Ok(());
    }
    std::fs::remove_dir_all(root)
        .with_context(|| format!("removing {} (the kill-switch needs root)", root.display()))?;
    println!(
        "kill-switch engaged offline: removed {}, all Kavach programs detached",
        root.display()
    );
    Ok(())
}

fn write_secret(path: &Path, contents: &str) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(contents.as_bytes())?;
    f.write_all(b"\n")?;
    Ok(())
}

/// A local kavach.toml (compiled, generation 2) or the daemon's active policy.
fn policy_source(sock: &Path, local: Option<&Path>) -> Result<(CompiledPolicy, u32)> {
    match local {
        Some(p) => Ok((load_policy_file(p)?, 2)),
        None => active_policy(sock)?
            .ok_or_else(|| anyhow!("no active policy (use --policy kavach.toml)")),
    }
}

fn explain(sock: &Path, a: ExplainArgs) -> Result<()> {
    let (policy, generation) = policy_source(sock, a.policy.as_deref())?;
    for l in explain_lines(&policy, generation, &a)? {
        println!("{l}");
    }
    Ok(())
}

/// What `--tool` / `--jsonrpc` ask the gateway to decide.
enum L7Input {
    Tool(String),
    Frame(Vec<u8>),
}

impl L7Input {
    fn from_args(a: &ExplainArgs) -> Result<Option<Self>> {
        Ok(match (&a.tool, &a.jsonrpc) {
            (Some(t), _) => Some(Self::Tool(t.clone())),
            (None, Some(f)) => Some(Self::Frame(match f.strip_prefix('@') {
                Some(path) => std::fs::read(path).with_context(|| format!("reading {path}"))?,
                None => f.clone().into_bytes(),
            })),
            (None, None) => None,
        })
    }
}

fn describe_l7(a: &kavach_gateway::Action) -> String {
    use kavach_gateway::Action as A;
    match a {
        A::ToolCall { tool } => format!("tools/call {tool}"),
        A::ResourceRead { uri } => format!("resources/read {uri}"),
        A::AgentMessage => "message/send (A2A delegation)".into(),
        A::Control => "control (handshake / discovery)".into(),
        A::Other { method } => format!("method {method}"),
    }
}

fn decision_word(d: kavach_gateway::Decision) -> &'static str {
    match d {
        kavach_gateway::Decision::Allow => "allow",
        kavach_gateway::Decision::Deny => "deny",
    }
}

/// Classify and decide one frame with a gateway policy: (decision, call, reason).
fn gateway_decide(g: &CompiledGateway, frame: &[u8]) -> (&'static str, String, String) {
    match kavach_gateway::classify(frame) {
        Ok(action) => {
            let (d, why) = g.to_tool_policy().explain(&action);
            (decision_word(d), describe_l7(&action), why)
        }
        Err(e) => (
            "deny",
            "unparseable frame".into(),
            format!("{e:?}: not one JSON-RPC 2.0 request; unparseable frames fail closed"),
        ),
    }
}

fn gateway_explain_lines(g: &CompiledGateway, input: &L7Input) -> Vec<String> {
    let (d, call, why) = match input {
        L7Input::Tool(t) => {
            let action = kavach_gateway::Action::ToolCall { tool: t.clone() };
            let (d, why) = g.to_tool_policy().explain(&action);
            (decision_word(d), describe_l7(&action), why)
        }
        L7Input::Frame(f) => gateway_decide(g, f),
    };
    vec![
        format!("  call:    {call}"),
        format!("l7 verdict: {d}  ({why})"),
    ]
}

fn tls_word(g: &CompiledGateway) -> &'static str {
    match g.tls {
        kavach_policy::schema::GatewayTls::Deny => "deny",
        kavach_policy::schema::GatewayTls::Allow => "allow",
    }
}

fn gateway_list_lines(p: &CompiledPolicy) -> Vec<String> {
    if p.gateways.is_empty() {
        return vec!["no gateway policies".into()];
    }
    let mut out = Vec::new();
    for g in &p.gateways {
        let mut rules: Vec<&str> = p
            .rules
            .iter()
            .filter(|r| p.rule_gateway(r).is_some_and(|rg| rg.name == g.name))
            .map(|r| r.name.as_str())
            .collect();
        rules.dedup();
        out.push(format!(
            "{}  tls={}  agent_messages={}  other={}  rules: {}",
            g.name,
            tls_word(g),
            g.allow_agent_messages,
            g.allow_other,
            if rules.is_empty() {
                "-".into()
            } else {
                rules.join(", ")
            }
        ));
        for (k, v) in [
            ("allow_tools", &g.allow_tools),
            ("deny_tools", &g.deny_tools),
            ("allow_resources", &g.allow_resources),
        ] {
            if !v.is_empty() {
                out.push(format!("  {k:<16} {}", v.join(" ")));
            }
        }
    }
    out
}

fn gateway_test_lines(g: &CompiledGateway, text: &str, json: bool) -> Vec<String> {
    text.lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .map(|(i, l)| {
            let (d, call, why) = gateway_decide(g, l.as_bytes());
            if json {
                serde_json::json!({
                    "line": i + 1, "decision": d, "call": call, "reason": why,
                })
                .to_string()
            } else {
                format!("{:>4}  {d:<5}  {call:<40}  {why}", i + 1)
            }
        })
        .collect()
}

fn explain_lines(policy: &CompiledPolicy, generation: u32, a: &ExplainArgs) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let l7 = L7Input::from_args(a)?;
    let sha = match a.binary.as_deref() {
        None => None,
        Some(s) if s.starts_with("sha256:") => Some(
            hex::decode(&s[7..])?
                .try_into()
                .map_err(|_| anyhow!("sha256 must be 32 bytes"))?,
        ),
        Some(path) => Some(
            Sha256::digest(std::fs::read(path).with_context(|| format!("reading {path}"))?).into(),
        ),
    };
    let exe = a.binary.as_deref().filter(|b| !b.starts_with("sha256:"));
    let facts = Facts {
        sha256: sha,
        exe,
        uid: a.uid,
        user_name: a.user.as_deref(),
        cgroup: a.cgroup.as_deref(),
    };
    let proto = match a.proto.as_str() {
        "tcp" => KV_PROTO_TCP,
        "udp" => KV_PROTO_UDP,
        "icmp" => KV_PROTO_ICMP,
        "icmpv6" => KV_PROTO_ICMPV6,
        other => bail!("unknown proto {other}"),
    };
    let tables = OfflineTables::new(policy, &facts, &[], generation & 1);
    let clocks = Clocks {
        unix_ns: now_unix() * 1_000_000_000,
        boot_ns: 1,
    };
    let table = policy.to_kernel(generation, 0, clocks);
    let snap = Snapshot::new(&table, generation).ok_or_else(|| anyhow!("invalid policy table"))?;
    let dir = if a.ingress {
        KV_DIR_INGRESS
    } else {
        KV_DIR_EGRESS
    };
    let mask = if a.ingress {
        0
    } else {
        kavach_core::identity_mask(&tables, &snap, &tables.who())
    };
    let remote = to_mapped(a.to);
    let bypass = table.hdr.flags & KV_POL_F_NO_LOOPBACK_BYPASS == 0;
    if !a.ingress && bypass && kavach_common::addr::is_loopback(remote) {
        out.push("verdict: allow (loopback bypass)".into());
        if l7.is_some() {
            out.push("l7: not evaluated (the flow is not punted)".into());
        }
        return Ok(out);
    }
    let q = FlowQuery {
        dir,
        mask,
        remote,
        port: a.port,
        proto,
    };
    out.push(format!(
        "identity: selectors matched = {:#b} {}",
        mask,
        (0..policy.selectors.len())
            .filter(|i| mask & (1 << i) != 0)
            .map(|i| format!("#{i}"))
            .collect::<Vec<_>>()
            .join(" ")
    ));
    let mut lines = Vec::new();
    let d = kavach_core::evaluate_traced(&tables, &snap, &q, 1, |i, m| {
        let r = &policy.rules[i];
        let why = match m {
            None => "MATCH".to_owned(),
            Some(Miss::Direction) => return,
            Some(Miss::Identity) => "skip: identity does not match `who`".into(),
            Some(Miss::Protocol) => "skip: protocol".into(),
            Some(Miss::Port) => format!("skip: port not in {}-{}", r.port_lo, r.port_hi),
            Some(Miss::RemoteAddress) => "skip: address not in set".into(),
            Some(Miss::Expired) => "skip: ttl expired".into(),
        };
        lines.push(format!("  [{i:>3}] {:<28} {why}", r.name));
    });
    out.extend(lines);
    let verdict = format!("{:?}", d.verdict).to_lowercase();
    match d.rule_index {
        Some(i) => out.push(format!(
            "verdict: {verdict}  (rule {:?}{})",
            policy.rules[i].name,
            if d.punted {
                ", punt resolved by fail mode"
            } else {
                ""
            }
        )),
        None => out.push(format!(
            "verdict: {verdict}  (default {})",
            if a.ingress { "ingress" } else { "egress" }
        )),
    }
    let rule = d
        .rule_index
        .map(|i| &policy.rules[i])
        .filter(|r| r.verdict == Verdict::Punt as u8);
    match (rule, &l7) {
        (None, Some(_)) => out.push("l7: not evaluated (the flow is not punted)".into()),
        (None, None) => {}
        (Some(r), l7) => match policy.rule_gateway(r) {
            None => out.push(format!(
                "gateway: none (rule {:?} names no gateway policy; its fail mode decides)",
                r.name
            )),
            Some(g) => {
                out.push(format!("gateway: {}  (tls = {})", g.name, tls_word(g)));
                match l7 {
                    Some(input) => out.extend(gateway_explain_lines(g, input)),
                    None => out.push(
                        "  pass --tool <name> or --jsonrpc '<frame>' to evaluate a call".into(),
                    ),
                }
            }
        },
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = r#"
version = 1
[defaults]
egress = "drop"
[gateway.github-agent]
allow_tools     = ["github.*"]
deny_tools      = ["github.delete_*"]
allow_resources = ["repo://acme/"]
[[rule]]
id   = "dns"
allow = { to = "1.1.1.1", port = 53, proto = "udp" }
[[rule]]
id   = "mcp"
punt = { to = "203.0.113.0/24", port = 443, proto = "tcp", gateway = "github-agent" }
"#;

    #[test]
    fn agent_kill_switch_cli_and_request() {
        let cli = Cli::try_parse_from(["kavachctl", "agent", "kill", "support-bot"]).unwrap();
        assert!(matches!(
            cli.cmd,
            Cmd::Agent(AgentCmd::Kill { ref id }) if id == "support-bot"
        ));
        let cli = Cli::try_parse_from(["kavachctl", "agent", "enable", "support-bot"]).unwrap();
        assert!(matches!(cli.cmd, Cmd::Agent(AgentCmd::Enable { .. })));
        let req = Request::AgentKillSwitch {
            id: "support-bot".into(),
            disabled: true,
        };
        let line = String::from_utf8(encode(&req)).unwrap();
        assert_eq!(
            line,
            "{\"op\":\"agent_kill_switch\",\"id\":\"support-bot\",\"disabled\":true}\n"
        );
        assert_eq!(serde_json::from_str::<Request>(line.trim()).unwrap(), req);
    }

    fn args(to: &str, port: u16) -> ExplainArgs {
        ExplainArgs {
            to: to.parse().unwrap(),
            port,
            proto: "tcp".into(),
            ingress: false,
            binary: None,
            uid: None,
            user: None,
            cgroup: None,
            policy: None,
            tool: None,
            jsonrpc: None,
        }
    }

    fn explained(a: &ExplainArgs) -> String {
        let p = kavach_policy::compile(POLICY, 0).unwrap().policy;
        explain_lines(&p, 2, a).unwrap().join("\n")
    }

    #[test]
    fn explain_evaluates_tool_calls_on_punted_flows() {
        let mut a = args("203.0.113.9", 443);
        a.tool = Some("github.delete_repo".into());
        let out = explained(&a);
        assert!(
            out.contains("verdict: drop  (rule \"mcp\", punt resolved by fail mode)"),
            "{out}"
        );
        assert!(out.contains("gateway: github-agent  (tls = deny)"), "{out}");
        assert!(
            out.contains("  call:    tools/call github.delete_repo"),
            "{out}"
        );
        assert!(
            out.contains("l7 verdict: deny  (deny_tools pattern \"github.delete_*\")"),
            "{out}"
        );

        a.tool = Some("github.create_issue".into());
        assert!(explained(&a).contains("l7 verdict: allow  (allow_tools pattern \"github.*\")"));

        a.tool = None;
        a.jsonrpc = Some(
            r#"{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"repo://acme/x"}}"#
                .into(),
        );
        let out = explained(&a);
        assert!(
            out.contains("call:    resources/read repo://acme/x"),
            "{out}"
        );
        assert!(out.contains("l7 verdict: allow  (allow_resources prefix \"repo://acme/\")"));

        a.jsonrpc = Some("[]".into());
        assert!(explained(&a).contains("l7 verdict: deny  (Batch:"));

        a.jsonrpc = None;
        assert!(explained(&a).contains("pass --tool <name>"));
    }

    #[test]
    fn explain_skips_l7_for_flows_that_are_not_punted() {
        let mut a = args("1.1.1.1", 53);
        a.proto = "udp".into();
        a.tool = Some("github.x".into());
        let out = explained(&a);
        assert!(out.contains("verdict: allow  (rule \"dns\")"), "{out}");
        assert!(
            out.contains("l7: not evaluated (the flow is not punted)"),
            "{out}"
        );
        assert!(!out.contains("gateway:"), "{out}");
    }

    #[test]
    fn explain_reads_frames_from_a_file() {
        let t = tempfile::tempdir().unwrap();
        let f = t.path().join("frame.json");
        std::fs::write(
            &f,
            r#"{"jsonrpc":"2.0","id":1,"method":"message/send","params":{}}"#,
        )
        .unwrap();
        let mut a = args("203.0.113.9", 443);
        a.jsonrpc = Some(format!("@{}", f.display()));
        let out = explained(&a);
        assert!(
            out.contains("l7 verdict: deny  (allow_agent_messages = false)"),
            "{out}"
        );
    }

    #[test]
    fn gateway_test_and_list_output() {
        let p = kavach_policy::compile(POLICY, 0).unwrap().policy;
        let g = p.gateway("github-agent").unwrap();
        let frames = r#"
# allowed
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"github.get_issue"}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"shell.exec"}}
{"jsonrpc":"2.0","id":3,"method":"tools/list"}
not json
"#;
        let out = gateway_test_lines(g, frames, false);
        assert_eq!(out.len(), 4, "{out:?}");
        assert!(
            out[0].starts_with("   3  allow  tools/call github.get_issue"),
            "{out:?}"
        );
        assert!(
            out[1].contains("deny   tools/call shell.exec")
                && out[1].ends_with("no allow_tools pattern matches")
        );
        assert!(out[2].contains("allow  control"));
        assert!(out[3].contains("deny   unparseable frame"));
        let j: serde_json::Value =
            serde_json::from_str(&gateway_test_lines(g, frames, true)[1]).unwrap();
        assert_eq!(j["decision"], "deny");
        assert_eq!(j["line"], 4);

        let l = gateway_list_lines(&p).join("\n");
        assert!(
            l.contains("github-agent  tls=deny  agent_messages=false  other=false  rules: mcp"),
            "{l}"
        );
        assert!(l.contains("  deny_tools       github.delete_*"), "{l}");
    }

    #[test]
    fn offline_kill_switch_removes_every_abi_version() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("kavach");
        for v in ["v1", "v2"] {
            std::fs::create_dir_all(root.join(v)).unwrap();
            std::fs::write(root.join(v).join("xdp_link"), b"").unwrap();
        }
        kill_switch_offline(&root).unwrap();
        assert!(!root.exists());
        // idempotent: nothing pinned is not an error (uninstall runs it unconditionally)
        kill_switch_offline(&root).unwrap();
    }
}
