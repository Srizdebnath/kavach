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
use kavach_policy::compile::{CompiledPolicy, Severity};
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
        /// Only show these kinds (xdp_drop, egress, ingress, exec, exe_tainted).
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
    Explain(ExplainArgs),
    /// Verify the hash-chained audit log.
    Audit {
        #[arg(default_value = "/var/log/kavach/audit.log")]
        log: PathBuf,
    },
    /// Detach every program and remove all pins (root only).
    KillSwitch {
        #[arg(long)]
        yes: bool,
    },
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
                "ok: {} rules, {} selectors, {} address sets, source sha256 {}",
                p.rules.len(),
                p.selectors.len(),
                p.sets.len(),
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
        Cmd::KillSwitch { yes } => {
            if !yes {
                bail!("this detaches ALL Kavach enforcement on this host; re-run with --yes");
            }
            Conn::open(sock)?.call(&Request::KillSwitch)?;
            println!("kill-switch engaged: all Kavach programs detached");
        }
    }
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

fn explain(sock: &Path, a: ExplainArgs) -> Result<()> {
    let (policy, generation) = match &a.policy {
        Some(p) => (load_policy_file(p)?, 2),
        None => active_policy(sock)?
            .ok_or_else(|| anyhow!("no active policy (use --policy kavach.toml)"))?,
    };
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
    let tables = OfflineTables::new(&policy, &facts, &[], generation & 1);
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
        println!("verdict: allow (loopback bypass)");
        return Ok(());
    }
    let q = FlowQuery {
        dir,
        mask,
        remote,
        port: a.port,
        proto,
    };
    println!(
        "identity: selectors matched = {:#b} {}",
        mask,
        (0..policy.selectors.len())
            .filter(|i| mask & (1 << i) != 0)
            .map(|i| format!("#{i}"))
            .collect::<Vec<_>>()
            .join(" ")
    );
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
    for l in lines {
        println!("{l}");
    }
    let verdict = format!("{:?}", d.verdict).to_lowercase();
    match d.rule_index {
        Some(i) => println!(
            "verdict: {verdict}  (rule {:?}{})",
            policy.rules[i].name,
            if d.punted {
                ", punt resolved by fail mode"
            } else {
                ""
            }
        ),
        None => println!(
            "verdict: {verdict}  (default {})",
            if a.ingress { "ingress" } else { "egress" }
        ),
    }
    Ok(())
}
