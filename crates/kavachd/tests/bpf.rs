//! Privileged tests that run the real eBPF programs in the running kernel.
//!
//! They need CAP_BPF/CAP_SYS_ADMIN, so they are `#[ignore]`d by default. Run them with
//! `scripts/priv-test.sh` (builds as the user, runs the test binary under sudo).
//! Every test uses a private pin directory and engages the kill-switch on drop. The LSM test
//! only ever denies TEST-NET-1 (192.0.2.0/24) destinations, so it cannot disturb the host.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use aya::maps::{MapData, RingBuf};
use aya::programs::{ProgramError, SchedClassifier, TestRun, TestRunOptions, Xdp};
use ipnet::IpNet;
use kavach_common::abi::*;
use kavach_common::addr::to_mapped;
use kavach_core::{FlowQuery, Snapshot};
use kavach_policy::kernel::{Facts, OfflineTables};
use kavachd::config::Config;
use kavachd::daemon::{self, Daemon, KeyReport};
use kavachd::kernel::{self, Kernel};

const XDP_DROP: u32 = 1;
const XDP_PASS: u32 = 2;
const TC_OK: u32 = 0;
const TC_SHOT: u32 = 2;

static N: AtomicU32 = AtomicU32::new(0);

/// A loaded Kernel in a private pin dir, cleaned up on drop.
struct Fixture {
    daemon: Option<Daemon>,
    _tmp: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let n = N.fetch_add(1, Ordering::SeqCst);
        let pin = std::path::PathBuf::from(format!(
            "/sys/fs/bpf/kavach-test-{}-{n}",
            std::process::id()
        ));
        let k = Kernel::load(&pin).expect("load (are you root?)");
        let tmp = tempfile::tempdir().unwrap();
        let cfg = Config {
            pin_dir: pin,
            state_dir: tmp.path().join("state"),
            audit_log: tmp.path().join("audit.log"),
            trusted_keys_dir: tmp.path().join("keys"),
            ..Config::default()
        };
        Self {
            daemon: Some(Daemon::new(cfg, k)),
            _tmp: tmp,
        }
    }
    fn d(&mut self) -> &mut Daemon {
        self.daemon.as_mut().unwrap()
    }
    fn k(&mut self) -> &mut Kernel {
        self.d().kernel.as_mut().unwrap()
    }
    fn xdp(&mut self, pkt: &[u8]) -> u32 {
        let prog: &mut Xdp = self
            .k()
            .bpf_mut()
            .program_mut("kavach_xdp")
            .unwrap()
            .try_into()
            .unwrap();
        if prog.fd().is_err() {
            prog.load().unwrap();
        }
        run(prog, pkt).unwrap()
    }
    fn tc(&mut self, name: &str, pkt: &[u8]) -> u32 {
        let prog: &mut SchedClassifier = self
            .k()
            .bpf_mut()
            .program_mut(name)
            .unwrap()
            .try_into()
            .unwrap();
        if prog.fd().is_err() {
            prog.load().unwrap();
        }
        run(prog, pkt).unwrap()
    }
    fn stat(&mut self, r: StatReason) -> u64 {
        self.k().stats().unwrap()[r as usize]
    }
    fn apply_toml(&mut self, src: &str) -> Arc<kavach_policy::CompiledPolicy> {
        let p = Arc::new(
            kavach_policy::compile(src, kernel::unix_ns() / 1_000_000_000)
                .expect("policy")
                .policy,
        );
        let serial = self.d().serial + 1;
        self.d().stage(p.clone(), serial).expect("stage");
        p
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(mut d) = self.daemon.take()
            && let Some(k) = d.kernel.take()
        {
            let _ = k.kill_switch();
        }
    }
}

fn run<
    P: TestRun<Opts<'static> = TestRunOptions<'static>, Result = aya::programs::TestRunResult>,
>(
    p: &P,
    pkt: &[u8],
) -> Result<u32, ProgramError> {
    // SAFETY-free lifetime laundering is not needed: copy into a leaked buffer for 'static opts.
    let data: &'static [u8] = Box::leak(pkt.to_vec().into_boxed_slice());
    let opts = TestRunOptions {
        data_in: Some(data),
        ..Default::default()
    };
    p.test_run(opts).map(|r| r.return_value)
}

// ---------------------------------------------------------------------------------------------
// Packet builders
// ---------------------------------------------------------------------------------------------

const TCP_SYN: u8 = 0x02;
const TCP_ACK: u8 = 0x10;

fn eth(proto: u16, vlans: &[u16]) -> Vec<u8> {
    let mut p = vec![0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2];
    for v in vlans {
        p.extend_from_slice(&0x8100u16.to_be_bytes());
        p.extend_from_slice(&v.to_be_bytes());
    }
    p.extend_from_slice(&proto.to_be_bytes());
    p
}

fn l4(proto: u8, sport: u16, dport: u16, flags: u8) -> Vec<u8> {
    match proto {
        6 => {
            let mut t = vec![0u8; 20];
            t[0..2].copy_from_slice(&sport.to_be_bytes());
            t[2..4].copy_from_slice(&dport.to_be_bytes());
            t[12] = 5 << 4;
            t[13] = flags;
            t
        }
        17 => {
            let mut u = vec![0u8; 8];
            u[0..2].copy_from_slice(&sport.to_be_bytes());
            u[2..4].copy_from_slice(&dport.to_be_bytes());
            u[4..6].copy_from_slice(&8u16.to_be_bytes());
            u
        }
        _ => vec![8, 0, 0, 0, 0, 1, 0, 1], // ICMP echo request, id 1
    }
}

fn v4_pkt(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    proto: u8,
    sport: u16,
    dport: u16,
    flags: u8,
    vlans: &[u16],
) -> Vec<u8> {
    let mut p = eth(0x0800, vlans);
    let body = l4(proto, sport, dport, flags);
    let mut ip = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, proto, 0, 0];
    let total = (20 + body.len()) as u16;
    ip[2..4].copy_from_slice(&total.to_be_bytes());
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    p.extend(ip);
    p.extend(body);
    p
}

fn v6_pkt(src: Ipv6Addr, dst: Ipv6Addr, proto: u8, sport: u16, dport: u16, flags: u8) -> Vec<u8> {
    let mut p = eth(0x86DD, &[]);
    let body = l4(proto, sport, dport, flags);
    let mut ip = vec![0x60, 0, 0, 0];
    ip.extend_from_slice(&(body.len() as u16).to_be_bytes());
    ip.push(proto);
    ip.push(64);
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    p.extend(ip);
    p.extend(body);
    p
}

fn syn(src: [u8; 4], dport: u16) -> Vec<u8> {
    v4_pkt(
        Ipv4Addr::from(src),
        Ipv4Addr::new(10, 9, 9, 9),
        6,
        40000,
        dport,
        TCP_SYN,
        &[],
    )
}

fn enable_xdp(f: &mut Fixture, flags: u32, pps: u64, burst: u64) {
    let (emission_ns, tau_ns) = kernel::gcra(pps, burst);
    f.k()
        .set_xdp_config(XdpConfig {
            emission_ns,
            tau_ns,
            sample_rate: 1,
            flags,
        })
        .unwrap();
}

// ---------------------------------------------------------------------------------------------
// XDP (v0.1)
// ---------------------------------------------------------------------------------------------

#[test]
#[ignore = "needs root: scripts/priv-test.sh"]
fn xdp_blocklist_v4_v6_vlan() {
    let mut f = Fixture::new();
    enable_xdp(&mut f, KV_XDP_F_BLOCKLIST, 1, 1);
    f.k()
        .block_add("203.0.113.0/24".parse().unwrap(), 0, 7)
        .unwrap();
    f.k()
        .block_add("2001:db8:bad::/48".parse().unwrap(), 0, 8)
        .unwrap();

    assert_eq!(f.xdp(&syn([203, 0, 113, 77], 443)), XDP_DROP);
    assert_eq!(f.xdp(&syn([203, 0, 114, 1], 443)), XDP_PASS);
    // QinQ-tagged frame from a blocked source
    let q = v4_pkt(
        Ipv4Addr::new(203, 0, 113, 1),
        Ipv4Addr::new(10, 0, 0, 1),
        17,
        5,
        53,
        0,
        &[10, 20],
    );
    assert_eq!(f.xdp(&q), XDP_DROP);
    let bad6: Ipv6Addr = "2001:db8:bad:1::5".parse().unwrap();
    let ok6: Ipv6Addr = "2001:db8:600d::5".parse().unwrap();
    assert_eq!(
        f.xdp(&v6_pkt(bad6, Ipv6Addr::LOCALHOST, 6, 1, 2, TCP_SYN)),
        XDP_DROP
    );
    assert_eq!(
        f.xdp(&v6_pkt(ok6, Ipv6Addr::LOCALHOST, 6, 1, 2, TCP_SYN)),
        XDP_PASS
    );
    assert_eq!(f.stat(StatReason::XdpDropBlocklist), 3);

    // Removing the entry lets traffic through again; listing shows the v6 entry.
    f.k().block_del("203.0.113.0/24".parse().unwrap()).unwrap();
    assert_eq!(f.xdp(&syn([203, 0, 113, 77], 443)), XDP_PASS);
    let list = f.d().block_list().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].cidr, "2001:db8:bad::/48");
}

#[test]
#[ignore = "needs root: scripts/priv-test.sh"]
fn xdp_blocklist_expiry() {
    let mut f = Fixture::new();
    enable_xdp(&mut f, KV_XDP_F_BLOCKLIST, 1, 1);
    let past = kernel::boot_ns() - 1;
    f.k()
        .block_add("198.51.100.0/24".parse().unwrap(), past, 0)
        .unwrap();
    f.k()
        .block_add(
            "198.51.101.0/24".parse().unwrap(),
            kernel::boot_ns() + 60_000_000_000,
            0,
        )
        .unwrap();
    assert_eq!(
        f.xdp(&syn([198, 51, 100, 1], 80)),
        XDP_PASS,
        "expired entry ignored"
    );
    assert_eq!(f.xdp(&syn([198, 51, 101, 1], 80)), XDP_DROP);
    assert_eq!(f.d().purge_blocklist().unwrap(), 1);
}

#[test]
#[ignore = "needs root: scripts/priv-test.sh"]
fn xdp_malformed_frames_pass() {
    let mut f = Fixture::new();
    enable_xdp(&mut f, KV_XDP_F_BLOCKLIST | KV_XDP_F_RATELIMIT, 1, 1);
    let full = syn([1, 2, 3, 4], 80);
    // (BPF_PROG_TEST_RUN itself rejects frames shorter than an Ethernet header)
    for cut in [14, 20, 33, 40] {
        assert_eq!(f.xdp(&full[..cut]), XDP_PASS, "truncated at {cut}");
    }
    // IHL < 5 is invalid
    let mut bad = full.clone();
    bad[14] = 0x44;
    assert_eq!(f.xdp(&bad), XDP_PASS);
    // ARP is not ours
    let mut arp = eth(0x0806, &[]);
    arp.extend([0u8; 28]);
    assert_eq!(f.xdp(&arp), XDP_PASS);
    assert!(f.stat(StatReason::XdpUnparsed) >= 6);
}

#[test]
#[ignore = "needs root: scripts/priv-test.sh"]
fn xdp_gcra_rate_limit_and_v6_slash64() {
    let mut f = Fixture::new();
    // 1 pps, burst 3: three packets conform back-to-back, the fourth does not.
    enable_xdp(&mut f, KV_XDP_F_RATELIMIT, 1, 3);
    let p = syn([192, 0, 2, 10], 80);
    let verdicts: Vec<u32> = (0..5).map(|_| f.xdp(&p)).collect();
    assert_eq!(verdicts, [XDP_PASS, XDP_PASS, XDP_PASS, XDP_DROP, XDP_DROP]);
    // A different source has its own budget.
    assert_eq!(f.xdp(&syn([192, 0, 2, 11], 80)), XDP_PASS);
    // IPv6 sources share one budget per /64.
    let a: Ipv6Addr = "2001:db8:1:2::1".parse().unwrap();
    let b: Ipv6Addr = "2001:db8:1:2:ffff::9".parse().unwrap();
    let dst = Ipv6Addr::LOCALHOST;
    let mut v = Vec::new();
    for i in 0..4 {
        let src = if i % 2 == 0 { a } else { b };
        v.push(f.xdp(&v6_pkt(src, dst, 17, 1, 2, 0)));
    }
    assert_eq!(v, [XDP_PASS, XDP_PASS, XDP_PASS, XDP_DROP]);
    assert_eq!(f.stat(StatReason::XdpDropRate), 3);
}

// ---------------------------------------------------------------------------------------------
// TC + policy hot-swap (v0.3)
// ---------------------------------------------------------------------------------------------

const INGRESS_POLICY: &str = r#"
version = 1
[defaults]
egress = "allow"
ingress = "drop"
[[rule]]
id = "ssh-from-lan"
direction = "ingress"
allow = { from = "10.0.0.0/8", port = 22, proto = "tcp" }
[[rule]]
id = "web"
direction = "ingress"
allow = { port = [80, 443], proto = "tcp" }
[[rule]]
id = "dns-log"
direction = "ingress"
log = { from = ["192.0.2.0/24", "2001:db8::/32"], port = 53, proto = "udp" }
"#;

#[test]
#[ignore = "needs root: scripts/priv-test.sh"]
fn tc_ingress_rules_and_always_pass() {
    let mut f = Fixture::new();
    // No policy yet: observe only.
    assert_eq!(f.tc("kavach_tc_ingress", &syn([8, 8, 8, 8], 22)), TC_OK);
    f.apply_toml(INGRESS_POLICY);

    assert_eq!(f.tc("kavach_tc_ingress", &syn([10, 1, 1, 1], 22)), TC_OK);
    assert_eq!(f.tc("kavach_tc_ingress", &syn([8, 8, 8, 8], 22)), TC_SHOT);
    assert_eq!(f.tc("kavach_tc_ingress", &syn([8, 8, 8, 8], 443)), TC_OK);
    assert_eq!(f.tc("kavach_tc_ingress", &syn([8, 8, 8, 8], 3306)), TC_SHOT);
    // Mid-stream TCP with no state passes (FR-TC-3)
    let mid = v4_pkt(
        Ipv4Addr::new(8, 8, 4, 4),
        Ipv4Addr::new(10, 9, 9, 9),
        6,
        1,
        3306,
        TCP_ACK,
        &[],
    );
    assert_eq!(f.tc("kavach_tc_ingress", &mid), TC_OK);
    // DHCP reply and ICMP errors always pass; ICMP echo request is judged (default drop)
    let dhcp = v4_pkt(
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::BROADCAST,
        17,
        67,
        68,
        0,
        &[],
    );
    assert_eq!(f.tc("kavach_tc_ingress", &dhcp), TC_OK);
    let mut unreach = v4_pkt(
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(10, 9, 9, 9),
        1,
        0,
        0,
        0,
        &[],
    );
    let off = 14 + 20;
    unreach[off] = 3;
    assert_eq!(f.tc("kavach_tc_ingress", &unreach), TC_OK);
    let echo = v4_pkt(
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(10, 9, 9, 9),
        1,
        0,
        0,
        0,
        &[],
    );
    assert_eq!(f.tc("kavach_tc_ingress", &echo), TC_SHOT);
    // Cached verdict on the second packet of the denied flow
    let hits = f.stat(StatReason::FlowCacheHit);
    assert_eq!(f.tc("kavach_tc_ingress", &syn([8, 8, 8, 8], 22)), TC_SHOT);
    assert_eq!(f.stat(StatReason::FlowCacheHit), hits + 1);
}

#[test]
#[ignore = "needs root: scripts/priv-test.sh"]
fn hot_swap_reevaluates_cached_flows() {
    let mut f = Fixture::new();
    f.apply_toml(INGRESS_POLICY);
    assert_eq!(f.tc("kavach_tc_ingress", &syn([8, 8, 8, 8], 22)), TC_SHOT);
    let g1 = f.d().generation;

    // New policy allows ssh from anywhere: the cached deny must not survive the swap.
    let opened = INGRESS_POLICY.replace(r#"from = "10.0.0.0/8", port = 22"#, "port = 22");
    f.apply_toml(&opened);
    assert_eq!(f.d().generation, g1 + 1);
    assert_eq!(f.tc("kavach_tc_ingress", &syn([8, 8, 8, 8], 22)), TC_OK);
    assert!(f.stat(StatReason::FlowCacheStale) >= 1);

    // The inactive slot keeps the old table; the active header carries the new generation.
    let active = f.d().generation & 1;
    let hdr = f.k().policy_header(active).unwrap();
    assert_eq!(hdr.generation, g1 + 1);
    assert_eq!(f.k().generation().unwrap(), g1 + 1);
}

/// Differential test (T69): the C program and kavach-core must agree on every flow.
#[test]
#[ignore = "needs root: scripts/priv-test.sh"]
fn differential_tc_ingress_vs_core() {
    let mut f = Fixture::new();
    let p = f.apply_toml(INGRESS_POLICY);
    let generation = f.d().generation;
    let table = p.to_kernel(
        generation,
        1,
        kavach_policy::kernel::Clocks {
            unix_ns: 0,
            boot_ns: 0,
        },
    );
    let snap = Snapshot::new(&table, generation).unwrap();
    let offline = OfflineTables::new(&p, &Facts::default(), &[], generation & 1);

    let mut seed: u64 = 0x5eed_cafe;
    let mut rnd = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let srcs: [[u8; 4]; 5] = [
        [10, 0, 0, 0],
        [192, 0, 2, 0],
        [8, 8, 8, 0],
        [172, 16, 0, 0],
        [10, 255, 255, 0],
    ];
    let ports = [22u16, 53, 80, 443, 3306, 8080];
    let mut checked = 0;
    for i in 0..400u32 {
        let r = rnd();
        let mut src = srcs[(r % 5) as usize];
        src[3] = (i % 250) as u8 + 1;
        src[2] = ((i / 250) % 250) as u8;
        let dport = ports[((r >> 8) % 6) as usize];
        let proto = if (r >> 16) & 1 == 0 { 6 } else { 17 };
        let sport = 20000 + i as u16; // unique 5-tuple => always a new flow
        let pkt = v4_pkt(
            Ipv4Addr::from(src),
            Ipv4Addr::new(10, 9, 9, 9),
            proto,
            sport,
            dport,
            TCP_SYN,
            &[],
        );
        let kernel_verdict = f.tc("kavach_tc_ingress", &pkt);
        let q = FlowQuery {
            dir: KV_DIR_INGRESS,
            mask: 0,
            remote: to_mapped(IpAddr::V4(Ipv4Addr::from(src))),
            port: dport,
            proto,
        };
        let d = kavach_core::evaluate(&offline, &snap, &q, 0);
        let core_verdict = if d.verdict == Verdict::Drop {
            TC_SHOT
        } else {
            TC_OK
        };
        assert_eq!(
            kernel_verdict, core_verdict,
            "divergence on {src:?} {proto}/{dport}: core={d:?}"
        );
        checked += 1;
    }
    assert_eq!(checked, 400);
}

// ---------------------------------------------------------------------------------------------
// LSM identity egress (v0.2) — live connect()/sendto() through the real hooks
// ---------------------------------------------------------------------------------------------

fn drain(rb: &mut RingBuf<MapData>) -> Vec<Event> {
    let mut out = Vec::new();
    while let Some(item) = rb.next() {
        out.push(kavachd::events::decode(&item).unwrap());
    }
    out
}

/// Step 1 of the classification protocol, by hand (the test owns the ring buffer).
fn key_report(
    f: &mut Fixture,
    rb: &mut RingBuf<MapData>,
    path: &str,
) -> (KeyReport, std::fs::File) {
    let (nonce, file) = f.d().open_for_report(path).unwrap();
    let rep = drain(rb)
        .iter()
        .find_map(KeyReport::from_event)
        .expect("LSM answered the armed key request");
    assert_eq!(rep.nonce, nonce);
    (rep, file)
}

/// The whole protocol; true if the classification was committed.
fn classify(f: &mut Fixture, rb: &mut RingBuf<MapData>, path: &str) -> bool {
    let (rep, file) = key_report(f, rb, path);
    assert!(!rep.writers, "{path} has no open writers");
    let info = daemon::hash_file(file).unwrap();
    f.d()
        .commit_classification(rep.key, info, rep.nonce)
        .unwrap()
}

#[test]
#[ignore = "needs root + BPF LSM: scripts/priv-test.sh"]
fn lsm_identity_egress_end_to_end() {
    let lsms = std::fs::read_to_string("/sys/kernel/security/lsm").unwrap_or_default();
    if !lsms.contains("bpf") {
        eprintln!("skipping: BPF LSM not active");
        return;
    }
    let mut f = Fixture::new();
    let mut rb = f.k().take_events().unwrap();
    f.k().attach_lsm().expect("attach LSM");

    // Classify THIS test binary via the real path: task scan → Exec event → hash → exe_class.
    f.k().scan_tasks().unwrap();
    let me = std::process::id();
    let mut key = None;
    while let Some(item) = rb.next() {
        let e = kavachd::events::decode(&item).unwrap();
        if e.kind == EventKind::Exec as u8 && e.pid == me {
            key = Some(ExeKey {
                dev: e.rule_id,
                generation: e.generation,
                ino: e.identity,
            });
        }
    }
    let key = key.expect("task scan reported this process");
    let exe = std::fs::read_link("/proc/self/exe").unwrap();
    let (rep, file) = key_report(&mut f, &mut rb, &format!("/proc/{me}/exe"));
    assert_eq!(rep.key, key, "key report matches the task scan's key");
    assert!(!rep.writers);
    let info = daemon::hash_file(file).unwrap();
    assert_eq!(std::path::Path::new(&info.path), exe);
    let sha = hex::encode(info.sha256);
    // one-shot: a second read-open by this thread reports nothing
    drop(std::fs::File::open("/proc/self/exe").unwrap());
    assert!(
        !drain(&mut rb)
            .iter()
            .any(|e| e.kind == EventKind::KeyReport as u8),
        "key request is one-shot"
    );

    let policy = format!(
        r#"
version = 1
[defaults]
egress = "allow"
ingress = "allow"
[[rule]]
id = "this-binary-no-testnet-tcp"
who = {{ binary = "sha256:{sha}" }}
deny = {{ to = "192.0.2.1", port = 9, proto = "tcp" }}
[[rule]]
id = "uid-no-testnet-udp"
who = {{ user = {uid} }}
deny = {{ to = "192.0.2.0/24", port = 9, proto = "udp" }}
[[rule]]
id = "log-testnet-other"
log = {{ to = "192.0.2.0/24" }}
"#,
        uid = nix::unistd::getuid().as_raw()
    );
    f.apply_toml(&policy);
    // the placeholder (mask 0) survived the policy stage; commit the hash over it
    assert_eq!(
        f.k().exe_class(&key).unwrap().map(|c| c.nonce),
        Some(rep.nonce)
    );
    assert!(f.d().commit_classification(key, info, rep.nonce).unwrap());

    // TCP connect to the denied destination fails with EPERM straight from the LSM hook.
    let denied: SocketAddr = "192.0.2.1:9".parse().unwrap();
    let err =
        TcpStream::connect_timeout(&denied, std::time::Duration::from_millis(200)).unwrap_err();
    assert_eq!(
        err.raw_os_error(),
        Some(nix::libc::EPERM),
        "expected EPERM, got {err:?} (exe {exe:?})"
    );

    // Unconnected UDP sendto is judged per destination (uid selector).
    let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
    let err = sock.send_to(b"x", "192.0.2.7:9").unwrap_err();
    assert_eq!(err.raw_os_error(), Some(nix::libc::EPERM));
    // Other destinations/ports are untouched (the log rule only logs).
    sock.send_to(b"x", "192.0.2.7:10")
        .expect("allowed (logged)");
    // Loopback is exempt by default.
    let lo = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.send_to(b"x", lo.local_addr().unwrap())
        .expect("loopback bypass");

    assert!(f.stat(StatReason::EgressDrop) >= 2);
    assert!(f.stat(StatReason::EgressLog) >= 1);
    let mut saw_drop = false;
    while let Some(item) = rb.next() {
        let e = kavachd::events::decode(&item).unwrap();
        if e.kind == EventKind::EgressVerdict as u8
            && e.verdict == Verdict::Drop as u8
            && e.pid == me
        {
            saw_drop = true;
        }
    }
    assert!(saw_drop, "drop events carry the pid");

    // A running binary cannot even be opened for write (ETXTBSY), so exercise FR-ID-3 on a
    // copy: exec it (→ Exec event with its kernel key), classify it, then write-open it.
    let dir = tempfile::tempdir_in("/var/tmp").unwrap();
    let copy = dir.path().join("kv-true");
    std::fs::copy("/usr/bin/true", &copy).unwrap();
    assert!(
        std::process::Command::new(&copy)
            .status()
            .unwrap()
            .success()
    );
    let mut copy_key = None;
    while let Some(item) = rb.next() {
        let e = kavachd::events::decode(&item).unwrap();
        if e.kind == EventKind::Exec as u8 && e.comm.starts_with(b"kv-true") {
            copy_key = Some(ExeKey {
                dev: e.rule_id,
                generation: e.generation,
                ino: e.identity,
            });
        }
    }
    let copy_key = copy_key.expect("exec of the copy was reported");
    let path = copy.to_str().unwrap();
    let classified = |f: &mut Fixture| f.k().exe_class(&copy_key).unwrap().is_some();
    let write_open = || {
        drop(
            std::fs::OpenOptions::new()
                .append(true)
                .open(&copy)
                .unwrap(),
        )
    };
    let chmod = |mode| {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(mode)).unwrap()
    };

    // FR-ID-3: write-open deletes the classification and says so.
    assert!(classify(&mut f, &mut rb, path));
    assert!(classified(&mut f));
    write_open();
    assert!(!classified(&mut f), "write-open revoked the class");
    assert!(
        drain(&mut rb)
            .iter()
            .any(|e| e.kind == EventKind::ExeTainted as u8 && e.identity == copy_key.ino),
        "ExeTainted event emitted"
    );

    // chmod -x / write / chmod +x is a write too.
    assert!(classify(&mut f, &mut rb, path));
    chmod(0o644);
    write_open();
    chmod(0o755);
    assert!(
        !classified(&mut f),
        "non-executable mode does not skip the taint"
    );

    // A writer that already holds the file open is reported; nothing is classified.
    let writer = std::fs::OpenOptions::new()
        .append(true)
        .open(&copy)
        .unwrap();
    let (rep, _file) = key_report(&mut f, &mut rb, path);
    assert!(rep.writers, "open writer reported");
    f.d().abandon_classification(rep.key, rep.nonce);
    assert!(!classified(&mut f), "placeholder removed");
    drop(writer);

    // Modified between the key report and the commit: the commit fails.
    let (rep, file) = key_report(&mut f, &mut rb, path);
    assert!(!rep.writers);
    write_open();
    let info = daemon::hash_file(file).unwrap();
    assert!(
        !f.d()
            .commit_classification(rep.key, info, rep.nonce)
            .unwrap(),
        "stale hash refused"
    );
    assert!(!classified(&mut f));
    assert!(!f.d().exe_cache.contains_key(&copy_key));

    // truncate(2) by path revokes it too.
    assert!(classify(&mut f, &mut rb, path));
    nix::unistd::truncate(&copy, 0).unwrap();
    assert!(!classified(&mut f), "truncate revoked the class");
    let _ = IpNet::from(IpAddr::V4(Ipv4Addr::LOCALHOST));
}

// ---------------------------------------------------------------------------------------------
// Real traffic: network namespace + veth pair (T31)
// ---------------------------------------------------------------------------------------------

struct Netns {
    ns: String,
    host_if: String,
}

impl Netns {
    fn new(tag: u32) -> Self {
        let ns = format!("kvt{}{tag}", std::process::id() % 10000);
        let host_if = format!("kvh{tag}");
        let peer = format!("kvn{tag}");
        let sh = |args: &str| {
            let ok = std::process::Command::new("sh")
                .arg("-c")
                .arg(args)
                .status()
                .unwrap()
                .success();
            assert!(ok, "setup failed: {args}");
        };
        sh(&format!("ip netns add {ns}"));
        sh(&format!("ip link add {host_if} type veth peer name {peer}"));
        sh(&format!("ip link set {peer} netns {ns}"));
        sh(&format!(
            "ip addr add 10.203.{tag}.1/24 dev {host_if} && ip link set {host_if} up"
        ));
        sh(&format!(
            "ip -n {ns} addr add 10.203.{tag}.2/24 dev {peer} && ip -n {ns} link set {peer} up && ip -n {ns} link set lo up"
        ));
        Self { ns, host_if }
    }

    /// Run a shell snippet inside the namespace; true if it exits 0.
    fn run(&self, cmd: &str) -> bool {
        std::process::Command::new("ip")
            .args(["netns", "exec", &self.ns, "timeout", "3", "bash", "-c", cmd])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .success()
    }
}

impl Drop for Netns {
    fn drop(&mut self) {
        let _ = std::process::Command::new("ip")
            .args(["link", "del", &self.host_if])
            .status();
        let _ = std::process::Command::new("ip")
            .args(["netns", "del", &self.ns])
            .status();
    }
}

#[test]
#[ignore = "needs root: scripts/priv-test.sh"]
fn netns_veth_real_traffic_xdp_and_tc() {
    // Run this test thread in a private network namespace: the host's own firewall (e.g. an
    // INPUT drop policy) and interfaces are untouched and cannot interfere.
    nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).expect("unshare(CLONE_NEWNET)");
    let mut f = Fixture::new();
    let n = Netns::new(7);
    let mode = f
        .k()
        .attach_xdp(&n.host_if, "auto")
        .expect("attach XDP to veth");
    f.k().attach_tc(&n.host_if).expect("attach TC to veth");
    enable_xdp(&mut f, KV_XDP_F_BLOCKLIST, 1, 1);
    eprintln!("xdp mode on veth: {mode}");

    let open = TcpListenerGuard::bind("10.203.7.1:47081");
    let closed = TcpListenerGuard::bind("10.203.7.1:47080");
    let tcp = |port: u16| format!("echo > /dev/tcp/10.203.7.1/{port}");

    // Baseline: everything reachable.
    assert!(n.run("ping -c1 -W1 10.203.7.1"), "baseline ping");
    assert!(n.run(&tcp(47080)) && n.run(&tcp(47081)), "baseline tcp");

    // TC ingress policy: deny new TCP to :47080 from the namespace subnet; replies keep flowing.
    f.apply_toml(
        r#"
version = 1
[defaults]
egress = "allow"
ingress = "allow"
[[rule]]
id = "no-47080-from-lab"
direction = "ingress"
deny = { from = "10.203.7.0/24", port = 47080, proto = "tcp" }
"#,
    );
    assert!(!n.run(&tcp(47080)), "47080 must be dropped at TC ingress");
    assert!(n.run(&tcp(47081)), "47081 still allowed");
    assert!(n.run("ping -c1 -W1 10.203.7.1"), "icmp unaffected");
    assert!(f.stat(StatReason::IngressDrop) >= 1);

    // XDP blocklist: the whole peer is cut off before the stack sees a packet.
    f.k()
        .block_add("10.203.7.2/32".parse().unwrap(), 0, 1)
        .unwrap();
    assert!(!n.run("ping -c1 -W1 10.203.7.1"), "blocked at XDP");
    assert!(!n.run(&tcp(47081)), "blocked at XDP");
    assert!(f.stat(StatReason::XdpDropBlocklist) >= 1);
    f.k().block_del("10.203.7.2/32".parse().unwrap()).unwrap();
    assert!(n.run("ping -c1 -W1 10.203.7.1"), "unblocked");
    drop((open, closed));
}

/// A listener that accepts in the background so client connects complete.
struct TcpListenerGuard(#[allow(dead_code)] std::thread::JoinHandle<()>);

impl TcpListenerGuard {
    fn bind(addr: &str) -> Self {
        let l = std::net::TcpListener::bind(addr).unwrap();
        Self(std::thread::spawn(move || {
            for s in l.incoming() {
                drop(s);
            }
        }))
    }
}
