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
    differential_tc_ingress(&mut Fixture::new());
}

/// The same 400 flows with kavach.ko loaded (v0.4): the verdicts must not change. Skipped when
/// the module is not loaded; `kernel/kavach-ko/ci.sh selftest` runs this suite with it loaded,
/// inside a virtme-ng guest (never insmod it on the host).
#[test]
#[ignore = "needs root + kavach.ko: scripts/priv-test.sh"]
fn differential_tc_ingress_vs_core_with_kavach_ko() {
    match kernel::evaluator() {
        kernel::Evaluator::Builtin => {
            eprintln!("skipping: kavach.ko not loaded");
            return;
        }
        kernel::Evaluator::ModuleUnbound => eprintln!(
            "kavach.ko loaded; the aya loader cannot bind module kfuncs, so this checks that the \
             module's presence leaves loading and verdicts unchanged"
        ),
    }
    differential_tc_ingress(&mut Fixture::new());
}

/// Differential corpus over *raw* policy tables (not only what the compiler emits): random
/// rule mixes incl. Punt with both fail modes, out-of-range and Punt verdicts and defaults, expired and
/// unexpired TTLs, address sets that are empty or out of the 64-bit range, protocol/port
/// edges, and an `n_rules` above `KV_MAX_RULES`. The C `kv_evaluate` (whichever evaluator the
/// loaded programs use) must give kavach-core's verdict on every flow; kavach-core is also
/// what kavach.ko runs, so this pins the evaluator kavach.ko replaces.
#[test]
#[ignore = "needs root: scripts/priv-test.sh"]
fn differential_random_policy_tables_vs_core() {
    let mut f = Fixture::new();
    // Compiled policy only for its address sets (two sets in the active slot).
    let p = f.apply_toml(INGRESS_POLICY);
    let generation = f.d().generation;
    let slot = generation & 1;
    let offline = OfflineTables::new(&p, &Facts::default(), &[], slot);

    let mut seed: u64 = 0x0dd5_eed5;
    let mut rnd = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let pick = |r: u64, xs: &[u64]| xs[(r % xs.len() as u64) as usize];
    let srcs: [[u8; 4]; 5] = [
        [10, 1, 2, 0],
        [192, 0, 2, 0],
        [8, 8, 8, 0],
        [172, 16, 0, 0],
        [203, 0, 113, 0],
    ];
    let ports = [0u64, 1, 22, 53, 80, 443, 3306, 8080, 65535];
    let mut table: Box<Policy> = Box::default();
    let mut sport = 1024u16;
    let (mut flows, mut drops) = (0u32, 0u32);
    for round in 0..24u32 {
        let n = match round {
            0 => 0,
            1 => KV_MAX_RULES as usize,
            _ => 1 + (rnd() % 48) as usize,
        };
        *table = Policy::default();
        table.hdr.n_rules = if round == 1 { 5000 } else { n as u32 };
        table.hdr.flags = KV_POL_F_VALID;
        table.hdr.default_egress = pick(rnd(), &[0, 1, 2, 3, 9]) as u8;
        table.hdr.default_ingress = pick(rnd(), &[0, 1, 2, 3, 9]) as u8;
        table.hdr.generation = generation;
        for (i, r) in table.rules[..n].iter_mut().enumerate() {
            let lo = pick(rnd(), &ports) as u16;
            *r = Rule {
                sel: pick(rnd(), &[0, 0, 0, 1]),
                id: 1000 + i as u32,
                remote_set: pick(rnd(), &[0, 0, 1, 2, 3, 65]) as u32,
                port_lo: lo,
                port_hi: pick(rnd(), &[lo as u64, lo as u64, 65535, 443]).max(lo as u64) as u16,
                proto: pick(rnd(), &[0, 0, 6, 17, 1]) as u8,
                dir: if rnd() % 5 == 0 {
                    KV_DIR_EGRESS
                } else {
                    KV_DIR_INGRESS
                },
                verdict: pick(rnd(), &[0, 0, 1, 2, 3, 7]) as u8,
                fail: if rnd() & 1 == 0 {
                    KV_FAIL_OPEN
                } else {
                    KV_FAIL_CLOSED
                },
                // 1 ns after boot is long past; u64::MAX never comes.
                not_after_ns: pick(rnd(), &[0, 0, 1, u64::MAX]),
                gateway: pick(rnd(), &[0, 1]) as u16,
                ..Rule::default()
            };
        }
        f.k().write_slot(slot, &table).unwrap();
        let snap = Snapshot::new(&table, generation).unwrap();
        for _ in 0..60 {
            let r = rnd();
            let mut src = srcs[(r % 5) as usize];
            src[3] = ((r >> 8) % 250) as u8 + 1;
            let dport = pick(r >> 16, &ports[2..]) as u16;
            let proto = if (r >> 32) & 1 == 0 { 6 } else { 17 };
            sport = sport.wrapping_add(1).max(1024); // unique 5-tuple => always a new flow
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
            let d = kavach_core::evaluate(&offline, &snap, &q, kernel::boot_ns());
            let core_verdict = if d.verdict == Verdict::Drop {
                TC_SHOT
            } else {
                TC_OK
            };
            assert_eq!(
                kernel_verdict, core_verdict,
                "round {round}: divergence on {src:?} {proto}/{dport}: core={d:?}"
            );
            flows += 1;
            drops += u32::from(core_verdict == TC_SHOT);
        }
    }
    eprintln!("{flows} flows over 24 raw tables, {drops} dropped: C == kavach-core");
    assert!(drops > 0 && drops < flows, "corpus exercises both outcomes");
}

/// Fallback (v0.4) on a kernel without kavach.ko: the weak `kavach_evaluate` ksym stays
/// unresolved, every caller of `kv_evaluate` (LSM connect/sendmsg, TC ingress/egress) passes the
/// verifier with the kfunc call eliminated as dead code, kavachd reports the built-in
/// evaluator, and the C evaluator's verdicts equal kavach-core's.
#[test]
#[ignore = "needs root: scripts/priv-test.sh"]
fn evaluator_falls_back_to_c_without_kavach_ko() {
    use aya::programs::Lsm;
    if std::path::Path::new(kernel::KAVACH_KO_BTF).exists() {
        eprintln!("skipping: kavach.ko is loaded (this test checks the fallback)");
        return;
    }
    assert_eq!(kernel::evaluator(), kernel::Evaluator::Builtin);

    let mut f = Fixture::new();
    let btf = aya::Btf::from_sys_fs().unwrap();
    for (name, hook) in [
        ("kavach_connect", "socket_connect"),
        ("kavach_sendmsg", "socket_sendmsg"),
    ] {
        let prog: &mut Lsm = f
            .k()
            .bpf_mut()
            .program_mut(name)
            .unwrap()
            .try_into()
            .unwrap();
        prog.load(hook, &btf)
            .unwrap_or_else(|e| panic!("verifier rejected {name}: {e:?}"));
        assert_no_kfunc_call(name, prog.fd().unwrap());
    }
    for name in ["kavach_tc_ingress", "kavach_tc_egress"] {
        let prog: &mut SchedClassifier = f
            .k()
            .bpf_mut()
            .program_mut(name)
            .unwrap()
            .try_into()
            .unwrap();
        prog.load()
            .unwrap_or_else(|e| panic!("verifier rejected {name}: {e:?}"));
        assert_no_kfunc_call(name, prog.fd().unwrap());
    }
    differential_tc_ingress(&mut f);
}

/// The verifier-translated instructions of `fd` contain no kfunc call (`BPF_PSEUDO_KFUNC_CALL`).
fn assert_no_kfunc_call(name: &str, fd: &aya::programs::ProgramFd) {
    let insns = xlated_insns(fd);
    assert!(!insns.is_empty(), "{name}: no translated instructions");
    const CALL: u8 = 0x85; // BPF_JMP | BPF_CALL
    const PSEUDO_KFUNC_CALL: u8 = 2;
    let kfunc_calls = insns
        .as_chunks::<8>()
        .0
        .iter()
        .filter(|i| i[0] == CALL && i[1] >> 4 == PSEUDO_KFUNC_CALL)
        .count();
    // Sanity check of the decoding: every caller makes helper calls (map lookups, ...).
    let helper_calls = insns
        .as_chunks::<8>()
        .0
        .iter()
        .filter(|i| i[0] == CALL && i[1] >> 4 == 0)
        .count();
    assert!(helper_calls > 0, "{name}: no helper calls decoded");
    assert_eq!(
        kfunc_calls, 0,
        "{name}: kfunc call survived without kavach.ko"
    );
}

/// `BPF_OBJ_GET_INFO_BY_FD` → `xlated_prog_insns` (aya does not expose them).
fn xlated_insns(fd: &aya::programs::ProgramFd) -> Vec<u8> {
    use std::os::fd::{AsFd, AsRawFd};
    // The leading fields of `struct bpf_prog_info`; the kernel fills min(info_len, its size).
    #[repr(C)]
    #[derive(Default)]
    struct ProgInfo {
        prog_type: u32,
        id: u32,
        tag: [u8; 8],
        jited_prog_len: u32,
        xlated_prog_len: u32,
        jited_prog_insns: u64,
        xlated_prog_insns: u64,
    }
    #[repr(C)]
    struct InfoAttr {
        bpf_fd: u32,
        info_len: u32,
        info: u64,
    }
    const BPF_OBJ_GET_INFO_BY_FD: nix::libc::c_long = 15;
    let raw = fd.as_fd().as_raw_fd() as u32;
    let get = |info: &mut ProgInfo| {
        let mut attr = InfoAttr {
            bpf_fd: raw,
            info_len: size_of::<ProgInfo>() as u32,
            info: info as *mut ProgInfo as u64,
        };
        // SAFETY: bpf(2) with a valid attr for this command; the kernel writes at most
        // `info_len` bytes to `info` and `xlated_prog_len` bytes to `xlated_prog_insns`.
        let r = unsafe {
            nix::libc::syscall(
                nix::libc::SYS_bpf,
                BPF_OBJ_GET_INFO_BY_FD,
                &mut attr as *mut InfoAttr,
                size_of::<InfoAttr>() as u32,
            )
        };
        assert_eq!(
            r,
            0,
            "BPF_OBJ_GET_INFO_BY_FD: {}",
            std::io::Error::last_os_error()
        );
    };
    let mut info = ProgInfo::default();
    get(&mut info);
    let mut buf = vec![0u8; info.xlated_prog_len as usize];
    let mut info = ProgInfo {
        xlated_prog_len: buf.len() as u32,
        xlated_prog_insns: buf.as_mut_ptr() as u64,
        ..ProgInfo::default()
    };
    get(&mut info);
    buf.truncate(info.xlated_prog_len as usize);
    buf
}

fn differential_tc_ingress(f: &mut Fixture) {
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
    let info = daemon::hash_file(&mut { file }).unwrap();
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
    eprintln!(
        "lsm file_truncate hook: {}",
        if kernel::lsm_hook_available("file_truncate") {
            "attached"
        } else {
            "absent (< 6.2): path_truncate covers ftruncate/O_TRUNC"
        }
    );

    // Classify THIS test binary via the real path: task scan → Exec event → hash → exe_class.
    f.k().scan_tasks().unwrap();
    let me = std::process::id();
    let mut key = None;
    while let Some(item) = rb.next() {
        let e = kavachd::events::decode(&item).unwrap();
        if e.kind == EventKind::Exec as u8 && e.pid == me {
            key = Some(e.exe_key());
        }
    }
    let key = key.expect("task scan reported this process");
    let exe = std::fs::read_link("/proc/self/exe").unwrap();
    let (rep, file) = key_report(&mut f, &mut rb, &format!("/proc/{me}/exe"));
    assert_eq!(rep.key, key, "key report matches the task scan's key");
    assert!(!rep.writers);
    let info = daemon::hash_file(&mut { file }).unwrap();
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
            copy_key = Some(e.exe_key());
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
    let (rep, file) = key_report(&mut f, &mut rb, path);
    drop(file);
    assert!(rep.writers, "open writer reported");
    f.d().abandon_classification(rep.key, rep.nonce);
    assert!(!classified(&mut f), "placeholder removed");
    drop(writer);

    // Modified between the key report and the commit: the commit fails.
    let (rep, file) = key_report(&mut f, &mut rb, path);
    assert!(!rep.writers);
    write_open();
    let info = daemon::hash_file(&mut { file }).unwrap();
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

    // open(O_RDONLY | O_TRUNC) truncates without FMODE_WRITE (file_truncate hook).
    std::fs::copy("/usr/bin/true", &copy).unwrap();
    assert!(classify(&mut f, &mut rb, path));
    {
        use std::os::unix::fs::OpenOptionsExt;
        drop(
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_TRUNC)
                .open(&copy),
        );
    }
    assert!(!classified(&mut f), "O_RDONLY|O_TRUNC revoked the class");

    // A freed inode takes its class with it, so a recycled inode address inherits nothing.
    assert!(classify(&mut f, &mut rb, path));
    std::fs::remove_file(&copy).unwrap();
    for _ in 0..50 {
        if !classified(&mut f) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(!classified(&mut f), "inode_free_security removed the class");

    // memfd: written without file_open and without i_writecount, so never classifiable.
    // SAFETY: plain syscall with a valid NUL-terminated name; the fd is owned below.
    let fd = unsafe { nix::libc::memfd_create(c"kv-memfd".as_ptr(), 0) };
    assert!(fd >= 0);
    // SAFETY: fd is a fresh descriptor we own.
    let mut mem = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(fd) };
    std::io::Write::write_all(&mut mem, &std::fs::read("/usr/bin/true").unwrap()).unwrap();
    let (rep, _file) = key_report(&mut f, &mut rb, &format!("/proc/self/fd/{fd}"));
    assert!(rep.untrusted_fs, "memfd is on an internal mount");
    assert!(
        f.k().exe_class(&rep.key).unwrap().is_none(),
        "no placeholder for an untrusted filesystem"
    );

    // ext4 on a loop device: trusted only while root alone can rewrite the image.
    let img = dir.path().join("fs.img");
    let mnt = dir.path().join("mnt");
    std::fs::create_dir(&mnt).unwrap();
    let sh = |c: &str| {
        std::process::Command::new("sh")
            .args(["-c", c])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    };
    if sh(&format!(
        "truncate -s 8M {i} && mkfs.ext4 -q -F {i} && mount -o loop {i} {m} && cp /usr/bin/true {m}/t",
        i = img.display(),
        m = mnt.display()
    )) {
        let (rep, file) = key_report(&mut f, &mut rb, mnt.join("t").to_str().unwrap());
        assert!(!rep.untrusted_fs, "loop devices are judged in user space");
        f.d().abandon_classification(rep.key, rep.nonce);
        kavachd::backing::vouch(&file).expect("root-owned 0644 image is trusted");
        std::os::unix::fs::chown(&img, Some(65534), None).unwrap();
        let err = kavachd::backing::vouch(&file).unwrap_err();
        drop(file);
        let _ = sh(&format!("umount {}", mnt.display()));
        assert!(
            format!("{err:#}").contains("non-root"),
            "user-owned image refused: {err:#}"
        );
        // device-mapper stacked on that loop device: the walk follows `slaves/`.
        let dm = format!("kvt{}", std::process::id());
        if sh(&format!(
            "l=$(losetup -f --show {i}) && echo \"0 $(blockdev --getsz $l) linear $l 0\" | dmsetup create {dm} && mount /dev/mapper/{dm} {m}",
            i = img.display(),
            m = mnt.display()
        )) {
            let file = std::fs::File::open(mnt.join("t")).unwrap();
            let err = kavachd::backing::vouch(&file).unwrap_err();
            drop(file);
            let _ = sh(&format!(
                "umount {m}; dmsetup remove {dm}; losetup -j {i} -O NAME -n | xargs -r -n1 losetup -d",
                m = mnt.display(),
                i = img.display()
            ));
            assert!(
                format!("{err:#}").contains("non-root"),
                "dm over user loop refused: {err:#}"
            );
        } else {
            let _ = sh(&format!("dmsetup remove {dm}"));
            eprintln!("skipping dm-over-loop check (dmsetup unavailable)");
        }
    } else {
        let _ = sh(&format!("umount {}", mnt.display()));
        eprintln!("skipping loop-device check (mkfs.ext4 / loop mount unavailable)");
    }
    let _ = IpNet::from(IpAddr::V4(Ipv4Addr::LOCALHOST));
}

#[test]
#[ignore = "needs root + BPF LSM: scripts/priv-test.sh"]
fn lsm_strict_mode_refuses_unclassified_until_hashed() {
    let lsms = std::fs::read_to_string("/sys/kernel/security/lsm").unwrap_or_default();
    if !lsms.contains("bpf") {
        eprintln!("skipping: BPF LSM not active");
        return;
    }
    let mut f = Fixture::new();
    let mut rb = f.k().take_events().unwrap();
    f.k().attach_lsm().expect("attach LSM");
    // A hash selector (for some other binary) + strict mode; nothing denies this traffic.
    f.apply_toml(&format!(
        r#"
version = 1
[defaults]
egress = "allow"
ingress = "allow"
unclassified = "deny"
[[rule]]
id = "other-binary"
who = {{ binary = "sha256:{}" }}
deny = {{ to = "192.0.2.0/24", port = 1 }}
"#,
        "ab".repeat(32)
    ));
    let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
    let err = sock.send_to(b"x", "192.0.2.5:9").unwrap_err();
    assert_eq!(
        err.raw_os_error(),
        Some(nix::libc::EPERM),
        "unclassified binary refused"
    );
    assert!(f.stat(StatReason::EgressUnclassified) >= 1);

    // Classify this test binary through the real protocol: now it is let through.
    let me = std::process::id();
    assert!(classify(&mut f, &mut rb, &format!("/proc/{me}/exe")));
    sock.send_to(b"x", "192.0.2.5:9")
        .expect("classified binary allowed");
}

#[test]
#[ignore = "needs root + BPF LSM: scripts/priv-test.sh"]
fn lsm_overlay_executables_use_the_real_file() {
    let lsms = std::fs::read_to_string("/sys/kernel/security/lsm").unwrap_or_default();
    let Ok(curl) = std::fs::canonicalize("/usr/bin/curl") else {
        eprintln!("skipping: needs /usr/bin/curl");
        return;
    };
    if !lsms.contains("bpf") {
        eprintln!("skipping: BPF LSM not active");
        return;
    }
    let dir = tempfile::tempdir_in("/var/tmp").unwrap();
    let d = |n: &str| {
        let p = dir.path().join(n);
        std::fs::create_dir(&p).unwrap();
        p
    };
    let (lower, upper, work, merged) = (d("lower"), d("upper"), d("work"), d("merged"));
    std::fs::copy(&curl, lower.join("c")).unwrap();
    let ok = std::process::Command::new("mount")
        .args(["-t", "overlay", "overlay", "-o"])
        .arg(format!(
            "lowerdir={},upperdir={},workdir={}",
            lower.display(),
            upper.display(),
            work.display()
        ))
        .arg(&merged)
        .status()
        .is_ok_and(|s| s.success());
    if !ok {
        eprintln!("skipping: overlay mount failed");
        return;
    }
    struct Umount(std::path::PathBuf);
    impl Drop for Umount {
        fn drop(&mut self) {
            let _ = std::process::Command::new("umount").arg(&self.0).status();
        }
    }
    let _umount = Umount(merged.clone());

    let mut f = Fixture::new();
    let mut rb = f.k().take_events().unwrap();
    f.k().attach_lsm().expect("attach LSM");
    let sha = hex::encode(
        daemon::hash_file(&mut std::fs::File::open(&curl).unwrap())
            .unwrap()
            .sha256,
    );
    f.apply_toml(&format!(
        r#"
version = 1
[defaults]
egress = "allow"
ingress = "allow"
[[rule]]
id = "curl-no-testnet"
who = {{ binary = "sha256:{sha}" }}
deny = {{ to = "192.0.2.3", port = 9, proto = "tcp" }}
"#
    ));

    // Reading through the overlay reports the REAL (lower) inode, not the overlay one.
    let (rep, file) = key_report(&mut f, &mut rb, merged.join("c").to_str().unwrap());
    let lower_ino =
        std::os::unix::fs::MetadataExt::ino(&std::fs::metadata(lower.join("c")).unwrap());
    assert_eq!(rep.key.ino, lower_ino, "key is the backing file's inode");
    assert!(!rep.untrusted_fs && !rep.writers);
    let info = daemon::hash_file(&mut { file }).unwrap();
    assert!(
        f.d()
            .commit_classification(rep.key, info, rep.nonce)
            .unwrap()
    );

    // A process running from the overlay is identified by that real file at connect time.
    let run = |ip: &str| {
        std::process::Command::new(merged.join("c"))
            .args(["-sS", "-m", "1", &format!("http://{ip}:9/")])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .code()
    };
    assert_eq!(
        run("192.0.2.3"),
        Some(7),
        "denied by hash from inside the overlay (EPERM)"
    );

    // A rootless user rewriting the layer file directly taints the real inode.
    drop(
        std::fs::OpenOptions::new()
            .append(true)
            .open(lower.join("c"))
            .unwrap(),
    );
    assert!(
        f.k().exe_class(&rep.key).unwrap().is_none(),
        "layer write revoked the class"
    );
    assert_eq!(
        run("192.0.2.3"),
        Some(28),
        "unclassified after the layer was modified (timeout)"
    );
}

// ---------------------------------------------------------------------------------------------
// Benchmarks (real kernel): `KAVACH_BENCH_OUT=bench.json scripts/priv-test.sh bench_report`
// ---------------------------------------------------------------------------------------------

/// Average kernel-side ns per run, as measured by BPF_PROG_TEST_RUN itself (`repeat`).
fn ns_per_run<
    P: TestRun<Opts<'static> = TestRunOptions<'static>, Result = aya::programs::TestRunResult>,
>(
    p: &P,
    pkt: &[u8],
    repeat: u32,
) -> (u32, f64) {
    let data: &'static [u8] = Box::leak(pkt.to_vec().into_boxed_slice());
    let mut best = f64::MAX;
    let mut rv = 0;
    for _ in 0..5 {
        let r = p
            .test_run(TestRunOptions {
                data_in: Some(data),
                repeat,
                ..Default::default()
            })
            .unwrap();
        rv = r.return_value;
        best = best.min(r.duration.as_nanos() as f64);
    }
    (rv, best)
}

fn policy_with(n: usize) -> String {
    let mut s = String::from("version = 1\n[defaults]\negress = \"allow\"\ningress = \"allow\"\n");
    // At most 64 distinct address sets per policy: cycle 64 /24s, keep ports unique so no rule
    // shadows another and only rule `n-1` matches its own (cidr, port).
    for i in 0..n {
        s += &format!(
            "[[rule]]\nid = \"r{i}\"\ndirection = \"ingress\"\ndeny = {{ from = \"172.16.{}.0/24\", port = {}, proto = \"tcp\" }}\n",
            i % 64,
            1000 + i
        );
    }
    s
}

#[test]
#[ignore = "needs root: scripts/priv-test.sh"]
fn bench_report() {
    let Ok(out) = std::env::var("KAVACH_BENCH_OUT") else {
        eprintln!("skipping: set KAVACH_BENCH_OUT=<file.json>");
        return;
    };
    const R: u32 = 200_000;
    let mut f = Fixture::new();
    let mut res = serde_json::Map::new();
    let mut put = |k: &str, v: serde_json::Value| {
        eprintln!("{k:<34} {v}");
        res.insert(k.into(), v);
    };

    // --- XDP ---------------------------------------------------------------------------
    let clean = syn([198, 51, 100, 7], 443);
    let bad = syn([203, 0, 113, 9], 443);
    let xdp_ns = |f: &mut Fixture, pkt: &[u8]| {
        let prog: &mut Xdp = f
            .k()
            .bpf_mut()
            .program_mut("kavach_xdp")
            .unwrap()
            .try_into()
            .unwrap();
        if prog.fd().is_err() {
            prog.load().unwrap();
        }
        ns_per_run(prog, pkt, R)
    };
    // Shipped defaults: blocklist on, verdict events sampled 1-in-64.
    let cfg = |flags, pps, burst| {
        let (emission_ns, tau_ns) = kernel::gcra(pps, burst);
        XdpConfig {
            emission_ns,
            tau_ns,
            sample_rate: 64,
            flags,
        }
    };
    f.k().set_xdp_config(cfg(KV_XDP_F_BLOCKLIST, 1, 1)).unwrap();
    let (rv, ns) = xdp_ns(&mut f, &clean);
    assert_eq!(rv, XDP_PASS);
    put("xdp_pass_empty_blocklist_ns", ns.into());
    for i in 0..10_000u32 {
        let ip = Ipv4Addr::from(0x0a00_0000 + i);
        f.k().block_add(IpNet::from(IpAddr::V4(ip)), 0, 0).unwrap();
    }
    f.k()
        .block_add("203.0.113.0/24".parse().unwrap(), 0, 0)
        .unwrap();
    let (rv, ns) = xdp_ns(&mut f, &bad);
    assert_eq!(rv, XDP_DROP);
    put("xdp_blocklist_drop_10k_entries_ns", ns.into());
    let (rv, ns) = xdp_ns(&mut f, &clean);
    assert_eq!(rv, XDP_PASS);
    put("xdp_pass_10k_entries_ns", ns.into());
    f.k()
        .set_xdp_config(cfg(
            KV_XDP_F_BLOCKLIST | KV_XDP_F_RATELIMIT,
            1_000_000_000,
            1_000_000_000,
        ))
        .unwrap();
    let (rv, ns) = xdp_ns(&mut f, &clean);
    assert_eq!(rv, XDP_PASS);
    put("xdp_pass_blocklist_and_ratelimit_ns", ns.into());

    // --- policy hot swap ---------------------------------------------------------------
    for n in [10usize, 100, 1000] {
        let src = policy_with(n);
        let p = Arc::new(kavach_policy::compile(&src, 0).expect("policy").policy);
        let mut best = u128::MAX;
        for _ in 0..5 {
            let serial = f.d().serial + 1;
            let t = std::time::Instant::now();
            f.d().stage(p.clone(), serial).expect("stage");
            best = best.min(t.elapsed().as_micros());
        }
        put(&format!("apply_{n}_rules_us"), (best as u64).into());
    }

    // --- TC with a 1000-rule policy ----------------------------------------------------
    let tc_ns = |f: &mut Fixture, name: &str, pkt: &[u8]| {
        let prog: &mut SchedClassifier = f
            .k()
            .bpf_mut()
            .program_mut(name)
            .unwrap()
            .try_into()
            .unwrap();
        if prog.fd().is_err() {
            prog.load().unwrap();
        }
        ns_per_run(prog, pkt, R)
    };
    // last rule matches: worst-case linear position for the first packet, then cached
    let hit = syn([172, 16, (999 % 64) as u8, 1], 1999);
    let (rv, ns) = tc_ns(&mut f, "kavach_tc_ingress", &hit);
    assert_eq!(rv, TC_SHOT);
    put("tc_ingress_1000_rules_cached_flow_ns", ns.into());
    let (rv, ns) = tc_ns(&mut f, "kavach_tc_egress", &clean);
    assert_eq!(rv, TC_OK);
    put("tc_egress_ns", ns.into());

    // --- LSM: real connect() syscalls, without and with the LSM ------------------------
    let connect_ns = || {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let n = 200_000u32;
        let mut best = f64::MAX;
        for _ in 0..5 {
            let t = std::time::Instant::now();
            for i in 0..n {
                sock.connect(("127.0.0.1", 9 + (i & 1) as u16)).unwrap();
            }
            best = best.min(t.elapsed().as_nanos() as f64 / n as f64);
        }
        best
    };
    let base = connect_ns();
    put("connect_syscall_no_lsm_ns", base.into());
    let lsms = std::fs::read_to_string("/sys/kernel/security/lsm").unwrap_or_default();
    if lsms.contains("bpf") {
        f.k().attach_lsm().expect("attach LSM");
        let with = connect_ns();
        put("connect_syscall_lsm_1000_rules_ns", with.into());
        put("lsm_connect_overhead_ns", (with - base).max(0.0).into());
    }

    // --- verifier: instructions processed per program (deterministic size gate) --------
    let mut v = serde_json::Map::new();
    for (name, prog) in f.k().bpf_mut().programs() {
        if let Ok(info) = prog.info()
            && let Some(n) = info.verified_instruction_count()
        {
            v.insert(name.to_owned(), n.into());
        }
    }
    put("verified_insns", v.into());
    let uname = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    put("kernel", uname.trim().into());
    let cpu = std::fs::read_to_string("/proc/cpuinfo")
        .unwrap_or_default()
        .lines()
        .find(|l| l.starts_with("model name"))
        .and_then(|l| l.split(':').nth(1))
        .unwrap_or("?")
        .trim()
        .to_owned();
    put("cpu", cpu.into());
    std::fs::write(&out, serde_json::to_string_pretty(&res).unwrap()).unwrap();
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
    // tcx on >= 6.6, the legacy clsact/netlink fallback before (kernel matrix: 6.1).
    let tcx = aya::util::KernelVersion::current()
        .map_or(true, |v| v >= aya::util::KernelVersion::new(6, 6, 0));
    let legacy = f.k().tc_netlink_links();
    eprintln!(
        "tc attach on veth: {}",
        if legacy > 0 {
            "netlink/clsact (legacy)"
        } else {
            "tcx"
        }
    );
    assert_eq!(legacy, if tcx { 0 } else { 2 }, "TC attach mechanism");

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

// ---------------------------------------------------------------------------------------------
// Opt-in AF_XDP gateway backend
// ---------------------------------------------------------------------------------------------

fn xsk_stat(f: &mut Fixture, i: u32) -> u64 {
    f.k().xsk_stats().unwrap()[i as usize]
}

fn udp4(src: [u8; 4], dport: u16) -> Vec<u8> {
    v4_pkt(
        Ipv4Addr::from(src),
        Ipv4Addr::new(10, 9, 9, 9),
        17,
        40000,
        dport,
        0,
        &[],
    )
}

#[test]
#[ignore = "needs root: scripts/priv-test.sh"]
fn xdp_afxdp_redirect_is_gated_by_flag_port_and_deadline() {
    use kavach_gateway::afxdp::RedirectMaps;
    let mut f = Fixture::new();
    let sel = xsk_port_key(KV_PROTO_UDP, 47090);
    f.k().set_xsk_ports(&[sel]).unwrap();
    assert_eq!(f.k().xsk_ports().unwrap(), [sel]);
    let mut maps = f.k().xsk_maps().unwrap();
    let far = kernel::boot_ns() + 3_600_000_000_000;
    maps.set_alive_until(0, far).unwrap();

    // Backend off (the default): selected port and live deadline change nothing.
    enable_xdp(&mut f, KV_XDP_F_BLOCKLIST, 1, 1);
    assert_eq!(f.xdp(&udp4([198, 51, 100, 1], 47090)), XDP_PASS);
    assert_eq!(f.k().xsk_stats().unwrap(), [0, 0, 0, 0]);

    f.k().set_afxdp_redirect(true).unwrap();
    assert_ne!(f.k().xdp_config().unwrap().flags & KV_XDP_F_BLOCKLIST, 0);
    // Unselected ports and protocols are never looked at.
    assert_eq!(f.xdp(&syn([198, 51, 100, 1], 22)), XDP_PASS);
    assert_eq!(f.xdp(&udp4([198, 51, 100, 1], 47091)), XDP_PASS);
    assert_eq!(f.k().xsk_stats().unwrap(), [0, 0, 0, 0]);
    // Selected, deadline live, but no socket on queue 0: the redirect falls back to PASS.
    assert_eq!(f.xdp(&udp4([198, 51, 100, 1], 47090)), XDP_PASS);
    assert_eq!(xsk_stat(&mut f, KV_XSK_STAT_NO_SOCKET), 1);
    // Deadline lapsed (frozen gateway): PASS without touching the XSKMAP.
    maps.set_alive_until(0, 0).unwrap();
    assert_eq!(f.xdp(&udp4([198, 51, 100, 1], 47090)), XDP_PASS);
    assert_eq!(xsk_stat(&mut f, KV_XSK_STAT_STALE), 1);
    // The blocklist still runs first for gateway ports.
    maps.set_alive_until(0, far).unwrap();
    f.k()
        .block_add("198.51.100.7/32".parse().unwrap(), 0, 1)
        .unwrap();
    assert_eq!(f.xdp(&udp4([198, 51, 100, 7], 47090)), XDP_DROP);
    assert_eq!(xsk_stat(&mut f, KV_XSK_STAT_REDIRECT), 0);

    f.k().set_afxdp_redirect(false).unwrap();
    f.k().set_xsk_ports(&[]).unwrap();
    assert!(f.k().xsk_ports().unwrap().is_empty());
}

#[test]
#[ignore = "needs root: scripts/priv-test.sh"]
fn netns_veth_afxdp_redirect_and_watchdog() {
    use kavach_gateway::afxdp::{AfXdpConfig, Backend, LinuxSys, RxAction, XdpAttach};
    use std::sync::atomic::AtomicBool;
    use std::sync::mpsc;
    use std::time::Duration;

    nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).expect("unshare(CLONE_NEWNET)");
    let mut f = Fixture::new();
    let n = Netns::new(8);
    let mode = f
        .k()
        .attach_xdp(&n.host_if, "auto")
        .expect("attach XDP to veth");
    enable_xdp(&mut f, KV_XDP_F_BLOCKLIST, 1, 1);
    let cfg = AfXdpConfig {
        enabled: true,
        iface: n.host_if.clone(),
        queues: vec![0],
        ports: vec!["47090/udp".parse().unwrap()],
        watchdog_ms: 100,
        ring_size: 64,
        frame_size: 4096,
    };
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let hang = Arc::new(AtomicBool::new(false));
    let backend = Backend::start(
        Arc::new(LinuxSys),
        &cfg,
        XdpAttach::from_label(&mode),
        f.k().xsk_maps().unwrap(),
        {
            let hang = hang.clone();
            move |_| {
                let (tx, hang) = (tx.clone(), hang.clone());
                move |_: u32, frame: &mut [u8]| {
                    let _ = tx.send(frame.to_vec());
                    if hang.load(Ordering::SeqCst) {
                        std::thread::sleep(Duration::from_millis(1500));
                    }
                    RxAction::Consume
                }
            }
        },
    )
    .expect("AF_XDP backend on veth");
    eprintln!("xdp {mode}, AF_XDP modes {:?}", backend.modes());
    f.k().set_xsk_ports(&cfg.port_keys()).unwrap();
    f.k().set_afxdp_redirect(true).unwrap();

    let stack = UdpSocket::bind("10.203.8.1:47090").unwrap();
    stack
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let send = |msg: &str| n.run(&format!("echo -n {msg} > /dev/udp/10.203.8.1/47090"));
    let has = |frame: &[u8], needle: &[u8]| frame.windows(needle.len()).any(|w| w == needle);

    // A selected flow lands in the gateway, not in the kernel stack.
    assert!(send("kavach-xsk-1"));
    let frame = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("frame on AF_XDP");
    assert!(has(&frame, b"kavach-xsk-1"), "{frame:02x?}");
    let mut buf = [0u8; 64];
    assert!(
        stack.recv(&mut buf).is_err(),
        "redirected datagram must not reach the stack"
    );
    assert!(xsk_stat(&mut f, KV_XSK_STAT_REDIRECT) >= 1);

    // Everything else (the SSH stand-in included) stays on the stack.
    let _tcp = TcpListenerGuard::bind("10.203.8.1:47081");
    assert!(n.run("echo > /dev/tcp/10.203.8.1/47081"), "unselected TCP");
    assert!(n.run("ping -c1 -W1 10.203.8.1"), "ICMP");

    // Hang the consumer with one frame in hand and one queued: the watchdog detaches the queue
    // and the selected port falls back to the kernel stack.
    hang.store(true, Ordering::SeqCst);
    assert!(send("hang-1"));
    assert!(rx.recv_timeout(Duration::from_secs(2)).is_ok());
    assert!(send("hang-2"));
    std::thread::sleep(Duration::from_millis(400));
    hang.store(false, Ordering::SeqCst);
    assert!(send("after-detach"));
    let got = stack
        .recv(&mut buf)
        .expect("detached queue passes to the stack");
    assert_eq!(&buf[..got], b"after-detach");

    drop(backend);
    f.k().set_afxdp_redirect(false).unwrap();
}

// ---------------------------------------------------------------------------------------------
// L7 gateway redirect (punt data path)
// ---------------------------------------------------------------------------------------------

/// Every redirect program passes the verifier (also on kernels without the BPF LSM).
#[test]
#[ignore = "needs root: scripts/priv-test.sh"]
fn gateway_redirect_programs_load() {
    use aya::programs::Program;
    let mut f = Fixture::new();
    for name in kernel::GATEWAY_PROGS {
        match f.k().bpf_mut().program_mut(name).expect(name) {
            Program::CgroupSockAddr(p) => p.load(),
            Program::SockOps(p) => p.load(),
            _ => panic!("{name}: unexpected program type"),
        }
        .unwrap_or_else(|e| panic!("verifier rejected {name}: {e:?}"));
    }
}

/// A private cgroup v2 directory: the redirect is attached there only, so the rest of the host
/// is never redirected by the test.
struct TestCgroup {
    dir: std::path::PathBuf,
    mnt: Option<tempfile::TempDir>,
}

impl TestCgroup {
    fn new() -> Self {
        let mounts = std::fs::read_to_string("/proc/self/mounts").unwrap();
        let (root, mnt) = match kavachd::gateway::cgroup2_root(&mounts) {
            Some(r) => (r, None),
            None => {
                let t = tempfile::tempdir().unwrap();
                let ok = std::process::Command::new("mount")
                    .args(["-t", "cgroup2", "none"])
                    .arg(t.path())
                    .status()
                    .is_ok_and(|s| s.success());
                assert!(ok, "cgroup2 not mounted and mounting it failed");
                (t.path().to_path_buf(), Some(t))
            }
        };
        let dir = root.join(format!("kavach-test-gw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Self { dir, mnt }
    }

    /// Start `script` under bash inside this cgroup (it moves itself in before running it).
    fn spawn(&self, script: &str) -> std::process::Child {
        std::process::Command::new("bash")
            .arg("-c")
            .arg(format!(
                "echo $$ > {} && exec bash -c '{script}'",
                self.dir.join("cgroup.procs").display()
            ))
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap()
    }

    fn run(&self, script: &str) -> bool {
        self.spawn(script).wait().unwrap().success()
    }
}

impl Drop for TestCgroup {
    fn drop(&mut self) {
        for _ in 0..50 {
            if std::fs::remove_dir(&self.dir).is_ok() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        if let Some(m) = &self.mnt {
            let _ = std::process::Command::new("umount").arg(m.path()).status();
        }
    }
}

#[test]
#[ignore = "needs root + BPF LSM: scripts/priv-test.sh"]
fn gateway_redirects_punted_connects_and_records_orig_dst() {
    use kavach_gateway::OrigDst;
    use std::io::Read;
    use std::time::{Duration, Instant};
    let lsms = std::fs::read_to_string("/sys/kernel/security/lsm").unwrap_or_default();
    if !lsms.contains("bpf") {
        eprintln!("skipping: BPF LSM not active");
        return;
    }
    let mut f = Fixture::new();
    f.k().attach_lsm().expect("attach LSM");
    let cg = TestCgroup::new();
    f.k()
        .attach_gateway(&cg.dir)
        .expect("attach gateway programs");
    assert!(f.k().gateway_attached());

    // Only TEST-NET-1 and 2001:db8::/32, port 9, are punted to gateway "mcp" (fail closed);
    // port 10 is punted with no gateway named (never redirected); UDP to port 9 is punted to
    // "mcp" too, but UDP is never redirectable.
    let policy = f.apply_toml(
        r#"
version = 1
[defaults]
egress = "allow"
ingress = "allow"
[gateway.mcp]
allow_tools = ["search"]
[[rule]]
id = "punt-testnet"
punt = { to = ["192.0.2.0/24", "2001:db8::/32"], port = 9, proto = "tcp", gateway = "mcp" }
fail = "closed"
[[rule]]
id = "punt-no-gateway"
punt = { to = "192.0.2.0/24", port = 10, proto = "tcp" }
fail = "closed"
[[rule]]
id = "punt-udp"
punt = { to = "192.0.2.0/24", port = 9, proto = "udp", gateway = "mcp" }
fail = "closed"
"#,
    );
    let serial = f.d().serial;
    f.d().gateways.publish(&policy, serial);

    let listen: SocketAddr = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let gcfg = kavachd::config::GatewayConfig {
        enabled: true,
        listen,
        ..Default::default()
    };
    let mut base = kavachd::gateway::kernel_cfg(&gcfg, std::process::id(), 0);
    let mut live = |f: &mut Fixture, on: bool| {
        base.flags = if on { KV_GW_F_V4 } else { 0 };
        base.alive_until_ns = if on {
            kernel::boot_ns() + 60_000_000_000
        } else {
            0
        };
        f.k().set_gateway_cfg(base).unwrap();
    };
    let gws = |f: &mut Fixture, i: u32| f.k().gw_stats().unwrap()[i as usize];
    let orig = {
        let maps = f.k().gateway_maps().unwrap();
        kavachd::gateway::PinnedOrigDst::new(maps.into_orig(), f.d().gateways.clone())
    };

    // 1. Gateway dead: the fail mode (closed) refuses the connect.
    live(&mut f, false);
    assert!(
        !cg.run("echo hi > /dev/tcp/192.0.2.1/9"),
        "fail-closed punt with no gateway must be refused"
    );
    assert!(gws(&mut f, KV_GW_STAT_DEAD) >= 1);

    // 2. Gateway alive: v4 and v6 (a dual-stack socket goes to ::ffff:127.0.0.1) connects land
    // on our listener, and orig_dst knows where they were going while they are open.
    live(&mut f, true);
    for (dst, want) in [
        ("192.0.2.7/9", "192.0.2.7:9"),
        ("2001:db8::7/9", "[2001:db8::7]:9"),
    ] {
        let gw = std::net::TcpListener::bind(listen).unwrap();
        let mut child = cg.spawn(&format!(
            "exec 3<>/dev/tcp/{dst}; echo hello >&3; sleep 1; exec 3>&-"
        ));
        let (mut s, peer) = gw.accept().expect("redirected connect accepted");
        let local = s.local_addr().unwrap();
        assert_eq!(local, listen);
        let info = orig.lookup(peer, local).expect("orig_dst record");
        assert_eq!(info.dst, want.parse::<SocketAddr>().unwrap(), "{dst}");
        assert_eq!(info.rule_id, 1);
        assert_eq!(info.gateway, "mcp");
        assert_eq!(info.pid, child.id(), "pid of the connecting process");
        assert_ne!(info.cgroup_id, 0);
        // verdict write-back lands in the entry
        assert!(orig.record_verdict(peer, local, Verdict::Allow).unwrap());
        let r = orig.record(peer, local).unwrap();
        assert!(r.flags & KV_PUNT_F_DECIDED != 0);
        assert_eq!(r.verdict, Verdict::Allow as u8);
        let mut buf = Vec::new();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let _ = s.read_to_end(&mut buf);
        assert_eq!(buf, b"hello\n", "bytes reached the gateway");
        assert!(
            child.wait().unwrap().success(),
            "redirected connect succeeded"
        );
        // the client closed: its entry goes with it
        let deadline = Instant::now() + Duration::from_secs(2);
        while orig.lookup(peer, local).is_some() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(orig.lookup(peer, local).is_none(), "entry deleted on close");
    }
    assert!(gws(&mut f, KV_GW_STAT_REDIRECT) >= 2);
    assert!(gws(&mut f, KV_GW_STAT_ORIG_CLOSED) >= 2);

    // 3. A connection made straight to the gateway (not redirected) has no record.
    let gw = std::net::TcpListener::bind(listen).unwrap();
    let direct = TcpStream::connect(listen).unwrap();
    let (s, peer) = gw.accept().unwrap();
    assert!(orig.lookup(peer, s.local_addr().unwrap()).is_none());
    drop((direct, s, gw));

    // 4. The gateway's own process (this test, exempt by tgid) is neither refused nor
    // redirected. TEST-NET-1 is unroutable, so "allowed" shows as a timeout / unreachable.
    let before = gws(&mut f, KV_GW_STAT_EXEMPT);
    let r = TcpStream::connect_timeout(&"192.0.2.1:9".parse().unwrap(), Duration::from_millis(200));
    if let Err(e) = &r {
        assert_ne!(e.raw_os_error(), Some(nix::libc::EPERM), "gateway refused");
    }
    assert!(gws(&mut f, KV_GW_STAT_EXEMPT) > before);

    // 5. UDP punts keep the fail mode even with a live gateway.
    assert!(
        !cg.run("echo hi > /dev/udp/192.0.2.1/9"),
        "UDP punt is not redirectable: fail closed"
    );
    assert!(gws(&mut f, KV_GW_STAT_UNREDIRECTABLE) >= 1);

    // 6. A punt rule that names no gateway is never redirected: its fail mode decides.
    assert!(
        !cg.run("echo hi > /dev/tcp/192.0.2.1/10"),
        "punt without a gateway: fail closed"
    );
    assert!(gws(&mut f, KV_GW_STAT_NO_GATEWAY) >= 1);

    // 7. Gateway gone again: punts are refused again at once.
    live(&mut f, false);
    assert!(!cg.run("echo hi > /dev/tcp/192.0.2.1/9"));

    assert_eq!(f.k().detach_gateway(), kernel::GATEWAY_PROGS.len());
    assert!(!f.k().gateway_attached());
}

/// A fake kubepods tree under the real cgroup v2 root. Moves this process back to its original
/// cgroup and removes the tree on drop.
struct CgroupTree {
    base: std::path::PathBuf,
    home: std::path::PathBuf,
    dirs: Vec<std::path::PathBuf>,
}

impl CgroupTree {
    fn new(leaves: &[&str]) -> Self {
        let own = std::fs::read_to_string("/proc/self/cgroup").unwrap();
        let rel = own
            .lines()
            .find_map(|l| l.strip_prefix("0::"))
            .expect("cgroup v2")
            .trim_start_matches('/')
            .to_owned();
        let root = std::path::Path::new("/sys/fs/cgroup");
        let base = root.join(format!("kavach-test-{}", std::process::id()));
        let mut dirs = Vec::new();
        for l in leaves {
            let mut p = base.clone();
            for part in l.split('/') {
                p = p.join(part);
                if !dirs.contains(&p) {
                    std::fs::create_dir_all(&p).unwrap();
                    dirs.push(p.clone());
                }
            }
        }
        Self {
            base,
            home: root.join(rel),
            dirs,
        }
    }
    fn enter(&self, leaf: &str) {
        std::fs::write(
            self.base.join(leaf).join("cgroup.procs"),
            std::process::id().to_string(),
        )
        .unwrap();
    }
    fn leave(&self) {
        std::fs::write(
            self.home.join("cgroup.procs"),
            std::process::id().to_string(),
        )
        .unwrap();
    }
}

impl Drop for CgroupTree {
    fn drop(&mut self) {
        self.leave();
        for d in self.dirs.iter().rev() {
            let _ = std::fs::remove_dir(d);
        }
        let _ = std::fs::remove_dir(&self.base);
    }
}

#[test]
#[ignore = "needs root + BPF LSM + cgroup v2: scripts/priv-test.sh"]
fn lsm_k8s_and_spiffe_identity_by_cgroup() {
    use kavachd::workload::{K8sConfig, SourceKind, cgroup, source};
    let lsms = std::fs::read_to_string("/sys/kernel/security/lsm").unwrap_or_default();
    if !lsms.contains("bpf") {
        eprintln!("skipping: BPF LSM not active");
        return;
    }
    cgroup::ensure_cgroup2(std::path::Path::new("/sys/fs/cgroup")).expect("cgroup v2 host");
    let mut f = Fixture::new();
    f.k().attach_lsm().expect("attach LSM");

    const DB: &str = "1b3c5e7a-2d4f-4a6b-8c9d-0e1f2a3b4c5d";
    const NEW: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    const CID: &str = "4f1d0c6a2b3e5f7081928a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f";
    let db_leaf = format!("kubepods/burstable/pod{DB}/{CID}");
    let new_leaf = format!("kubepods/besteffort/pod{NEW}/{CID}");
    let tree = CgroupTree::new(&[&db_leaf, &new_leaf, "plain"]);

    let tmp = tempfile::tempdir().unwrap();
    let pods_file = tmp.path().join("pods.json");
    let write_pods = |app: &str| {
        std::fs::write(
            &pods_file,
            format!(
                r#"{{"items":[{{"metadata":{{"uid":"{DB}","namespace":"prod","name":"db-0","labels":{{"app":"{app}"}}}},"spec":{{"nodeName":"node-1","serviceAccountName":"db"}}}}]}}"#
            ),
        )
        .unwrap()
    };
    let cfg = K8sConfig {
        enabled: true,
        source: SourceKind::File,
        pods_file: pods_file.clone(),
        node_name: "node-1".into(),
        cgroup_root: tree.base.clone(), // a subtree of the real cgroup2 mount
        ..Default::default()
    };
    let mut src = source::build(&cfg).unwrap();
    let refresh = |f: &mut Fixture, src: &mut Box<dyn source::Source>| {
        let pods = src.fetch().unwrap();
        let d = f.d();
        d.workloads.enabled = true;
        d.workloads.view = cgroup::scan(&tree.base);
        d.workloads.pods = pods;
        d.sync_workloads(None).unwrap();
    };
    write_pods("db");
    // Startup order: prime (scan + fetch, no map writes), then the policy restore stages it.
    let _agent = kavachd::workload::prime(cfg.clone(), f.d()).expect("prime");
    assert_eq!(
        f.d().workloads.stats.entries,
        0,
        "prime does not write wl_class"
    );
    assert_eq!(f.d().workloads.view.roots.len(), 1);
    assert_eq!(f.d().workloads.view.pods.len(), 2);

    f.apply_toml(
        r#"
version = 1
[defaults]
egress = "allow"
ingress = "allow"
[[rule]]
id = "db-no-testnet-1"
who = { k8s = "app=db,ns=prod" }
fail = "open"
deny = { to = "192.0.2.1", port = 9, proto = "tcp" }
[[rule]]
id = "prod-sa-to-testnet-2"
who = { spiffe = "spiffe://cluster.local/ns/prod/*" }
fail = "closed"
allow = { to = "192.0.2.2", port = 9, proto = "tcp" }
[[rule]]
id = "nobody-else-to-testnet-2"
deny = { to = "192.0.2.2", port = 9, proto = "tcp" }
"#,
    );
    let st = f.d().workloads.stats.clone();
    assert_eq!((st.resolved, st.unknown, st.overflow), (1, 1, 0), "{st:?}");
    assert_eq!(st.entries, 3, "root + two pods");

    let connect = |last: u8| {
        let a: SocketAddr = format!("192.0.2.{last}:9").parse().unwrap();
        match TcpStream::connect_timeout(&a, std::time::Duration::from_millis(150)) {
            Ok(_) => false,
            Err(e) => e.raw_os_error() == Some(nix::libc::EPERM),
        }
    };

    // Resolved pod with app=db in prod: label rule denies .1, its SPIFFE ID is allowed to .2.
    tree.enter(&db_leaf);
    assert!(connect(1), "k8s label selector denies");
    assert!(!connect(2), "spiffe prefix allows");

    // Pod whose metadata is not known: the fail-open label rule is skipped, the fail-closed
    // spiffe rule refuses (unknown-identity twin).
    tree.enter(&new_leaf);
    assert!(!connect(1), "fail-open rule skipped for an unknown pod");
    assert!(connect(2), "fail-closed rule refuses an unknown pod");

    // Not a pod at all: neither workload rule applies; the catch-all deny on .2 does.
    tree.enter("plain");
    assert!(!connect(1));
    assert!(connect(2));

    // Relabel the db pod: the resolver updates wl_class in place (no policy apply).
    write_pods("cache");
    refresh(&mut f, &mut src);
    tree.enter(&db_leaf);
    assert!(!connect(1), "label no longer matches");
    assert!(!connect(2), "still in prod: spiffe allow");

    // A new policy generation recomputes the staged slot's workload masks before the flip.
    f.apply_toml(
        r#"
version = 1
[defaults]
egress = "allow"
[[rule]]
id = "cache-no-testnet-3"
who = { k8s = "app=cache" }
deny = { to = "192.0.2.3", port = 9, proto = "tcp" }
"#,
    );
    assert!(connect(3), "new slot's masks were staged");
    assert!(!connect(1));
    tree.leave();
    assert!(!connect(3), "outside the pod");

    // The pods' cgroups go away: their entries are deleted.
    drop(tree);
    let d = f.d();
    d.workloads.view = Default::default();
    d.sync_workloads(None).unwrap();
    assert_eq!(d.workloads.stats.entries, 0);
}
