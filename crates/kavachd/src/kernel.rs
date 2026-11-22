//! Everything that touches the kernel: loading, attaching and pinning programs, typed map access,
//! and the A/B policy swap primitives. All map layouts come from `kavach-common`.

use std::collections::HashMap as StdHashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::{Array, ArrayOfMaps, HashMap, MapData, MapError, PerCpuArray, RingBuf};
use aya::programs::links::{FdLink, PinnedLink};
use aya::programs::{Iter, Lsm, SchedClassifier, TcAttachType, Xdp, XdpMode};
use aya::{Btf, Ebpf, EbpfLoader};
use ipnet::IpNet;
use kavach_common::abi::*;
use kavach_common::addr::{from_mapped, mapped_prefix, mask_addr, to_mapped};
use tracing::{info, warn};

/// Bump whenever a map layout changes: pins live under `/sys/fs/bpf/kavach/v<ABI_VERSION>`.
pub const ABI_VERSION: u32 = 1;

/// The compiled eBPF object, embedded at build time (see build.rs).
pub static OBJECT: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/kavach.bpf.o"));

/// LSM hooks and the program implementing each.
pub const LSM_HOOKS: &[(&str, &str)] = &[
    ("kavach_connect", "socket_connect"),
    ("kavach_sendmsg", "socket_sendmsg"),
    ("kavach_exec", "bprm_committed_creds"),
    ("kavach_file_open", "file_open"),
    ("kavach_truncate", "path_truncate"),
    ("kavach_file_truncate", "file_truncate"),
    ("kavach_inode_free", "inode_free_security"),
];

/// `addr_sets` key payload after the LPM prefix length.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SlotAddr {
    pub slot: u32,
    pub addr: [u8; 16],
}
// SAFETY: #[repr(C)], u32 + [u8;16] = 20 bytes with no padding; any bit pattern is valid.
unsafe impl aya::Pod for SlotAddr {}

#[derive(Debug)]
pub struct Kernel {
    bpf: Ebpf,
    pin_dir: Option<PathBuf>,
    sync_inner: Option<MapData>,
    pub xdp: Vec<(String, String)>,
    pub tc: Vec<String>,
    pub lsm: bool,
}

fn btf() -> Result<Btf> {
    Btf::from_sys_fs().context("kernel BTF (/sys/kernel/btf/vmlinux) is required")
}

impl Kernel {
    /// Load the object, re-using pinned maps under `pin_dir` (so a daemon restart never loses
    /// state or opens an enforcement gap). Tests pass a private directory.
    pub fn load(pin_dir: &Path) -> Result<Self> {
        let btf = btf()?;
        let fresh = !pin_dir.exists();
        std::fs::create_dir_all(pin_dir.join("links"))
            .with_context(|| format!("creating {} (is bpffs mounted?)", pin_dir.display()))?;
        let loaded = EbpfLoader::new()
            .btf(&btf)
            .default_map_pin_directory(pin_dir)
            .load(OBJECT);
        let mut bpf = match loaded {
            Ok(b) => b,
            Err(e) => {
                // Never leave a half-populated pin dir behind that a later start would re-adopt.
                if fresh {
                    let _ = std::fs::remove_dir_all(pin_dir);
                }
                return Err(e).context("loading eBPF object");
            }
        };
        let sync_inner = bpf.take_map("sync_inner").and_then(|m| match m {
            aya::maps::Map::Array(d) => Some(d),
            _ => None,
        });
        Ok(Self {
            bpf,
            pin_dir: Some(pin_dir.to_path_buf()),
            sync_inner,
            xdp: vec![],
            tc: vec![],
            lsm: false,
        })
    }

    fn link_pin(&self, name: &str) -> Option<PathBuf> {
        self.pin_dir.as_ref().map(|d| d.join("links").join(name))
    }

    // ---------------------------------------------------------------------------------------
    // Attach
    // ---------------------------------------------------------------------------------------

    /// Attach XDP to `iface`. Atomically replaces a previously pinned Kavach link (upgrade
    /// without a gap). Returns the mode used.
    pub fn attach_xdp(&mut self, iface: &str, mode: &str) -> Result<String> {
        let pin = self.link_pin(&format!("xdp-{iface}"));
        let prog: &mut Xdp = self
            .bpf
            .program_mut("kavach_xdp")
            .ok_or_else(|| anyhow!("kavach_xdp missing"))?
            .try_into()?;
        if prog.fd().is_err() {
            prog.load()?;
        }
        let ifname = std::ffi::CString::new(iface)?;
        if let Some(pin) = pin.as_ref().filter(|p| p.exists()) {
            let old = PinnedLink::from_pin(pin).context("re-adopting pinned XDP link")?;
            let fd: FdLink = old.into();
            prog.attach_to_link(aya::programs::xdp::XdpLink::try_from(fd)?)
                .context("replacing XDP program on existing link")?;
            info!(iface, "XDP program replaced in place");
            return Ok("replaced".into());
        }
        let tries: &[(XdpMode, &str)] = match mode {
            "native" => &[(XdpMode::Driver, "native")],
            "skb" => &[(XdpMode::Skb, "generic")],
            _ => &[(XdpMode::Driver, "native"), (XdpMode::Skb, "generic")],
        };
        let mut last = None;
        for (m, label) in tries {
            match prog.attach(ifname.as_c_str(), *m) {
                Ok(id) => {
                    if let Some(pin) = pin {
                        let link = prog.take_link(id)?;
                        match FdLink::try_from(link) {
                            Ok(fd) => {
                                fd.pin(&pin).context("pinning XDP link")?;
                            }
                            Err(_) => warn!(iface, "XDP attached via netlink: not pinnable"),
                        }
                    }
                    self.xdp.push((iface.to_owned(), (*label).to_owned()));
                    return Ok((*label).to_owned());
                }
                Err(e) => last = Some(e),
            }
        }
        Err(anyhow!("attaching XDP to {iface}: {:?}", last))
    }

    /// Attach TC ingress + egress to `iface` (tcx on >= 6.6, clsact netlink before).
    pub fn attach_tc(&mut self, iface: &str) -> Result<()> {
        let cname = std::ffi::CString::new(iface)?;
        let _ = aya::programs::tc::qdisc_add_clsact(cname.as_c_str()); // needed (and harmless) for netlink
        for (name, at) in [
            ("kavach_tc_ingress", TcAttachType::Ingress),
            ("kavach_tc_egress", TcAttachType::Egress),
        ] {
            let pin = self.link_pin(&format!("{name}-{iface}"));
            let prog: &mut SchedClassifier = self
                .bpf
                .program_mut(name)
                .ok_or_else(|| anyhow!("{name} missing"))?
                .try_into()?;
            if prog.fd().is_err() {
                prog.load()?;
            }
            let ifname = std::ffi::CString::new(iface)?;
            let id = prog
                .attach(ifname.as_c_str(), at)
                .with_context(|| format!("attaching {name} to {iface}"))?;
            if let Some(pin) = pin {
                let link = prog.take_link(id)?;
                match FdLink::try_from(link) {
                    Ok(fd) => {
                        // Attach-before-detach: the new link is live, now drop the old one.
                        if pin.exists() {
                            std::fs::remove_file(&pin)?;
                        }
                        fd.pin(&pin)?;
                    }
                    Err(_) => warn!(
                        iface,
                        name, "TC attached via netlink (kernel < 6.6): not pinnable"
                    ),
                }
            }
        }
        self.tc.push(iface.to_owned());
        Ok(())
    }

    /// Load and attach every BPF-LSM program.
    pub fn attach_lsm(&mut self) -> Result<()> {
        let lsms = std::fs::read_to_string("/sys/kernel/security/lsm").unwrap_or_default();
        if !lsms.split(',').any(|l| l.trim() == "bpf") {
            bail!("BPF LSM is not active (add `bpf` to the lsm= kernel command line)");
        }
        let btf = btf()?;
        for (name, hook) in LSM_HOOKS {
            let pin = self.link_pin(name);
            let prog: &mut Lsm = self
                .bpf
                .program_mut(name)
                .ok_or_else(|| anyhow!("{name} missing"))?
                .try_into()?;
            if prog.fd().is_err() {
                prog.load(hook, &btf)
                    .with_context(|| format!("loading {name}"))?;
            }
            let id = prog.attach().with_context(|| format!("attaching {name}"))?;
            if let Some(pin) = pin {
                let fd: FdLink = prog.take_link(id)?.into();
                if pin.exists() {
                    std::fs::remove_file(&pin)?;
                }
                fd.pin(&pin)?;
            }
        }
        self.lsm = true;
        Ok(())
    }

    /// Run the task iterator once: emits an `Exec` event for every unclassified process.
    pub fn scan_tasks(&mut self) -> Result<()> {
        let btf = btf()?;
        let prog: &mut Iter = self
            .bpf
            .program_mut("kavach_task_scan")
            .ok_or_else(|| anyhow!("kavach_task_scan missing"))?
            .try_into()?;
        if prog.fd().is_err() {
            prog.load("task", &btf)?;
        }
        let id = prog.attach()?;
        let link = prog.take_link(id)?;
        let mut file = link.into_file()?;
        std::io::copy(&mut file, &mut std::io::sink())?;
        Ok(())
    }

    /// Detach everything and remove every pin (kill-switch, NFR-REL-2).
    pub fn kill_switch(self) -> Result<()> {
        if let Some(dir) = &self.pin_dir
            && dir.exists()
        {
            std::fs::remove_dir_all(dir).with_context(|| format!("removing {}", dir.display()))?;
        }
        drop(self.bpf); // closes program/link fds; unpinned links detach
        Ok(())
    }

    // ---------------------------------------------------------------------------------------
    // Maps
    // ---------------------------------------------------------------------------------------

    fn map(&mut self, name: &str) -> Result<&mut aya::maps::Map> {
        self.bpf
            .map_mut(name)
            .ok_or_else(|| anyhow!("map {name} missing"))
    }

    pub fn take_events(&mut self) -> Result<RingBuf<MapData>> {
        let m = self
            .bpf
            .take_map("events")
            .ok_or_else(|| anyhow!("events map missing"))?;
        Ok(RingBuf::try_from(m)?)
    }

    pub fn set_xdp_config(&mut self, cfg: XdpConfig) -> Result<()> {
        let mut a: Array<_, XdpConfig> = Array::try_from(self.map("xdp_cfg")?)?;
        a.set(0, &cfg, 0)?;
        Ok(())
    }

    pub fn xdp_config(&mut self) -> Result<XdpConfig> {
        let a: Array<_, XdpConfig> = Array::try_from(self.map("xdp_cfg")?)?;
        Ok(a.get(&0, 0)?)
    }

    pub fn block_add(&mut self, net: IpNet, expires_ns: u64, reason: u32) -> Result<()> {
        let mut t: LpmTrie<_, [u8; 16], BlockVal> = LpmTrie::try_from(self.map("blocklist")?)?;
        let k = BlockKey::from_cidr(net.network(), net.prefix_len());
        t.insert(
            &Key::new(k.prefixlen, k.addr),
            &BlockVal {
                expires_ns,
                reason,
                _pad: 0,
            },
            0,
        )?;
        Ok(())
    }

    pub fn block_del(&mut self, net: IpNet) -> Result<()> {
        let mut t: LpmTrie<_, [u8; 16], BlockVal> = LpmTrie::try_from(self.map("blocklist")?)?;
        let k = BlockKey::from_cidr(net.network(), net.prefix_len());
        t.remove(&Key::new(k.prefixlen, k.addr))
            .map_err(|_| anyhow!("{net} is not blocked"))?;
        Ok(())
    }

    pub fn block_list(&mut self) -> Result<Vec<(IpNet, BlockVal)>> {
        let t: LpmTrie<_, [u8; 16], BlockVal> = LpmTrie::try_from(self.map("blocklist")?)?;
        let mut out = Vec::new();
        for item in t.iter() {
            let (k, v) = item?;
            out.push((key_to_net(k.prefix_len(), k.data()), v));
        }
        Ok(out)
    }

    pub fn stats(&mut self) -> Result<Vec<u64>> {
        let a: PerCpuArray<_, u64> = PerCpuArray::try_from(self.map("stats")?)?;
        let mut out = Vec::with_capacity(KV_STAT_MAX as usize);
        for i in 0..KV_STAT_MAX {
            out.push(a.get(&i, 0)?.iter().sum());
        }
        Ok(out)
    }

    pub fn generation(&mut self) -> Result<u32> {
        let a: Array<_, u32> = Array::try_from(self.map("policy_gen")?)?;
        Ok(a.get(&0, 0)?)
    }

    pub fn policy_header(&mut self, slot: u32) -> Result<PolicyHeader> {
        let a: Array<_, Policy> = Array::try_from(self.map("policy_slots")?)?;
        Ok(a.get(&slot, 0)?.hdr)
    }

    /// Write a whole policy into `slot` (must be the inactive one).
    pub fn write_slot(&mut self, slot: u32, p: &Policy) -> Result<()> {
        let mut a: Array<_, Policy> = Array::try_from(self.map("policy_slots")?)?;
        a.set(slot, p, 0)?;
        Ok(())
    }

    /// Flip the active generation with one 32-bit write (FR-HS-1).
    pub fn set_generation(&mut self, generation: u32) -> Result<()> {
        let mut a: Array<_, u32> = Array::try_from(self.map("policy_gen")?)?;
        a.set(0, &generation, 0)?;
        Ok(())
    }

    /// Wait for every in-flight non-sleepable BPF program: updating a map-in-map makes the
    /// kernel call synchronize_rcu() before returning (FR-HS-3).
    pub fn synchronize(&mut self) -> Result<()> {
        let inner = self
            .sync_inner
            .take()
            .ok_or_else(|| anyhow!("sync_inner missing"))?;
        let res = (|| -> Result<()> {
            let mut outer: ArrayOfMaps<_, MapData> = ArrayOfMaps::try_from(self.map("sync_rcu")?)?;
            outer.set(0, &inner, 0)?;
            Ok(())
        })();
        self.sync_inner = Some(inner);
        res
    }

    /// Replace every `addr_sets` entry of `slot`.
    pub fn write_addr_sets(
        &mut self,
        slot: u32,
        flat: &[kavach_policy::kernel::FlatPrefix],
    ) -> Result<()> {
        let mut t: LpmTrie<_, SlotAddr, u64> = LpmTrie::try_from(self.map("addr_sets")?)?;
        let stale: Vec<Key<SlotAddr>> = t
            .keys()
            .filter_map(Result::ok)
            .filter(|k| k.data().slot == slot)
            .collect();
        for k in stale {
            let _ = t.remove(&k);
        }
        for p in flat {
            let k = Key::new(
                AddrKey::HEADER_BITS + p.prefix,
                SlotAddr { slot, addr: p.addr },
            );
            t.insert(&k, &p.bitmap, 0)?;
        }
        Ok(())
    }

    // Classification maps: per-slot masks, read-modify-write so the other slot is preserved.

    pub fn set_uid_masks(&mut self, slot: u32, want: &StdHashMap<u32, u64>) -> Result<()> {
        let mut m: HashMap<_, u32, ClassVal> = HashMap::try_from(self.map("uid_class")?)?;
        update_class_map(&mut m, slot, want)
    }

    pub fn set_cgroup_masks(&mut self, slot: u32, want: &StdHashMap<u64, u64>) -> Result<()> {
        let mut m: HashMap<_, u64, ClassVal> = HashMap::try_from(self.map("cgroup_class")?)?;
        update_class_map(&mut m, slot, want)
    }

    /// Update an **existing** classification (`BPF_EXIST`). `Ok(false)` when the entry is gone:
    /// the LSM deleted it because the file was modified, so the caller's hash is stale.
    pub fn update_exe_class(&mut self, key: &ExeKey, class: ExeClass) -> Result<bool> {
        const BPF_EXIST: u64 = 2;
        let mut m: HashMap<_, ExeKey, ExeClass> = HashMap::try_from(self.map("exe_class")?)?;
        match m.insert(key, &class, BPF_EXIST) {
            Ok(()) => Ok(true),
            Err(MapError::SyscallError(e))
                if e.io_error.raw_os_error() == Some(nix::libc::ENOENT) =>
            {
                Ok(false)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Unconditional write, for tests that fabricate classifications.
    pub fn set_exe_class(&mut self, key: &ExeKey, class: ExeClass) -> Result<()> {
        let mut m: HashMap<_, ExeKey, ExeClass> = HashMap::try_from(self.map("exe_class")?)?;
        m.insert(key, &class, 0)?;
        Ok(())
    }

    /// Disarm the key request only if it is still ours: a late (timed-out) opener must not wipe
    /// a newer request. All user-space writes to `key_req` happen under the state lock, so this
    /// check-then-clear is atomic with respect to them.
    pub fn disarm_key_req(&mut self, nonce: u64) -> Result<()> {
        let cur = {
            let m: Array<_, KeyReq> = Array::try_from(self.map("key_req")?)?;
            m.get(&0, 0)?
        };
        if cur.nonce == nonce {
            self.set_key_req(0, 0)?;
        }
        Ok(())
    }

    /// Arm (or, with `nonce == 0`, disarm) the one-shot key request for thread `tid`.
    pub fn set_key_req(&mut self, nonce: u64, tid: u32) -> Result<()> {
        let mut m: Array<_, KeyReq> = Array::try_from(self.map("key_req")?)?;
        m.set(
            0,
            &KeyReq {
                nonce,
                tid,
                _pad: 0,
            },
            0,
        )?;
        Ok(())
    }

    pub fn exe_class_keys(&mut self) -> Result<Vec<ExeKey>> {
        let m: HashMap<_, ExeKey, ExeClass> = HashMap::try_from(self.map("exe_class")?)?;
        Ok(m.keys().filter_map(Result::ok).collect())
    }

    pub fn remove_exe_class(&mut self, key: &ExeKey) -> Result<()> {
        let mut m: HashMap<_, ExeKey, ExeClass> = HashMap::try_from(self.map("exe_class")?)?;
        let _ = m.remove(key);
        Ok(())
    }

    pub fn exe_class(&mut self, key: &ExeKey) -> Result<Option<ExeClass>> {
        let m: HashMap<_, ExeKey, ExeClass> = HashMap::try_from(self.map("exe_class")?)?;
        Ok(m.get(key, 0).ok())
    }

    /// Program test-run access for the BPF test-suite.
    pub fn bpf_mut(&mut self) -> &mut Ebpf {
        &mut self.bpf
    }
}

fn update_class_map<K: aya::Pod + Eq + std::hash::Hash + Copy>(
    m: &mut HashMap<&mut MapData, K, ClassVal>,
    slot: u32,
    want: &StdHashMap<K, u64>,
) -> Result<()> {
    let s = (slot & 1) as usize;
    let existing: Vec<(K, ClassVal)> = m.iter().filter_map(Result::ok).collect();
    for (k, mut v) in existing {
        let new = want.get(&k).copied().unwrap_or(0);
        if v.mask[s] != new {
            v.mask[s] = new;
            if v.mask == [0, 0] {
                let _ = m.remove(&k);
            } else {
                m.insert(&k, &v, 0)?;
            }
        }
    }
    for (k, mask) in want {
        if m.get(k, 0).is_err() && *mask != 0 {
            let mut v = ClassVal::default();
            v.mask[s] = *mask;
            m.insert(k, &v, 0)?;
        }
    }
    Ok(())
}

pub fn key_to_net(prefix: u32, addr: [u8; 16]) -> IpNet {
    let ip = from_mapped(addr);
    let len = match ip {
        IpAddr::V4(_) => prefix.saturating_sub(96) as u8,
        IpAddr::V6(_) => prefix as u8,
    };
    IpNet::new(ip, len).unwrap_or_else(|_| IpNet::from(ip))
}

/// Normalised blocklist key for display/testing.
pub fn mapped_key(net: IpNet) -> (u32, [u8; 16]) {
    let p = mapped_prefix(net.network(), net.prefix_len());
    (p, mask_addr(to_mapped(net.network()), p))
}

/// `CLOCK_BOOTTIME` now, in ns (the clock every `_ns` deadline in the maps uses).
pub fn boot_ns() -> u64 {
    let ts = nix::time::clock_gettime(nix::time::ClockId::CLOCK_BOOTTIME).expect("CLOCK_BOOTTIME");
    ts.tv_sec() as u64 * 1_000_000_000 + ts.tv_nsec() as u64
}

pub fn unix_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// GCRA parameters for `pps` packets/s with a `burst`.
pub fn gcra(pps: u64, burst: u64) -> (u64, u64) {
    let emission = 1_000_000_000 / pps.max(1);
    (emission, emission.saturating_mul(burst.max(1) - 1))
}
