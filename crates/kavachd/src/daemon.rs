//! Daemon state: the loaded kernel side, the policy in each A/B slot, the identity broker's
//! executable cache, and the operations that change any of them (apply, classify, block...).

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{BufReader, Read};
use std::net::{IpAddr, ToSocketAddrs};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};
use ipnet::IpNet;
use kavach_api::audit::Chain;
use kavach_api::{ApplyReport, BlockEntry, Status};
use kavach_common::abi::*;
use kavach_policy::VerifyingKey;
use kavach_policy::bundle::{self, TrustPolicy};
use kavach_policy::compile::{CompiledPolicy, User};
use kavach_policy::kernel::{Clocks, flatten_sets};
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::config::Config;
use crate::kernel::{self, Kernel};

#[derive(Debug, Clone)]
pub struct ExeInfo {
    pub sha256: [u8; 32],
    pub path: String,
    /// Nonce of the committed `exe_class` entry this hash belongs to (0 until committed).
    /// Mask updates and restart reconciliation only touch an entry whose nonce matches, so a
    /// stale row can never re-arm a placeholder or a re-classified inode.
    pub nonce: u64,
}

/// The LSM's answer to an armed [`KeyReq`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyReport {
    pub key: ExeKey,
    pub nonce: u64,
    /// The inode had open writers: its content may change under the hash.
    pub writers: bool,
    /// The file is on a filesystem whose content cannot be vouched for (no placeholder).
    pub untrusted_fs: bool,
}

impl KeyReport {
    pub fn from_event(e: &Event) -> Option<Self> {
        (e.kind == EventKind::KeyReport as u8).then_some(Self {
            key: e.exe_key(),
            nonce: e.cgroup_id,
            writers: e.verdict & KV_REPORT_WRITERS != 0,
            untrusted_fs: e.verdict & KV_REPORT_UNTRUSTED_FS != 0,
        })
    }
}

#[derive(Debug)]
pub struct Audit {
    chain: Chain,
    file: Option<File>,
}

impl Audit {
    pub fn open(path: &std::path::Path) -> Self {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let chain = match File::open(path) {
            Ok(f) => match Chain::resume(BufReader::new(f)) {
                Ok(c) => c,
                Err(e) => {
                    let broken = path
                        .with_extension(format!("broken-{}", kernel::unix_ns() / 1_000_000_000));
                    warn!(error = %e, moved_to = %broken.display(), "audit log failed verification; starting a new chain");
                    let _ = std::fs::rename(path, &broken);
                    Chain::default()
                }
            },
            Err(_) => Chain::default(),
        };
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .ok();
        if file.is_none() {
            warn!(path = %path.display(), "audit log not writable; audit records go to the journal only");
        }
        Self { chain, file }
    }

    pub fn record(&mut self, kind: &str, data: serde_json::Value) {
        let ts = kernel::unix_ns() / 1_000_000_000;
        match self.file.as_mut() {
            Some(f) => {
                if let Err(e) = self.chain.write(f, ts, kind, data) {
                    warn!(error = %e, "audit write failed");
                }
            }
            None => {
                let rec = self.chain.append(ts, kind, data);
                info!(target: "audit", record = %serde_json::to_string(&rec).unwrap_or_default());
            }
        }
    }
}

#[derive(Debug)]
pub struct Daemon {
    pub cfg: Config,
    pub kernel: Option<Kernel>,
    pub slots: [Option<Arc<CompiledPolicy>>; 2],
    pub generation: u32,
    pub serial: u64,
    pub expired: bool,
    pub exe_cache: HashMap<ExeKey, ExeInfo>,
    pub fqdns: BTreeMap<String, Vec<IpAddr>>,
    pub audit: Audit,
    pub started: Instant,
    /// Classifications waiting for their `KeyReport`: nonce → broker.
    pub key_waiters: HashMap<u64, tokio::sync::oneshot::Sender<KeyReport>>,
    next_nonce: u64,
    /// The broker's priority queue for pre-classification (absent in tests that drive the
    /// protocol by hand).
    pub prewarm_tx: Option<tokio::sync::mpsc::Sender<crate::events::IdentityJob>>,
    /// Pre-classification jobs queued by the last apply and not finished yet.
    pub prewarm_pending: usize,
    /// Read-only fds on pre-classified, policy-named executables. A class lives exactly as long
    /// as its inode (`inode_free_security` deletes it); holding the file keeps an idle binary's
    /// inode, and so its classification, from being evicted. Not a writer: taint still works.
    pub pinned: HashMap<String, File>,
    /// Wakes the hash scanner (full scan) after the active policy changed.
    pub scan_kick: Arc<tokio::sync::Notify>,
    /// L7 gateway policies of the active bundle, for the gateway proxy (clone the handle).
    pub gateways: crate::gateway_policies::GatewayPolicies,
    /// k8s / SPIFFE node agent state (`crate::workload`).
    pub workloads: crate::workload::Workloads,
}

impl Daemon {
    pub fn new(cfg: Config, kernel: Kernel) -> Self {
        let audit = Audit::open(&cfg.audit_log);
        Self {
            cfg,
            kernel: Some(kernel),
            slots: [None, None],
            generation: 0,
            serial: 0,
            expired: false,
            exe_cache: HashMap::new(),
            fqdns: BTreeMap::new(),
            audit,
            started: Instant::now(),
            key_waiters: HashMap::new(),
            // never reuse a nonce across restarts (placeholders outlive a crashed daemon)
            next_nonce: kernel::unix_ns(),
            prewarm_tx: None,
            prewarm_pending: 0,
            pinned: HashMap::new(),
            scan_kick: Arc::new(tokio::sync::Notify::new()),
            gateways: Default::default(),
            workloads: Default::default(),
        }
    }

    pub fn k(&mut self) -> Result<&mut Kernel> {
        self.kernel
            .as_mut()
            .ok_or_else(|| anyhow!("kill-switch engaged: kernel side detached"))
    }

    pub fn active(&self) -> Option<&Arc<CompiledPolicy>> {
        self.slots[(self.generation & 1) as usize].as_ref()
    }

    // -----------------------------------------------------------------------------------------
    // Identity dimension tables (per slot)
    // -----------------------------------------------------------------------------------------

    fn exe_dim_mask(p: &CompiledPolicy, info: &ExeInfo) -> u64 {
        p.selectors
            .iter()
            .enumerate()
            .filter(|(_, s)| {
                s.constrains_exe() && s.exe_matches(Some(info.sha256), Some(&info.path))
            })
            .fold(0, |m, (i, _)| m | (1 << i))
    }

    fn uid_table(p: &CompiledPolicy) -> HashMap<u32, u64> {
        let mut t = HashMap::new();
        for (i, s) in p.selectors.iter().enumerate() {
            for u in &s.users {
                let uid = match u {
                    User::Uid(n) => Some(*n),
                    User::Name(n) => nix::unistd::User::from_name(n)
                        .ok()
                        .flatten()
                        .map(|u| u.uid.as_raw()),
                };
                match uid {
                    Some(uid) => *t.entry(uid).or_insert(0) |= 1 << i,
                    None => {
                        warn!(user = ?u, "policy names an unknown user; selector cannot match it")
                    }
                }
            }
        }
        t
    }

    fn cgroup_table(p: &CompiledPolicy) -> HashMap<u64, u64> {
        let mut t = HashMap::new();
        for (i, s) in p.selectors.iter().enumerate() {
            for c in &s.cgroups {
                let path = PathBuf::from("/sys/fs/cgroup").join(c);
                match std::fs::metadata(&path) {
                    // cgroup v2 id == kernfs inode number of the cgroup directory.
                    Ok(md) => *t.entry(md.ino()).or_insert(0) |= 1 << i,
                    Err(_) => {
                        warn!(cgroup = %path.display(), "cgroup does not exist (yet); selector inactive until re-apply")
                    }
                }
            }
        }
        t
    }

    fn resolve_fqdns(&mut self, p: &CompiledPolicy) -> Vec<(u32, IpNet)> {
        let mut out = Vec::new();
        for (i, set) in p.sets.iter().enumerate() {
            for name in &set.fqdns {
                let ips = match (name.as_str(), 0u16).to_socket_addrs() {
                    Ok(it) => {
                        let mut v: Vec<IpAddr> = it.map(|a| a.ip()).collect();
                        v.sort();
                        v.dedup();
                        v
                    }
                    Err(e) => {
                        warn!(fqdn = name, error = %e, "DNS resolution failed; keeping last known addresses");
                        self.fqdns.get(name).cloned().unwrap_or_default()
                    }
                };
                for ip in &ips {
                    out.push((i as u32 + 1, IpNet::from(*ip)));
                }
                self.fqdns.insert(name.clone(), ips);
            }
        }
        out
    }

    // -----------------------------------------------------------------------------------------
    // A/B staging (FR-HS-1..5)
    // -----------------------------------------------------------------------------------------

    /// Stage `p` into the inactive slot and flip. Returns the flip+drain time in µs.
    pub fn stage(&mut self, p: Arc<CompiledPolicy>, serial: u64) -> Result<u64> {
        let new_gen = self.generation.wrapping_add(1);
        let slot = new_gen & 1;
        let s = slot as usize;

        // 1. classification masks for the new slot (the active slot's masks are untouched)
        let uids = Self::uid_table(&p);
        let cgs = Self::cgroup_table(&p);
        let exes: Vec<(ExeKey, u64, u64)> = self
            .exe_cache
            .iter()
            .map(|(k, info)| (*k, info.nonce, Self::exe_dim_mask(&p, info)))
            .collect();
        let extra = self.resolve_fqdns(&p);
        let mut entries = p.static_set_entries();
        entries.extend(extra);
        let flat = flatten_sets(&entries);
        let clocks = Clocks {
            unix_ns: kernel::unix_ns(),
            boot_ns: kernel::boot_ns(),
        };
        let table = p.to_kernel(new_gen, serial, clocks);

        let cached: HashMap<ExeKey, u64> =
            self.exe_cache.iter().map(|(k, i)| (*k, i.nonce)).collect();
        let k = self.k()?;
        k.set_uid_masks(slot, &uids)?;
        k.set_cgroup_masks(slot, &cgs)?;
        for (key, nonce, mask) in exes {
            if let Some(mut c) = k.exe_class(&key)?
                && committed_by(&c, nonce)
            {
                c.mask[s] = mask;
                k.update_exe_class(&key, c)?; // false = tainted meanwhile: stays deleted
            }
        }
        // A committed class we hold no matching hash for would keep a stale mask in the new
        // slot. Placeholders belong to an in-flight classification and are left alone.
        for key in k.exe_class_keys()? {
            if let Some(c) = k.exe_class(&key)?
                && c.flags & KV_EXE_F_COMMITTED != 0
                && cached.get(&key) != Some(&c.nonce)
            {
                k.remove_exe_class(&key)?;
            }
        }
        // 2. address sets + rule table into the inactive slot
        k.write_addr_sets(slot, &flat)?;
        self.sync_workloads(Some((slot, &*p)))?;
        let k = self.k()?;
        k.write_slot(slot, &table)?;
        // 3. flip with one 32-bit write, then wait out in-flight programs
        let t0 = Instant::now();
        k.set_generation(new_gen)?;
        k.synchronize()?;
        let micros = t0.elapsed().as_micros() as u64;

        self.slots[s] = Some(p.clone());
        self.generation = new_gen;
        self.serial = serial;
        Ok(micros)
    }

    fn trust(&self) -> Result<TrustPolicy> {
        let mut trusted = Vec::new();
        if let Ok(dir) = std::fs::read_dir(&self.cfg.trusted_keys_dir) {
            for e in dir.flatten() {
                let path = e.path();
                if path.extension().is_some_and(|x| x == "pub") {
                    match read_pubkey(&path) {
                        Ok(k) => trusted.push(k),
                        Err(err) => {
                            warn!(key = %path.display(), error = %err, "ignoring unreadable trusted key")
                        }
                    }
                }
            }
        }
        let revoked = self
            .cfg
            .revoked_keys
            .iter()
            .filter_map(|h| hex::decode(h).ok()?.try_into().ok())
            .collect();
        Ok(TrustPolicy {
            trusted,
            revoked,
            fleet: self.cfg.fleet.clone(),
            active_serial: self.serial,
            now_unix: kernel::unix_ns() / 1_000_000_000,
        })
    }

    /// Verify and (unless `dry_run`) apply a signed bundle.
    pub fn apply(&mut self, bytes: &[u8], dry_run: bool) -> Result<ApplyReport> {
        let trust = self.trust()?;
        if trust.trusted.is_empty() {
            bail!("no trusted keys in {}", self.cfg.trusted_keys_dir.display());
        }
        let v = bundle::verify(bytes, &trust, true)?;
        let changes = match self.active() {
            Some(old) => kavach_policy::diff::diff(old, &v.policy)
                .iter()
                .map(ToString::to_string)
                .collect(),
            None => vec!["+ initial policy".to_owned()],
        };
        let mut report = ApplyReport {
            dry_run,
            serial: v.header.serial,
            generation: self.generation,
            rules: v.policy.rules.len() as u32,
            changes,
            ..Default::default()
        };
        if dry_run {
            return Ok(report);
        }
        let policy = Arc::new(v.policy);
        report.swap_micros = self.stage(policy.clone(), v.header.serial)?;
        self.gateways.publish(&policy, v.header.serial);
        report.generation = self.generation;
        report.warnings.extend(self.prewarm(&policy));
        report.warnings.extend(self.workload_warnings(&policy));
        let identity_rules = policy.rules.iter().filter(|r| r.sel != 0).count();
        if identity_rules > 0 && !self.k()?.lsm {
            report.warnings.push(format!(
                "BPF-LSM is not attached: {identity_rules} identity (`who`) rule(s) cannot match; \
                 see `kavachctl doctor`"
            ));
        }
        self.scan_kick.notify_one();
        self.expired = false;
        persist(&self.cfg.state_dir, bytes)?;
        self.audit.record(
            "policy_apply",
            json!({
                "serial": v.header.serial,
                "generation": self.generation,
                "key_id": hex::encode(v.header.key_id),
                "source_sha256": hex::encode(policy.source_sha256),
                "rules": policy.rules.len(),
                "gateways": policy.gateways.len(),
                "changes": report.changes,
            }),
        );
        info!(
            serial = v.header.serial,
            generation = self.generation,
            swap_us = report.swap_micros,
            "policy applied"
        );
        Ok(report)
    }

    fn exe_cache_path(&self) -> PathBuf {
        self.cfg.state_dir.join("exe_cache.json")
    }

    /// Persist the executable cache so a restart can recompute masks for both slots.
    pub fn save_exe_cache(&self) {
        let rows: Vec<serde_json::Value> = self
            .exe_cache
            .iter()
            .map(|(k, v)| json!({ "inode": k.inode, "ino": k.ino, "dev": k.dev, "gen": k.generation, "nonce": v.nonce, "sha256": hex::encode(v.sha256), "path": v.path }))
            .collect();
        let _ = std::fs::create_dir_all(&self.cfg.state_dir);
        let tmp = self.exe_cache_path().with_extension("tmp");
        if std::fs::write(&tmp, serde_json::to_vec(&rows).unwrap_or_default()).is_ok() {
            let _ = std::fs::rename(&tmp, self.exe_cache_path());
        }
    }

    /// Reload the cache, then drop every kernel classification we cannot account for: those
    /// executables are re-reported on their next exec (or by the task scan) and re-hashed,
    /// instead of keeping a mask that is stale for the slot we are about to stage.
    pub fn reconcile_exe_cache(&mut self) -> Result<()> {
        if let Ok(bytes) = std::fs::read(self.exe_cache_path()) {
            let rows: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap_or_default();
            for r in rows {
                let (
                    Some(inode),
                    Some(ino),
                    Some(dev),
                    Some(gen_),
                    Some(nonce),
                    Some(sha),
                    Some(path),
                ) = (
                    r["inode"].as_u64(),
                    r["ino"].as_u64(),
                    r["dev"].as_u64(),
                    r["gen"].as_u64(),
                    r["nonce"].as_u64(),
                    r["sha256"]
                        .as_str()
                        .and_then(|h| hex::decode(h).ok()?.try_into().ok()),
                    r["path"].as_str(),
                )
                else {
                    continue; // includes rows in the old (dev, generation, ino) format
                };
                self.exe_cache.insert(
                    ExeKey {
                        inode,
                        ino,
                        dev: dev as u32,
                        generation: gen_ as u32,
                    },
                    ExeInfo {
                        sha256: sha,
                        path: path.to_owned(),
                        nonce,
                    },
                );
            }
        }
        let k = self
            .kernel
            .as_mut()
            .ok_or_else(|| anyhow!("kernel detached"))?;
        // Keep exactly the (row, committed class) pairs that belong together. Everything else
        // goes: placeholders of a crashed daemon, classes without a hash, and rows whose class
        // was tainted (or whose inode was freed) while we were down, or whose maps are new.
        let mut pruned = 0;
        let mut keep = std::collections::HashSet::new();
        for key in k.exe_class_keys()? {
            let ok = match (k.exe_class(&key)?, self.exe_cache.get(&key)) {
                (Some(c), Some(row)) => committed_by(&c, row.nonce),
                _ => false,
            };
            if ok {
                keep.insert(key);
            } else {
                k.remove_exe_class(&key)?;
                pruned += 1;
            }
        }
        let before = self.exe_cache.len();
        self.exe_cache.retain(|key, _| keep.contains(key));
        pruned += before - self.exe_cache.len();
        info!(
            cached = self.exe_cache.len(),
            pruned, "executable classifications reconciled"
        );
        Ok(())
    }

    /// Re-stage the persisted bundle at startup (expired bundles keep enforcing + alert).
    pub fn restore(&mut self) -> Result<()> {
        if let Ok(g) = self.k()?.generation() {
            self.generation = g; // continue the pinned generation counter
        }
        self.reconcile_exe_cache()?;
        let path = self.cfg.state_dir.join("active.kvb");
        let Ok(bytes) = std::fs::read(&path) else {
            info!("no persisted policy; enforcing nothing until `kavachctl apply`");
            return Ok(());
        };
        let mut trust = self.trust()?;
        trust.active_serial = 0;
        let v =
            bundle::verify(&bytes, &trust, false).context("persisted bundle no longer verifies")?;
        if v.expired {
            warn!(
                serial = v.header.serial,
                "active bundle has passed not_after: still enforcing, replace it"
            );
        }
        self.expired = v.expired;
        let policy = Arc::new(v.policy);
        self.stage(policy.clone(), v.header.serial)?;
        self.gateways.publish(&policy, v.header.serial);
        for w in self.prewarm(&policy) {
            warn!("{w}");
        }
        self.scan_kick.notify_one();
        info!(
            serial = self.serial,
            generation = self.generation,
            "restored persisted policy"
        );
        Ok(())
    }

    /// Re-resolve FQDNs; re-stage the active policy if any answer changed.
    pub fn refresh_dns(&mut self) -> Result<()> {
        let Some(p) = self.active().cloned() else {
            return Ok(());
        };
        if p.sets.iter().all(|s| s.fqdns.is_empty()) {
            return Ok(());
        }
        let before = self.fqdns.clone();
        let _ = self.resolve_fqdns(&p);
        if before != self.fqdns {
            let serial = self.serial;
            self.stage(p, serial)?;
            info!(
                generation = self.generation,
                "FQDN answers changed; policy re-staged"
            );
        }
        Ok(())
    }

    // -----------------------------------------------------------------------------------------
    // Executable classification (FR-ID-2/3)
    // -----------------------------------------------------------------------------------------

    /// Queue every executable the policy names by path for classification, so those binaries
    /// are classified before they first run instead of on their first exec. Returns warnings
    /// for paths that cannot be classified.
    pub fn prewarm(&mut self, p: &CompiledPolicy) -> Vec<String> {
        let mut warnings = Vec::new();
        let named: std::collections::HashSet<&String> =
            p.selectors.iter().flat_map(|s| s.exes.iter()).collect();
        self.pinned.retain(|path, _| named.contains(path));
        let Some(jobs) = self.prewarm_tx.clone() else {
            return warnings;
        };
        for path in p.selectors.iter().flat_map(|s| s.exes.iter()) {
            if path.contains('*') {
                continue;
            }
            if !std::fs::metadata(path).is_ok_and(|m| m.is_file()) {
                warnings.push(format!("{path}: not a regular file; it stays unclassified"));
                continue;
            }
            match jobs.try_send(crate::events::IdentityJob::Path { path: path.clone() }) {
                Ok(()) => self.prewarm_pending += 1,
                Err(_) => warnings.push(format!(
                    "{path}: identity queue full; it will be classified on its first exec"
                )),
            }
        }
        warnings
    }

    /// A fresh, never-zero nonce for one key request.
    pub fn take_nonce(&mut self) -> u64 {
        self.next_nonce = self.next_nonce.wrapping_add(1).max(1);
        self.next_nonce
    }

    /// Step 1 of the classification protocol (see `ExeClass`): arm the one-shot key request
    /// for this thread, read-open `path`, disarm. The LSM answers with a `KeyReport` carrying
    /// the returned nonce. Hash the returned file, never the path again.
    pub fn open_for_report(&mut self, path: &str) -> Result<(u64, File)> {
        let nonce = self.take_nonce();
        let tid = nix::unistd::gettid().as_raw() as u32;
        let k = self.k()?;
        k.set_key_req(nonce, tid)?;
        let f = File::open(path);
        k.disarm_key_req(nonce)?;
        Ok((nonce, f.with_context(|| format!("opening {path}"))?))
    }

    /// Step 3: publish the hash. `Ok(false)` when the file was modified since the key report
    /// (the LSM deleted the placeholder); nothing is classified then.
    pub fn commit_classification(
        &mut self,
        key: ExeKey,
        mut info: ExeInfo,
        nonce: u64,
    ) -> Result<bool> {
        let mask = self.exe_masks(&info);
        let ok = self.k()?.update_exe_class(
            &key,
            ExeClass {
                mask,
                nonce,
                flags: KV_EXE_F_COMMITTED,
            },
        )?;
        if ok {
            info.nonce = nonce;
            self.exe_cache.insert(key, info);
        } else {
            self.exe_cache.remove(&key);
        }
        self.save_exe_cache();
        Ok(ok)
    }

    /// Give up on a classification: remove our placeholder so the next exec reports again.
    pub fn abandon_classification(&mut self, key: ExeKey, nonce: u64) {
        if let Ok(k) = self.k()
            && let Ok(Some(c)) = k.exe_class(&key)
            && c.nonce == nonce
            && c.flags & KV_EXE_F_COMMITTED == 0
        {
            let _ = k.remove_exe_class(&key);
        }
    }

    pub fn exe_masks(&self, info: &ExeInfo) -> [u64; 2] {
        let mut m = [0u64; 2];
        for (s, slot) in self.slots.iter().enumerate() {
            if let Some(p) = slot {
                m[s] = Self::exe_dim_mask(p, info);
            }
        }
        m
    }

    pub fn status(&mut self) -> Status {
        let rules = self.active().map_or(0, |p| p.rules.len() as u32);
        let (xdp, tc, lsm) = match &self.kernel {
            Some(k) => (k.xdp.clone(), k.tc.clone(), k.lsm),
            None => (vec![], vec![], false),
        };
        Status {
            version: env!("CARGO_PKG_VERSION").into(),
            kernel: nix::sys::utsname::uname()
                .map(|u| u.release().to_string_lossy().into_owned())
                .unwrap_or_default(),
            generation: self.generation,
            serial: self.serial,
            policy_expired: self.expired,
            rules,
            xdp,
            tc,
            lsm,
            features: vec![
                ("kill_switch_engaged".into(), self.kernel.is_none()),
                ("k8s_identity".into(), self.workloads.enabled),
            ],
            uptime_secs: self.started.elapsed().as_secs(),
        }
    }

    pub fn block_list(&mut self) -> Result<Vec<BlockEntry>> {
        let now = kernel::boot_ns();
        Ok(self
            .k()?
            .block_list()?
            .into_iter()
            .map(|(net, v)| BlockEntry {
                cidr: net.to_string(),
                reason: v.reason,
                expires_in: (v.expires_ns != 0)
                    .then(|| v.expires_ns.saturating_sub(now) / 1_000_000_000),
            })
            .collect())
    }

    /// Remove expired blocklist entries (the XDP program already ignores them).
    pub fn purge_blocklist(&mut self) -> Result<usize> {
        let now = kernel::boot_ns();
        let k = self.k()?;
        let expired: Vec<IpNet> = k
            .block_list()?
            .into_iter()
            .filter(|(_, v)| v.expires_ns != 0 && v.expires_ns <= now)
            .map(|(n, _)| n)
            .collect();
        for n in &expired {
            let _ = k.block_del(*n);
        }
        Ok(expired.len())
    }
}

/// Hash an open file (the one the LSM reported); its path comes from the fd itself.
pub fn hash_file(f: &mut File) -> Result<ExeInfo> {
    use std::os::fd::AsRawFd;
    let path = std::fs::read_link(format!("/proc/self/fd/{}", f.as_raw_fd()))?
        .to_string_lossy()
        .trim_end_matches(" (deleted)")
        .to_owned();
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(ExeInfo {
        sha256: h.finalize().into(),
        path,
        nonce: 0,
    })
}

/// Public keys are 32 raw bytes or 64 hex characters.
pub fn read_pubkey(path: &std::path::Path) -> Result<VerifyingKey> {
    let raw = std::fs::read(path)?;
    let bytes: [u8; 32] = if raw.len() == 32 {
        raw.try_into().unwrap()
    } else {
        hex::decode(String::from_utf8_lossy(&raw).trim())?
            .try_into()
            .map_err(|_| anyhow!("public key must be 32 bytes"))?
    };
    Ok(VerifyingKey::from_bytes(&bytes)?)
}

fn persist(dir: &std::path::Path, bytes: &[u8]) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join("active.kvb.tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, dir.join("active.kvb"))?;
    Ok(())
}

/// `c` is the committed entry produced by the key request `nonce`.
fn committed_by(c: &ExeClass, nonce: u64) -> bool {
    c.flags & KV_EXE_F_COMMITTED != 0 && c.nonce == nonce
}
