//! v0.4 node agent: k8s-label and SPIFFE identity by cgroup.
//!
//! ```text
//! cgroupfs scan ──► pod cgroups (id → pod UID) ─┐
//!                                               ├─► per-cgroup workload masks ─► wl_class map
//! kubelet / apiserver / file ──► pod metadata ──┘   (both policy slots)          (diffed)
//! ```
//!
//! * Each kubepods **root** cgroup gets the policy's unknown-identity bits, so a pod that
//!   kavachd has not resolved yet (or never could: source down, map full) is caught by the
//!   fail-closed twins of workload rules. The kernel takes the nearest classified cgroup.
//! * Each **pod** cgroup gets the bits of the workload selectors its pod satisfies (possibly
//!   0, which still overrides the root), or the unknown bits while its metadata is missing.
//! * Masks are per policy slot; `Daemon::stage` writes the new slot's masks before the flip.
//!
//! Nothing here runs unless `[k8s] enabled = true`, so hosts without Kubernetes are unaffected.

pub mod cgroup;
pub mod http;
pub mod source;

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use aya::maps::{HashMap as BpfHashMap, MapError};
use kavach_common::abi::{ClassVal, KV_WL_MAX};
use kavach_policy::CompiledPolicy;
use kavach_policy::workload::{DEFAULT_SPIFFE_TEMPLATE, PodIdentity, WorkloadState};
use serde::Deserialize;
use tracing::{info, warn};

use crate::daemon::Daemon;
use cgroup::CgroupView;

/// `[k8s]` in kavachd.toml.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct K8sConfig {
    pub enabled: bool,
    pub source: SourceKind,
    /// This node's name (default: `$NODE_NAME`, else the hostname).
    pub node_name: String,
    /// SPIFFE trust domain used by `spiffe_template`.
    pub trust_domain: String,
    /// How a pod's SPIFFE ID is derived (see `kavach_policy::workload::render_spiffe`).
    pub spiffe_template: String,
    /// `source = "apiserver"`: base URL (default: in-cluster `KUBERNETES_SERVICE_HOST`).
    pub api_server: String,
    /// `source = "kubelet"`: base URL (default `https://<node_name>:10250`).
    pub kubelet_url: String,
    /// Bearer token, re-read on every request (empty = none).
    pub token_file: PathBuf,
    /// CA bundle that signs the API server's (or kubelet's) serving certificate.
    pub ca_file: PathBuf,
    /// `source = "file"`: a PodList JSON document.
    pub pods_file: PathBuf,
    /// Where the cgroup v2 hierarchy is mounted (must be the host's cgroup namespace).
    pub cgroup_root: PathBuf,
    /// Full re-list interval (label changes are picked up within this).
    pub resync_secs: u64,
    /// cgroupfs scan interval.
    pub scan_ms: u64,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SourceKind {
    Kubelet,
    #[default]
    Apiserver,
    File,
}

const SA_DIR: &str = "/var/run/secrets/kubernetes.io/serviceaccount";

impl Default for K8sConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            source: SourceKind::default(),
            node_name: String::new(),
            trust_domain: "cluster.local".into(),
            spiffe_template: DEFAULT_SPIFFE_TEMPLATE.into(),
            api_server: String::new(),
            kubelet_url: String::new(),
            token_file: format!("{SA_DIR}/token").into(),
            ca_file: format!("{SA_DIR}/ca.crt").into(),
            pods_file: PathBuf::new(),
            cgroup_root: "/sys/fs/cgroup".into(),
            resync_secs: 30,
            scan_ms: 500,
        }
    }
}

impl K8sConfig {
    pub fn node(&self) -> String {
        if !self.node_name.is_empty() {
            return self.node_name.clone();
        }
        std::env::var("NODE_NAME")
            .ok()
            .filter(|n| !n.is_empty())
            .or_else(|| {
                std::fs::read_to_string("/proc/sys/kernel/hostname")
                    .ok()
                    .map(|h| h.trim().to_owned())
            })
            .unwrap_or_default()
    }

    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self.scan_ms < 50 || self.resync_secs == 0 {
            return Err("[k8s] scan_ms must be >= 50 and resync_secs >= 1".into());
        }
        if !self.trust_domain.is_empty()
            && kavach_policy::workload::validate_spiffe_id(&format!(
                "spiffe://{}",
                self.trust_domain
            ))
            .is_err()
        {
            return Err(format!(
                "[k8s] trust_domain {:?} is not a valid SPIFFE trust domain",
                self.trust_domain
            ));
        }
        if !self.spiffe_template.starts_with("spiffe://") {
            return Err("[k8s] spiffe_template must start with spiffe://".into());
        }
        if self.node().is_empty() {
            return Err("[k8s] node_name is empty and $NODE_NAME / hostname are unset".into());
        }
        Ok(())
    }
}

/// Counters exported in `kavachctl metrics` / status.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkloadStats {
    pub roots: u64,
    pub pods: u64,
    pub resolved: u64,
    pub unknown: u64,
    pub entries: u64,
    /// Pod cgroups that did not fit in `wl_class` (cumulative). They fall back to the
    /// kubepods root, i.e. unknown identity, so fail-closed rules still refuse them.
    pub overflow: u64,
    pub source_errors: u64,
    pub source_ok: bool,
}

/// The node agent's state inside [`Daemon`].
#[derive(Debug, Default)]
pub struct Workloads {
    pub enabled: bool,
    pub view: CgroupView,
    /// Pod metadata by UID.
    pub pods: HashMap<String, PodIdentity>,
    /// What is in `wl_class` (loaded from the pinned map on first sync).
    written: Option<HashMap<u64, ClassVal>>,
    pub stats: WorkloadStats,
}

/// Masks for every kubepods root and pod cgroup, for both slots. Bounded by `max` (roots
/// first); returns the number of pod cgroups left out.
pub fn desired(
    view: &CgroupView,
    pods: &HashMap<String, PodIdentity>,
    slots: [Option<&CompiledPolicy>; 2],
    max: usize,
) -> (BTreeMap<u64, ClassVal>, usize) {
    let mask = |st: WorkloadState<'_>| {
        let mut v = ClassVal::default();
        for (s, p) in slots.iter().enumerate() {
            if let Some(p) = p {
                v.mask[s] = p.workload_mask(st);
            }
        }
        v
    };
    let mut out = BTreeMap::new();
    for (id, _) in &view.roots {
        if out.len() < max {
            out.insert(*id, mask(WorkloadState::Unknown));
        }
    }
    let mut overflow = 0;
    for (id, uid) in &view.pods {
        if out.len() >= max {
            overflow += 1;
            continue;
        }
        let st = match pods.get(uid) {
            Some(p) => WorkloadState::Resolved(p),
            None => WorkloadState::Unknown,
        };
        out.insert(*id, mask(st));
    }
    (out, overflow)
}

/// `(upserts, deletes)` that turn `current` into `want`.
pub fn plan(
    current: &HashMap<u64, ClassVal>,
    want: &BTreeMap<u64, ClassVal>,
) -> (Vec<(u64, ClassVal)>, Vec<u64>) {
    let up = want
        .iter()
        .filter(|(k, v)| current.get(k) != Some(v))
        .map(|(k, v)| (*k, *v))
        .collect();
    let mut del: Vec<u64> = current
        .keys()
        .filter(|k| !want.contains_key(k))
        .copied()
        .collect();
    del.sort_unstable();
    (up, del)
}

fn is_full(e: &MapError) -> bool {
    matches!(e, MapError::SyscallError(s)
        if matches!(s.io_error.raw_os_error(), Some(nix::libc::E2BIG | nix::libc::ENOSPC | nix::libc::ENOMEM)))
}

impl Daemon {
    /// Bring `wl_class` in line with the current pod view for both slots; `staged` overrides
    /// one slot's policy (used by `stage` before it flips to that slot).
    pub fn sync_workloads(&mut self, staged: Option<(u32, &CompiledPolicy)>) -> Result<()> {
        let mut slots: [Option<&CompiledPolicy>; 2] =
            [self.slots[0].as_deref(), self.slots[1].as_deref()];
        if let Some((s, p)) = staged {
            slots[(s & 1) as usize] = Some(p);
        }
        let wl = &mut self.workloads;
        let in_use = slots.iter().flatten().any(|p| p.workload_bits() != 0);
        let (want, overflow) = if wl.enabled && in_use {
            desired(&wl.view, &wl.pods, slots, KV_WL_MAX as usize)
        } else {
            (BTreeMap::new(), 0)
        };
        let Some(k) = self.kernel.as_mut() else {
            return Ok(());
        };
        let mut m: BpfHashMap<_, u64, ClassVal> = BpfHashMap::try_from(
            k.bpf_mut()
                .map_mut("wl_class")
                .ok_or_else(|| anyhow::anyhow!("wl_class map missing from the eBPF object"))?,
        )?;
        let written = wl
            .written
            .get_or_insert_with(|| m.iter().filter_map(Result::ok).collect());
        let (up, del) = plan(written, &want);
        for id in del {
            let _ = m.remove(&id);
            written.remove(&id);
        }
        let mut full = 0;
        for (id, v) in up {
            match m.insert(&id, &v, 0) {
                Ok(()) => {
                    written.insert(id, v);
                }
                Err(e) if is_full(&e) => full += 1,
                Err(e) => return Err(e.into()),
            }
        }
        let st = &mut wl.stats;
        st.overflow += (overflow + full) as u64;
        st.entries = written.len() as u64;
        st.roots = wl.view.roots.len() as u64;
        st.pods = wl.view.pods.len() as u64;
        st.resolved = wl
            .view
            .pods
            .iter()
            .filter(|(_, u)| wl.pods.contains_key(u))
            .count() as u64;
        st.unknown = st.pods - st.resolved;
        if overflow + full > 0 {
            warn!(
                left_out = overflow + full,
                max = KV_WL_MAX,
                "wl_class is full: those pods count as identity-unknown"
            );
        }
        Ok(())
    }

    /// Apply-time warnings for a policy with workload selectors.
    pub fn workload_warnings(&self, p: &CompiledPolicy) -> Vec<String> {
        if p.workload_bits() == 0 || self.workloads.enabled {
            return vec![];
        }
        vec![
            "the policy has k8s / spiffe selectors but [k8s] is not enabled in kavachd.toml: \
             they match nothing on this host"
                .into(),
        ]
    }

    /// Prometheus lines for the node agent.
    pub fn workload_metrics(&self) -> String {
        let s = &self.workloads.stats;
        if !self.workloads.enabled {
            return String::new();
        }
        format!(
            "# TYPE kavach_k8s_pods gauge\nkavach_k8s_pods{{state=\"resolved\"}} {}\nkavach_k8s_pods{{state=\"unknown\"}} {}\n\
             # TYPE kavach_k8s_wl_entries gauge\nkavach_k8s_wl_entries {}\n\
             # TYPE kavach_k8s_wl_overflow_total counter\nkavach_k8s_wl_overflow_total {}\n\
             # TYPE kavach_k8s_source_errors_total counter\nkavach_k8s_source_errors_total {}\n\
             # TYPE kavach_k8s_source_up gauge\nkavach_k8s_source_up {}\n",
            s.resolved,
            s.unknown,
            s.entries,
            s.overflow,
            s.source_errors,
            u8::from(s.source_ok)
        )
    }
}

/// A panicked holder leaves the state consistent enough to keep publishing (the supervisor
/// clears the poison as well).
fn lock(st: &Mutex<Daemon>) -> std::sync::MutexGuard<'_, Daemon> {
    st.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The node agent between [`prime`] and [`Agent::spawn`].
pub struct Agent {
    cfg: K8sConfig,
    src: Box<dyn source::Source>,
    pods: HashMap<String, PodIdentity>,
    last_fetch: Option<Instant>,
    last_view: Option<CgroupView>,
    last_warn: Option<Instant>,
    ok: bool,
    errors: u64,
}

impl std::fmt::Debug for Agent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Agent")
            .field("source", &self.src.describe())
            .finish_non_exhaustive()
    }
}

/// Validate, do the first cgroup scan and metadata fetch, and store them in `d`. Call it
/// **before** the persisted policy is restored: the restore's stage then writes real workload
/// masks instead of dropping the pinned ones (which would leave pods unclassified, i.e.
/// fail-open, until the agent's first pass). It does not touch `wl_class` itself, since no
/// policy slot is known yet.
pub fn prime(cfg: K8sConfig, d: &mut Daemon) -> Result<Agent> {
    cfg.validate().map_err(anyhow::Error::msg)?;
    cgroup::ensure_cgroup2(&cfg.cgroup_root)?;
    let src = source::build(&cfg)?;
    info!(source = %src.describe(), node = %cfg.node(), "k8s / SPIFFE identity agent starting");
    let mut a = Agent {
        cfg,
        src,
        pods: HashMap::new(),
        last_fetch: None,
        last_view: None,
        last_warn: None,
        ok: false,
        errors: 0,
    };
    d.workloads.enabled = true;
    if let Some(v) = a.poll() {
        a.store(v, d);
    }
    Ok(a)
}

impl Agent {
    /// Start the agent thread (blocking I/O; it locks the daemon only to publish).
    pub fn spawn(mut self, st: Arc<Mutex<Daemon>>) -> Result<()> {
        std::thread::Builder::new()
            .name("k8s-agent".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_millis(self.cfg.scan_ms));
                    let detached = lock(&st).kernel.is_none();
                    if detached {
                        return; // kill-switch
                    }
                    self.tick_with(&st);
                }
            })?;
        Ok(())
    }

    /// Scan, fetch if due, and report whether anything changed.
    fn poll(&mut self) -> Option<CgroupView> {
        let view = cgroup::scan(&self.cfg.cgroup_root);
        let missing = view.pods.iter().any(|(_, u)| !self.pods.contains_key(u));
        let resync = Duration::from_secs(self.cfg.resync_secs);
        let due = self
            .last_fetch
            .map(|t| t.elapsed())
            .is_none_or(|e| e >= resync || (missing && e >= Duration::from_secs(1)));
        let mut changed = self.last_view.as_ref() != Some(&view);
        if due {
            self.last_fetch = Some(Instant::now());
            match self.src.fetch() {
                Ok(p) => {
                    changed |= p != self.pods || !self.ok;
                    self.pods = p;
                    self.ok = true;
                }
                Err(e) => {
                    // Keep the last known metadata; unseen pods stay identity-unknown.
                    self.errors += 1;
                    changed |= self.ok || self.last_view.is_none();
                    self.ok = false;
                    if self
                        .last_warn
                        .is_none_or(|t| t.elapsed() >= Duration::from_secs(60))
                    {
                        warn!(source = %self.src.describe(), error = %format!("{e:#}"), "pod metadata fetch failed");
                        self.last_warn = Some(Instant::now());
                    }
                }
            }
        }
        changed.then_some(view)
    }

    fn store(&mut self, view: CgroupView, d: &mut Daemon) {
        d.workloads.view = view.clone();
        d.workloads.pods = self.pods.clone();
        d.workloads.stats.source_ok = self.ok;
        d.workloads.stats.source_errors = self.errors;
        self.last_view = Some(view);
    }

    fn publish(&mut self, view: CgroupView, d: &mut Daemon) {
        self.store(view, d);
        if let Err(e) = d.sync_workloads(None) {
            warn!(error = %format!("{e:#}"), "wl_class update failed");
        }
    }

    /// Like `tick`, but holds the daemon lock only to publish (fetches can take seconds).
    fn tick_with(&mut self, st: &Arc<Mutex<Daemon>>) {
        if let Some(v) = self.poll() {
            self.publish(v, &mut lock(st));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UID_DB: &str = "1b3c5e7a-2d4f-4a6b-8c9d-0e1f2a3b4c5d";
    const UID_WEB: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

    fn policy() -> CompiledPolicy {
        kavach_policy::compile(
            r#"
version = 1
[[rule]]
id = "db"
who = { k8s = "app=db" }
allow = { to = "10.0.0.0/8" }
[[rule]]
id = "prod-sa"
who = { spiffe = "spiffe://cluster.local/ns/prod/*" }
fail = "open"
deny = { to = "192.0.2.0/24" }
"#,
            0,
        )
        .unwrap()
        .policy
    }

    fn pods_from_file(path: &std::path::Path) -> HashMap<String, PodIdentity> {
        let cfg = K8sConfig {
            source: SourceKind::File,
            pods_file: path.into(),
            node_name: "node-1".into(),
            ..Default::default()
        };
        source::build(&cfg).unwrap().fetch().unwrap()
    }

    #[test]
    fn config_defaults_and_validation() {
        let c: crate::config::Config = toml::from_str("").unwrap();
        assert!(!c.k8s.enabled, "the node agent is off by default");
        let c: crate::config::Config = toml::from_str(
            "[k8s]\nenabled = true\nsource = \"kubelet\"\nnode_name = \"n1\"\ntrust_domain = \"example.org\"\n",
        )
        .unwrap();
        assert_eq!(c.k8s.source, SourceKind::Kubelet);
        assert_eq!(c.k8s.resync_secs, 30);
        c.k8s.validate().unwrap();
        assert!(toml::from_str::<crate::config::Config>("[k8s]\nsource = \"etcd\"\n").is_err());
        assert!(toml::from_str::<crate::config::Config>("[k8s]\nbogus = 1\n").is_err());
        let bad = K8sConfig {
            enabled: true,
            trust_domain: "Bad Domain".into(),
            node_name: "n".into(),
            ..Default::default()
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn desired_masks_cover_roots_resolved_and_unknown_pods() {
        let p = policy();
        // bits: 0 = db, 1 = db unknown twin, 2 = prod-sa (fail-open, no twin)
        let view = CgroupView {
            roots: vec![(10, "kubepods.slice".into())],
            pods: vec![
                (20, UID_DB.into()),
                (21, UID_WEB.into()),
                (22, "deadbeef-0000".into()),
            ],
        };
        let t = tempfile::tempdir().unwrap();
        let f = t.path().join("pods.json");
        std::fs::write(
            &f,
            format!(
                r#"{{"items":[
 {{"metadata":{{"uid":"{UID_DB}","namespace":"prod","name":"db-0","labels":{{"app":"db"}}}},"spec":{{"nodeName":"node-1"}}}},
 {{"metadata":{{"uid":"{UID_WEB}","namespace":"dev","name":"web","labels":{{"app":"web"}}}},"spec":{{"nodeName":"node-1"}}}}]}}"#
            ),
        )
        .unwrap();
        let pods = pods_from_file(&f);
        // Slot 1 only (slot 0 empty).
        let (want, overflow) = desired(&view, &pods, [None, Some(&p)], 100);
        assert_eq!(overflow, 0);
        let m = |id: u64| want[&id].mask;
        assert_eq!(m(10), [0, 0b010], "root: unknown twin bits");
        assert_eq!(m(20), [0, 0b101], "db in prod: label + spiffe");
        assert_eq!(
            m(21),
            [0, 0],
            "web: resolved, matches nothing, still overrides the root"
        );
        assert_eq!(m(22), [0, 0b010], "pod without metadata: unknown");

        // Bounded: roots first, the rest is counted.
        let (want, overflow) = desired(&view, &pods, [Some(&p), Some(&p)], 2);
        assert_eq!(want.len(), 2);
        assert!(want.contains_key(&10));
        assert_eq!(overflow, 2);
    }

    #[test]
    fn resolver_diffs_as_pods_come_and_go() {
        let p = policy();
        let t = tempfile::tempdir().unwrap();
        let f = t.path().join("pods.json");
        let write = |labels: &str| {
            std::fs::write(
                &f,
                format!(
                    r#"{{"items":[{{"metadata":{{"uid":"{UID_DB}","namespace":"prod","labels":{{{labels}}}}},"spec":{{"nodeName":"node-1"}}}}]}}"#
                ),
            )
            .unwrap()
        };
        let mut view = CgroupView {
            roots: vec![(10, "kubepods".into())],
            pods: vec![(20, UID_DB.into())],
        };
        let slots = [Some(&p), None];
        let mut cur: HashMap<u64, ClassVal> = HashMap::new();
        let step = |view: &CgroupView, cur: &mut HashMap<u64, ClassVal>| {
            let pods = pods_from_file(&f);
            let (want, _) = desired(view, &pods, slots, 100);
            let (up, del) = plan(cur, &want);
            for id in &del {
                cur.remove(id);
            }
            for (id, v) in &up {
                cur.insert(*id, *v);
            }
            assert_eq!(cur.len(), want.len());
            (up.len(), del)
        };
        write(r#""app":"db""#);
        assert_eq!(
            step(&view, &mut cur),
            (2, vec![]),
            "first sync writes root + pod"
        );
        assert_eq!(cur[&20].mask[0], 0b101);
        assert_eq!(step(&view, &mut cur), (0, vec![]), "no change, no writes");
        write(r#""app":"cache""#); // relabel
        assert_eq!(step(&view, &mut cur), (1, vec![]));
        assert_eq!(cur[&20].mask[0], 0b100);
        view.pods.push((30, UID_WEB.into())); // new pod, metadata not listed yet
        assert_eq!(step(&view, &mut cur), (1, vec![]));
        assert_eq!(cur[&30].mask[0], 0b010, "unknown until listed");
        view.pods.retain(|(id, _)| *id != 20); // pod deleted
        assert_eq!(step(&view, &mut cur), (0, vec![20]));
        view = CgroupView::default(); // kubelet gone
        assert_eq!(step(&view, &mut cur), (0, vec![10, 30]));
        assert!(cur.is_empty());
    }

    #[test]
    fn spawn_refuses_without_a_usable_setup() {
        let t = tempfile::tempdir().unwrap();
        let cfg = K8sConfig {
            enabled: true,
            node_name: "n".into(),
            source: SourceKind::File,
            pods_file: t.path().join("p.json"),
            cgroup_root: t.path().into(), // not cgroup2
            ..Default::default()
        };
        // No daemon needed: the checks fail before it is touched.
        assert!(cfg.validate().is_ok());
        assert!(cgroup::ensure_cgroup2(&cfg.cgroup_root).is_err());
    }
}
