//! Per-identity anomaly engine (detection only; it never changes a verdict).
//!
//! Input is the egress events the kernel already sends to user space: every `Drop` and `Log`
//! verdict (FR-EG-4). Allowed connections that match no `log` rule are not seen, so "connection
//! rate" means connection attempts that a drop or log rule saw.
//!
//! An identity is `(uid, cgroup_id, comm)`. The kernel event carries no executable hash. The
//! selector mask is not used either, because it changes meaning with every policy generation.
//!
//! For each identity, time is cut into fixed windows. The engine keeps four per-window counters:
//!
//! | metric          | counts                                                       |
//! |-----------------|--------------------------------------------------------------|
//! | `conn_rate`     | egress events                                                |
//! | `deny_rate`     | egress events with a `drop` verdict                          |
//! | `distinct_dsts` | distinct destination addresses (HyperLogLog, 64 registers)   |
//! | `new_dst_ports` | `(proto, port)` pairs never seen before for this identity     |
//!
//! When a window closes, its counts are folded into an EWMA mean and variance. Windows with no
//! events count as zeros. No alerts are raised for the first `learning_windows` windows. After
//! that, a metric is anomalous when its count in the current window meets all three conditions:
//!
//! * `x >= floor`, where the floor is `min_count`, or `min_new_ports` for `new_dst_ports`;
//! * `x >= ratio_threshold * mean`;
//! * `(x - mean) / sigma >= z_threshold`, with `sigma = sqrt(max(var, mean, 1))`. The variance
//!   never drops below Poisson noise, so a baseline that has always been flat cannot alarm on
//!   jitter.
//!
//! Counts only grow inside a window, so the check runs on every event and a spike is reported
//! while it is happening, not one window later. A metric alerts at most once per window and
//! once per `cooldown_secs`. An anomalous window is folded into the baseline clipped to
//! `mean + z_threshold * sigma`, so a sustained attack cannot quickly re-baseline itself as normal.
//!
//! Memory is bounded. At most `max_identities` identities are tracked, and the least recently
//! seen one is evicted. Each identity holds a fixed-size HyperLogLog and a 1024-bit port filter,
//! about 400 bytes in all. A new identity is always learning, so flooding the table with fresh
//! identities cannot produce alerts. It can evict a real baseline, though, and an evicted
//! identity starts learning again.
//!
//! Time is injected as nanoseconds on any monotonic clock (kavachd passes the event's
//! `ts_ns`), which keeps the engine deterministic under test.

use std::collections::{BTreeMap, HashMap};
use std::hash::{Hash, Hasher};

use serde::{Deserialize, Serialize};

/// `[anomaly]` in kavachd.toml.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AnomalyConfig {
    pub enabled: bool,
    pub window_secs: u64,
    /// Windows (empty ones included) observed before an identity can alert.
    pub learning_windows: u32,
    /// EWMA weight of the newest window (0 < alpha <= 1).
    pub alpha: f64,
    pub z_threshold: f64,
    pub ratio_threshold: f64,
    /// Absolute floor for `conn_rate`, `deny_rate` and `distinct_dsts`.
    pub min_count: u32,
    /// Absolute floor for `new_dst_ports`.
    pub min_new_ports: u32,
    /// Minimum seconds between two alerts for the same identity and metric.
    pub cooldown_secs: u64,
    pub max_identities: usize,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            window_secs: 60,
            learning_windows: 30,
            alpha: 0.1,
            z_threshold: 4.0,
            ratio_threshold: 3.0,
            min_count: 10,
            min_new_ports: 3,
            cooldown_secs: 600,
            max_identities: 1024,
        }
    }
}

impl AnomalyConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.window_secs == 0 {
            return Err("anomaly.window_secs must be > 0".into());
        }
        if !(self.alpha > 0.0 && self.alpha <= 1.0) {
            return Err("anomaly.alpha must be in (0, 1]".into());
        }
        if !(self.z_threshold.is_finite() && self.ratio_threshold.is_finite()) {
            return Err("anomaly thresholds must be finite".into());
        }
        if self.max_identities == 0 {
            return Err("anomaly.max_identities must be > 0".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct IdentityKey {
    pub uid: u32,
    pub cgroup_id: u64,
    pub comm: [u8; 16],
}

impl IdentityKey {
    pub fn comm_str(&self) -> String {
        let end = self.comm.iter().position(|b| *b == 0).unwrap_or(16);
        String::from_utf8_lossy(&self.comm[..end]).into_owned()
    }
}

/// One egress event, reduced to what the engine needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observation {
    pub key: IdentityKey,
    pub pid: u32,
    /// Destination address (IPv4-mapped for v4).
    pub dst: [u8; 16],
    pub proto: u8,
    pub dport: u16,
    pub denied: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Metric {
    ConnRate,
    DenyRate,
    DistinctDsts,
    NewDstPorts,
}

impl Metric {
    pub const ALL: [Metric; 4] = [
        Metric::ConnRate,
        Metric::DenyRate,
        Metric::DistinctDsts,
        Metric::NewDstPorts,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Metric::ConnRate => "conn_rate",
            Metric::DenyRate => "deny_rate",
            Metric::DistinctDsts => "distinct_dsts",
            Metric::NewDstPorts => "new_dst_ports",
        }
    }

    fn idx(self) -> usize {
        self as usize
    }
}

/// A detection, ready to be rendered as an `anomaly` event.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Anomaly {
    pub ts_ns: u64,
    pub uid: u32,
    pub cgroup_id: u64,
    pub comm: String,
    /// The pid of the event that crossed the threshold.
    pub pid: u32,
    pub metric: Metric,
    /// Count in the current (partial) window.
    pub value: f64,
    pub baseline_mean: f64,
    pub baseline_sigma: f64,
    pub z: f64,
    pub window_secs: u64,
}

impl Anomaly {
    pub fn summary(&self) -> String {
        format!(
            "{}={:.0}/{}s baseline={:.1}±{:.1} z={:.1}",
            self.metric.name(),
            self.value,
            self.window_secs,
            self.baseline_mean,
            self.baseline_sigma,
            self.z
        )
    }
}

/// Online mean / variance (exponentially weighted).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
struct Ewma {
    mean: f64,
    var: f64,
    init: bool,
}

impl Ewma {
    fn update(&mut self, x: f64, alpha: f64) {
        if !self.init {
            *self = Ewma {
                mean: x,
                var: 0.0,
                init: true,
            };
            return;
        }
        let diff = x - self.mean;
        let incr = alpha * diff;
        self.mean += incr;
        self.var = (1.0 - alpha) * (self.var + diff * incr);
    }

    fn sigma(&self) -> f64 {
        self.var.max(self.mean).max(1.0).sqrt()
    }
}

const HLL_P: u32 = 6;
const HLL_M: usize = 1 << HLL_P;

/// Tiny HyperLogLog (64 registers, about 13% standard error; linear counting below 160).
#[derive(Debug, Clone, Copy, PartialEq)]
struct Hll([u8; HLL_M]);

impl Hll {
    fn new() -> Self {
        Self([0; HLL_M])
    }

    /// Returns true when a register grew (the estimate may have changed).
    fn insert(&mut self, h: u64) -> bool {
        let j = (h >> (64 - HLL_P)) as usize;
        let w = h << HLL_P;
        let rho = (w.leading_zeros().min(64 - HLL_P) + 1) as u8;
        if rho > self.0[j] {
            self.0[j] = rho;
            true
        } else {
            false
        }
    }

    fn estimate(&self) -> f64 {
        let m = HLL_M as f64;
        let mut sum = 0.0;
        let mut zeros = 0u32;
        for &r in &self.0 {
            sum += 2f64.powi(-(r as i32));
            zeros += (r == 0) as u32;
        }
        let raw = 0.709 * m * m / sum;
        if raw <= 2.5 * m && zeros > 0 {
            m * (m / zeros as f64).ln()
        } else {
            raw
        }
    }
}

const PORT_BITS: usize = 1024;

/// One-hash Bloom filter of `(proto, port)` pairs. A false positive under-reports a new port,
/// which is the safe direction for a detector.
#[derive(Debug, Clone, Copy, PartialEq)]
struct PortFilter([u64; PORT_BITS / 64]);

impl PortFilter {
    /// Returns true when the pair was not present (and records it).
    fn insert(&mut self, h: u64) -> bool {
        let bit = (h % PORT_BITS as u64) as usize;
        let (w, b) = (bit / 64, 1u64 << (bit % 64));
        let new = self.0[w] & b == 0;
        self.0[w] |= b;
        new
    }
}

#[derive(Debug, Clone)]
struct Track {
    /// Start of the current window (ns).
    window_start: u64,
    windows_seen: u32,
    counts: [u32; 3],
    dsts: Hll,
    ports: PortFilter,
    base: [Ewma; 4],
    /// Last alert time per metric (ns), and whether the current window already alerted.
    last_alert: [Option<u64>; 4],
    alerted_window: [bool; 4],
    lru: u64,
}

impl Track {
    fn new(now: u64, lru: u64) -> Self {
        Self {
            window_start: now,
            windows_seen: 0,
            counts: [0; 3],
            dsts: Hll::new(),
            ports: PortFilter([0; PORT_BITS / 64]),
            base: [Ewma::default(); 4],
            last_alert: [None; 4],
            alerted_window: [false; 4],
            lru,
        }
    }

    fn value(&self, m: Metric) -> f64 {
        match m {
            Metric::ConnRate => self.counts[0] as f64,
            Metric::DenyRate => self.counts[1] as f64,
            Metric::NewDstPorts => self.counts[2] as f64,
            Metric::DistinctDsts => {
                if self.counts[0] == 0 {
                    0.0
                } else {
                    self.dsts.estimate()
                }
            }
        }
    }

    fn learning(&self, cfg: &AnomalyConfig) -> bool {
        self.windows_seen < cfg.learning_windows
    }

    /// Fold `x` into metric `m`'s baseline, clipping outliers once learning is over.
    fn fold(&mut self, m: Metric, x: f64, cfg: &AnomalyConfig) {
        let learning = self.learning(cfg);
        let b = &mut self.base[m.idx()];
        let x = if !learning && b.init {
            x.min(b.mean + cfg.z_threshold * b.sigma())
        } else {
            x
        };
        b.update(x, cfg.alpha);
    }

    /// Close every window that ended at or before `now`.
    fn roll(&mut self, now: u64, cfg: &AnomalyConfig) {
        let win = cfg.window_secs.saturating_mul(1_000_000_000);
        if now < self.window_start.saturating_add(win) {
            return;
        }
        let elapsed = (now - self.window_start) / win;
        for m in Metric::ALL {
            let x = self.value(m);
            self.fold(m, x, cfg);
        }
        self.windows_seen = self.windows_seen.saturating_add(1);
        // Idle windows are zeros; past ~64 of them the EWMA has forgotten everything anyway.
        for _ in 1..elapsed.min(64) {
            for m in Metric::ALL {
                self.fold(m, 0.0, cfg);
            }
            self.windows_seen = self.windows_seen.saturating_add(1);
        }
        if elapsed > 64 {
            self.windows_seen = self
                .windows_seen
                .saturating_add((elapsed - 64).min(u32::MAX as u64) as u32);
        }
        self.window_start += elapsed * win;
        self.counts = [0; 3];
        self.dsts = Hll::new();
        self.alerted_window = [false; 4];
    }

    fn check(&mut self, m: Metric, now: u64, cfg: &AnomalyConfig) -> Option<(f64, f64, f64, f64)> {
        let i = m.idx();
        if self.learning(cfg) || self.alerted_window[i] || !self.base[i].init {
            return None;
        }
        let cooldown = cfg.cooldown_secs.saturating_mul(1_000_000_000);
        if self.last_alert[i].is_some_and(|t| now.saturating_sub(t) < cooldown) {
            return None;
        }
        let x = self.value(m);
        let floor = if m == Metric::NewDstPorts {
            cfg.min_new_ports
        } else {
            cfg.min_count
        } as f64;
        let b = self.base[i];
        let sigma = b.sigma();
        let z = (x - b.mean) / sigma;
        if x >= floor && x >= cfg.ratio_threshold * b.mean && z >= cfg.z_threshold {
            self.alerted_window[i] = true;
            self.last_alert[i] = Some(now);
            Some((x, b.mean, sigma, z))
        } else {
            None
        }
    }
}

/// The engine: a bounded table of per-identity baselines.
#[derive(Debug)]
pub struct Engine {
    cfg: AnomalyConfig,
    seed: u64,
    tracks: HashMap<IdentityKey, Track>,
    /// LRU order: touch sequence → identity.
    order: BTreeMap<u64, IdentityKey>,
    seq: u64,
    evictions: u64,
}

impl Engine {
    /// `seed` keys the address/port hashes so a remote party cannot pick colliding values.
    pub fn new(cfg: AnomalyConfig, seed: u64) -> Self {
        Self {
            cfg,
            seed,
            tracks: HashMap::new(),
            order: BTreeMap::new(),
            seq: 0,
            evictions: 0,
        }
    }

    pub fn tracked(&self) -> usize {
        self.tracks.len()
    }

    pub fn evictions(&self) -> u64 {
        self.evictions
    }

    pub fn is_tracked(&self, k: &IdentityKey) -> bool {
        self.tracks.contains_key(k)
    }

    fn hash(&self, tag: u8, bytes: &[u8]) -> u64 {
        let mut h = std::hash::DefaultHasher::new();
        self.seed.hash(&mut h);
        tag.hash(&mut h);
        bytes.hash(&mut h);
        h.finish()
    }

    /// Feed one event observed at `now` (ns, monotonic). Returns the anomalies it triggered.
    pub fn observe(&mut self, now: u64, o: &Observation) -> Vec<Anomaly> {
        self.seq += 1;
        let seq = self.seq;
        if let Some(t) = self.tracks.get_mut(&o.key) {
            self.order.remove(&t.lru);
            t.lru = seq;
        } else {
            if self.tracks.len() >= self.cfg.max_identities
                && let Some((_, victim)) = self.order.pop_first()
            {
                self.tracks.remove(&victim);
                self.evictions += 1;
            }
            self.tracks.insert(o.key, Track::new(now, seq));
        }
        self.order.insert(seq, o.key);

        let dst_h = self.hash(0, &o.dst);
        let port_h = self.hash(1, &[o.proto, (o.dport >> 8) as u8, o.dport as u8]);
        let cfg = &self.cfg;
        let t = self.tracks.get_mut(&o.key).expect("inserted above");
        t.roll(now, cfg);

        let mut touched = [true, o.denied, false, false];
        t.counts[0] = t.counts[0].saturating_add(1);
        if o.denied {
            t.counts[1] = t.counts[1].saturating_add(1);
        }
        touched[Metric::DistinctDsts.idx()] = t.dsts.insert(dst_h);
        if t.ports.insert(port_h) {
            t.counts[2] = t.counts[2].saturating_add(1);
            touched[Metric::NewDstPorts.idx()] = true;
        }

        let mut out = Vec::new();
        for m in Metric::ALL {
            if !touched[m.idx()] {
                continue;
            }
            if let Some((value, mean, sigma, z)) = t.check(m, now, cfg) {
                out.push(Anomaly {
                    ts_ns: now,
                    uid: o.key.uid,
                    cgroup_id: o.key.cgroup_id,
                    comm: o.key.comm_str(),
                    pid: o.pid,
                    metric: m,
                    value,
                    baseline_mean: mean,
                    baseline_sigma: sigma,
                    z,
                    window_secs: cfg.window_secs,
                });
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: u64 = 1_000_000_000;

    fn cfg() -> AnomalyConfig {
        AnomalyConfig {
            window_secs: 10,
            learning_windows: 5,
            cooldown_secs: 60,
            max_identities: 4,
            ..Default::default()
        }
    }

    fn key(n: u8) -> IdentityKey {
        let mut comm = [0u8; 16];
        comm[..4].copy_from_slice(b"curl");
        comm[4] = b'0' + n;
        IdentityKey {
            uid: 1000,
            cgroup_id: 7,
            comm,
        }
    }

    fn obs(k: IdentityKey, dst: u32, dport: u16, denied: bool) -> Observation {
        let mut a = [0u8; 16];
        a[10] = 0xff;
        a[11] = 0xff;
        a[12..].copy_from_slice(&dst.to_be_bytes());
        Observation {
            key: k,
            pid: 42,
            dst: a,
            proto: 6,
            dport,
            denied,
        }
    }

    /// `per_window` events to one destination/port at the start of each of `n` windows,
    /// starting at window index `from`. Returns all anomalies.
    fn steady(e: &mut Engine, k: IdentityKey, from: u64, n: u64, per_window: u32) -> Vec<Anomaly> {
        let mut out = Vec::new();
        for w in from..from + n {
            for i in 0..per_window {
                out.extend(e.observe(w * 10 * S + i as u64 * 1000, &obs(k, 1, 443, false)));
            }
        }
        out
    }

    #[test]
    fn defaults_validate_and_bad_values_are_refused() {
        assert!(AnomalyConfig::default().validate().is_ok());
        for bad in [
            AnomalyConfig {
                window_secs: 0,
                ..Default::default()
            },
            AnomalyConfig {
                alpha: 0.0,
                ..Default::default()
            },
            AnomalyConfig {
                max_identities: 0,
                ..Default::default()
            },
        ] {
            assert!(bad.validate().is_err());
        }
    }

    #[test]
    fn ewma_tracks_mean_and_variance() {
        let mut b = Ewma::default();
        for _ in 0..200 {
            b.update(10.0, 0.1);
        }
        assert!((b.mean - 10.0).abs() < 1e-9 && b.var < 1e-9);
        // Poisson-ish floor: sigma never below sqrt(mean).
        assert!((b.sigma() - 10f64.sqrt()).abs() < 1e-9);
        let mut b = Ewma::default();
        for i in 0..2000 {
            b.update(if i % 2 == 0 { 0.0 } else { 20.0 }, 0.05);
        }
        assert!((b.mean - 10.0).abs() < 1.0, "{}", b.mean);
        assert!((b.var.sqrt() - 10.0).abs() < 1.5, "{}", b.var);
    }

    #[test]
    fn hll_is_close_for_small_and_large_sets() {
        let e = Engine::new(cfg(), 1);
        for n in [1u32, 5, 20, 100, 1000, 5000] {
            let mut h = Hll::new();
            for i in 0..n {
                h.insert(e.hash(0, &i.to_be_bytes()));
            }
            // re-inserting never changes anything
            assert!(!h.insert(e.hash(0, &0u32.to_be_bytes())));
            let est = h.estimate();
            let err = (est - n as f64).abs() / n as f64;
            assert!(err < 0.35, "n={n} est={est}");
        }
    }

    #[test]
    fn no_alerts_while_learning() {
        let mut e = Engine::new(cfg(), 1);
        let k = key(0);
        // A huge first window and wildly varying traffic during learning: silence.
        let mut out = steady(&mut e, k, 0, 1, 500);
        for w in 1..5 {
            for i in 0..(w * 37 % 11) as u32 {
                out.extend(e.observe(w * 10 * S + i as u64, &obs(k, i, 1000 + i as u16, true)));
            }
        }
        assert!(out.is_empty(), "{out:?}");
    }

    #[test]
    fn spike_after_learning_is_detected_in_window() {
        let mut e = Engine::new(cfg(), 1);
        let k = key(0);
        assert!(steady(&mut e, k, 0, 20, 3).is_empty());
        // Window 20: a burst. The alert fires as soon as the thresholds are crossed.
        let mut fired_at = None;
        for i in 0..40u32 {
            let a = e.observe(200 * S + i as u64, &obs(k, 1, 443, false));
            if let Some(a) = a.iter().find(|a| a.metric == Metric::ConnRate) {
                fired_at.get_or_insert((i, a.clone()));
            }
        }
        let (i, a) = fired_at.expect("conn_rate spike detected");
        assert!((9..=15).contains(&i), "fired at event {i}");
        assert_eq!(a.comm, "curl0");
        assert_eq!(a.uid, 1000);
        assert!(a.z >= 4.0 && (a.baseline_mean - 3.0).abs() < 0.5, "{a:?}");
        assert!(a.summary().starts_with("conn_rate="));
    }

    #[test]
    fn normal_variation_does_not_alert() {
        let mut e = Engine::new(cfg(), 1);
        let k = key(0);
        let mut out = Vec::new();
        for w in 0..200u64 {
            let n = 20 + (w * 7919 % 9) as u32; // 20..28
            for i in 0..n {
                out.extend(e.observe(w * 10 * S + i as u64, &obs(k, i % 3, 443, false)));
            }
        }
        assert!(out.is_empty(), "{out:?}");
    }

    #[test]
    fn small_absolute_counts_stay_below_the_floor() {
        let mut e = Engine::new(cfg(), 1);
        let k = key(0);
        steady(&mut e, k, 0, 20, 1);
        // 1 → 9 is a big ratio but under min_count = 10.
        let out = steady(&mut e, k, 20, 1, 9);
        assert!(out.is_empty(), "{out:?}");
    }

    #[test]
    fn deny_spread_and_port_metrics() {
        let mut e = Engine::new(cfg(), 1);
        let k = key(0);
        steady(&mut e, k, 0, 20, 5);
        // Scan: many destinations and ports, all denied.
        let mut got = std::collections::HashSet::new();
        for i in 0..60u32 {
            for a in e.observe(200 * S + i as u64, &obs(k, 100 + i, 2000 + i as u16, true)) {
                got.insert(a.metric);
            }
        }
        for m in Metric::ALL {
            assert!(got.contains(&m), "{m:?} not detected: {got:?}");
        }
    }

    #[test]
    fn new_ports_only_count_once() {
        let mut e = Engine::new(cfg(), 1);
        let k = key(0);
        for w in 0..10u64 {
            for p in [80u16, 443, 8080, 443] {
                e.observe(w * 10 * S, &obs(k, 1, p, false));
            }
            // The first window sees three new pairs; every later one revisits known ports.
            assert_eq!(e.tracks[&k].counts[2], if w == 0 { 3 } else { 0 });
        }
        // The baseline started at 3 and decays towards 0 as no new ports appear.
        let mean = e.tracks[&k].base[Metric::NewDstPorts.idx()].mean;
        assert!((3.0 * 0.9f64.powi(8) - mean).abs() < 1e-9, "{mean}");
        // Same port over UDP is a different pair.
        let mut u = obs(k, 1, 443, false);
        u.proto = 17;
        e.observe(100 * S, &u);
        assert_eq!(e.tracks[&k].counts[2], 1);
    }

    #[test]
    fn cooldown_suppresses_repeats_then_expires() {
        let mut e = Engine::new(cfg(), 1);
        let k = key(0);
        steady(&mut e, k, 0, 20, 3);
        let count = |out: &[Anomaly]| out.iter().filter(|a| a.metric == Metric::ConnRate).count();
        // Burst in window 20: exactly one alert even though every later event is over threshold.
        let first = steady(&mut e, k, 20, 1, 60);
        assert_eq!(count(&first), 1);
        // Windows 21..25 (≤ 60 s later): cooldown.
        let again = steady(&mut e, k, 21, 4, 60);
        assert_eq!(count(&again), 0, "{again:?}");
        // Back to normal, then another burst after the cooldown: alerts again. Clipping kept the
        // baseline from absorbing the burst.
        steady(&mut e, k, 25, 10, 3);
        let later = steady(&mut e, k, 35, 1, 60);
        assert_eq!(count(&later), 1, "{later:?}");
    }

    #[test]
    fn idle_gap_decays_baseline_and_counts_as_learning_time() {
        let mut e = Engine::new(cfg(), 1);
        let k = key(0);
        e.observe(0, &obs(k, 1, 443, false));
        // One event, then silence for 1000 s: learning is over, the baseline is ~0.
        e.observe(1000 * S, &obs(k, 1, 443, false));
        let t = &e.tracks[&k];
        assert!(t.windows_seen >= 5);
        assert!(t.base[0].mean < 0.01);
        assert_eq!(t.window_start, 1000 * S);
        // So a burst from a normally idle identity is flagged.
        let out = steady(&mut e, k, 101, 1, 30);
        assert!(out.iter().any(|a| a.metric == Metric::ConnRate));
    }

    #[test]
    fn out_of_order_timestamps_are_harmless() {
        let mut e = Engine::new(cfg(), 1);
        let k = key(0);
        e.observe(100 * S, &obs(k, 1, 443, false));
        // An event stamped slightly earlier on another CPU lands in the current window.
        e.observe(100 * S - 5, &obs(k, 1, 443, false));
        assert_eq!(e.tracks[&k].counts[0], 2);
    }

    #[test]
    fn lru_evicts_least_recently_seen_identity() {
        let mut e = Engine::new(cfg(), 1);
        for n in 0..4 {
            e.observe(n as u64, &obs(key(n), 1, 443, false));
        }
        // Touch key(0) so key(1) is the oldest.
        e.observe(10, &obs(key(0), 1, 443, false));
        e.observe(11, &obs(key(9), 1, 443, false));
        assert_eq!(e.tracked(), 4);
        assert_eq!(e.evictions(), 1);
        assert!(e.is_tracked(&key(0)) && e.is_tracked(&key(9)));
        assert!(!e.is_tracked(&key(1)));
        assert_eq!(e.order.len(), e.tracks.len());
    }

    #[test]
    fn evicted_identity_relearns_and_flood_cannot_alert() {
        let mut e = Engine::new(cfg(), 1);
        let k = key(0);
        steady(&mut e, k, 0, 20, 3);
        // A flood of fresh identities pushes `k` out; none of them can alert while learning.
        let mut out = Vec::new();
        for n in 1..=4u8 {
            out.extend(steady(&mut e, key(n), 20, 1, 200));
        }
        assert!(!e.is_tracked(&k));
        assert!(out.is_empty());
        // `k` comes back learning from scratch.
        let back = steady(&mut e, k, 21, 1, 200);
        assert!(back.is_empty());
        assert_eq!(e.tracks[&k].windows_seen, 0);
    }

    #[test]
    fn deterministic_for_a_given_seed() {
        let run = |seed| {
            let mut e = Engine::new(cfg(), seed);
            let k = key(0);
            steady(&mut e, k, 0, 20, 4);
            let mut out = Vec::new();
            for i in 0..80u32 {
                out.extend(e.observe(200 * S + i as u64, &obs(k, i, i as u16, true)));
            }
            out
        };
        assert_eq!(run(7), run(7));
        assert!(!run(7).is_empty());
    }
}
