//! `/etc/kavach/kavachd.toml` — host configuration (not policy).

use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Interfaces that get XDP + TC programs. Empty = none (LSM egress still works).
    /// `"auto"` = the interfaces carrying a default route (IPv4 or IPv6) at startup.
    pub interfaces: Vec<String>,
    /// `auto` (native, falling back to generic), `native`, `skb`.
    pub xdp_mode: String,
    /// Attach TC flow tracking on `interfaces`.
    pub tc: bool,
    /// Attach the BPF-LSM egress hooks (needs `bpf` in /sys/kernel/security/lsm).
    pub lsm: bool,
    /// Versioned pin directory: a changed map layout never re-adopts old pins.
    pub pin_dir: PathBuf,
    pub socket: PathBuf,
    pub state_dir: PathBuf,
    pub audit_log: PathBuf,
    pub trusted_keys_dir: PathBuf,
    /// Hex key ids (first 8 bytes of SHA-256(pubkey)) that must be refused.
    pub revoked_keys: Vec<String>,
    /// Bundles must be signed for this fleet.
    pub fleet: String,
    /// Group (besides root) allowed to use the read-only and policy API. Kill-switch is root-only.
    pub control_group: Option<String>,
    pub ratelimit: Option<RateLimit>,
    /// 1-in-N sampling of XDP/ingress drop events (0 = off).
    pub sample_rate: u32,
    /// FQDN refresh bounds (FR-EG-3).
    pub dns_min_ttl_secs: u64,
    pub dns_max_ttl_secs: u64,
    /// Directories whose executables are hashed ahead of time when the policy names binaries by
    /// hash (non-recursive, watched with inotify). Empty = classify hash-named binaries on exec.
    pub hash_scan_dirs: Vec<PathBuf>,
    /// Per-identity anomaly detection on the event stream (detection only).
    pub anomaly: crate::anomaly::AnomalyConfig,
    /// L7 gateway (v0.4 preview).
    pub gateway: GatewayConfig,
    /// `[k8s]`: k8s-label / SPIFFE identity node agent (off by default).
    pub k8s: crate::workload::K8sConfig,
}

/// `[gateway]`.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct GatewayConfig {
    /// `[gateway.afxdp]`: opt-in AF_XDP RX backend (off by default).
    pub afxdp: kavach_gateway::afxdp::AfXdpConfig,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RateLimit {
    pub pps: u64,
    pub burst: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interfaces: Vec::new(),
            xdp_mode: "auto".into(),
            tc: true,
            lsm: true,
            pin_dir: format!("/sys/fs/bpf/kavach/v{}", crate::kernel::ABI_VERSION).into(),
            socket: kavach_api::DEFAULT_SOCKET.into(),
            state_dir: "/var/lib/kavach".into(),
            audit_log: "/var/log/kavach/audit.log".into(),
            trusted_keys_dir: "/etc/kavach/trusted_keys".into(),
            revoked_keys: Vec::new(),
            fleet: "default".into(),
            control_group: None,
            ratelimit: None,
            sample_rate: 64,
            dns_min_ttl_secs: 5,
            dns_max_ttl_secs: 3600,
            hash_scan_dirs: [
                "/usr/bin",
                "/usr/sbin",
                "/usr/local/bin",
                "/usr/local/sbin",
                "/bin",
                "/sbin",
                "/usr/libexec",
            ]
            .map(PathBuf::from)
            .to_vec(),
            anomaly: Default::default(),
            gateway: GatewayConfig::default(),
            k8s: Default::default(),
        }
    }
}

/// Interfaces that carry a default route, from `/proc/net/route` and `/proc/net/ipv6_route`.
pub fn default_route_interfaces() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |i: &str| {
        if i != "lo" && !out.iter().any(|o| o == i) {
            out.push(i.to_owned());
        }
    };
    if let Ok(s) = std::fs::read_to_string("/proc/net/route") {
        for l in s.lines().skip(1) {
            let f: Vec<&str> = l.split_whitespace().collect();
            // Iface Destination Gateway Flags ... Mask: default = dest 0 and mask 0, RTF_UP set
            if f.len() >= 8
                && f[1] == "00000000"
                && f[7] == "00000000"
                && u16::from_str_radix(f[3], 16).is_ok_and(|fl| fl & 1 != 0)
            {
                push(f[0]);
            }
        }
    }
    if let Ok(s) = std::fs::read_to_string("/proc/net/ipv6_route") {
        for l in s.lines() {
            let f: Vec<&str> = l.split_whitespace().collect();
            // dest plen src splen nexthop metric refcnt use flags iface; default = ::/0 via a gateway
            if f.len() >= 10
                && f[1] == "00"
                && f[0].bytes().all(|b| b == b'0')
                && f[4].bytes().any(|b| b != b'0')
            {
                push(f[9]);
            }
        }
    }
    out
}

impl Config {
    /// Replace `"auto"` in `interfaces` with the current default-route interfaces.
    pub fn resolve_interfaces(&mut self) {
        if self.interfaces.iter().any(|i| i == "auto") {
            let auto = default_route_interfaces();
            self.interfaces.retain(|i| i != "auto");
            for i in auto {
                if !self.interfaces.contains(&i) {
                    self.interfaces.push(i);
                }
            }
        }
    }

    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(s) => {
                let c: Self = toml::from_str(&s)?;
                c.anomaly.validate().map_err(anyhow::Error::msg)?;
                c.k8s.validate().map_err(anyhow::Error::msg)?;
                Ok(c)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::warn!(path = %path.display(), "no config file, using defaults");
                Ok(Self::default())
            }
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn example_config_parses() {
        let c: super::Config =
            toml::from_str(include_str!("../../../examples/kavachd.toml")).unwrap();
        assert_eq!(c.interfaces, ["auto"]);
        assert_eq!(c.ratelimit.unwrap().pps, 20000);
        // The example documents the defaults verbatim.
        assert_eq!(c.anomaly, crate::anomaly::AnomalyConfig::default());
        assert!(c.anomaly.validate().is_ok());
        assert!(
            !c.gateway.afxdp.enabled,
            "AF_XDP backend is never on by default"
        );
        assert!(!super::Config::default().gateway.afxdp.enabled);
    }

    #[test]
    fn anomaly_section_is_optional_and_partial() {
        let c: super::Config =
            toml::from_str("[anomaly]\nenabled = false\nz_threshold = 6.0\n").unwrap();
        assert!(!c.anomaly.enabled);
        assert_eq!(c.anomaly.z_threshold, 6.0);
        assert_eq!(c.anomaly.window_secs, 60);
        let c: super::Config = toml::from_str("").unwrap();
        assert!(c.anomaly.enabled);
        assert!(toml::from_str::<super::Config>("[anomaly]\nbogus = 1\n").is_err());
    }

    #[test]
    fn gateway_afxdp_section_parses() {
        let c: super::Config = toml::from_str(
            r#"
[gateway.afxdp]
enabled = true
iface = "eth0"
queues = [0, 1]
ports = [8443, "443/udp"]
watchdog_ms = 200
"#,
        )
        .unwrap();
        let a = &c.gateway.afxdp;
        assert!(a.enabled);
        assert_eq!(a.queues, [0, 1]);
        assert_eq!(a.watchdog_ms, 200);
        a.validate().unwrap();
        assert!(toml::from_str::<super::Config>("[gateway.afxdp]\nbogus = 1").is_err());
    }

    #[test]
    fn auto_resolves_to_real_default_route_interfaces() {
        let mut c = super::Config {
            interfaces: vec!["auto".into()],
            ..Default::default()
        };
        c.resolve_interfaces();
        assert!(!c.interfaces.iter().any(|i| i == "auto" || i == "lo"));
        // every resolved name is a real interface on this host
        for i in &c.interfaces {
            assert!(
                std::path::Path::new("/sys/class/net").join(i).exists(),
                "{i}"
            );
        }
    }
}
