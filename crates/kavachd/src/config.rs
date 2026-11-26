//! `/etc/kavach/kavachd.toml` — host configuration (not policy).

use std::net::SocketAddr;
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
}

/// `[gateway]`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct GatewayConfig {
    /// Redirect punted TCP connects to the L7 gateway (`cgroup/connect4|6` + sockops on the
    /// root cgroup). Off: punts resolve through the rule's fail mode.
    pub enabled: bool,
    /// The gateway's IPv4 listener. Must be a loopback address: punted traffic never leaves
    /// the host on its way to the gateway.
    pub listen: SocketAddr,
    /// Optional IPv6 listener (`[::1]:port`). Without it, IPv6 sockets are redirected to the
    /// IPv4-mapped `listen` (`IPV6_V6ONLY` sockets cannot be; their punts use the fail mode).
    pub listen6: Option<SocketAddr>,
    /// cgroup v2 directory of an out-of-process gateway (e.g.
    /// `/sys/fs/cgroup/system.slice/kavach-gateway.service`). Its connects are never redirected.
    /// kavachd itself is always exempt (it hosts the in-process proxy).
    pub exempt_cgroup: Option<PathBuf>,
    /// `[gateway.proxy]`: limits of the in-process L7 proxy kavachd runs while `enabled`.
    /// Its listen address is always `listen` above.
    pub proxy: kavach_gateway::ProxyConfig,
    /// `[gateway.afxdp]`: opt-in AF_XDP RX backend (off by default).
    pub afxdp: kavach_gateway::afxdp::AfXdpConfig,
}

/// Default gateway listener (the proxy's default bind address).
pub const DEFAULT_GATEWAY_LISTEN: SocketAddr = SocketAddr::V4(std::net::SocketAddrV4::new(
    std::net::Ipv4Addr::LOCALHOST,
    15001,
));

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: DEFAULT_GATEWAY_LISTEN,
            listen6: None,
            exempt_cgroup: None,
            proxy: Default::default(),
            afxdp: Default::default(),
        }
    }
}

impl GatewayConfig {
    /// Check the redirect settings (a disabled gateway is always valid).
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        match self.listen {
            SocketAddr::V4(a) if a.ip().is_loopback() && a.port() != 0 => {}
            other => {
                return Err(format!(
                    "gateway.listen = {other}: must be an IPv4 loopback address with a port \
                     (punted connections must not leave the host)"
                ));
            }
        }
        if let Some(l6) = self.listen6 {
            match l6 {
                SocketAddr::V6(a) if a.ip().is_loopback() && a.port() != 0 => {}
                other => {
                    return Err(format!("gateway.listen6 = {other}: must be [::1]:<port>"));
                }
            }
        }
        if self.proxy.listen != kavach_gateway::ProxyConfig::default().listen
            && self.proxy.listen != self.listen
        {
            return Err(
                "gateway.proxy.listen: set the listener once, as gateway.listen (the redirect \
                 target and the proxy must agree)"
                    .into(),
            );
        }
        if let Some(cg) = &self.exempt_cgroup
            && !cg.is_absolute()
        {
            return Err(format!(
                "gateway.exempt_cgroup = {}: must be an absolute cgroup v2 directory",
                cg.display()
            ));
        }
        Ok(())
    }
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
                c.gateway.validate().map_err(anyhow::Error::msg)?;
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
        assert_eq!(
            c.gateway,
            super::GatewayConfig::default(),
            "example = defaults"
        );
        assert!(!c.gateway.enabled, "punt redirect is never on by default");
    }

    #[test]
    fn gateway_redirect_section_parses_and_validates() {
        let c: super::Config = toml::from_str(
            r#"
[gateway]
enabled = true
listen = "127.0.0.1:15001"
listen6 = "[::1]:15001"
exempt_cgroup = "/sys/fs/cgroup/system.slice/kavach-gateway.service"
"#,
        )
        .unwrap();
        assert!(c.gateway.enabled);
        assert_eq!(c.gateway.listen, super::DEFAULT_GATEWAY_LISTEN);
        assert_eq!(c.gateway.listen6, Some("[::1]:15001".parse().unwrap()));
        c.gateway.validate().unwrap();
        let bad = |s: &str| {
            let c: super::Config = toml::from_str(s).unwrap();
            c.gateway.validate().unwrap_err()
        };
        assert!(bad("[gateway]\nenabled = true\nlisten = \"10.0.0.1:15001\"").contains("loopback"));
        assert!(bad("[gateway]\nenabled = true\nlisten = \"127.0.0.1:0\"").contains("port"));
        assert!(bad("[gateway]\nenabled = true\nlisten = \"[::1]:15001\"").contains("IPv4"));
        assert!(bad("[gateway]\nenabled = true\nlisten6 = \"[::2]:1\"").contains("listen6"));
        assert!(bad("[gateway]\nenabled = true\nexempt_cgroup = \"x\"").contains("absolute"));
        assert!(
            bad("[gateway]\nenabled = true\n[gateway.proxy]\nlisten = \"127.0.0.1:9\"")
                .contains("once")
        );
        let c: super::Config =
            toml::from_str("[gateway]\nenabled = true\n[gateway.proxy]\nmax_connections = 8")
                .unwrap();
        assert_eq!(c.gateway.proxy.max_connections, 8);
        c.gateway.validate().unwrap();
        // disabled: anything goes (it is not used)
        let c: super::Config = toml::from_str("[gateway]\nlisten = \"10.0.0.1:1\"").unwrap();
        c.gateway.validate().unwrap();
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
