//! `/etc/kavach/kavachd.toml` — host configuration (not policy).

use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Interfaces that get XDP + TC programs. Empty = none (LSM egress still works).
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
        }
    }
}

impl Config {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(s) => Ok(toml::from_str(&s)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::warn!(path = %path.display(), "no config file, using defaults");
                Ok(Self::default())
            }
            Err(e) => Err(e.into()),
        }
    }
}
