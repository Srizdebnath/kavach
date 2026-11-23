//! `kavach-gateway`: run the agent-gateway proxy standalone, in explicit-proxy mode.
//!
//! Inside kavachd the original destination of each flow comes from the kernel. Standalone,
//! every connection goes to one configured `[upstream]`, which is how to put the gateway in
//! front of a single MCP / A2A server (or try it out):
//!
//! ```toml
//! [proxy]                 # kavach_gateway::ProxyConfig; every field optional
//! listen = "127.0.0.1:15001"
//! tls = "deny"
//!
//! [upstream]
//! addr = "127.0.0.1:8080"
//! gateway = "dev"         # which [gateways.*] policy applies
//!
//! [gateways.dev]          # kavach_gateway::ToolPolicy
//! allow_tools = ["search", "github.*"]
//! deny_tools = ["github.delete_repo"]
//! ```
//!
//! Decision events are printed to stdout as JSON lines; logs go to stderr (`RUST_LOG`).
//! `SIGHUP` reloads `[gateways]` without dropping connections.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use kavach_gateway::ToolPolicy;
use kavach_gateway::proxy::{
    ChannelSink, Gateway, OrigInfo, PolicyStore, ProxyConfig, StaticOrigDst,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(default)]
    proxy: ProxyConfig,
    upstream: Upstream,
    #[serde(default)]
    gateways: HashMap<String, ToolPolicy>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Upstream {
    addr: SocketAddr,
    gateway: String,
    #[serde(default)]
    rule_id: u32,
}

fn load(path: &Path) -> Result<File> {
    let src =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    toml::from_str(&src).with_context(|| format!("parsing {}", path.display()))
}

fn config_path() -> Result<PathBuf> {
    let mut args = std::env::args_os().skip(1);
    let path = match (args.next(), args.next(), args.next()) {
        (Some(flag), Some(p), None) if flag == "--config" || flag == "-c" => p,
        (Some(p), None, None) if p != "--help" && p != "-h" => p,
        _ => bail!("usage: kavach-gateway [--config] <gateway.toml>"),
    };
    Ok(path.into())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let path = config_path()?;
    let file = load(&path)?;
    if !file.gateways.contains_key(&file.upstream.gateway) {
        tracing::warn!(
            gateway = %file.upstream.gateway,
            "no [gateways] policy for the upstream; every frame will be denied"
        );
    }

    let policies = Arc::new(PolicyStore::new(file.gateways));
    let upstream = file.upstream.addr;
    let resolver = Arc::new(StaticOrigDst(OrigInfo {
        dst: upstream,
        rule_id: file.upstream.rule_id,
        gateway: file.upstream.gateway,
        cgroup_id: 0,
        pid: 0,
    }));
    let (tx, mut rx) = tokio::sync::mpsc::channel(4096);
    let sink = Arc::new(ChannelSink::new(tx));
    let gw = Gateway::bind(file.proxy, resolver, policies.clone(), sink).await?;
    tracing::info!(listen = %gw.local_addr(), %upstream, "kavach-gateway listening");

    tokio::spawn(async move {
        use std::io::Write;
        while let Some(ev) = rx.recv().await {
            if let Ok(line) = serde_json::to_string(&ev) {
                let _ = writeln!(std::io::stdout().lock(), "{line}");
            }
        }
    });

    let mut hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    let reload = async move {
        while hup.recv().await.is_some() {
            match load(&path) {
                Ok(f) => {
                    policies.replace(f.gateways);
                    tracing::info!(gateways = ?policies.names(), "policies reloaded");
                }
                Err(e) => tracing::error!(
                    error = %format!("{e:#}"),
                    "reload failed; keeping the current policies"
                ),
            }
        }
    };
    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    tokio::select! {
        r = gw.serve_until(shutdown) => r?,
        _ = reload => {}
    }
    Ok(())
}
