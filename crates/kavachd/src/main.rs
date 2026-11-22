//! kavachd — the Kavach host daemon.
//!
//! Loads and pins the eBPF programs, attaches XDP/TC/LSM, restores and applies signed policy,
//! classifies executables, and serves the local control API. If kavachd exits, the pinned
//! programs keep enforcing the last policy (FR-D-6); `kavachctl kill-switch` detaches everything.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use kavach_common::abi::*;
use tokio::sync::{Notify, broadcast, mpsc};
use tracing::{error, info, warn};

use kavachd::config::Config;
use kavachd::daemon::Daemon;
use kavachd::kernel::{self, Kernel};
use kavachd::{api, events};

#[derive(Parser, Debug)]
#[command(version, about = "Kavach kernel-native firewall daemon")]
struct Args {
    #[arg(short, long, default_value = "/etc/kavach/kavachd.toml")]
    config: PathBuf,
    /// Extra interfaces to protect (added to the config file list).
    #[arg(short, long)]
    interface: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    let mut cfg = Config::load(&args.config)?;
    cfg.interfaces.extend(args.interface);
    cfg.resolve_interfaces();
    info!(interfaces = ?cfg.interfaces, "XDP/TC interfaces");

    let mut k = Kernel::load(&cfg.pin_dir).context("loading Kavach eBPF programs")?;

    let mut xdp = XdpConfig {
        sample_rate: cfg.sample_rate,
        flags: KV_XDP_F_BLOCKLIST,
        ..Default::default()
    };
    if let Some(rl) = cfg.ratelimit {
        let (e, t) = kernel::gcra(rl.pps, rl.burst);
        xdp.emission_ns = e;
        xdp.tau_ns = t;
        xdp.flags |= KV_XDP_F_RATELIMIT;
    }
    k.set_xdp_config(xdp)?;

    let mut xdp_failed = vec![];
    for iface in &cfg.interfaces {
        match k.attach_xdp(iface, &cfg.xdp_mode) {
            Ok(mode) => info!(iface, mode, "XDP attached"),
            Err(e) => {
                error!(iface, error = %format!("{e:#}"), "XDP attach failed");
                xdp_failed.push(iface.clone());
            }
        }
        if cfg.tc {
            match k.attach_tc(iface) {
                Ok(()) => info!(iface, "TC attached"),
                Err(e) => error!(iface, error = %format!("{e:#}"), "TC attach failed"),
            }
        }
    }
    if cfg.lsm {
        match k.attach_lsm() {
            Ok(()) => info!("BPF-LSM identity egress attached"),
            Err(e) => {
                warn!(error = %format!("{e:#}"), "BPF-LSM unavailable: identity egress disabled")
            }
        }
    }

    let rb = k.take_events()?;
    let xdp_mode = cfg.xdp_mode.clone();
    let scan_dirs = cfg.hash_scan_dirs.clone();
    let state = Arc::new(Mutex::new(Daemon::new(cfg, k)));
    let (tx, _) = broadcast::channel(4096);
    let (jobs_tx, jobs_rx) = mpsc::channel(8192);
    let (prewarm_tx, prewarm_rx) = mpsc::channel(4096);
    let prewarm_rx = Arc::new(tokio::sync::Mutex::new(prewarm_rx));
    let shutdown = Arc::new(Notify::new());

    let events_fd = events::event_fd(rb)?;
    let jobs_rx = Arc::new(tokio::sync::Mutex::new(jobs_rx));
    supervise("event reader", state.clone(), {
        let (st, tx, jobs, fd) = (
            state.clone(),
            tx.clone(),
            jobs_tx.clone(),
            events_fd.clone(),
        );
        move || events::reader(fd.clone(), st.clone(), tx.clone(), jobs.clone())
    });
    supervise("identity broker", state.clone(), {
        let (st, rx, pw) = (state.clone(), jobs_rx.clone(), prewarm_rx.clone());
        move || {
            let (st, rx, pw) = (st.clone(), rx.clone(), pw.clone());
            async move {
                events::identity_broker(st, rx, pw).await;
                Ok(())
            }
        }
    });

    {
        let mut st = state.lock().expect("fresh state");
        st.prewarm_tx = Some(prewarm_tx.clone());
        if let Err(e) = st.restore() {
            error!(error = %format!("{e:#}"), "could not restore persisted policy");
        }
        // Upgrade across an ABI bump: our programs and policy are live now, so detach the
        // previous version's, then give XDP the interfaces its link was holding.
        match st.k().and_then(|k| k.retire_stale_abis()) {
            Ok(old) if !old.is_empty() => {
                warn!(retired = ?old, "detached programs pinned by an older Kavach ABI");
                // bpffs frees an unlinked pin after an RCU grace period, so the old link lets
                // go of the interface shortly after the unlink: retry for up to ~2 s.
                for iface in &xdp_failed {
                    let mut last = None;
                    for _ in 0..40 {
                        match st.k().and_then(|k| k.attach_xdp(iface, &xdp_mode)) {
                            Ok(mode) => {
                                info!(iface, mode, "XDP attached");
                                last = None;
                                break;
                            }
                            Err(e) => last = Some(e),
                        }
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                    if let Some(e) = last {
                        error!(iface, error = %format!("{e:#}"), "XDP attach failed");
                    }
                }
            }
            Ok(_) => {}
            Err(e) => error!(error = %format!("{e:#}"), "could not retire older ABI pins"),
        }
        // Classify processes that were running before we started.
        if let Err(e) = st.k().and_then(|k| k.scan_tasks()) {
            warn!(error = %format!("{e:#}"), "startup task scan failed");
        }
    }

    // Hash pre-classification of the standard binary directories (+ inotify).
    supervise("hash scanner", state.clone(), {
        let st = state.clone();
        let kick = state.lock().expect("fresh state").scan_kick.clone();
        move || kavachd::scan::scanner(st.clone(), scan_dirs.clone(), kick.clone())
    });

    // Housekeeping: blocklist expiry + FQDN refresh.
    supervise("housekeeping", state.clone(), {
        let st = state.clone();
        move || housekeeping(st.clone())
    });

    let api = tokio::spawn(api::serve(state.clone(), tx.clone(), shutdown.clone()));

    tokio::select! {
        _ = tokio::signal::ctrl_c() => info!("SIGINT: exiting; pinned programs keep enforcing"),
        _ = sigterm() => info!("SIGTERM: exiting; pinned programs keep enforcing"),
        _ = shutdown.notified() => info!("kill-switch: exiting"),
        r = api => error!(result = ?r, "control API stopped"),
    }
    Ok(())
}

async fn sigterm() {
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(mut s) => {
            s.recv().await;
        }
        Err(_) => std::future::pending::<()>().await,
    }
}

async fn housekeeping(st: Arc<Mutex<Daemon>>) -> Result<()> {
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    let mut n: u64 = 0;
    loop {
        tick.tick().await;
        n += 1;
        let Ok(mut s) = st.lock() else { continue };
        if s.kernel.is_none() {
            return Ok(());
        }
        let _ = s.purge_blocklist();
        let every = (s.cfg.dns_min_ttl_secs.max(30) / 30).max(1);
        if n.is_multiple_of(every)
            && let Err(e) = s.refresh_dns()
        {
            warn!(error = %format!("{e:#}"), "FQDN refresh failed");
        }
    }
}

/// Supervise a daemon task; restarts are audited and clear a poisoned state lock.
fn supervise<F, Fut>(name: &'static str, state: Arc<Mutex<Daemon>>, make: F)
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<()>> + Send + 'static,
{
    kavachd::supervise::spawn(name, make, move |task, why| {
        if state.is_poisoned() {
            state.clear_poison();
        }
        if let Ok(mut st) = state.lock() {
            st.audit.record(
                "task_restart",
                serde_json::json!({ "task": task, "reason": why }),
            );
        }
    });
}
