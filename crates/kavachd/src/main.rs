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
    let mut xdp_modes: Vec<(String, String)> = vec![];
    for iface in &cfg.interfaces {
        match k.attach_xdp(iface, &cfg.xdp_mode) {
            Ok(mode) => {
                info!(iface, mode, "XDP attached");
                xdp_modes.push((iface.clone(), mode));
            }
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
    if cfg.lsm && !kavachd::kernel::in_initial_pid_ns() {
        error!(
            "BPF-LSM not attached: kavachd is not in the host PID namespace, so it could not \
             classify any executable and identity rules would never match. Run kavachd on the \
             host or with `--pid=host` (XDP and TC enforcement are unaffected)"
        );
    } else if cfg.lsm {
        match k.attach_lsm() {
            Ok(()) => info!("BPF-LSM identity egress attached"),
            Err(e) => {
                warn!(error = %format!("{e:#}"), "BPF-LSM unavailable: identity egress disabled")
            }
        }
    }

    // The active bundle's gateway policies (published by the daemon on every apply/restore);
    // the redirect resolves gateway names from it.
    let gateways = kavachd::gateway_policies::GatewayPolicies::new();
    let gateways_handle = gateways.clone();
    let gw_cfg = cfg.gateway.clone();
    // L7 gateway redirect for punted TCP connects. Lives until kavachd exits; on exit (or a
    // crash) the liveness deadline lapses and punts fall back to their fail mode. The proxy
    // resolves original destinations through `gateway.orig` (kavach_gateway::OrigDst).
    let _gateway = if cfg.gateway.enabled {
        match kavachd::gateway::start(&mut k, &cfg.gateway, std::process::id(), gateways.clone()) {
            Ok(g) => {
                info!(listen = %cfg.gateway.listen, listen6 = ?cfg.gateway.listen6,
                      "L7 gateway redirect attached (active while the listener is up)");
                Some(g)
            }
            Err(e) => {
                error!(error = %format!("{e:#}"), "L7 gateway redirect not started; punts use their fail mode");
                None
            }
        }
    } else {
        kavachd::gateway::disable(&mut k);
        None
    };

    // Opt-in AF_XDP gateway backend; lives until kavachd exits (its sockets close with it).
    let _afxdp = start_afxdp(&mut k, &cfg, &xdp_modes);

    let rb = k.take_events()?;
    let xdp_mode = cfg.xdp_mode.clone();
    let scan_dirs = cfg.hash_scan_dirs.clone();
    let state = Arc::new(Mutex::new({
        let mut d = Daemon::new(cfg, k);
        d.gateways = gateways; // shared with the redirect's OrigDst
        d
    }));
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

    // The in-process L7 proxy. kavachd's own tgid is exempt from redirection, so the proxy's
    // upstream connects are never looped back to itself. Decisions go to the audit log.
    let proxy_stop = Arc::new(Notify::new());
    if let Some(g) = &_gateway {
        let (etx, mut erx) = mpsc::channel::<kavach_gateway::DecisionEvent>(4096);
        let sink: Arc<dyn kavach_gateway::EventSink> =
            Arc::new(kavach_gateway::proxy::ChannelSink::new(etx));
        let st = state.clone();
        tokio::spawn(async move {
            let mut throttle = kavachd::gateway::AuditThrottle::new(10);
            while let Some(ev) = erx.recv().await {
                if !throttle.admit(&ev) {
                    continue;
                }
                if let Ok(mut s) = st.lock() {
                    s.audit.record(
                        "gateway_decision",
                        serde_json::to_value(&ev).unwrap_or_default(),
                    );
                }
            }
        });
        let (gcfg, orig, pols, stop) = (
            gw_cfg.clone(),
            g.orig.clone(),
            gateways_handle.clone(),
            proxy_stop.clone(),
        );
        tokio::spawn(async move {
            let r = kavachd::gateway::serve_proxy(&gcfg, orig, pols, sink, stop.notified()).await;
            if let Err(e) = r {
                // The heartbeat sees no listener: punts keep using their fail mode.
                error!(error = %e, listen = %gcfg.listen, "L7 gateway proxy stopped");
            }
        });
    }

    let api = tokio::spawn(api::serve(state.clone(), tx.clone(), shutdown.clone()));

    tokio::select! {
        _ = tokio::signal::ctrl_c() => info!("SIGINT: exiting; pinned programs keep enforcing"),
        _ = sigterm() => info!("SIGTERM: exiting; pinned programs keep enforcing"),
        _ = shutdown.notified() => info!("kill-switch: exiting"),
        r = api => error!(result = ?r, "control API stopped"),
    }
    // Stop redirecting first (the heartbeat zeroes the deadline), then close the proxy.
    drop(_gateway);
    proxy_stop.notify_one();
    Ok(())
}

/// Start the AF_XDP backend when `[gateway.afxdp] enabled = true`. Order matters: sockets are
/// bound and published (with live watchdog deadlines) first, then the port selection, and the
/// XDP redirect flag last. When disabled, stale port selections from an earlier run are cleared
/// (`set_xdp_config` above already cleared the flag), so the fast path is unchanged.
fn start_afxdp(
    k: &mut Kernel,
    cfg: &Config,
    xdp_modes: &[(String, String)],
) -> Option<kavach_gateway::afxdp::Backend> {
    use kavach_gateway::afxdp::{Backend, CountingSink, LinuxSys, XdpAttach};
    let a = &cfg.gateway.afxdp;
    if !a.enabled {
        if let Err(e) = k.set_xsk_ports(&[]) {
            warn!(error = %format!("{e:#}"), "could not clear AF_XDP port selection");
        }
        return None;
    }
    let started = (|| -> Result<Backend> {
        a.validate().map_err(anyhow::Error::msg)?;
        let label = xdp_modes
            .iter()
            .find(|(i, _)| *i == a.iface)
            .map(|(_, m)| m.as_str())
            .with_context(|| {
                format!(
                    "gateway.afxdp.iface {} has no Kavach XDP program (list it in `interfaces`)",
                    a.iface
                )
            })?;
        let maps = k.xsk_maps()?;
        let b = Backend::start(
            Arc::new(LinuxSys),
            a,
            XdpAttach::from_label(label),
            maps,
            |_| CountingSink::default(),
        )?;
        k.set_xsk_ports(&a.port_keys())?;
        k.set_afxdp_redirect(true)?;
        Ok(b)
    })();
    match started {
        Ok(b) => {
            let ports: Vec<String> = a.ports.iter().map(|p| p.to_string()).collect();
            let modes: Vec<String> = b.modes().iter().map(|(q, m)| format!("{q}:{m}")).collect();
            warn!(
                iface = %a.iface, ?ports, ?modes, watchdog_ms = a.watchdog_ms,
                "AF_XDP gateway backend ON: frames to these ports are consumed (counted, then \
                 dropped) in user space, because AF_XDP cannot hand a frame back to the kernel \
                 stack; they bypass TC ingress policy. Punted connections do not use this path \
                 ([gateway] enabled redirects them at connect())"
            );
            Some(b)
        }
        Err(e) => {
            let _ = k.set_afxdp_redirect(false);
            let _ = k.set_xsk_ports(&[]);
            error!(error = %format!("{e:#}"), "AF_XDP gateway backend not started; fast path unchanged");
            None
        }
    }
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
