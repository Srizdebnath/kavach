//! Control API: newline-delimited JSON over a 0600 Unix socket, authorised with SO_PEERCRED
//! (FR-D-3, SR-1, SR-5). Root may do everything; members of `control_group` everything except
//! the kill-switch.

use std::os::unix::fs::PermissionsExt;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow};
use ipnet::IpNet;
use kavach_api::{EventRecord, MAX_LINE, Request, Response, encode};
use kavach_common::abi::*;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, Notify};
use tracing::{info, warn};

use crate::daemon::Daemon;
use crate::kernel;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Root,
    Operator,
}

pub async fn serve(
    state: Arc<Mutex<Daemon>>,
    events: broadcast::Sender<EventRecord>,
    shutdown: Arc<Notify>,
) -> Result<()> {
    let (path, group) = {
        let st = state.lock().map_err(|_| anyhow!("state poisoned"))?;
        (st.cfg.socket.clone(), st.cfg.control_group.clone())
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).with_context(|| format!("binding {}", path.display()))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(if group.is_some() { 0o660 } else { 0o600 }))?;
    let gid = group.as_deref().and_then(|g| nix::unistd::Group::from_name(g).ok().flatten()).map(|g| g.gid.as_raw());
    if let Some(gid) = gid {
        let _ = nix::unistd::chown(&path, None, Some(nix::unistd::Gid::from_raw(gid)));
    }
    info!(socket = %path.display(), "control API listening");
    loop {
        let (stream, _) = listener.accept().await?;
        let cred = match stream.peer_cred() {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "no peer credentials; refusing connection");
                continue;
            }
        };
        let role = if cred.uid() == 0 {
            Role::Root
        } else if gid.is_some_and(|g| g == cred.gid()) {
            Role::Operator
        } else {
            warn!(uid = cred.uid(), "unauthorised control connection refused");
            continue;
        };
        let (st, ev, sd) = (state.clone(), events.clone(), shutdown.clone());
        tokio::spawn(async move {
            if let Err(e) = client(stream, role, st, ev, sd).await {
                warn!(error = %e, "control client error");
            }
        });
    }
}

async fn client(
    stream: UnixStream,
    role: Role,
    state: Arc<Mutex<Daemon>>,
    events: broadcast::Sender<EventRecord>,
    shutdown: Arc<Notify>,
) -> Result<()> {
    let (rd, mut wr) = stream.into_split();
    let mut lines = BufReader::new(rd).lines();
    while let Some(line) = lines.next_line().await? {
        if line.len() > MAX_LINE {
            wr.write_all(&encode(&Response::Error { message: "request too large".into() })).await?;
            return Ok(());
        }
        let req: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                wr.write_all(&encode(&Response::Error { message: format!("bad request: {e}") })).await?;
                continue;
            }
        };
        match req {
            Request::Events => {
                let mut rx = events.subscribe();
                loop {
                    match rx.recv().await {
                        Ok(ev) => {
                            if wr.write_all(&encode(&Response::Event(ev))).await.is_err() {
                                return Ok(());
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            let msg = Response::Error { message: format!("{n} events dropped (slow reader)") };
                            if wr.write_all(&encode(&msg)).await.is_err() {
                                return Ok(());
                            }
                        }
                        Err(_) => return Ok(()),
                    }
                }
            }
            Request::KillSwitch => {
                let resp = if role != Role::Root {
                    Response::Error { message: "kill-switch requires root".into() }
                } else {
                    let r = (|| -> Result<()> {
                        let mut st = state.lock().map_err(|_| anyhow!("state poisoned"))?;
                        st.audit.record("kill_switch", json!({}));
                        let k = st.kernel.take().ok_or_else(|| anyhow!("already engaged"))?;
                        k.kill_switch()
                    })();
                    match r {
                        Ok(()) => {
                            warn!("KILL-SWITCH engaged: all programs detached and unpinned");
                            shutdown.notify_one();
                            Response::Ok
                        }
                        Err(e) => Response::Error { message: e.to_string() },
                    }
                };
                wr.write_all(&encode(&resp)).await?;
            }
            other => {
                let st = state.clone();
                let resp = tokio::task::spawn_blocking(move || handle(&st, other))
                    .await
                    .unwrap_or_else(|e| Response::Error { message: e.to_string() });
                wr.write_all(&encode(&resp)).await?;
            }
        }
    }
    Ok(())
}

const STAT_NAMES: &[&str] = &[
    "xdp_pass",
    "xdp_drop_blocklist",
    "xdp_drop_rate",
    "xdp_unparsed",
    "egress_allow",
    "egress_drop",
    "egress_log",
    "ingress_allow",
    "ingress_drop",
    "flow_cache_hit",
    "flow_cache_miss",
    "events_lost",
    "policy_no_slot",
    "exe_unclassified",
    "flow_cache_stale",
];

fn handle(state: &Arc<Mutex<Daemon>>, req: Request) -> Response {
    let mut st = match state.lock() {
        Ok(s) => s,
        Err(_) => return Response::Error { message: "state poisoned".into() },
    };
    match handle_inner(&mut st, req) {
        Ok(r) => r,
        Err(e) => Response::Error { message: format!("{e:#}") },
    }
}

fn handle_inner(st: &mut Daemon, req: Request) -> Result<Response> {
    Ok(match req {
        Request::Status => Response::Status(st.status()),
        Request::Stats => {
            let v = st.k()?.stats()?;
            Response::Stats {
                counters: STAT_NAMES.iter().zip(v).map(|(n, c)| ((*n).to_owned(), c)).collect(),
            }
        }
        Request::Metrics => {
            let v = st.k()?.stats()?;
            let mut text = String::from("# HELP kavach_packets_total Kavach verdict counters\n# TYPE kavach_packets_total counter\n");
            for (n, c) in STAT_NAMES.iter().zip(v) {
                text.push_str(&format!("kavach_packets_total{{reason=\"{n}\"}} {c}\n"));
            }
            text.push_str(&format!(
                "# TYPE kavach_policy_generation gauge\nkavach_policy_generation {}\n# TYPE kavach_policy_serial gauge\nkavach_policy_serial {}\n# TYPE kavach_policy_expired gauge\nkavach_policy_expired {}\n",
                st.generation, st.serial, u8::from(st.expired)
            ));
            Response::Metrics { text }
        }
        Request::BlockAdd { cidr, ttl_secs, reason } => {
            let net = parse_net(&cidr)?;
            let expires = ttl_secs.map_or(0, |t| kernel::boot_ns() + t * 1_000_000_000);
            st.k()?.block_add(net, expires, reason.unwrap_or(0))?;
            st.audit.record("block_add", json!({ "cidr": net.to_string(), "ttl_secs": ttl_secs, "reason": reason }));
            Response::Ok
        }
        Request::BlockDel { cidr } => {
            let net = parse_net(&cidr)?;
            st.k()?.block_del(net)?;
            st.audit.record("block_del", json!({ "cidr": net.to_string() }));
            Response::Ok
        }
        Request::BlockList => Response::BlockList { entries: st.block_list()? },
        Request::RateLimit { pps, burst } => {
            anyhow::ensure!(pps > 0 && burst > 0, "pps and burst must be > 0");
            let k = st.k()?;
            let mut cfg = k.xdp_config()?;
            let (emission_ns, tau_ns) = kernel::gcra(pps, burst);
            cfg.emission_ns = emission_ns;
            cfg.tau_ns = tau_ns;
            cfg.flags |= KV_XDP_F_RATELIMIT;
            k.set_xdp_config(cfg)?;
            st.audit.record("ratelimit", json!({ "pps": pps, "burst": burst }));
            Response::Ok
        }
        Request::RateLimitOff => {
            let k = st.k()?;
            let mut cfg = k.xdp_config()?;
            cfg.flags &= !KV_XDP_F_RATELIMIT;
            k.set_xdp_config(cfg)?;
            st.audit.record("ratelimit_off", json!({}));
            Response::Ok
        }
        Request::Apply { bundle, dry_run } => Response::Applied(st.apply(&bundle, dry_run)?),
        Request::ActivePolicy => Response::ActivePolicy {
            policy: st.active().map(|p| postcard::to_allocvec(p.as_ref())).transpose()?,
            serial: st.serial,
            generation: st.generation,
        },
        Request::Events | Request::KillSwitch => unreachable!("handled by the async client loop"),
    })
}

fn parse_net(s: &str) -> Result<IpNet> {
    IpNet::from_str(s)
        .or_else(|_| std::net::IpAddr::from_str(s).map(IpNet::from))
        .map(|n| n.trunc())
        .map_err(|_| anyhow!("{s:?} is not an IP or CIDR"))
}
