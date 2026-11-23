//! `kavachctl top`: a live terminal dashboard over the control socket.
//!
//! Data comes from the existing protocol only: `status` + `stats` are polled every `--interval`
//! on one connection, and a second connection subscribes to `events`. Everything that turns
//! those responses into what is on screen ([`TopState`], [`draw`]) is pure and unit-tested; the
//! impure shell ([`run`]) only moves bytes and keys.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use kavach_api::{EventRecord, Request, Response, Status};
use ratatui::Frame;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, Paragraph, Row, Table};

use crate::Conn;

/// Recent events kept for the stream pane.
pub const EVENT_RING: usize = 256;
/// Distinct identities / rules tracked before the least recently seen is evicted.
pub const MAX_KEYS: usize = 4096;

/// Parse `--interval`: `500ms`, `2s`, or a bare number of seconds (`0.5`).
pub fn parse_interval(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    let (num, scale) = if let Some(n) = s.strip_suffix("ms") {
        (n, 0.001)
    } else if let Some(n) = s.strip_suffix('s') {
        (n, 1.0)
    } else {
        (s, 1.0)
    };
    let v: f64 = num
        .trim()
        .parse()
        .map_err(|_| format!("invalid interval {s:?} (try 1s, 500ms or 0.5)"))?;
    let secs = v * scale;
    if !secs.is_finite() || !(0.1..=3600.0).contains(&secs) {
        return Err(format!("interval {s:?} must be between 100ms and 1h"));
    }
    Ok(Duration::from_secs_f64(secs))
}

/// `src:sport → dst:dport`, shared with `kavachctl events`.
pub fn format_flow(e: &EventRecord) -> String {
    match (&e.src, &e.dst) {
        (Some(s), Some(d)) => format!("{s}:{} → {d}:{}", e.sport, e.dport),
        (None, Some(d)) => format!("→ {d}:{}", e.dport),
        (Some(s), None) => format!("{s}:{}", e.sport),
        _ => String::new(),
    }
}

/// The rule an event is attributed to, as shown in the rules pane.
pub fn rule_label(e: &EventRecord) -> String {
    if e.kind == "xdp_drop" {
        return format!(
            "xdp {}",
            if e.reason.is_empty() {
                "drop"
            } else {
                &e.reason
            }
        );
    }
    match &e.rule {
        Some(r) => r.clone(),
        None if e.rule_id == 0 => "default".into(),
        None => format!("#{}", e.rule_id),
    }
}

fn is_flow(e: &EventRecord) -> bool {
    matches!(e.kind.as_str(), "xdp_drop" | "egress" | "ingress")
}

fn is_drop(e: &EventRecord) -> bool {
    e.kind == "xdp_drop" || e.verdict == "drop"
}

/// Who a flow event belongs to. XDP drops happen before any socket exists, so they are keyed by
/// their source address instead of a process.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Identity {
    pub exe: String,
    pub uid: Option<u32>,
    pub cgroup: Option<u64>,
}

impl Identity {
    pub fn of(e: &EventRecord) -> Self {
        if e.kind == "xdp_drop" {
            return Self {
                exe: format!("[xdp] {}", e.src.as_deref().unwrap_or("?")),
                uid: None,
                cgroup: None,
            };
        }
        Self {
            exe: if e.comm.is_empty() {
                format!("pid {}", e.pid)
            } else {
                e.comm.clone()
            },
            uid: Some(e.uid),
            cgroup: Some(e.cgroup_id),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tally {
    pub flows: u64,
    pub drops: u64,
    /// Arrival order of the last event, for eviction.
    pub last_seq: u64,
}

impl Tally {
    fn add(&mut self, drop: bool, seq: u64) {
        self.flows += 1;
        self.drops += u64::from(drop);
        self.last_seq = seq;
    }
}

/// One enforcement program's verdict counters, folded from the daemon's per-reason counters.
#[derive(Debug, Clone, PartialEq)]
pub struct ProgramRow {
    pub name: &'static str,
    pub attach: String,
    pub pass: u64,
    pub drop: u64,
    pub pass_rate: f64,
    pub drop_rate: f64,
}

/// Which counters make up each program's pass / drop totals.
const PROGRAMS: &[(&str, &[&str], &[&str])] = &[
    (
        "xdp",
        &["xdp_pass"],
        &["xdp_drop_blocklist", "xdp_drop_rate"],
    ),
    (
        "tc-egress",
        &["egress_allow", "egress_log"],
        &["egress_drop", "egress_unclassified"],
    ),
    ("tc-ingress", &["ingress_allow"], &["ingress_drop"]),
];

/// Everything the dashboard knows, built only from protocol responses.
#[derive(Debug, Clone, Default)]
pub struct TopState {
    pub status: Option<Status>,
    pub counters: BTreeMap<String, u64>,
    /// Per-second rate of each counter over the last poll interval.
    pub rates: BTreeMap<String, f64>,
    last_sample: Option<(Duration, BTreeMap<String, u64>)>,
    pub identities: HashMap<Identity, Tally>,
    pub rules: HashMap<String, Tally>,
    pub events: VecDeque<EventRecord>,
    pub events_seen: u64,
    /// Events the daemon dropped because this client read too slowly.
    pub events_lagged: u64,
    pub error: Option<String>,
}

impl TopState {
    pub fn apply_status(&mut self, s: Status) {
        self.status = Some(s);
    }

    /// Record a `stats` sample taken at `at` (any monotonic clock). Rates are the delta to the
    /// previous sample; a counter that went backwards (daemon restart, kill-switch) rates 0.
    pub fn apply_stats(&mut self, counters: Vec<(String, u64)>, at: Duration) {
        let now: BTreeMap<String, u64> = counters.into_iter().collect();
        self.rates.clear();
        if let Some((t0, prev)) = &self.last_sample {
            let dt = at.saturating_sub(*t0).as_secs_f64();
            if dt > 0.0 {
                for (k, v) in &now {
                    let d = v.saturating_sub(prev.get(k).copied().unwrap_or(*v));
                    self.rates.insert(k.clone(), d as f64 / dt);
                }
            }
        }
        self.last_sample = Some((at, now.clone()));
        self.counters = now;
    }

    pub fn apply_event(&mut self, e: EventRecord) {
        self.events_seen += 1;
        let seq = self.events_seen;
        if is_flow(&e) {
            let drop = is_drop(&e);
            bump(&mut self.identities, Identity::of(&e), drop, seq);
            bump(&mut self.rules, rule_label(&e), drop, seq);
        }
        if self.events.len() == EVENT_RING {
            self.events.pop_front();
        }
        self.events.push_back(e);
    }

    /// Route one response line from either connection.
    pub fn apply(&mut self, r: Response, at: Duration) {
        match r {
            Response::Status(s) => self.apply_status(s),
            Response::Stats { counters } => self.apply_stats(counters, at),
            Response::Event(e) => self.apply_event(e),
            Response::Error { message } => {
                if let Some(n) = message
                    .strip_suffix(" events dropped (slow reader)")
                    .and_then(|n| n.parse::<u64>().ok())
                {
                    self.events_lagged += n;
                } else {
                    self.error = Some(message);
                }
            }
            _ => {}
        }
    }

    fn counter(&self, k: &str) -> u64 {
        self.counters.get(k).copied().unwrap_or(0)
    }

    fn rate(&self, k: &str) -> f64 {
        self.rates.get(k).copied().unwrap_or(0.0)
    }

    pub fn programs(&self) -> Vec<ProgramRow> {
        let st = self.status.as_ref();
        let attach = |name: &str| -> String {
            let Some(s) = st else { return "?".into() };
            let v: Vec<String> = match name {
                "xdp" => s.xdp.iter().map(|(i, m)| format!("{i}({m})")).collect(),
                _ => s.tc.clone(),
            };
            if v.is_empty() {
                "detached".into()
            } else {
                v.join(",")
            }
        };
        PROGRAMS
            .iter()
            .map(|(name, pass, drop)| ProgramRow {
                name,
                attach: attach(name),
                pass: pass.iter().map(|k| self.counter(k)).sum(),
                drop: drop.iter().map(|k| self.counter(k)).sum(),
                pass_rate: pass.iter().map(|k| self.rate(k)).sum(),
                drop_rate: drop.iter().map(|k| self.rate(k)).sum(),
            })
            .collect()
    }
}

fn bump<K: Eq + std::hash::Hash + Clone>(m: &mut HashMap<K, Tally>, k: K, drop: bool, seq: u64) {
    if !m.contains_key(&k)
        && m.len() >= MAX_KEYS
        && let Some(old) = m
            .iter()
            .min_by_key(|(_, t)| t.last_seq)
            .map(|(k, _)| k.clone())
    {
        m.remove(&old);
    }
    m.entry(k).or_default().add(drop, seq);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Pane {
    #[default]
    Programs,
    Identities,
    Rules,
    Events,
}

impl Pane {
    pub fn next(self) -> Self {
        match self {
            Self::Programs => Self::Identities,
            Self::Identities => Self::Rules,
            Self::Rules => Self::Events,
            Self::Events => Self::Programs,
        }
    }
    pub fn prev(self) -> Self {
        match self {
            Self::Programs => Self::Events,
            Self::Identities => Self::Programs,
            Self::Rules => Self::Identities,
            Self::Events => Self::Rules,
        }
    }
}

/// Table sort order; `s` cycles the focused pane's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Sort {
    /// Most drops first: "top denied". The default — a firewall operator looks here first.
    #[default]
    Drops,
    /// Most flows first: "top talkers".
    Flows,
    Name,
}

impl Sort {
    pub fn next(self) -> Self {
        match self {
            Self::Drops => Self::Flows,
            Self::Flows => Self::Name,
            Self::Name => Self::Drops,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::Drops => "drops",
            Self::Flows => "flows",
            Self::Name => "name",
        }
    }
}

/// Order `rows` by `sort`, ties broken by name so output is deterministic.
pub fn sorted<K: Ord + Clone>(m: &HashMap<K, Tally>, sort: Sort) -> Vec<(K, Tally)> {
    let mut v: Vec<(K, Tally)> = m.iter().map(|(k, t)| (k.clone(), *t)).collect();
    v.sort_by(|(ka, a), (kb, b)| {
        let primary = match sort {
            Sort::Drops => (b.drops, b.flows).cmp(&(a.drops, a.flows)),
            Sort::Flows => (b.flows, b.drops).cmp(&(a.flows, a.drops)),
            Sort::Name => std::cmp::Ordering::Equal,
        };
        primary.then_with(|| ka.cmp(kb))
    });
    v
}

/// View state that is not data: focus, sort orders, pause.
#[derive(Debug, Clone, Default)]
pub struct Ui {
    pub focus: Pane,
    pub sort_programs: Sort,
    pub sort_identities: Sort,
    pub sort_rules: Sort,
    pub paused: bool,
    pub interval: Duration,
}

/// What a key press asks the event loop to do.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    None,
    Quit,
    /// Pause toggled; the shell freezes / unfreezes the displayed snapshot.
    Pause,
}

impl Ui {
    pub fn key(&mut self, code: KeyCode, mods: KeyModifiers) -> Action {
        match code {
            KeyCode::Char('q') | KeyCode::Esc => return Action::Quit,
            KeyCode::Char('c') if mods.contains(KeyModifiers::CONTROL) => return Action::Quit,
            KeyCode::Char('p') | KeyCode::Char(' ') => {
                self.paused = !self.paused;
                return Action::Pause;
            }
            KeyCode::Tab => self.focus = self.focus.next(),
            KeyCode::BackTab => self.focus = self.focus.prev(),
            KeyCode::Char('s') => {
                let s = match self.focus {
                    Pane::Programs => &mut self.sort_programs,
                    Pane::Identities => &mut self.sort_identities,
                    Pane::Rules => &mut self.sort_rules,
                    Pane::Events => return Action::None, // always newest first
                };
                *s = s.next();
            }
            _ => {}
        }
        Action::None
    }
}

fn pane_block(title: String, focused: bool) -> Block<'static> {
    let b = Block::bordered().title(title);
    if focused {
        b.border_style(Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD))
    } else {
        b
    }
}

fn hdr(cells: &[&'static str]) -> Row<'static> {
    Row::new(cells.iter().copied()).style(Style::new().add_modifier(Modifier::BOLD))
}

fn uptime(s: u64) -> String {
    match s {
        s if s >= 86_400 => format!("{}d{:02}h", s / 86_400, s % 86_400 / 3600),
        s if s >= 3600 => format!("{}h{:02}m", s / 3600, s % 3600 / 60),
        s => format!("{}m{:02}s", s / 60, s % 60),
    }
}

fn header(st: &TopState, ui: &Ui) -> Vec<Line<'static>> {
    let dim = Style::new().fg(Color::DarkGray);
    let mut l1 = vec![Span::styled(
        "kavach top",
        Style::new().add_modifier(Modifier::BOLD),
    )];
    let mut l2 = Vec::new();
    match &st.status {
        Some(s) => {
            l1.push(Span::raw(format!(
                "  kavachd {}  kernel {}  up {}  │  policy serial {}  gen {}  rules {}",
                s.version,
                s.kernel,
                uptime(s.uptime_secs),
                s.serial,
                s.generation,
                s.rules
            )));
            if s.policy_expired {
                l1.push(Span::styled(
                    "  EXPIRED",
                    Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
                ));
            }
            let xdp = if s.xdp.is_empty() {
                "off".to_owned()
            } else {
                s.xdp
                    .iter()
                    .map(|(i, m)| format!("{i}({m})"))
                    .collect::<Vec<_>>()
                    .join(",")
            };
            let tc = if s.tc.is_empty() {
                "off".to_owned()
            } else {
                s.tc.join(",")
            };
            let killed = s
                .features
                .iter()
                .any(|(n, on)| n == "kill_switch_engaged" && *on);
            l2.push(Span::raw(format!(
                "attach  xdp {xdp}  tc {tc}  lsm {}",
                if s.lsm { "on" } else { "off" }
            )));
            if killed {
                l2.push(Span::styled(
                    "  KILL-SWITCH ENGAGED",
                    Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
                ));
            }
        }
        None => l1.push(Span::styled("  waiting for kavachd…", dim)),
    }
    l2.push(Span::styled(
        format!(
            "  │  cache hit {:.0}/s miss {:.0}/s  │  events {} (lost {}, lagged {})",
            st.rate("flow_cache_hit"),
            st.rate("flow_cache_miss"),
            st.events_seen,
            st.counter("events_lost"),
            st.events_lagged
        ),
        dim,
    ));
    let mut l3 = vec![Span::styled(
        format!("every {:.1}s", ui.interval.as_secs_f64()),
        dim,
    )];
    if ui.paused {
        l3.push(Span::styled(
            "  PAUSED",
            Style::new()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ));
    }
    if let Some(e) = &st.error {
        l3.push(Span::styled(
            format!("  error: {e}"),
            Style::new().fg(Color::Red),
        ));
    }
    vec![Line::from(l1), Line::from(l2), Line::from(l3)]
}

fn drop_style(n: u64) -> Style {
    if n > 0 {
        Style::new().fg(Color::Red)
    } else {
        Style::new()
    }
}

fn programs_table(st: &TopState, ui: &Ui) -> Table<'static> {
    let mut rows = st.programs();
    match ui.sort_programs {
        Sort::Drops => rows.sort_by(|a, b| b.drop_rate.total_cmp(&a.drop_rate)),
        Sort::Flows => {
            rows.sort_by(|a, b| (b.pass_rate + b.drop_rate).total_cmp(&(a.pass_rate + a.drop_rate)))
        }
        Sort::Name => rows.sort_by_key(|r| r.name),
    }
    let rows = rows.into_iter().map(|r| {
        Row::new(vec![
            Cell::from(r.name),
            Cell::from(r.attach),
            Cell::from(r.pass.to_string()),
            Cell::from(r.drop.to_string()).style(drop_style(r.drop)),
            Cell::from(format!("{:.1}", r.pass_rate)),
            Cell::from(format!("{:.1}", r.drop_rate)).style(drop_style(r.drop_rate as u64)),
        ])
    });
    Table::new(
        rows,
        [
            Constraint::Length(11),
            Constraint::Fill(1),
            Constraint::Length(12),
            Constraint::Length(12),
            Constraint::Length(10),
            Constraint::Length(10),
        ],
    )
    .header(hdr(&[
        "program", "attach", "pass", "drop", "pass/s", "drop/s",
    ]))
    .block(pane_block(
        format!(" programs [sort: {}] ", ui.sort_programs.label()),
        ui.focus == Pane::Programs,
    ))
}

fn identities_table(st: &TopState, ui: &Ui, height: u16) -> Table<'static> {
    let title = match ui.sort_identities {
        Sort::Drops => "top denied",
        Sort::Flows => "top talkers",
        Sort::Name => "identities",
    };
    let n = height.saturating_sub(3) as usize;
    let rows = sorted(&st.identities, ui.sort_identities)
        .into_iter()
        .take(n)
        .map(|(id, t)| {
            Row::new(vec![
                Cell::from(id.exe),
                Cell::from(id.uid.map_or("-".into(), |u| u.to_string())),
                Cell::from(id.cgroup.map_or("-".into(), |c| c.to_string())),
                Cell::from(t.flows.to_string()),
                Cell::from(t.drops.to_string()).style(drop_style(t.drops)),
            ])
        });
    Table::new(
        rows,
        [
            Constraint::Fill(1),
            Constraint::Length(6),
            Constraint::Length(8),
            Constraint::Length(7),
            Constraint::Length(7),
        ],
    )
    .header(hdr(&["exe", "uid", "cgroup", "flows", "drops"]))
    .block(pane_block(
        format!(" {title} [sort: {}] ", ui.sort_identities.label()),
        ui.focus == Pane::Identities,
    ))
}

fn rules_table(st: &TopState, ui: &Ui, height: u16) -> Table<'static> {
    let n = height.saturating_sub(3) as usize;
    let rows = sorted(&st.rules, ui.sort_rules)
        .into_iter()
        .take(n)
        .map(|(r, t)| {
            Row::new(vec![
                Cell::from(r),
                Cell::from(t.flows.to_string()),
                Cell::from(t.drops.to_string()).style(drop_style(t.drops)),
            ])
        });
    Table::new(
        rows,
        [
            Constraint::Fill(1),
            Constraint::Length(7),
            Constraint::Length(7),
        ],
    )
    .header(hdr(&["rule", "hits", "drops"]))
    .block(pane_block(
        format!(" rules hit [sort: {}] ", ui.sort_rules.label()),
        ui.focus == Pane::Rules,
    ))
}

fn event_line(e: &EventRecord) -> Line<'static> {
    let ts = format!("{:>10.3}", e.ts_ns as f64 / 1e9);
    let verdict = if e.verdict.is_empty() {
        "-"
    } else {
        &e.verdict
    };
    let vstyle = if is_drop(e) {
        Style::new().fg(Color::Red)
    } else {
        Style::new().fg(Color::Green)
    };
    let mut detail = format!(" {:<44}", format_flow(e));
    // XDP runs before any socket exists: no process, and the reason is already the rule label.
    if e.kind != "xdp_drop" {
        if !e.comm.is_empty() {
            detail.push_str(&format!(" {}", e.comm));
        }
        detail.push_str(&format!(" pid={} uid={}", e.pid, e.uid));
        if is_flow(e) {
            detail.push_str(&format!(" rule={}", rule_label(e)));
        }
        if !e.reason.is_empty() {
            detail.push_str(&format!(" {}", e.reason));
        }
    } else {
        detail.push_str(&format!(" rule={}", rule_label(e)));
    }
    Line::from(vec![
        Span::styled(ts, Style::new().fg(Color::DarkGray)),
        Span::raw(format!(" {:<11} ", e.kind)),
        Span::styled(format!("{verdict:<5}"), vstyle),
        Span::raw(detail),
    ])
}

fn events_pane(st: &TopState, ui: &Ui, height: u16) -> Paragraph<'static> {
    let n = height.saturating_sub(2) as usize;
    let lines: Vec<Line> = st.events.iter().rev().take(n).map(event_line).collect();
    Paragraph::new(lines).block(pane_block(
        " recent events (newest first) ".into(),
        ui.focus == Pane::Events,
    ))
}

/// Render the whole dashboard. Pure: depends only on its arguments.
pub fn draw(f: &mut Frame, st: &TopState, ui: &Ui) {
    let [head, progs, mid, evs, foot] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(6),
        Constraint::Fill(1),
        Constraint::Fill(1),
        Constraint::Length(1),
    ])
    .areas(f.area());
    let [ids, rules] =
        Layout::horizontal([Constraint::Percentage(60), Constraint::Percentage(40)]).areas(mid);
    f.render_widget(Paragraph::new(header(st, ui)), head);
    f.render_widget(programs_table(st, ui), progs);
    f.render_widget(identities_table(st, ui, ids.height), ids);
    f.render_widget(rules_table(st, ui, rules.height), rules);
    f.render_widget(events_pane(st, ui, evs.height), evs);
    f.render_widget(
        Paragraph::new("q quit  p pause  tab/shift-tab switch pane  s sort pane")
            .style(Style::new().fg(Color::DarkGray)),
        foot,
    );
}

/// Messages from the background event subscriber.
enum Msg {
    Resp(Response),
    Disconnected(String),
}

/// Subscribe to `events` forever, reconnecting if kavachd restarts.
fn subscribe(socket: PathBuf, tx: mpsc::Sender<Msg>) {
    loop {
        let err = match Conn::open(&socket).and_then(|mut c| {
            c.send(&Request::Events)?;
            loop {
                let r = c.recv()?;
                if tx.send(Msg::Resp(r)).is_err() {
                    return Ok(());
                }
            }
        }) {
            Ok(()) => return, // the UI hung up
            Err(e) => format!("event stream: {e:#}"),
        };
        if tx.send(Msg::Disconnected(err)).is_err() {
            return;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// Restores the terminal however `run` exits (`ratatui::try_init` already installs a panic hook
/// that restores before the panic message prints).
struct TermGuard;

impl Drop for TermGuard {
    fn drop(&mut self) {
        ratatui::restore();
    }
}

pub fn run(socket: &Path, interval: Duration) -> Result<()> {
    // Fail before touching the terminal if the daemon is unreachable or refuses us.
    let mut conn = Conn::open(socket)?;
    let first = conn.call(&Request::Status)?;
    let mut poll = Some(conn);
    let (tx, rx) = mpsc::channel();
    let sock = socket.to_owned();
    std::thread::spawn(move || subscribe(sock, tx));

    let mut terminal = ratatui::try_init().map_err(|e| anyhow!("initialising terminal: {e}"))?;
    let _guard = TermGuard;
    let start = Instant::now();
    let mut live = TopState::default();
    live.apply(first, Duration::ZERO);
    let mut frozen: Option<TopState> = None;
    let mut ui = Ui {
        interval,
        ..Ui::default()
    };
    let mut next_poll = Instant::now();
    loop {
        if Instant::now() >= next_poll {
            next_poll = Instant::now() + interval;
            if poll.is_none() {
                poll = Conn::open(socket).ok();
            }
            if let Some(c) = poll.as_mut() {
                let res = c
                    .call(&Request::Status)
                    .and_then(|s| Ok((s, c.call(&Request::Stats)?)));
                match res {
                    Ok((s, stats)) => {
                        live.error = None;
                        live.apply(s, start.elapsed());
                        live.apply(stats, start.elapsed());
                    }
                    Err(e) => {
                        live.error = Some(format!("{e:#}"));
                        poll = None;
                    }
                }
            } else {
                live.error = Some("kavachd unreachable; retrying".into());
            }
        }
        while let Ok(m) = rx.try_recv() {
            match m {
                Msg::Resp(r) => live.apply(r, start.elapsed()),
                Msg::Disconnected(e) => live.error = Some(e),
            }
        }
        let shown = frozen.as_ref().unwrap_or(&live);
        terminal.draw(|f| draw(f, shown, &ui))?;

        let wait = next_poll
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(200));
        if event::poll(wait)?
            && let Event::Key(k) = event::read()?
            && k.kind == KeyEventKind::Press
        {
            match ui.key(k.code, k.modifiers) {
                Action::Quit => return Ok(()),
                Action::Pause => frozen = ui.paused.then(|| live.clone()),
                Action::None => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn ev(kind: &str, verdict: &str, comm: &str, uid: u32, rule: Option<&str>) -> EventRecord {
        EventRecord {
            ts_ns: 12_345_000_000,
            kind: kind.into(),
            verdict: verdict.into(),
            proto: 6,
            src: Some("10.0.0.2".into()),
            dst: Some("1.1.1.1".into()),
            sport: 40000,
            dport: 443,
            pid: 100 + uid,
            uid,
            comm: comm.into(),
            cgroup_id: 7,
            rule_id: u32::from(rule.is_some()),
            rule: rule.map(Into::into),
            generation: 2,
            ..Default::default()
        }
    }

    fn status() -> Status {
        Status {
            version: "0.3.0".into(),
            kernel: "6.12.1".into(),
            generation: 2,
            serial: 42,
            rules: 5,
            xdp: vec![("eth0".into(), "native".into())],
            tc: vec!["eth0".into()],
            lsm: true,
            uptime_secs: 3725,
            ..Default::default()
        }
    }

    fn counters(pass: u64, drop: u64) -> Vec<(String, u64)> {
        vec![
            ("xdp_pass".into(), pass),
            ("xdp_drop_blocklist".into(), drop),
            ("xdp_drop_rate".into(), drop),
            ("egress_allow".into(), pass * 2),
            ("egress_drop".into(), drop),
        ]
    }

    /// A deterministic state: two polls 2 s apart plus a handful of events.
    fn sample() -> TopState {
        let mut st = TopState::default();
        st.apply(Response::Status(status()), Duration::ZERO);
        st.apply_stats(counters(100, 10), Duration::from_secs(10));
        st.apply_stats(counters(300, 30), Duration::from_secs(12));
        for _ in 0..3 {
            st.apply_event(ev("egress", "drop", "curl", 1000, Some("deny-exfil")));
        }
        st.apply_event(ev("egress", "allow", "nginx", 33, Some("web-out")));
        st.apply_event(ev("egress", "allow", "nginx", 33, Some("web-out")));
        st.apply_event(ev("egress", "allow", "nginx", 33, None));
        let mut x = ev("xdp_drop", "drop", "", 0, None);
        x.reason = "blocklist".into();
        x.src = Some("203.0.113.9".into());
        st.apply_event(x);
        st.apply_event(EventRecord {
            kind: "exec".into(),
            comm: "bash".into(),
            pid: 9,
            ..Default::default()
        });
        st
    }

    #[test]
    fn interval_parsing() {
        assert_eq!(parse_interval("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_interval("2s").unwrap(), Duration::from_secs(2));
        assert_eq!(parse_interval("0.5").unwrap(), Duration::from_millis(500));
        assert!(parse_interval("10ms").is_err());
        assert!(parse_interval("fast").is_err());
        assert!(parse_interval("NaN").is_err());
    }

    #[test]
    fn rates_come_from_counter_deltas() {
        let st = sample();
        let p = st.programs();
        let xdp = &p[0];
        assert_eq!((xdp.name, xdp.pass, xdp.drop), ("xdp", 300, 60));
        assert_eq!((xdp.pass_rate, xdp.drop_rate), (100.0, 20.0));
        assert_eq!(xdp.attach, "eth0(native)");
        let eg = &p[1];
        assert_eq!((eg.pass_rate, eg.drop_rate), (200.0, 10.0));
        assert_eq!(p[2].pass, 0);
    }

    #[test]
    fn counter_reset_rates_zero_not_huge() {
        let mut st = TopState::default();
        st.apply_stats(counters(1000, 0), Duration::from_secs(1));
        st.apply_stats(counters(5, 0), Duration::from_secs(2));
        assert_eq!(st.programs()[0].pass_rate, 0.0);
        assert_eq!(st.programs()[0].pass, 5);
        // First sample has no rate at all.
        let mut fresh = TopState::default();
        fresh.apply_stats(counters(1000, 0), Duration::from_secs(1));
        assert!(fresh.rates.is_empty());
    }

    #[test]
    fn events_aggregate_into_identities_and_rules() {
        let st = sample();
        assert_eq!(st.events.len(), 8);
        assert_eq!(st.events_seen, 8);
        let ids = sorted(&st.identities, Sort::Drops);
        assert_eq!(ids[0].0.exe, "curl");
        assert_eq!(ids[0].1.drops, 3);
        assert_eq!(ids[1].0.exe, "[xdp] 203.0.113.9");
        assert_eq!(ids[1].0.uid, None);
        let talkers = sorted(&st.identities, Sort::Flows);
        assert_eq!(talkers[0].0.exe, "curl"); // 3 flows, tie with nginx broken by drops
        assert_eq!(talkers[1].0.exe, "nginx");
        assert_eq!(talkers[1].1.flows, 3);
        // exec events are streamed but not aggregated.
        assert_eq!(st.identities.len(), 3);
        let rules = sorted(&st.rules, Sort::Name);
        let names: Vec<_> = rules.iter().map(|(r, _)| r.as_str()).collect();
        assert_eq!(names, ["default", "deny-exfil", "web-out", "xdp blocklist"]);
    }

    #[test]
    fn lag_notices_count_and_errors_surface() {
        let mut st = TopState::default();
        let lag = |n: u64| Response::Error {
            message: format!("{n} events dropped (slow reader)"),
        };
        st.apply(lag(5), Duration::ZERO);
        st.apply(lag(7), Duration::ZERO);
        assert_eq!(st.events_lagged, 12);
        assert!(st.error.is_none());
        st.apply(
            Response::Error {
                message: "no kernel".into(),
            },
            Duration::ZERO,
        );
        assert_eq!(st.error.as_deref(), Some("no kernel"));
    }

    #[test]
    fn rings_and_maps_are_bounded() {
        let mut st = TopState::default();
        for i in 0..(MAX_KEYS as u32 + 10) {
            st.apply_event(ev("egress", "allow", &format!("p{i}"), i, None));
        }
        assert_eq!(st.events.len(), EVENT_RING);
        assert_eq!(st.identities.len(), MAX_KEYS);
        // The oldest identities were evicted, the newest kept.
        assert!(!st.identities.keys().any(|k| k.exe == "p0"));
        assert!(st.identities.keys().any(|k| k.exe == "p4105"));
    }

    #[test]
    fn keys_drive_ui_state() {
        let mut ui = Ui::default();
        let none = KeyModifiers::NONE;
        assert_eq!(ui.key(KeyCode::Tab, none), Action::None);
        assert_eq!(ui.focus, Pane::Identities);
        ui.key(KeyCode::Char('s'), none);
        assert_eq!(ui.sort_identities, Sort::Flows);
        assert_eq!(ui.sort_rules, Sort::Drops);
        ui.key(KeyCode::BackTab, none);
        ui.key(KeyCode::BackTab, none);
        assert_eq!(ui.focus, Pane::Events);
        ui.key(KeyCode::Char('s'), none);
        assert_eq!(ui.sort_rules, Sort::Drops);
        assert_eq!(ui.key(KeyCode::Char('p'), none), Action::Pause);
        assert!(ui.paused);
        assert_eq!(ui.key(KeyCode::Char('q'), none), Action::Quit);
        assert_eq!(
            ui.key(KeyCode::Char('c'), KeyModifiers::CONTROL),
            Action::Quit
        );
    }

    fn render(st: &TopState, ui: &Ui, w: u16, h: u16) -> Terminal<TestBackend> {
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        t.draw(|f| draw(f, st, ui)).unwrap();
        t
    }

    fn screen(t: &Terminal<TestBackend>) -> String {
        let b = t.backend().buffer();
        let mut out = String::new();
        for y in 0..b.area.height {
            let mut line = String::new();
            for x in 0..b.area.width {
                line.push_str(b[(x, y)].symbol());
            }
            out.push_str(line.trim_end());
            out.push('\n');
        }
        out
    }

    const SNAPSHOT: &str = include_str!("../tests/snapshots/top.txt");

    #[test]
    fn dashboard_snapshot() {
        let ui = Ui {
            interval: Duration::from_secs(1),
            ..Ui::default()
        };
        let got = screen(&render(&sample(), &ui, 120, 32));
        if std::env::var_os("KAVACH_UPDATE_SNAPSHOTS").is_some() {
            std::fs::write(
                concat!(env!("CARGO_MANIFEST_DIR"), "/tests/snapshots/top.txt"),
                &got,
            )
            .unwrap();
            return;
        }
        assert_eq!(
            got, SNAPSHOT,
            "re-run with KAVACH_UPDATE_SNAPSHOTS=1 after reviewing:\n{got}"
        );
    }

    #[test]
    fn focus_and_pause_are_visible() {
        let mut ui = Ui {
            interval: Duration::from_secs(1),
            ..Ui::default()
        };
        ui.key(KeyCode::Tab, KeyModifiers::NONE);
        ui.key(KeyCode::Char('p'), KeyModifiers::NONE);
        let t = render(&sample(), &ui, 120, 32);
        let s = screen(&t);
        assert!(s.contains("PAUSED"));
        // The identities pane (top-left of the middle row) has the focused border colour.
        let b = t.backend().buffer();
        assert_eq!(b[(0, 9)].fg, Color::Cyan);
        assert_ne!(b[(0, 3)].fg, Color::Cyan);
    }

    #[test]
    fn renders_without_daemon_data_and_tiny_terminals() {
        let ui = Ui::default();
        let s = screen(&render(&TopState::default(), &ui, 80, 24));
        assert!(s.contains("waiting for kavachd"));
        assert!(s.contains("detached") || s.contains('?'));
        // Must not panic on degenerate sizes.
        render(&sample(), &ui, 10, 3);
        render(&sample(), &ui, 1, 1);
    }
}
