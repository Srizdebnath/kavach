//! Per-agent rate and spend budgets (FR-GW-3).
//!
//! Calls are counted in a sliding 60-second window and spend is accumulated per UTC day in
//! integer micro-USD (never floats, so repeated charges cannot drift). The clock is injectable
//! so tests can advance a window or day without sleeping.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::AgentPolicy;

/// Wall-clock seconds, injectable for tests.
pub trait BudgetClock: Send + Sync + fmt::Debug {
    /// Current unix time in seconds.
    fn unix_secs(&self) -> u64;
}

/// Production clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl BudgetClock for SystemClock {
    fn unix_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// A test clock; each advance is explicit.
#[derive(Debug, Clone, Default)]
pub struct ManualClock(Arc<Mutex<u64>>);

impl ManualClock {
    /// A clock starting at `unix_secs`.
    pub fn new(unix_secs: u64) -> Self {
        Self(Arc::new(Mutex::new(unix_secs)))
    }

    /// Set the current time.
    pub fn set(&self, unix_secs: u64) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = unix_secs;
    }

    /// Move the current time forward.
    pub fn advance(&self, secs: u64) {
        let mut t = self.0.lock().unwrap_or_else(|e| e.into_inner());
        *t = t.saturating_add(secs);
    }
}

impl BudgetClock for ManualClock {
    fn unix_secs(&self) -> u64 {
        *self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Shared budget counters, owned by the gateway's `Shared` state.
#[derive(Debug)]
pub struct Budgets {
    calls: Mutex<HashMap<String, Vec<u64>>>,
    spend: Mutex<HashMap<(String, u64), u64>>,
    clock: Arc<dyn BudgetClock>,
}

impl Default for Budgets {
    fn default() -> Self {
        Self::new(Arc::new(SystemClock))
    }
}

impl Budgets {
    /// Counters using `clock`.
    pub fn new(clock: Arc<dyn BudgetClock>) -> Self {
        Self {
            calls: Mutex::new(HashMap::new()),
            spend: Mutex::new(HashMap::new()),
            clock,
        }
    }

    /// Charge one tool call to `agent`, or refuse it when a limit would be exceeded.
    /// Nothing is charged on a refusal.
    pub fn charge(&self, agent: &str, policy: &AgentPolicy) -> bool {
        if policy.calls_per_min.is_none() && policy.usd_per_day_micros.is_none() {
            return true;
        }
        let now = self.clock.unix_secs();
        let day = now / 86_400;
        let price = policy.usd_per_call_micros;

        // Check both limits before committing either, so a refused call is not charged.
        if let Some(limit) = policy.usd_per_day_micros {
            let spend = self.spend.lock().unwrap_or_else(|e| e.into_inner());
            let charged = spend.get(&(agent.to_owned(), day)).copied().unwrap_or(0);
            if charged.saturating_add(price) > limit {
                return false;
            }
        }
        {
            let mut calls = self.calls.lock().unwrap_or_else(|e| e.into_inner());
            let window = calls.entry(agent.to_owned()).or_default();
            window.retain(|t| now.saturating_sub(*t) < 60);
            if policy
                .calls_per_min
                .is_some_and(|limit| window.len() >= limit as usize)
            {
                return false;
            }
            window.push(now);
        }
        let mut spend = self.spend.lock().unwrap_or_else(|e| e.into_inner());
        let entry = spend.entry((agent.to_owned(), day)).or_default();
        *entry = entry.saturating_add(price);
        true
    }

    /// Calls charged to `agent` in the current 60-second window (tests, metrics).
    pub fn calls_in_window(&self, agent: &str) -> usize {
        let now = self.clock.unix_secs();
        let mut calls = self.calls.lock().unwrap_or_else(|e| e.into_inner());
        let window = calls.entry(agent.to_owned()).or_default();
        window.retain(|t| now.saturating_sub(*t) < 60);
        window.len()
    }

    /// Micro-USD charged to `agent` today (tests, metrics).
    pub fn spend_micros_today(&self, agent: &str) -> u64 {
        let day = self.clock.unix_secs() / 86_400;
        self.spend
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&(agent.to_owned(), day))
            .copied()
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sliding_window_and_daily_spend() {
        let clock = ManualClock::new(10_000);
        let budgets = Budgets::new(Arc::new(clock.clone()));
        let p = AgentPolicy {
            calls_per_min: Some(2),
            usd_per_day_micros: Some(3_000),
            usd_per_call_micros: 1_000,
            ..Default::default()
        };
        assert!(budgets.charge("bot", &p));
        assert!(budgets.charge("bot", &p));
        assert_eq!(budgets.calls_in_window("bot"), 2);
        assert_eq!(budgets.spend_micros_today("bot"), 2_000);
        // Third call would exceed both the minute and day limits: nothing is charged.
        assert!(!budgets.charge("bot", &p));
        assert_eq!(budgets.spend_micros_today("bot"), 2_000);
        // The minute window resets; the UTC day does not.
        clock.advance(61);
        assert!(budgets.charge("bot", &p));
        assert_eq!(budgets.calls_in_window("bot"), 1);
        assert_eq!(budgets.spend_micros_today("bot"), 3_000);
        assert!(!budgets.charge("bot", &p));
        // Next day resets the spend accumulator.
        clock.advance(86_400);
        assert!(budgets.charge("bot", &p));
        assert_eq!(budgets.spend_micros_today("bot"), 1_000);
    }
}
