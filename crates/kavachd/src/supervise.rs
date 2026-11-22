//! Task supervision: a crashed user-space task is restarted with backoff. Kernel enforcement
//! never depends on these tasks, so this is about keeping events, identity classification and
//! housekeeping alive, not about safety.

use std::future::Future;
use std::time::{Duration, Instant};

use anyhow::Result;
use tracing::error;

/// Initial restart delay; doubles per consecutive failure up to [`MAX_BACKOFF`].
pub const MIN_BACKOFF: Duration = Duration::from_secs(1);
/// Upper bound on the restart delay.
pub const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Run `make()` forever. If the task panics or returns `Err`, call `on_restart(name, reason)`,
/// wait out the backoff, and start a fresh instance. `Ok(())` means the task is finished.
/// The backoff resets after a run that stayed healthy for a minute.
pub fn spawn<F, Fut, R>(name: &'static str, make: F, on_restart: R) -> tokio::task::JoinHandle<()>
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: Future<Output = Result<()>> + Send + 'static,
    R: Fn(&str, &str) + Send + 'static,
{
    spawn_with(name, make, on_restart, MIN_BACKOFF)
}

fn spawn_with<F, Fut, R>(
    name: &'static str,
    mut make: F,
    on_restart: R,
    min: Duration,
) -> tokio::task::JoinHandle<()>
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: Future<Output = Result<()>> + Send + 'static,
    R: Fn(&str, &str) + Send + 'static,
{
    tokio::spawn(async move {
        let mut backoff = min;
        loop {
            let started = Instant::now();
            let why = match tokio::spawn(make()).await {
                Ok(Ok(())) => return,
                Ok(Err(e)) => format!("{e:#}"),
                Err(j) if j.is_panic() => "panicked".to_owned(),
                Err(_) => return, // cancelled at shutdown
            };
            if started.elapsed() > Duration::from_secs(60) {
                backoff = min;
            }
            error!(task = name, reason = %why, restart_in = ?backoff, "task stopped; restarting");
            on_restart(name, &why);
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    #[tokio::test]
    async fn restarts_after_panic_and_error_then_stops_on_ok() {
        let runs = Arc::new(AtomicU32::new(0));
        let restarts = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let r = runs.clone();
        let log = restarts.clone();
        let h = spawn_with(
            "t",
            move || {
                let n = r.fetch_add(1, Ordering::SeqCst);
                async move {
                    match n {
                        0 => panic!("boom"),
                        1 => anyhow::bail!("broken pipe"),
                        _ => Ok(()),
                    }
                }
            },
            move |_, why| log.lock().unwrap().push(why.to_owned()),
            Duration::from_millis(1),
        );
        tokio::time::timeout(Duration::from_secs(5), h)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(runs.load(Ordering::SeqCst), 3);
        assert_eq!(*restarts.lock().unwrap(), ["panicked", "broken pipe"]);
    }
}
