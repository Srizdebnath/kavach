//! Pre-classification by hash (closes the first-run window for `binary = "sha256:…"` rules).
//!
//! Path-named executables are pre-classified on apply. Hash-named ones would otherwise only be
//! classified on their first exec, so a short-lived first run could finish before its hash is
//! known. The scanner hashes the executables in the standard binary directories (cached by
//! inode + size + mtime + ctime, so unchanged files are never re-hashed), queues every file whose
//! hash the active policy names as a priority `Path` job, and watches the directories with
//! inotify so upgraded or newly installed binaries are picked up as they land.
//!
//! Files elsewhere (a copy in /tmp, …) are still classified on exec; `unclassified = "deny"`
//! makes that window fail closed.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify, WatchDescriptor};
use tokio::io::unix::AsyncFd;
use tokio::sync::Notify;
use tracing::{debug, info};

use crate::daemon::{self, Daemon};
use crate::events::IdentityJob;

/// (dev, ino) → (size, mtime ns, ctime ns, sha256)
type Cache = HashMap<(u64, u64), (u64, i64, i64, [u8; 32])>;

/// Run forever: full scan on `kick` (apply / restore), single files on inotify events.
pub async fn scanner(
    state: Arc<Mutex<Daemon>>,
    dirs: Vec<PathBuf>,
    kick: Arc<Notify>,
) -> Result<()> {
    let dirs = dedupe(&dirs);
    let ino = Inotify::init(InitFlags::IN_NONBLOCK | InitFlags::IN_CLOEXEC)?;
    let mut wds: HashMap<WatchDescriptor, PathBuf> = HashMap::new();
    for d in &dirs {
        let mask =
            AddWatchFlags::IN_CLOSE_WRITE | AddWatchFlags::IN_MOVED_TO | AddWatchFlags::IN_ATTRIB;
        if let Ok(wd) = ino.add_watch(d.as_path(), mask) {
            wds.insert(wd, d.clone());
        }
    }
    // The wrapper owns the inotify fd for the AsyncFd's whole lifetime (the safety condition).
    #[allow(deprecated)]
    let fd = AsyncFd::new(InotifyFd(ino))?;
    let cache = Arc::new(Mutex::new(Cache::new()));
    loop {
        let targets: Option<Vec<PathBuf>> = tokio::select! {
            _ = kick.notified() => None, // full scan
            r = fd.readable() => {
                let mut g = r?;
                let evs = g.get_inner().0.read_events().unwrap_or_default();
                g.clear_ready();
                Some(evs.into_iter().filter_map(|e| Some(wds.get(&e.wd)?.join(e.name?))).collect())
            }
        };
        let wanted = wanted(&state);
        if wanted.is_empty() {
            continue;
        }
        let (d, c) = (dirs.clone(), cache.clone());
        let full = targets.is_none();
        let found = tokio::task::spawn_blocking(move || {
            let mut c = c.lock().unwrap_or_else(|e| e.into_inner());
            let files = targets.unwrap_or_else(|| list(&d));
            matches(&files, &wanted, &mut c)
        })
        .await?;
        if full {
            info!(matched = found.len(), "hash pre-classification scan done");
        }
        let Ok(st) = state.lock() else { continue };
        let Some(tx) = st.prewarm_tx.clone() else {
            continue;
        };
        drop(st);
        for path in found {
            debug!(path, "pre-classifying hash-named executable");
            let _ = tx.try_send(IdentityJob::Path { path });
        }
    }
}

/// Hashes named by the active policy.
fn wanted(state: &Arc<Mutex<Daemon>>) -> HashSet<[u8; 32]> {
    state
        .lock()
        .ok()
        .and_then(|s| {
            s.active().map(|p| {
                p.selectors
                    .iter()
                    .flat_map(|s| s.binaries.iter().copied())
                    .collect()
            })
        })
        .unwrap_or_default()
}

fn dedupe(dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    dirs.iter()
        .filter_map(|d| std::fs::canonicalize(d).ok())
        .filter(|d| seen.insert(d.clone()))
        .collect()
}

fn list(dirs: &[PathBuf]) -> Vec<PathBuf> {
    dirs.iter()
        .filter_map(|d| std::fs::read_dir(d).ok())
        .flatten()
        .flatten()
        .map(|e| e.path())
        .collect()
}

/// Canonical paths of the executables among `files` whose SHA-256 is in `wanted`.
pub fn matches(files: &[PathBuf], wanted: &HashSet<[u8; 32]>, cache: &mut Cache) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for f in files {
        let Ok(md) = std::fs::metadata(f) else {
            continue;
        };
        if !md.is_file() || md.permissions().mode() & 0o111 == 0 {
            continue;
        }
        let id = (md.dev(), md.ino());
        if !seen.insert(id) {
            continue; // symlinks / hard links to a file already looked at
        }
        let stamp = (
            md.size(),
            md.mtime() * 1_000_000_000 + md.mtime_nsec(),
            md.ctime() * 1_000_000_000 + md.ctime_nsec(),
        );
        let sha = match cache.get(&id) {
            Some(&(s, m, c, h)) if (s, m, c) == stamp => h,
            _ => {
                let Some(h) = hash(f) else { continue };
                cache.insert(id, (stamp.0, stamp.1, stamp.2, h));
                h
            }
        };
        if wanted.contains(&sha)
            && let Ok(p) = std::fs::canonicalize(f)
        {
            out.push(p.to_string_lossy().into_owned());
        }
    }
    out
}

fn hash(p: &Path) -> Option<[u8; 32]> {
    let mut f = File::open(p).ok()?;
    daemon::hash_file(&mut f).ok().map(|i| i.sha256)
}

struct InotifyFd(Inotify);

impl std::os::fd::AsRawFd for InotifyFd {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsFd;
        self.0.as_fd().as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_by_hash_and_caches_unchanged_files() {
        let dir = tempfile::tempdir().unwrap();
        let mk = |name: &str, body: &[u8], mode: u32| {
            let p = dir.path().join(name);
            std::fs::write(&p, body).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
            p
        };
        let a = mk("a", b"payload-a", 0o755);
        let _b = mk("b", b"payload-b", 0o755);
        let _c = mk("c", b"payload-a", 0o644); // same bytes, not executable: ignored
        let want: HashSet<[u8; 32]> = [hash(&a).unwrap()].into();
        let mut cache = Cache::new();
        let files = list(&[dir.path().to_path_buf()]);
        let got = matches(&files, &want, &mut cache);
        assert_eq!(
            got,
            vec![
                std::fs::canonicalize(&a)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            ]
        );
        assert_eq!(cache.len(), 2, "only executables are hashed");

        // A cached entry is reused while the stat stamp is unchanged…
        let key = {
            let md = std::fs::metadata(&a).unwrap();
            (md.dev(), md.ino())
        };
        cache.get_mut(&key).unwrap().3 = [0; 32];
        assert!(
            matches(&files, &want, &mut cache).is_empty(),
            "stale cache value used"
        );
        // …and refreshed once the file changes.
        std::fs::write(&a, b"payload-a").unwrap();
        assert_eq!(matches(&files, &want, &mut cache).len(), 1);
    }
}
