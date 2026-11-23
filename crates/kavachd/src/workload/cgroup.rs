//! Pod cgroups on cgroup v2: which cgroup ids belong to which pod.
//!
//! The kubelet puts every pod under a `kubepods` subtree, in one of two layouts:
//!
//! ```text
//! systemd driver : kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<uid_>.slice/
//!                      cri-containerd-<id>.scope | crio-<id>.scope | crio-conmon-<id>.scope
//!                      | docker-<id>.scope
//! cgroupfs driver: kubepods/burstable/pod<uid>/<id>
//! ```
//!
//! (`guaranteed` pods sit directly under the root; kind / nested setups prefix the whole tree,
//! e.g. `kubelet.slice/kubelet-kubepods.slice/...`). The systemd driver escapes the dashes of
//! the pod UID as underscores. A cgroup v2 id is the kernfs inode number of its directory,
//! which is what `bpf_get_current_cgroup_id()` returns.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

/// `CGROUP2_SUPER_MAGIC`.
const CGROUP2_SUPER_MAGIC: i64 = 0x6367_7270;

/// Refuse anything but the unified (v2) hierarchy: on v1 / hybrid hosts pods live in the v1
/// controllers, where `bpf_get_current_cgroup_id()` cannot see them.
pub fn ensure_cgroup2(root: &Path) -> Result<()> {
    let st = nix::sys::statfs::statfs(root)
        .map_err(|e| anyhow::anyhow!("statfs {}: {e}", root.display()))?;
    #[allow(clippy::unnecessary_cast)] // the field type differs between libcs
    let magic = st.filesystem_type().0 as i64;
    if magic != CGROUP2_SUPER_MAGIC {
        bail!(
            "{} is not a cgroup v2 mount (cgroup v1 / hybrid hierarchy): k8s / SPIFFE identity \
             needs the unified hierarchy (systemd.unified_cgroup_hierarchy=1, the default since \
             Kubernetes 1.25 on current distros)",
            root.display()
        );
    }
    Ok(())
}

/// The container runtime that owns a container cgroup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Runtime {
    Containerd,
    CriO,
    Docker,
    /// cgroupfs driver: a bare container id.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerRef {
    pub runtime: Runtime,
    pub id: String,
    /// CRI-O's `crio-conmon-<id>.scope` monitor process (part of the pod, not the container).
    pub conmon: bool,
}

/// What a cgroup path says about its pod.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodCgroup {
    /// Pod UID with dashes (as the API reports it).
    pub uid: String,
    /// Path of the pod-level cgroup (relative to the cgroup root, no leading `/`).
    pub pod_path: String,
    pub container: Option<ContainerRef>,
}

/// Is `name` the root of a kubepods tree (`kubepods`, `kubepods.slice`,
/// `kubelet-kubepods.slice`)? QoS slices (`kubepods-burstable.slice`) are not roots.
pub fn is_kubepods_root(name: &str) -> bool {
    let base = name.strip_suffix(".slice").unwrap_or(name);
    base == "kubepods" || base.ends_with("-kubepods")
}

fn valid_uid(u: &str) -> bool {
    (8..=64).contains(&u.len()) && u.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
}

/// The pod UID of a pod-level cgroup name, if it is one.
pub fn pod_uid_of(name: &str) -> Option<String> {
    let base = name.strip_suffix(".slice").unwrap_or(name);
    // systemd: ...-pod<uid_with_underscores>; cgroupfs: pod<uid>
    let raw = match base.rfind("-pod") {
        Some(i) if name.ends_with(".slice") => &base[i + 4..],
        _ => base.strip_prefix("pod")?,
    };
    let uid = raw.replace('_', "-");
    valid_uid(&uid).then_some(uid)
}

fn is_hex_id(s: &str) -> bool {
    (12..=128).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The container of a container-level cgroup name.
pub fn container_of(name: &str) -> Option<ContainerRef> {
    let (runtime, rest, conmon) = if let Some(scope) = name.strip_suffix(".scope") {
        if let Some(id) = scope.strip_prefix("cri-containerd-") {
            (Runtime::Containerd, id, false)
        } else if let Some(id) = scope.strip_prefix("crio-conmon-") {
            (Runtime::CriO, id, true)
        } else if let Some(id) = scope.strip_prefix("crio-") {
            (Runtime::CriO, id, false)
        } else {
            (Runtime::Docker, scope.strip_prefix("docker-")?, false)
        }
    } else {
        (Runtime::Unknown, name, false)
    };
    is_hex_id(rest).then(|| ContainerRef {
        runtime,
        id: rest.to_owned(),
        conmon,
    })
}

/// Parse a cgroup v2 path (relative to the root, or as in `/proc/<pid>/cgroup`'s `0::` line).
/// `None` when it is not inside a pod. A v1 line (`4:memory:/...`) is an error.
pub fn parse_pod_cgroup(path: &str) -> Result<Option<PodCgroup>> {
    let path = if let Some((hier, rest)) = path.split_once(':') {
        // /proc/<pid>/cgroup syntax: "<id>:<controllers>:<path>"
        let (ctrl, p) = rest.split_once(':').unwrap_or(("", rest));
        if hier != "0" || !ctrl.is_empty() {
            bail!("{path:?} is a cgroup v1 hierarchy entry; only cgroup v2 is supported");
        }
        p
    } else {
        path
    };
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    let Some(root) = parts.iter().position(|p| is_kubepods_root(p)) else {
        return Ok(None);
    };
    // The pod cgroup is at most two levels below the root (root/qos/pod or root/pod).
    for (i, p) in parts.iter().enumerate().skip(root + 1).take(2) {
        if let Some(uid) = pod_uid_of(p) {
            return Ok(Some(PodCgroup {
                uid,
                pod_path: parts[..=i].join("/"),
                container: parts.get(i + 1).and_then(|c| container_of(c)),
            }));
        }
    }
    Ok(None)
}

/// What a scan of the cgroup tree found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CgroupView {
    /// Roots of kubepods trees: (cgroup id, path).
    pub roots: Vec<(u64, String)>,
    /// Pod-level cgroups: (cgroup id, pod UID), sorted by id.
    pub pods: Vec<(u64, String)>,
}

/// How deep to look for a kubepods root (kind nests it under `kubelet.slice`, container
/// runtimes running kubelets under `system.slice/<x>.service`, ...).
const ROOT_SEARCH_DEPTH: usize = 4;

/// Walk `root` (a cgroup v2 mount) for kubepods trees and their pod cgroups.
pub fn scan(root: &Path) -> CgroupView {
    let mut v = CgroupView::default();
    find_roots(root, root, 0, &mut v);
    v.roots.sort();
    v.pods.sort();
    v.pods.dedup();
    v
}

fn subdirs(dir: &Path) -> impl Iterator<Item = (PathBuf, String)> {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|e| Some((e.path(), e.file_name().into_string().ok()?)))
}

fn rel(root: &Path, p: &Path) -> String {
    p.strip_prefix(root)
        .unwrap_or(p)
        .to_string_lossy()
        .into_owned()
}

fn ino(p: &Path) -> Option<u64> {
    std::fs::metadata(p).ok().map(|m| m.ino())
}

fn find_roots(root: &Path, dir: &Path, depth: usize, v: &mut CgroupView) {
    for (p, name) in subdirs(dir) {
        if is_kubepods_root(&name) {
            if let Some(id) = ino(&p) {
                v.roots.push((id, rel(root, &p)));
            }
            find_pods(&p, 0, v);
        } else if depth + 1 < ROOT_SEARCH_DEPTH {
            find_roots(root, &p, depth + 1, v);
        }
    }
}

fn find_pods(dir: &Path, depth: usize, v: &mut CgroupView) {
    for (p, name) in subdirs(dir) {
        if let Some(uid) = pod_uid_of(&name) {
            if let Some(id) = ino(&p) {
                v.pods.push((id, uid));
            }
        } else if depth == 0 {
            find_pods(&p, 1, v); // QoS slice
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UID: &str = "1b3c5e7a-2d4f-4a6b-8c9d-0e1f2a3b4c5d";
    const UID_: &str = "1b3c5e7a_2d4f_4a6b_8c9d_0e1f2a3b4c5d";
    const CID: &str = "4f1d0c6a2b3e5f7081928a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f";

    fn pod(path: &str) -> PodCgroup {
        parse_pod_cgroup(path)
            .unwrap()
            .unwrap_or_else(|| panic!("{path} is a pod cgroup"))
    }

    #[test]
    fn systemd_driver_containerd() {
        let p = pod(&format!(
            "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod{UID_}.slice/cri-containerd-{CID}.scope"
        ));
        assert_eq!(p.uid, UID);
        assert_eq!(
            p.pod_path,
            format!("kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod{UID_}.slice")
        );
        let c = p.container.unwrap();
        assert_eq!(
            (c.runtime, c.id.as_str(), c.conmon),
            (Runtime::Containerd, CID, false)
        );
    }

    #[test]
    fn systemd_driver_crio_docker_and_guaranteed_qos() {
        let p = pod(&format!(
            "kubepods.slice/kubepods-pod{UID_}.slice/crio-{CID}.scope"
        ));
        assert_eq!(p.uid, UID);
        assert_eq!(p.container.unwrap().runtime, Runtime::CriO);
        let p = pod(&format!(
            "kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod{UID_}.slice/crio-conmon-{CID}.scope"
        ));
        assert!(p.container.unwrap().conmon);
        let p = pod(&format!(
            "kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod{UID_}.slice/docker-{CID}.scope"
        ));
        assert_eq!(p.container.unwrap().runtime, Runtime::Docker);
    }

    #[test]
    fn cgroupfs_driver_and_pod_level_paths() {
        let p = pod(&format!("/kubepods/burstable/pod{UID}/{CID}"));
        assert_eq!(p.uid, UID);
        assert_eq!(p.pod_path, format!("kubepods/burstable/pod{UID}"));
        assert_eq!(p.container.unwrap().runtime, Runtime::Unknown);
        let p = pod(&format!("/kubepods/pod{UID}"));
        assert!(p.container.is_none());
        // static pods have md5-style UIDs without dashes
        let p = pod("/kubepods/besteffort/podd41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(p.uid, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn nested_kind_and_proc_cgroup_syntax() {
        let p = pod(&format!(
            "0::/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod{UID_}.slice/cri-containerd-{CID}.scope"
        ));
        assert_eq!(p.uid, UID);
        assert!(
            p.pod_path
                .starts_with("kubelet.slice/kubelet-kubepods.slice/")
        );
        assert_eq!(p.container.unwrap().id, CID);
    }

    #[test]
    fn non_pod_paths() {
        for p in [
            "/",
            "/system.slice/sshd.service",
            "/user.slice/user-1000.slice/session-2.scope",
            "/kubepods.slice",
            "/kubepods.slice/kubepods-burstable.slice",
            "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podnothex.slice",
            "/system.slice/kubepods-pod1234.slice", // not under a kubepods root
            "/kubepods/burstable/x/pod1b3c5e7a-2d4f-4a6b-8c9d-0e1f2a3b4c5d", // too deep
        ] {
            assert_eq!(parse_pod_cgroup(p).unwrap(), None, "{p}");
        }
        assert!(container_of("init.scope").is_none());
        assert!(container_of("cri-containerd-xyz.scope").is_none());
    }

    #[test]
    fn cgroup_v1_is_refused() {
        let e =
            parse_pod_cgroup(&format!("4:memory:/kubepods/burstable/pod{UID}/{CID}")).unwrap_err();
        assert!(e.to_string().contains("v1"), "{e}");
        assert!(parse_pod_cgroup("1:name=systemd:/kubepods").is_err());
        // a directory that is not a cgroup2 mount
        let t = tempfile::tempdir().unwrap();
        let e = ensure_cgroup2(t.path()).unwrap_err();
        assert!(e.to_string().contains("cgroup v1"), "{e}");
    }

    #[test]
    fn this_host_is_cgroup2() {
        // Every supported host (and CI runner) has the unified hierarchy.
        if Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
            ensure_cgroup2(Path::new("/sys/fs/cgroup")).unwrap();
        }
    }

    #[test]
    fn scan_finds_roots_and_pods_in_both_layouts() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        let mk = |p: &str| std::fs::create_dir_all(r.join(p)).unwrap();
        mk(&format!(
            "kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod{UID_}.slice/cri-containerd-{CID}.scope"
        ));
        mk("kubepods.slice/kubepods-podaaaaaaaa_bbbb_cccc_dddd_eeeeeeeeeeee.slice");
        mk(
            "kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-podffffffff_0000_1111_2222_333333333333.slice",
        );
        mk("system.slice/sshd.service");
        mk("other/deep/deeper/deepest/kubepods"); // below the search depth
        let v = scan(r);
        let roots: Vec<&str> = v.roots.iter().map(|(_, p)| p.as_str()).collect();
        assert_eq!(roots.len(), 2, "{roots:?}");
        assert!(roots.contains(&"kubepods.slice"));
        assert!(roots.contains(&"kubelet.slice/kubelet-kubepods.slice"));
        let mut uids: Vec<&str> = v.pods.iter().map(|(_, u)| u.as_str()).collect();
        uids.sort();
        assert_eq!(
            uids,
            [
                UID,
                "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "ffffffff-0000-1111-2222-333333333333"
            ]
        );
        // ids are the directories' inode numbers
        let pod_dir = r.join(format!(
            "kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod{UID_}.slice"
        ));
        let id = std::fs::metadata(pod_dir).unwrap().ino();
        assert!(v.pods.contains(&(id, UID.to_owned())));
    }
}
