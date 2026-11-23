//! `kavachctl doctor`: check this host against Kavach's real requirements and say how to fix
//! what is missing. Reads only kernel interfaces; needs no daemon and no root (some checks are
//! more precise as root).

use std::path::Path;

pub struct Check {
    pub name: &'static str,
    pub ok: bool,
    /// Required for enforcement (false = degraded feature only).
    pub required: bool,
    pub detail: String,
    pub fix: &'static str,
}

fn kernel_release() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_default()
        .trim()
        .to_owned()
}

fn version(rel: &str) -> (u32, u32) {
    let mut it = rel
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty());
    let maj = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let min = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    (maj, min)
}

/// `[k8s]` of kavachd.toml, as far as doctor needs it.
#[derive(Debug, Default, PartialEq)]
struct K8sCfg {
    enabled: bool,
    source: String,
    files: Vec<String>,
}

fn k8s_cfg(toml_src: &str) -> K8sCfg {
    let v: toml::Table = toml_src.parse().unwrap_or_default();
    let Some(k) = v.get("k8s").and_then(|k| k.as_table()) else {
        return K8sCfg::default();
    };
    let s = |key: &str, def: &str| {
        k.get(key)
            .and_then(|v| v.as_str())
            .unwrap_or(def)
            .to_owned()
    };
    let source = s("source", "apiserver");
    const SA: &str = "/var/run/secrets/kubernetes.io/serviceaccount";
    let files = if source == "file" {
        vec![s("pods_file", "")]
    } else {
        let ca = s("ca_file", &format!("{SA}/ca.crt"));
        let token = s("token_file", &format!("{SA}/token"));
        let http_url = s(
            if source == "kubelet" {
                "kubelet_url"
            } else {
                "api_server"
            },
            "",
        );
        // A plain-http loopback proxy needs no CA.
        let mut f = if http_url.starts_with("http://") {
            vec![]
        } else {
            vec![ca]
        };
        if !token.is_empty() {
            f.push(token);
        }
        f
    };
    K8sCfg {
        enabled: k.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false),
        source,
        files,
    }
}

/// Kubepods tree roots directly (or 1-3 levels) under the cgroup root.
fn kubepods_roots(root: &Path, depth: usize) -> usize {
    let Ok(rd) = std::fs::read_dir(root) else {
        return 0;
    };
    rd.flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            let base = n.strip_suffix(".slice").unwrap_or(&n).to_owned();
            if base == "kubepods" || base.ends_with("-kubepods") {
                1
            } else if depth < 3 {
                kubepods_roots(&e.path(), depth + 1)
            } else {
                0
            }
        })
        .sum()
}

/// The k8s / SPIFFE identity check (not required: only identity rules depend on it).
fn k8s_check(cfg: &K8sCfg, cg2: bool, roots: usize, readable: &dyn Fn(&str) -> bool) -> Check {
    let name = "k8s / SPIFFE identity";
    let mk = |ok: bool, detail: String, fix: &'static str| Check {
        name,
        ok,
        required: false,
        detail,
        fix,
    };
    if !cfg.enabled {
        return if roots == 0 {
            mk(true, "off (not a Kubernetes node)".into(), "")
        } else {
            mk(
                false,
                format!("off, but {roots} kubepods cgroup tree(s) found"),
                "k8s / spiffe selectors match nothing until [k8s] enabled = true in kavachd.toml",
            )
        };
    }
    if !cg2 {
        return mk(
            false,
            "cgroup v1 / hybrid hierarchy".into(),
            "pod identity needs cgroup v2 (systemd.unified_cgroup_hierarchy=1)",
        );
    }
    let missing: Vec<&str> = cfg
        .files
        .iter()
        .filter(|f| f.is_empty() || !readable(f))
        .map(String::as_str)
        .collect();
    if !missing.is_empty() {
        return mk(
            false,
            format!("source {}: cannot read {missing:?}", cfg.source),
            "set ca_file / token_file (or pods_file) in [k8s]; in a pod, mount the service \
             account token (RBAC: pods list for apiserver, nodes/proxy get for kubelet)",
        );
    }
    mk(
        roots > 0,
        format!("source {}, {roots} kubepods tree(s)", cfg.source),
        "no kubepods cgroup tree under /sys/fs/cgroup: is the kubelet running, and is kavachd \
         in the host cgroup namespace?",
    )
}

pub fn checks() -> Vec<Check> {
    // PROC_PID_INIT_INO: the initial PID namespace's fixed inode.
    let host_pidns = std::fs::read_link("/proc/self/ns/pid")
        .is_ok_and(|l| l.to_string_lossy() == "pid:[4026531836]");
    let rel = kernel_release();
    let (maj, min) = version(&rel);
    let lsm = std::fs::read_to_string("/sys/kernel/security/lsm").unwrap_or_default();
    let lsm_readable = Path::new("/sys/kernel/security/lsm").exists();
    let bpffs = std::fs::read_to_string("/proc/mounts")
        .unwrap_or_default()
        .lines()
        .any(|l| l.split_whitespace().nth(2) == Some("bpf"));
    let cg2 = Path::new("/sys/fs/cgroup/cgroup.controllers").exists();
    let memlock = std::fs::read_to_string("/proc/self/limits")
        .unwrap_or_default()
        .lines()
        .find(|l| l.starts_with("Max locked memory"))
        .map(|l| l.split_whitespace().nth(3).unwrap_or("?").to_owned())
        .unwrap_or_else(|| "?".into());
    let systemd = Path::new("/run/systemd/system").exists();
    let k8s = k8s_check(
        &k8s_cfg(&std::fs::read_to_string("/etc/kavach/kavachd.toml").unwrap_or_default()),
        cg2,
        kubepods_roots(Path::new("/sys/fs/cgroup"), 0),
        &|f| std::fs::File::open(f).is_ok(),
    );
    vec![
        Check {
            name: "kernel >= 6.1",
            ok: (maj, min) >= (6, 1),
            required: true,
            detail: rel.clone(),
            fix: "upgrade to a 6.1 LTS or newer kernel",
        },
        Check {
            name: "BTF (CO-RE)",
            ok: Path::new("/sys/kernel/btf/vmlinux").exists(),
            required: true,
            detail: "/sys/kernel/btf/vmlinux".into(),
            fix: "use a kernel built with CONFIG_DEBUG_INFO_BTF=y (all major distros ship it)",
        },
        Check {
            name: "BPF LSM active",
            ok: lsm.split(',').any(|m| m.trim() == "bpf"),
            required: false,
            detail: if lsm_readable {
                format!("lsm={}", lsm.trim())
            } else {
                "securityfs not readable (run as root)".into()
            },
            fix: "identity egress needs it: add `lsm=<current list>,bpf` to the kernel command \
                  line (GRUB: GRUB_CMDLINE_LINUX in /etc/default/grub, then update-grub / \
                  grub-mkconfig; systemd-boot: /etc/kernel/cmdline), then reboot",
        },
        Check {
            name: "host PID namespace",
            ok: host_pidns,
            required: false,
            detail: std::fs::read_link("/proc/self/ns/pid")
                .map(|l| l.display().to_string())
                .unwrap_or_else(|_| "unknown".into()),
            fix: "identity egress needs kavachd in the host PID namespace: run it on the host, \
                  or in a container with `--pid=host`",
        },
        Check {
            name: "bpffs mounted",
            ok: bpffs,
            required: true,
            detail: "/sys/fs/bpf".into(),
            fix: "mount -t bpf bpf /sys/fs/bpf (systemd mounts it automatically)",
        },
        Check {
            name: "cgroup v2",
            ok: cg2,
            required: false,
            detail: "/sys/fs/cgroup".into(),
            fix: "cgroup selectors need the unified hierarchy (systemd.unified_cgroup_hierarchy=1)",
        },
        Check {
            name: "TC ingress (kernel >= 6.6 uses TCX)",
            ok: true,
            required: false,
            detail: if (maj, min) >= (6, 6) {
                "TCX".into()
            } else {
                "legacy clsact fallback".into()
            },
            fix: "",
        },
        Check {
            name: "locked memory",
            ok: memlock == "unlimited" || maj > 5 || (maj == 5 && min >= 11),
            required: false,
            detail: format!("{memlock} (kernels >= 5.11 account BPF memory to cgroups)"),
            fix: "LimitMEMLOCK=infinity (the shipped unit sets it)",
        },
        Check {
            name: "systemd",
            ok: systemd,
            required: false,
            detail: "/run/systemd/system".into(),
            fix: "without systemd, run kavachd under your init's supervisor (see docs/INSTALL.md)",
        },
        k8s,
    ]
}

/// Print the report; returns false if a required check failed.
pub fn run() -> bool {
    let mut all = true;
    for c in checks() {
        let mark = match (c.ok, c.required) {
            (true, _) => "ok  ",
            (false, true) => "FAIL",
            (false, false) => "warn",
        };
        println!("{mark}  {:<36} {}", c.name, c.detail);
        if !c.ok && !c.fix.is_empty() {
            println!("      fix: {}", c.fix);
        }
        all &= c.ok || !c.required;
    }
    all
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_kernel_versions() {
        assert_eq!(super::version("7.1.9-arch1-2"), (7, 1));
        assert_eq!(super::version("6.1.0-27-amd64"), (6, 1));
        assert_eq!(super::version("5.15.0"), (5, 15));
    }

    #[test]
    fn k8s_identity_check() {
        use super::*;
        let yes = |_: &str| true;
        let no = |_: &str| false;
        let off = k8s_cfg("");
        assert!(!off.enabled);
        assert!(k8s_check(&off, true, 0, &yes).ok, "non-k8s host: fine");
        assert!(!k8s_check(&off, true, 2, &yes).ok, "kubepods but agent off");

        let api = k8s_cfg("[k8s]\nenabled = true\n");
        assert_eq!(api.source, "apiserver");
        assert_eq!(api.files.len(), 2, "CA + token");
        assert!(k8s_check(&api, true, 1, &yes).ok);
        assert!(!k8s_check(&api, false, 1, &yes).ok, "cgroup v1 refused");
        let c = k8s_check(&api, true, 1, &no);
        assert!(!c.ok && c.detail.contains("ca.crt"), "{}", c.detail);
        assert!(!k8s_check(&api, true, 0, &yes).ok, "no kubepods tree");

        let proxy = k8s_cfg(
            "[k8s]\nenabled = true\nsource = \"kubelet\"\nkubelet_url = \"http://127.0.0.1:10255\"\ntoken_file = \"\"\n",
        );
        assert!(proxy.files.is_empty());
        let file = k8s_cfg("[k8s]\nenabled = true\nsource = \"file\"\n");
        assert!(
            !k8s_check(&file, true, 1, &yes).ok,
            "file source needs pods_file"
        );
    }

    #[test]
    fn runs_on_this_host() {
        let c = super::checks();
        assert!(c.iter().any(|c| c.name.starts_with("kernel")));
    }
}
