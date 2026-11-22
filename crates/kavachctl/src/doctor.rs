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

pub fn checks() -> Vec<Check> {
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
    fn runs_on_this_host() {
        let c = super::checks();
        assert!(c.iter().any(|c| c.name.starts_with("kernel")));
    }
}
