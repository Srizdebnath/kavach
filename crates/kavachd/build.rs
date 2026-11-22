//! Compile bpf/kavach.bpf.c with clang and embed the object in kavachd.
//! Set KAVACH_BPF_OBJ to use a prebuilt object instead (e.g. in cross builds).
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let bpf = root.join("bpf");
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("kavach.bpf.o");
    println!("cargo:rerun-if-env-changed=KAVACH_BPF_OBJ");
    for f in [
        "kavach.bpf.c",
        "xdp_filter.c",
        "tc_flow.c",
        "lsm_egress.c",
        "include/kavach_bpf.h",
        "include/kavach_eval.h",
        "include/kavach_abi.h",
    ] {
        println!("cargo:rerun-if-changed={}", bpf.join(f).display());
    }
    if let Ok(prebuilt) = std::env::var("KAVACH_BPF_OBJ") {
        std::fs::copy(prebuilt, &out).expect("copy KAVACH_BPF_OBJ");
        return;
    }
    let vmlinux = bpf.join("include/vmlinux.h");
    if !vmlinux.exists() {
        let o = Command::new("bpftool")
            .args([
                "btf",
                "dump",
                "file",
                "/sys/kernel/btf/vmlinux",
                "format",
                "c",
            ])
            .output()
            .expect("bpftool is required to generate vmlinux.h (or run `cargo xtask vmlinux`)");
        assert!(o.status.success(), "bpftool failed");
        std::fs::write(&vmlinux, o.stdout).unwrap();
    }
    let arch = match std::env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_str() {
        "x86_64" => "x86",
        "aarch64" => "arm64",
        other => panic!("unsupported target arch {other}"),
    };
    let status = Command::new(std::env::var("CLANG").unwrap_or_else(|_| "clang".into()))
        .args([
            "-O2",
            "-g",
            "-target",
            "bpf",
            "-mcpu=v3",
            "-Wall",
            "-Werror",
            "-Wno-unused-function",
            "-Wno-missing-declarations",
        ])
        .arg(format!("-D__TARGET_ARCH_{arch}"))
        .arg("-I")
        .arg(bpf.join("include"))
        .arg("-c")
        .arg(bpf.join("kavach.bpf.c"))
        .arg("-o")
        .arg(&out)
        .status()
        .expect("clang is required to build the eBPF programs");
    assert!(status.success(), "clang failed to compile bpf/kavach.bpf.c");
}
