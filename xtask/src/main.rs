//! Developer automation: `cargo xtask <cmd>`.
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(about = "Kavach build automation")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate bpf/include/kavach_abi.h from kavach-common (cbindgen).
    Codegen {
        /// Fail if the generated header differs from the committed one.
        #[arg(long)]
        check: bool,
    },
    /// Dump bpf/include/vmlinux.h from the running kernel's BTF.
    Vmlinux,
    /// Compile bpf/kavach.bpf.c to target/bpf/kavach.bpf.o.
    BuildBpf,
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Codegen { check } => codegen(check),
        Cmd::Vmlinux => vmlinux(),
        Cmd::BuildBpf => build_bpf(),
    }
}

/// Render the ABI header as a string.
fn render_header() -> Result<String> {
    let root = root();
    let cfg = cbindgen::Config::from_file(root.join("cbindgen.toml"))
        .map_err(|e| anyhow::anyhow!("cbindgen.toml: {e}"))?;
    let mut out = Vec::new();
    cbindgen::Builder::new()
        .with_config(cfg)
        .with_src(root.join("crates/kavach-common/src/abi.rs"))
        .generate()
        .context("cbindgen failed")?
        .write(&mut out);
    let mut h = String::from_utf8(out)?;
    // Use kernel fixed-width types so the header works with vmlinux.h and <linux/types.h>.
    for (from, to) in [
        ("uint64_t", "__u64"),
        ("uint32_t", "__u32"),
        ("uint16_t", "__u16"),
        ("uint8_t", "__u8"),
    ] {
        h = h.replace(from, to);
    }
    // Mirror the Rust layout assertions on the C side.
    let mut asserts =
        String::from("\n/* Layout must match crates/kavach-common (checked at compile time). */\n");
    for (name, size) in kavach_common::abi::LAYOUT {
        asserts.push_str(&format!(
            "_Static_assert(sizeof(struct {name}) == {size}, \"ABI drift: {name}\");\n"
        ));
    }
    asserts.push_str(
        "_Static_assert(__builtin_offsetof(struct kv_flow_key, src) == 8, \"ABI drift\");\n\
         _Static_assert(__builtin_offsetof(struct kv_event, key) == 16, \"ABI drift\");\n\
         _Static_assert(__builtin_offsetof(struct kv_event, comm) == 88, \"ABI drift\");\n",
    );
    let guard_end = h.rfind("#endif").context("no include guard end")?;
    h.insert_str(guard_end, &asserts);
    Ok(h)
}

fn codegen(check: bool) -> Result<()> {
    let path = root().join("bpf/include/kavach_abi.h");
    let new = render_header()?;
    if check {
        let old = std::fs::read_to_string(&path).unwrap_or_default();
        if old != new {
            bail!("{} is stale: run `cargo xtask codegen`", path.display());
        }
        println!("kavach_abi.h is up to date");
        return Ok(());
    }
    std::fs::write(&path, new)?;
    println!("wrote {}", path.display());
    Ok(())
}

fn vmlinux() -> Result<()> {
    let path = root().join("bpf/include/vmlinux.h");
    let out = Command::new("bpftool")
        .args([
            "btf",
            "dump",
            "file",
            "/sys/kernel/btf/vmlinux",
            "format",
            "c",
        ])
        .output()
        .context("running bpftool (install `bpf`/`bpftool`)")?;
    if !out.status.success() {
        bail!("bpftool failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    std::fs::write(&path, out.stdout)?;
    println!("wrote {}", path.display());
    Ok(())
}

fn build_bpf() -> Result<()> {
    let root = root();
    if !root.join("bpf/include/vmlinux.h").exists() {
        vmlinux()?;
    }
    let out_dir = root.join("target/bpf");
    std::fs::create_dir_all(&out_dir)?;
    for entry in std::fs::read_dir(root.join("bpf"))? {
        let p = entry?.path();
        // Only the unity translation unit is compiled; it #includes the program sources.
        if p.file_name().is_some_and(|n| n == "kavach.bpf.c") {
            let obj = out_dir.join("kavach.bpf.o");
            let status = Command::new("clang")
                .args(bpf_cflags())
                .arg("-I")
                .arg(root.join("bpf/include"))
                .arg("-c")
                .arg(&p)
                .arg("-o")
                .arg(&obj)
                .status()
                .context("running clang")?;
            if !status.success() {
                bail!("clang failed on {}", p.display());
            }
            println!("built {}", obj.display());
        }
    }
    Ok(())
}

/// Flags shared with crates/kavachd/build.rs.
fn bpf_cflags() -> Vec<String> {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x86",
        "aarch64" => "arm64",
        other => other,
    };
    [
        "-O2",
        "-g",
        "-target",
        "bpf",
        "-mcpu=v3",
        "-Wall",
        "-Werror",
        "-Wno-unused-function",
        "-Wno-missing-declarations",
        &format!("-D__TARGET_ARCH_{arch}"),
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}
