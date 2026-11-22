//! Who controls the bytes under a file? Before a hash is committed, kavachd walks the file's
//! whole block-device stack (partitions, device-mapper, md, loop, multi-device btrfs) and
//! refuses it if any layer can be rewritten by someone other than root.
//!
//! The LSM already refuses kernel-internal mounts, network/FUSE/overlay filesystems and
//! nbd/ublk devices on its own; this covers stacks the kernel side cannot trace (dm-crypt on a
//! loop image unlocked through udisks, btrfs spanning several devices, loop images in a
//! user-writable file).

use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

const BTRFS_SUPER_MAGIC: i64 = 0x9123_683E;
const MAX_DEPTH: usize = 8;

/// `Ok(())` if every layer under `f` is root-controlled.
pub fn vouch(f: &File) -> Result<()> {
    let md = f.metadata()?;
    for dev in fs_devices(f, md.dev())? {
        vouch_dev(dev, 0)?;
    }
    Ok(())
}

/// The block devices a filesystem lives on (none for tmpfs and other memory filesystems).
fn fs_devices(f: &File, st_dev: u64) -> Result<Vec<u64>> {
    if major(st_dev) != 0 {
        return Ok(vec![st_dev]);
    }
    let sfs = nix::sys::statfs::fstatfs(f)?;
    if sfs.filesystem_type().0 as i64 != BTRFS_SUPER_MAGIC {
        return Ok(vec![]); // anonymous device without a disk (tmpfs, ...)
    }
    btrfs_devices(f)
}

fn btrfs_devices(f: &File) -> Result<Vec<u64>> {
    // BTRFS_IOC_FS_INFO = _IOR(0x94, 31, struct btrfs_ioctl_fs_info_args /* 1024 bytes */)
    const BTRFS_IOC_FS_INFO: u64 = 0x8400_941F;
    let mut args = [0u8; 1024];
    // SAFETY: the ioctl writes at most 1024 bytes into `args`, which is that large; the fd is
    // a valid open file for the duration of the call.
    let r = unsafe { nix::libc::ioctl(f.as_raw_fd(), BTRFS_IOC_FS_INFO as _, args.as_mut_ptr()) };
    if r != 0 {
        bail!("BTRFS_IOC_FS_INFO: {}", std::io::Error::last_os_error());
    }
    let uuid = |b: &[u8]| {
        let h = hex::encode(b);
        format!(
            "{}-{}-{}-{}-{}",
            &h[..8],
            &h[8..12],
            &h[12..16],
            &h[16..20],
            &h[20..]
        )
    };
    // fsid at offset 16; metadata_uuid (used for the sysfs name when the feature is on) at 50.
    let candidates = [uuid(&args[16..32]), uuid(&args[50..66])];
    let dir = candidates
        .iter()
        .map(|u| PathBuf::from(format!("/sys/fs/btrfs/{u}/devices")))
        .find(|p| p.is_dir())
        .context("btrfs devices not listed in sysfs")?;
    let mut out = Vec::new();
    for e in std::fs::read_dir(&dir)? {
        let p = e?.path();
        out.push(read_dev(&p.join("dev")).with_context(|| format!("{}", p.display()))?);
    }
    if out.is_empty() {
        bail!("btrfs filesystem with no devices");
    }
    Ok(out)
}

fn vouch_dev(dev: u64, depth: usize) -> Result<()> {
    if depth > MAX_DEPTH {
        bail!("block-device stack deeper than {MAX_DEPTH}");
    }
    let sys = PathBuf::from(format!("/sys/dev/block/{}:{}", major(dev), minor(dev)));
    let real = std::fs::canonicalize(&sys).with_context(|| format!("{}", sys.display()))?;
    // A partition: judge the whole disk it belongs to.
    if real.join("partition").exists() {
        let parent = real.parent().context("partition without a disk")?;
        return vouch_dev(read_dev(&parent.join("dev"))?, depth + 1);
    }
    let name = real
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if name.starts_with("nbd") || name.starts_with("ublk") {
        bail!("{name}: device served by a user-space process");
    }
    if name.starts_with("loop") {
        vouch_loop(&name, &real, depth)?;
    }
    // device-mapper, md, ...: every lower device must hold up too.
    if let Ok(slaves) = std::fs::read_dir(real.join("slaves")) {
        for s in slaves {
            let s = s?.path();
            vouch_dev(read_dev(&s.join("dev"))?, depth + 1)?;
        }
    }
    Ok(())
}

/// A loop device is only as trustworthy as its image: root-owned, writable by root alone, and
/// itself on a trustworthy device. The image is identified by the inode the driver holds
/// (`LOOP_GET_STATUS64`), not by its (renameable) path.
fn vouch_loop(name: &str, sys: &Path, depth: usize) -> Result<()> {
    #[repr(C)]
    struct LoopInfo64 {
        lo_device: u64,
        lo_inode: u64,
        lo_rdevice: u64,
        lo_offset: u64,
        lo_sizelimit: u64,
        lo_number: u32,
        lo_encrypt_type: u32,
        lo_encrypt_key_size: u32,
        lo_flags: u32,
        lo_file_name: [u8; 64],
        lo_crypt_name: [u8; 64],
        lo_encrypt_key: [u8; 32],
        lo_init: [u64; 2],
    }
    const LOOP_GET_STATUS64: u64 = 0x4C05;

    let dev = File::open(format!("/dev/{name}")).with_context(|| format!("opening /dev/{name}"))?;
    // SAFETY: LoopInfo64 is plain old data, all-zero is a valid value.
    let mut info: LoopInfo64 = unsafe { std::mem::zeroed() };
    // SAFETY: the ioctl fills exactly one `struct loop_info64`, which `info` is (232 bytes).
    let r = unsafe {
        nix::libc::ioctl(
            dev.as_raw_fd(),
            LOOP_GET_STATUS64 as _,
            &mut info as *mut LoopInfo64,
        )
    };
    if r != 0 {
        bail!(
            "{name}: LOOP_GET_STATUS64: {}",
            std::io::Error::last_os_error()
        );
    }
    let backing = std::fs::read_to_string(sys.join("loop/backing_file"))
        .with_context(|| format!("{name}: no backing file"))?;
    let backing = backing.trim_end();
    let md = std::fs::metadata(backing)
        .with_context(|| format!("{name}: backing file {backing} is gone (deleted?)"))?;
    if md.dev() != info.lo_device || md.ino() != info.lo_inode {
        bail!("{name}: {backing} is no longer the image the loop device holds");
    }
    // (A read-only loop does not help: the image file itself can still be rewritten.)
    if md.uid() != 0 || md.permissions().mode() & 0o022 != 0 {
        bail!("{name}: image {backing} can be rewritten by a non-root user");
    }
    // …and the filesystem holding the image must hold up as well.
    let img = File::open(backing)?;
    for d in fs_devices(&img, md.dev())? {
        vouch_dev(d, depth + 1)?;
    }
    Ok(())
}

fn read_dev(p: &Path) -> Result<u64> {
    let s = std::fs::read_to_string(p)?;
    let (ma, mi) = s.trim().split_once(':').context("malformed dev file")?;
    Ok(nix::libc::makedev(ma.parse()?, mi.parse()?))
}

fn major(dev: u64) -> u32 {
    nix::libc::major(dev)
}

fn minor(dev: u64) -> u32 {
    nix::libc::minor(dev)
}
