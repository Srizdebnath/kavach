//! Raw AF_XDP system interface (`<linux/if_xdp.h>`), behind the [`Sys`] trait so the setup and
//! mode-negotiation logic can be tested with a mock. Together with [`super::ring`] this is the
//! only code in the crate that uses `unsafe`; every block states why it is sound.
#![allow(unsafe_code)]

use std::io;
use std::os::fd::RawFd;
use std::ptr::NonNull;
use std::sync::Arc;

/// `AF_XDP` address family.
pub const AF_XDP: i32 = 44;
/// `SOL_XDP` socket option level.
pub const SOL_XDP: i32 = 283;
/// `getsockopt`: ring mmap offsets ([`MmapOffsets`]).
pub const XDP_MMAP_OFFSETS: i32 = 1;
/// `setsockopt`: RX ring size.
pub const XDP_RX_RING: i32 = 2;
/// `setsockopt`: TX ring size.
pub const XDP_TX_RING: i32 = 3;
/// `setsockopt`: register the UMEM ([`UmemReg`]).
pub const XDP_UMEM_REG: i32 = 4;
/// `setsockopt`: fill ring size.
pub const XDP_UMEM_FILL_RING: i32 = 5;
/// `setsockopt`: completion ring size.
pub const XDP_UMEM_COMPLETION_RING: i32 = 6;
/// `getsockopt`: [`XdpStatistics`].
pub const XDP_STATISTICS: i32 = 7;
/// `getsockopt`: `struct xdp_options` (`u32` flags).
pub const XDP_OPTIONS: i32 = 8;

/// `sxdp_flags`: force copy mode.
pub const XDP_COPY: u16 = 1 << 1;
/// `sxdp_flags`: force zero-copy mode (fails if the driver cannot do it).
pub const XDP_ZEROCOPY: u16 = 1 << 2;
/// `sxdp_flags`: the kernel sets [`XDP_RING_NEED_WAKEUP`] instead of polling the rings.
pub const XDP_USE_NEED_WAKEUP: u16 = 1 << 3;

/// Ring `flags` bit: user space must kick the kernel (`recvfrom`/`sendto`/`poll`).
pub const XDP_RING_NEED_WAKEUP: u32 = 1;
/// `xdp_options.flags` bit: the socket is bound in zero-copy mode.
pub const XDP_OPTIONS_ZEROCOPY: u32 = 1;

/// mmap page offset of the RX ring.
pub const XDP_PGOFF_RX_RING: u64 = 0;
/// mmap page offset of the TX ring.
pub const XDP_PGOFF_TX_RING: u64 = 0x8000_0000;
/// mmap page offset of the fill ring.
pub const XDP_UMEM_PGOFF_FILL_RING: u64 = 0x1_0000_0000;
/// mmap page offset of the completion ring.
pub const XDP_UMEM_PGOFF_COMPLETION_RING: u64 = 0x1_8000_0000;

/// `struct xdp_ring_offset`: byte offsets of one ring's fields inside its mapping.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RingOffset {
    /// Producer index (`u32`).
    pub producer: u64,
    /// Consumer index (`u32`).
    pub consumer: u64,
    /// First descriptor.
    pub desc: u64,
    /// Ring flags (`u32`, [`XDP_RING_NEED_WAKEUP`]).
    pub flags: u64,
}

/// `struct xdp_mmap_offsets`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MmapOffsets {
    /// RX ring.
    pub rx: RingOffset,
    /// TX ring.
    pub tx: RingOffset,
    /// Fill ring.
    pub fr: RingOffset,
    /// Completion ring.
    pub cr: RingOffset,
}

/// `struct xdp_umem_reg` (32 bytes; `tx_metadata_len` is padding before 6.8).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UmemReg {
    /// Start of the UMEM area (page aligned).
    pub addr: u64,
    /// Length in bytes.
    pub len: u64,
    /// Frame (chunk) size.
    pub chunk_size: u32,
    /// Headroom the kernel leaves in front of each frame.
    pub headroom: u32,
    /// `XDP_UMEM_*` flags (none used).
    pub flags: u32,
    /// TX metadata length (unused).
    pub tx_metadata_len: u32,
}

/// `struct sockaddr_xdp`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SockaddrXdp {
    /// Always [`AF_XDP`].
    pub family: u16,
    /// `XDP_*` bind flags.
    pub flags: u16,
    /// Interface index.
    pub ifindex: u32,
    /// RX/TX queue id.
    pub queue_id: u32,
    /// UMEM owner fd with [`XDP_SHARED_UMEM`].
    pub shared_umem_fd: u32,
}

/// `struct xdp_desc`: one RX/TX descriptor.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct XdpDesc {
    /// Offset of the packet inside the UMEM.
    pub addr: u64,
    /// Packet length.
    pub len: u32,
    /// Options (unused).
    pub options: u32,
}

/// `struct xdp_statistics`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct XdpStatistics {
    /// Dropped for reasons other than invalid descriptors.
    pub rx_dropped: u64,
    /// Dropped because of invalid descriptors.
    pub rx_invalid_descs: u64,
    /// Invalid TX descriptors.
    pub tx_invalid_descs: u64,
    /// Dropped because the RX ring was full.
    pub rx_ring_full: u64,
    /// The fill ring was empty when a frame arrived.
    pub rx_fill_ring_empty_descs: u64,
    /// The TX ring was empty when the kernel wanted to send.
    pub tx_ring_empty_descs: u64,
}

const _: () = assert!(std::mem::size_of::<RingOffset>() == 32);
const _: () = assert!(std::mem::size_of::<MmapOffsets>() == 128);
const _: () = assert!(std::mem::size_of::<UmemReg>() == 32);
const _: () = assert!(std::mem::size_of::<SockaddrXdp>() == 16);
const _: () = assert!(std::mem::size_of::<XdpDesc>() == 16);
const _: () = assert!(std::mem::size_of::<XdpStatistics>() == 48);

/// A block of memory shared with the kernel: a ring mapping, the UMEM, or (in tests) a
/// zeroed heap block. Freed when dropped.
#[derive(Debug)]
pub struct Region {
    ptr: NonNull<u8>,
    len: usize,
    heap_words: Option<usize>,
}

// SAFETY: a Region is plain memory with no thread affinity; all concurrent access goes through
// atomics (ring indices) or is partitioned by ring ownership (descriptors, frames).
unsafe impl Send for Region {}
// SAFETY: as above; `&Region` only hands out raw pointers and bounds-checked copies.
unsafe impl Sync for Region {}

impl Region {
    /// A zeroed, 8-byte aligned heap block (for mocks and tests).
    pub fn heap(len: usize) -> Self {
        let words = len.div_ceil(8).max(1);
        let b: Box<[u64]> = vec![0u64; words].into_boxed_slice();
        let ptr = NonNull::new(Box::into_raw(b) as *mut u8).expect("Box is non-null");
        Self {
            ptr,
            len,
            heap_words: Some(words),
        }
    }

    /// Adopt an `mmap` result.
    ///
    /// # Safety
    /// `ptr` must come from a successful `mmap` of exactly `len` bytes that nothing else unmaps.
    unsafe fn from_mmap(ptr: NonNull<u8>, len: usize) -> Self {
        Self {
            ptr,
            len,
            heap_words: None,
        }
    }

    /// Start of the block.
    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// True for a zero-length block.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Copy `data` to `off` (test kernel simulation).
    #[cfg(test)]
    pub(crate) fn write_at(&self, off: usize, data: &[u8]) {
        assert!(off + data.len() <= self.len);
        // SAFETY: bounds checked above; tests only write frames the user side does not hold.
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), self.ptr.as_ptr().add(off), data.len())
        }
    }

    /// Copy `len` bytes from `off` (test kernel simulation).
    #[cfg(test)]
    pub(crate) fn read_at(&self, off: usize, len: usize) -> Vec<u8> {
        assert!(off + len <= self.len);
        let mut v = vec![0; len];
        // SAFETY: bounds checked above.
        unsafe { std::ptr::copy_nonoverlapping(self.ptr.as_ptr().add(off), v.as_mut_ptr(), len) }
        v
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        match self.heap_words {
            Some(words) => {
                let slice =
                    std::ptr::slice_from_raw_parts_mut(self.ptr.as_ptr() as *mut u64, words);
                // SAFETY: `ptr` came from `Box::<[u64]>::into_raw` with this length in `heap`.
                drop(unsafe { Box::from_raw(slice) });
            }
            None => {
                // SAFETY: `from_mmap`'s contract: a mapping of `len` bytes owned by this Region.
                unsafe { libc::munmap(self.ptr.as_ptr().cast(), self.len) };
            }
        }
    }
}

/// The UMEM: `n_frames` frames of `frame_size` bytes shared with the kernel. Frame ownership
/// moves between user space and the kernel through the rings; this type only hands out frames
/// user space currently owns, and `&mut self` rules out a second Rust alias.
#[derive(Debug)]
pub struct Umem {
    region: Arc<Region>,
    frame_size: u32,
    n_frames: u32,
}

impl Umem {
    /// Wrap `region`, which must hold at least `n_frames * frame_size` bytes.
    pub fn new(region: Arc<Region>, frame_size: u32, n_frames: u32) -> io::Result<Self> {
        if !frame_size.is_power_of_two()
            || (frame_size as u64 * n_frames as u64) > region.len() as u64
        {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        Ok(Self {
            region,
            frame_size,
            n_frames,
        })
    }

    /// Start address (for `XDP_UMEM_REG`).
    pub fn addr(&self) -> u64 {
        self.region.as_ptr() as u64
    }

    /// Registered length in bytes.
    pub fn len(&self) -> u64 {
        self.frame_size as u64 * self.n_frames as u64
    }

    /// True if there are no frames.
    pub fn is_empty(&self) -> bool {
        self.n_frames == 0
    }

    /// Frame size.
    pub fn frame_size(&self) -> u32 {
        self.frame_size
    }

    /// Number of frames.
    pub fn n_frames(&self) -> u32 {
        self.n_frames
    }

    /// Start of the frame containing UMEM offset `addr` (aligned chunk mode).
    pub fn frame_base(&self, addr: u64) -> u64 {
        addr & !(self.frame_size as u64 - 1)
    }

    /// The `len` bytes at `addr`, if they lie inside one frame of the UMEM. The caller must own
    /// that frame under the ring protocol (it came off RX, or it is not posted to the kernel).
    pub fn frame_mut(&mut self, addr: u64, len: u32) -> Option<&mut [u8]> {
        let end = addr.checked_add(len as u64)?;
        if end > self.len() || (len > 0 && self.frame_base(addr) != self.frame_base(end - 1)) {
            return None;
        }
        // SAFETY: [addr, end) is inside the live region (checked against `len()`, which
        // `new` checked against the region size); the frame is owned by user space per the
        // caller contract, so the kernel does not write it concurrently, and `&mut self`
        // excludes any other Rust reference for the lifetime of the borrow.
        Some(unsafe {
            std::slice::from_raw_parts_mut(self.region.as_ptr().add(addr as usize), len as usize)
        })
    }

    /// The backing region (test kernel simulation).
    #[cfg(test)]
    pub(crate) fn region(&self) -> &Arc<Region> {
        &self.region
    }
}

/// Every system call the AF_XDP backend makes. [`LinuxSys`] is the real implementation; tests
/// substitute a mock to exercise setup, mode negotiation and ring handling without a kernel.
pub trait Sys: Send + Sync + 'static {
    /// `socket(AF_XDP, SOCK_RAW | SOCK_CLOEXEC, 0)`.
    fn socket(&self) -> io::Result<RawFd>;
    /// `close(fd)`.
    fn close(&self, fd: RawFd);
    /// `setsockopt(XDP_UMEM_REG)`.
    fn set_umem_reg(&self, fd: RawFd, reg: &UmemReg) -> io::Result<()>;
    /// `setsockopt(opt)` with a ring size (`XDP_*_RING`).
    fn set_ring_size(&self, fd: RawFd, opt: i32, entries: u32) -> io::Result<()>;
    /// `getsockopt(XDP_MMAP_OFFSETS)`.
    fn mmap_offsets(&self, fd: RawFd) -> io::Result<MmapOffsets>;
    /// `mmap` one ring of the socket.
    fn map_ring(&self, fd: RawFd, pgoff: u64, len: usize) -> io::Result<Arc<Region>>;
    /// Allocate the (page-aligned, zeroed) UMEM area.
    fn alloc_umem(&self, len: usize) -> io::Result<Arc<Region>>;
    /// `bind(fd, sockaddr_xdp)`.
    fn bind(&self, fd: RawFd, addr: &SockaddrXdp) -> io::Result<()>;
    /// `getsockopt(XDP_OPTIONS)` flags.
    fn options(&self, fd: RawFd) -> io::Result<u32>;
    /// `getsockopt(XDP_STATISTICS)`.
    fn statistics(&self, fd: RawFd) -> io::Result<XdpStatistics>;
    /// Kick RX processing after refilling (`recvfrom(MSG_DONTWAIT)`).
    fn wake_rx(&self, fd: RawFd) -> io::Result<()>;
    /// Kick TX processing (`sendto(MSG_DONTWAIT)`).
    fn kick_tx(&self, fd: RawFd) -> io::Result<()>;
    /// Wait up to `timeout_ms` for RX; `Ok(true)` if readable.
    fn poll_in(&self, fd: RawFd, timeout_ms: i32) -> io::Result<bool>;
    /// `if_nametoindex`.
    fn ifindex(&self, name: &str) -> io::Result<u32>;
    /// `CLOCK_BOOTTIME` in ns: the clock of the BPF `xsk_alive` deadlines.
    fn now_boot_ns(&self) -> u64;
}

/// The real Linux system interface.
#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxSys;

fn cvt(r: libc::c_int) -> io::Result<libc::c_int> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

fn setsockopt<T>(fd: RawFd, opt: i32, v: &T) -> io::Result<()> {
    // SAFETY: `v` points to a live, initialised T of exactly the size passed.
    cvt(unsafe {
        libc::setsockopt(
            fd,
            SOL_XDP,
            opt,
            (v as *const T).cast(),
            std::mem::size_of::<T>() as libc::socklen_t,
        )
    })
    .map(drop)
}

/// `getsockopt` into a zeroed `T`; the kernel may write fewer bytes (older layouts).
fn getsockopt<T: Default>(fd: RawFd, opt: i32) -> io::Result<T> {
    let mut v = T::default();
    let mut len = std::mem::size_of::<T>() as libc::socklen_t;
    // SAFETY: `v` is a writable T and `len` its size; the kernel writes at most `len` bytes.
    cvt(unsafe { libc::getsockopt(fd, SOL_XDP, opt, (&mut v as *mut T).cast(), &mut len) })?;
    Ok(v)
}

fn mmap(fd: RawFd, len: usize, pgoff: u64, flags: libc::c_int) -> io::Result<Arc<Region>> {
    let off =
        libc::off_t::try_from(pgoff).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: a fresh mapping at a kernel-chosen address; no existing memory is affected.
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            flags,
            fd,
            off,
        )
    };
    if p == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    let p = NonNull::new(p.cast::<u8>()).ok_or_else(|| io::Error::from(io::ErrorKind::Other))?;
    // SAFETY: `p` is the result of the successful mmap of `len` bytes above.
    Ok(Arc::new(unsafe { Region::from_mmap(p, len) }))
}

/// Errors from a kick that just mean "nothing to do right now".
fn benign_kick(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::EAGAIN | libc::EBUSY | libc::ENOBUFS | libc::ENETDOWN | libc::EINTR)
    )
}

impl Sys for LinuxSys {
    fn socket(&self) -> io::Result<RawFd> {
        // SAFETY: plain syscall with constant arguments.
        cvt(unsafe { libc::socket(AF_XDP, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) })
    }

    fn close(&self, fd: RawFd) {
        // SAFETY: the backend closes each fd it opened exactly once (see `socket::Fd`).
        unsafe { libc::close(fd) };
    }

    fn set_umem_reg(&self, fd: RawFd, reg: &UmemReg) -> io::Result<()> {
        setsockopt(fd, XDP_UMEM_REG, reg)
    }

    fn set_ring_size(&self, fd: RawFd, opt: i32, entries: u32) -> io::Result<()> {
        setsockopt(fd, opt, &entries)
    }

    fn mmap_offsets(&self, fd: RawFd) -> io::Result<MmapOffsets> {
        getsockopt(fd, XDP_MMAP_OFFSETS)
    }

    fn map_ring(&self, fd: RawFd, pgoff: u64, len: usize) -> io::Result<Arc<Region>> {
        mmap(fd, len, pgoff, libc::MAP_SHARED | libc::MAP_POPULATE)
    }

    fn alloc_umem(&self, len: usize) -> io::Result<Arc<Region>> {
        mmap(
            -1,
            len,
            0,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_POPULATE,
        )
    }

    fn bind(&self, fd: RawFd, addr: &SockaddrXdp) -> io::Result<()> {
        // SAFETY: `addr` is a live sockaddr_xdp and its exact size is passed.
        cvt(unsafe {
            libc::bind(
                fd,
                (addr as *const SockaddrXdp).cast(),
                std::mem::size_of::<SockaddrXdp>() as libc::socklen_t,
            )
        })
        .map(drop)
    }

    fn options(&self, fd: RawFd) -> io::Result<u32> {
        getsockopt::<u32>(fd, XDP_OPTIONS)
    }

    fn statistics(&self, fd: RawFd) -> io::Result<XdpStatistics> {
        getsockopt(fd, XDP_STATISTICS)
    }

    fn wake_rx(&self, fd: RawFd) -> io::Result<()> {
        // SAFETY: zero-length receive with null buffers, as the AF_XDP wakeup protocol expects.
        let r = unsafe {
            libc::recvfrom(
                fd,
                std::ptr::null_mut(),
                0,
                libc::MSG_DONTWAIT,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        match cvt(r as libc::c_int) {
            Err(e) if !benign_kick(&e) => Err(e),
            _ => Ok(()),
        }
    }

    fn kick_tx(&self, fd: RawFd) -> io::Result<()> {
        // SAFETY: zero-length send with null buffers, as the AF_XDP TX kick expects.
        let r = unsafe {
            libc::sendto(
                fd,
                std::ptr::null(),
                0,
                libc::MSG_DONTWAIT,
                std::ptr::null(),
                0,
            )
        };
        match cvt(r as libc::c_int) {
            Err(e) if !benign_kick(&e) => Err(e),
            _ => Ok(()),
        }
    }

    fn poll_in(&self, fd: RawFd, timeout_ms: i32) -> io::Result<bool> {
        let mut p = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd.
        match cvt(unsafe { libc::poll(&mut p, 1, timeout_ms) }) {
            Ok(n) => Ok(n > 0 && p.revents & libc::POLLIN != 0),
            Err(e) if e.raw_os_error() == Some(libc::EINTR) => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn ifindex(&self, name: &str) -> io::Result<u32> {
        let c = std::ffi::CString::new(name)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: `c` is a valid NUL-terminated string.
        match unsafe { libc::if_nametoindex(c.as_ptr()) } {
            0 => Err(io::Error::last_os_error()),
            i => Ok(i),
        }
    }

    fn now_boot_ns(&self) -> u64 {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: valid clock id and out-pointer.
        unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
        ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
    }
}
