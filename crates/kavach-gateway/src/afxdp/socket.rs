//! One AF_XDP socket bound to one RX queue, with its own UMEM and four rings.
//!
//! Frame accounting: the UMEM holds `2 * ring_size` frames. The first half starts on the fill
//! ring (owned by the kernel until it comes back on RX); the second half is the TX free list.
//! When a received frame is transmitted, a TX spare takes its place on the fill ring and the
//! received frame joins the TX side once the completion ring returns it, so each half always
//! holds exactly `ring_size` frames and the fill ring can never overflow.

use std::io;
use std::os::fd::RawFd;
use std::sync::Arc;

use super::BindMode;
use super::ring::{ConsRing, ProdRing, RingProbe};
use super::sys::{
    AF_XDP, SockaddrXdp, Sys, Umem, UmemReg, XDP_OPTIONS_ZEROCOPY, XDP_PGOFF_RX_RING,
    XDP_PGOFF_TX_RING, XDP_RX_RING, XDP_TX_RING, XDP_UMEM_COMPLETION_RING, XDP_UMEM_FILL_RING,
    XDP_UMEM_PGOFF_COMPLETION_RING, XDP_UMEM_PGOFF_FILL_RING, XdpDesc, XdpStatistics,
};

/// What the frame handler wants done with a received frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RxAction {
    /// The gateway consumed the frame; recycle its buffer.
    Consume,
    /// Send the (possibly rewritten) frame back out of the same queue.
    Transmit,
}

/// Receives every frame redirected to one queue.
pub trait FrameHandler: Send + 'static {
    /// Handle one frame; `frame` may be rewritten in place before a [`RxAction::Transmit`].
    fn on_frame(&mut self, queue: u32, frame: &mut [u8]) -> RxAction;
}

impl<F: FnMut(u32, &mut [u8]) -> RxAction + Send + 'static> FrameHandler for F {
    fn on_frame(&mut self, queue: u32, frame: &mut [u8]) -> RxAction {
        self(queue, frame)
    }
}

/// Geometry of one socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketParams {
    /// Interface index.
    pub ifindex: u32,
    /// RX queue id.
    pub queue: u32,
    /// Entries in each of the four rings (power of two).
    pub ring_size: u32,
    /// UMEM frame size (2048 or 4096).
    pub frame_size: u32,
}

/// Counters kept by the consumer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SocketStats {
    /// Frames handed to the handler.
    pub rx_frames: u64,
    /// Bytes handed to the handler.
    pub rx_bytes: u64,
    /// Frames queued for transmission.
    pub tx_frames: u64,
    /// Transmit requests dropped (no TX buffer or ring slot).
    pub tx_dropped: u64,
    /// RX descriptors outside the UMEM (ignored, buffer recycled).
    pub invalid_descs: u64,
}

/// Closes the socket when the last holder (socket or watchdog) lets go, so a stale fd number
/// is never written to `xsk_sockets` after it was reused.
#[derive(Debug)]
pub struct SockFd<S: Sys> {
    sys: Arc<S>,
    fd: RawFd,
}

impl<S: Sys> SockFd<S> {
    /// The raw descriptor (valid while `self` lives).
    pub fn raw(&self) -> RawFd {
        self.fd
    }
}

impl<S: Sys> Drop for SockFd<S> {
    fn drop(&mut self) {
        self.sys.close(self.fd);
    }
}

/// Read-only view of the fill and RX ring indices of one socket (for the watchdog).
#[derive(Debug)]
pub struct QueueProbe {
    fill: RingProbe,
    rx: RingProbe,
}

/// Fill/RX indices at one instant.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProbeSample {
    /// Fill ring producer (advanced by user space when it returns buffers).
    pub fill_prod: u32,
    /// Fill ring consumer (advanced by the kernel when it takes buffers).
    pub fill_cons: u32,
    /// RX ring producer (advanced by the kernel).
    pub rx_prod: u32,
    /// RX ring consumer (advanced by user space).
    pub rx_cons: u32,
}

impl QueueProbe {
    /// Sample the indices.
    pub fn sample(&self) -> ProbeSample {
        let (fill_prod, fill_cons) = self.fill.indices();
        let (rx_prod, rx_cons) = self.rx.indices();
        ProbeSample {
            fill_prod,
            fill_cons,
            rx_prod,
            rx_cons,
        }
    }
}

/// An AF_XDP socket bound to one queue.
#[derive(Debug)]
pub struct XskSocket<S: Sys> {
    // Declared first so it drops first: the socket closes before its mappings go away.
    fd: Arc<SockFd<S>>,
    sys: Arc<S>,
    umem: Umem,
    fill: ProdRing<u64>,
    comp: ConsRing<u64>,
    rx: ConsRing<XdpDesc>,
    tx: ProdRing<XdpDesc>,
    tx_free: Vec<u64>,
    refill: Vec<u64>,
    mode: BindMode,
    queue: u32,
    stats: SocketStats,
}

fn bad(what: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, what)
}

impl<S: Sys> XskSocket<S> {
    /// Create, configure and bind a socket in `mode` (one rung of the negotiation ladder).
    /// On any error everything created so far is released.
    pub fn open(sys: Arc<S>, p: &SocketParams, mode: BindMode) -> io::Result<Self> {
        if !p.ring_size.is_power_of_two() || p.ring_size < 2 {
            return Err(bad("ring_size must be a power of two"));
        }
        if p.frame_size != 2048 && p.frame_size != 4096 {
            return Err(bad("frame_size must be 2048 or 4096"));
        }
        let ring = p.ring_size;
        let n_frames = ring * 2;
        let fd = Arc::new(SockFd {
            sys: sys.clone(),
            fd: sys.socket()?,
        });
        let raw = fd.raw();
        let region = sys.alloc_umem(n_frames as usize * p.frame_size as usize)?;
        let umem = Umem::new(region, p.frame_size, n_frames)?;
        sys.set_umem_reg(
            raw,
            &UmemReg {
                addr: umem.addr(),
                len: umem.len(),
                chunk_size: p.frame_size,
                headroom: 0,
                flags: 0,
                tx_metadata_len: 0,
            },
        )?;
        // The UMEM must be registered before its fill/completion rings are sized.
        sys.set_ring_size(raw, XDP_UMEM_FILL_RING, ring)?;
        sys.set_ring_size(raw, XDP_UMEM_COMPLETION_RING, ring)?;
        sys.set_ring_size(raw, XDP_RX_RING, ring)?;
        sys.set_ring_size(raw, XDP_TX_RING, ring)?;
        let off = sys.mmap_offsets(raw)?;
        let map = |pgoff: u64, o: &super::sys::RingOffset, desc: usize| {
            sys.map_ring(raw, pgoff, o.desc as usize + ring as usize * desc)
        };
        let fill = ProdRing::new(map(XDP_UMEM_PGOFF_FILL_RING, &off.fr, 8)?, &off.fr, ring)?;
        let comp = ConsRing::new(
            map(XDP_UMEM_PGOFF_COMPLETION_RING, &off.cr, 8)?,
            &off.cr,
            ring,
        )?;
        let rx = ConsRing::new(map(XDP_PGOFF_RX_RING, &off.rx, 16)?, &off.rx, ring)?;
        let tx = ProdRing::new(map(XDP_PGOFF_TX_RING, &off.tx, 16)?, &off.tx, ring)?;
        let fs = p.frame_size as u64;
        let mut s = Self {
            fd,
            sys,
            umem,
            fill,
            comp,
            rx,
            tx,
            tx_free: (ring..n_frames).rev().map(|i| i as u64 * fs).collect(),
            refill: (0..ring).map(|i| i as u64 * fs).collect(),
            mode,
            queue: p.queue,
            stats: SocketStats::default(),
        };
        // Post every RX buffer before binding: with zero-copy, the driver may pull from the
        // fill ring as soon as the pool is attached.
        if !s.flush_fill() {
            return Err(io::Error::other("fill ring rejected the initial buffers"));
        }
        s.sys.bind(
            raw,
            &SockaddrXdp {
                family: AF_XDP as u16,
                flags: mode.bind_flags(),
                ifindex: p.ifindex,
                queue_id: p.queue,
                shared_umem_fd: 0,
            },
        )?;
        if mode == BindMode::ZeroCopy
            && let Ok(o) = s.sys.options(raw)
            && o & XDP_OPTIONS_ZEROCOPY == 0
        {
            return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
        }
        Ok(s)
    }

    /// The bound mode.
    pub fn mode(&self) -> BindMode {
        self.mode
    }

    /// The queue id.
    pub fn queue(&self) -> u32 {
        self.queue
    }

    /// Shared handle on the descriptor (for `xsk_sockets` updates).
    pub fn fd(&self) -> Arc<SockFd<S>> {
        self.fd.clone()
    }

    /// Watchdog view of the fill and RX rings.
    pub fn probe(&self) -> QueueProbe {
        QueueProbe {
            fill: self.fill.probe(),
            rx: self.rx.probe(),
        }
    }

    /// Consumer counters.
    pub fn stats(&self) -> SocketStats {
        self.stats
    }

    /// Kernel counters (`XDP_STATISTICS`).
    pub fn kernel_stats(&self) -> io::Result<XdpStatistics> {
        self.sys.statistics(self.fd.raw())
    }

    /// Wait up to `timeout_ms` for frames.
    pub fn wait(&self, timeout_ms: i32) -> io::Result<bool> {
        self.sys.poll_in(self.fd.raw(), timeout_ms)
    }

    /// Post pending buffers to the fill ring; false if the ring had no room (kept for later).
    fn flush_fill(&mut self) -> bool {
        if self.refill.is_empty() {
            return true;
        }
        let n = self.refill.len() as u32;
        let Some(idx) = self.fill.reserve(n) else {
            return false;
        };
        for (i, a) in self.refill.drain(..).enumerate() {
            self.fill.write(idx.wrapping_add(i as u32), a);
        }
        self.fill.submit();
        if self.fill.needs_wakeup() {
            let _ = self.sys.wake_rx(self.fd.raw());
        }
        true
    }

    /// Return transmitted frames to the TX free list.
    pub fn reap_completions(&mut self) -> u32 {
        let (idx, n) = self.comp.peek(self.comp.size());
        for i in 0..n {
            let a = self.comp.read(idx.wrapping_add(i));
            self.tx_free.push(self.umem.frame_base(a));
        }
        if n > 0 {
            self.comp.release();
        }
        n
    }

    /// Handle up to `budget` received frames, recycle their buffers and reap completions.
    /// Returns the number of frames handled.
    pub fn process_rx(&mut self, budget: u32, h: &mut dyn FrameHandler) -> u32 {
        self.reap_completions();
        let (idx, n) = self.rx.peek(budget);
        let mut queued_tx = 0u32;
        for i in 0..n {
            let d = self.rx.read(idx.wrapping_add(i));
            let base = self.umem.frame_base(d.addr);
            let action = match self.umem.frame_mut(d.addr, d.len) {
                Some(frame) => {
                    self.stats.rx_frames += 1;
                    self.stats.rx_bytes += d.len as u64;
                    h.on_frame(self.queue, frame)
                }
                None => {
                    self.stats.invalid_descs += 1;
                    // Recycle the frame if the address is ours; never post a foreign one.
                    if base < self.umem.len() {
                        self.refill.push(base);
                    }
                    continue;
                }
            };
            if action == RxAction::Transmit
                && let Some(spare) = self.tx_free.last().copied()
                && let Some(t) = self.tx.reserve(1)
            {
                self.tx_free.pop();
                self.tx.write(t, d);
                self.refill.push(spare);
                queued_tx += 1;
                continue;
            }
            if action == RxAction::Transmit {
                self.stats.tx_dropped += 1;
            }
            self.refill.push(base);
        }
        if n > 0 {
            self.rx.release();
        }
        if queued_tx > 0 {
            self.stats.tx_frames += queued_tx as u64;
            self.tx.submit();
            if self.tx.needs_wakeup() || self.mode != BindMode::ZeroCopy {
                let _ = self.sys.kick_tx(self.fd.raw());
            }
        }
        // Cannot fail: each half of the UMEM holds exactly `ring_size` frames (see module docs).
        let _ = self.flush_fill();
        n
    }

    /// Kernel-side views of the four rings and the UMEM (test kernel simulation).
    #[cfg(test)]
    pub(crate) fn umem_region(&self) -> Arc<super::sys::Region> {
        self.umem.region().clone()
    }

    #[cfg(test)]
    pub(crate) fn free_tx(&self) -> usize {
        self.tx_free.len()
    }
}
