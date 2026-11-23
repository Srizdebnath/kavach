//! Single-producer / single-consumer AF_XDP rings over shared memory.
//!
//! Every ring is `size` (a power of two) descriptors plus a free-running `u32` producer and
//! consumer index; `index & (size - 1)` selects the slot and all arithmetic wraps. The side that
//! writes descriptors publishes them with a release store of its index; the other side reads
//! that index with an acquire load before touching the descriptors (the kernel side of the
//! protocol is `xskq_prod_*` / `xskq_cons_*` in `net/xdp/xsk_queue.h`).
//!
//! User space produces on the fill and TX rings ([`ProdRing`]) and consumes from the RX and
//! completion rings ([`ConsRing`]). The same types also play the kernel's role in tests.
#![allow(unsafe_code)]

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use super::sys::{Region, RingOffset, XDP_RING_NEED_WAKEUP};

fn inval(what: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, what)
}

/// Pointers into one ring mapping. Kept alive by the `Arc<Region>`.
#[derive(Debug)]
struct RingMem<T> {
    region: Arc<Region>,
    producer: *const AtomicU32,
    consumer: *const AtomicU32,
    flags: *const AtomicU32,
    desc: *mut T,
    size: u32,
}

// SAFETY: the pointers target the `Arc<Region>` this struct owns a reference to; index words
// are only accessed atomically, and descriptor slots are handed over by the ring protocol, so
// moving a ring to another thread is sound when its descriptors are.
unsafe impl<T: Send> Send for RingMem<T> {}

impl<T: Copy> RingMem<T> {
    fn new(region: Arc<Region>, off: &RingOffset, size: u32) -> io::Result<Self> {
        if size == 0 || !size.is_power_of_two() {
            return Err(inval("ring size must be a power of two"));
        }
        let len = region.len() as u64;
        for o in [off.producer, off.consumer, off.flags] {
            if !o.is_multiple_of(4) || o.checked_add(4).is_none_or(|e| e > len) {
                return Err(inval("ring index offset out of bounds"));
            }
        }
        let desc_end = (size as u64)
            .checked_mul(std::mem::size_of::<T>() as u64)
            .and_then(|b| b.checked_add(off.desc));
        if !off.desc.is_multiple_of(std::mem::align_of::<T>() as u64)
            || desc_end.is_none_or(|e| e > len)
        {
            return Err(inval("ring descriptors out of bounds"));
        }
        let base = region.as_ptr();
        // SAFETY: every offset was checked to lie (with its full width) inside the region and to
        // be suitably aligned (the region itself is at least 8-byte aligned).
        let (producer, consumer, flags, desc) = unsafe {
            (
                base.add(off.producer as usize) as *const AtomicU32,
                base.add(off.consumer as usize) as *const AtomicU32,
                base.add(off.flags as usize) as *const AtomicU32,
                base.add(off.desc as usize) as *mut T,
            )
        };
        Ok(Self {
            region,
            producer,
            consumer,
            flags,
            desc,
            size,
        })
    }

    fn producer(&self) -> &AtomicU32 {
        // SAFETY: in-bounds, aligned, kept alive by `self.region`; only accessed atomically.
        unsafe { &*self.producer }
    }

    fn consumer(&self) -> &AtomicU32 {
        // SAFETY: as for `producer`.
        unsafe { &*self.consumer }
    }

    fn flags(&self) -> u32 {
        // SAFETY: as for `producer`.
        unsafe { &*self.flags }.load(Ordering::Acquire)
    }

    fn read(&self, idx: u32) -> T {
        let slot = (idx & (self.size - 1)) as usize;
        // SAFETY: `slot < size`, so the read is inside the descriptor array checked in `new`.
        // The ring protocol makes this side the slot's owner (acquire on the peer's index).
        unsafe { self.desc.add(slot).read() }
    }

    fn write(&mut self, idx: u32, v: T) {
        let slot = (idx & (self.size - 1)) as usize;
        // SAFETY: as for `read`; the slot was reserved and is not yet published to the peer.
        unsafe { self.desc.add(slot).write(v) }
    }

    fn probe(&self) -> RingProbe {
        RingProbe {
            _region: self.region.clone(),
            producer: self.producer,
            consumer: self.consumer,
        }
    }
}

/// Read-only view of a ring's two indices, for the watchdog thread.
#[derive(Debug)]
pub struct RingProbe {
    _region: Arc<Region>,
    producer: *const AtomicU32,
    consumer: *const AtomicU32,
}

// SAFETY: only performs atomic loads on index words kept alive by `_region`.
unsafe impl Send for RingProbe {}
// SAFETY: as above; atomic loads are safe from any number of threads.
unsafe impl Sync for RingProbe {}

impl RingProbe {
    /// `(producer, consumer)`.
    pub fn indices(&self) -> (u32, u32) {
        // SAFETY: in-bounds aligned index words (checked when the ring was built), kept alive
        // by `_region`, accessed atomically.
        unsafe {
            (
                (*self.producer).load(Ordering::Acquire),
                (*self.consumer).load(Ordering::Acquire),
            )
        }
    }
}

/// The producing side of a ring (user space: fill and TX).
#[derive(Debug)]
pub struct ProdRing<T> {
    mem: RingMem<T>,
    /// Next index to hand out (reserved, maybe not yet submitted).
    cached_prod: u32,
    /// Last seen consumer index + `size`: the first index we may not write.
    cached_cons: u32,
}

impl<T: Copy> ProdRing<T> {
    /// Attach to the ring at `off` inside `region`.
    pub fn new(region: Arc<Region>, off: &RingOffset, size: u32) -> io::Result<Self> {
        let mem = RingMem::new(region, off, size)?;
        let cached_prod = mem.producer().load(Ordering::Relaxed);
        let cached_cons = mem.consumer().load(Ordering::Acquire).wrapping_add(size);
        Ok(Self {
            mem,
            cached_prod,
            cached_cons,
        })
    }

    /// Ring size.
    pub fn size(&self) -> u32 {
        self.mem.size
    }

    /// Free slots, refreshing the consumer index only when fewer than `want` are known free.
    pub fn free(&mut self, want: u32) -> u32 {
        let free = self.cached_cons.wrapping_sub(self.cached_prod);
        if free >= want {
            return free;
        }
        self.cached_cons = self
            .mem
            .consumer()
            .load(Ordering::Acquire)
            .wrapping_add(self.mem.size);
        self.cached_cons.wrapping_sub(self.cached_prod)
    }

    /// Reserve exactly `n` slots; returns the first index, or `None` (nothing reserved).
    pub fn reserve(&mut self, n: u32) -> Option<u32> {
        if self.free(n) < n {
            return None;
        }
        let idx = self.cached_prod;
        self.cached_prod = self.cached_prod.wrapping_add(n);
        Some(idx)
    }

    /// Fill reserved slot `idx`.
    pub fn write(&mut self, idx: u32, v: T) {
        self.mem.write(idx, v);
    }

    /// Publish every reserved slot to the consumer.
    pub fn submit(&mut self) {
        self.mem
            .producer()
            .store(self.cached_prod, Ordering::Release);
    }

    /// The consumer asked to be woken (`XDP_RING_NEED_WAKEUP`).
    pub fn needs_wakeup(&self) -> bool {
        self.mem.flags() & XDP_RING_NEED_WAKEUP != 0
    }

    /// Watchdog view.
    pub fn probe(&self) -> RingProbe {
        self.mem.probe()
    }
}

/// The consuming side of a ring (user space: RX and completion).
#[derive(Debug)]
pub struct ConsRing<T> {
    mem: RingMem<T>,
    /// Last seen producer index.
    cached_prod: u32,
    /// Next index to read (peeked, maybe not yet released).
    cached_cons: u32,
}

impl<T: Copy> ConsRing<T> {
    /// Attach to the ring at `off` inside `region`.
    pub fn new(region: Arc<Region>, off: &RingOffset, size: u32) -> io::Result<Self> {
        let mem = RingMem::new(region, off, size)?;
        let cached_cons = mem.consumer().load(Ordering::Relaxed);
        let cached_prod = mem.producer().load(Ordering::Acquire);
        Ok(Self {
            mem,
            cached_prod,
            cached_cons,
        })
    }

    /// Ring size.
    pub fn size(&self) -> u32 {
        self.mem.size
    }

    /// Up to `max` filled slots: `(first index, count)`. A peer that claims more entries than
    /// the ring holds is clamped to `size`, so a corrupt index never reads past the array.
    pub fn peek(&mut self, max: u32) -> (u32, u32) {
        let mut avail = self.cached_prod.wrapping_sub(self.cached_cons);
        if avail == 0 {
            self.cached_prod = self.mem.producer().load(Ordering::Acquire);
            avail = self.cached_prod.wrapping_sub(self.cached_cons);
        }
        let n = avail.min(max).min(self.mem.size);
        let idx = self.cached_cons;
        self.cached_cons = self.cached_cons.wrapping_add(n);
        (idx, n)
    }

    /// Read peeked slot `idx` (before [`Self::release`]).
    pub fn read(&self, idx: u32) -> T {
        self.mem.read(idx)
    }

    /// Hand every peeked slot back to the producer.
    pub fn release(&mut self) {
        self.mem
            .consumer()
            .store(self.cached_cons, Ordering::Release);
    }

    /// The producer asked to be woken (`XDP_RING_NEED_WAKEUP`).
    pub fn needs_wakeup(&self) -> bool {
        self.mem.flags() & XDP_RING_NEED_WAKEUP != 0
    }

    /// Watchdog view.
    pub fn probe(&self) -> RingProbe {
        self.mem.probe()
    }
}

/// Offsets used for heap-backed rings in tests and mocks: indices on separate cache lines.
#[cfg(test)]
pub const TEST_OFFSETS: RingOffset = RingOffset {
    producer: 0,
    consumer: 64,
    flags: 128,
    desc: 192,
};

/// Bytes needed for a ring of `size` `T`s at `off`.
#[cfg(test)]
pub fn ring_bytes<T>(off: &RingOffset, size: u32) -> usize {
    off.desc as usize + size as usize * std::mem::size_of::<T>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::afxdp::sys::XdpDesc;

    fn pair(size: u32) -> (Arc<Region>, ProdRing<u64>, ConsRing<u64>) {
        let r = Arc::new(Region::heap(ring_bytes::<u64>(&TEST_OFFSETS, size)));
        let p = ProdRing::new(r.clone(), &TEST_OFFSETS, size).unwrap();
        let c = ConsRing::new(r.clone(), &TEST_OFFSETS, size).unwrap();
        (r, p, c)
    }

    fn set_index(r: &Region, off: u64, v: u32) {
        r.write_at(off as usize, &v.to_ne_bytes());
    }

    #[test]
    fn rejects_bad_geometry() {
        let r = Arc::new(Region::heap(ring_bytes::<u64>(&TEST_OFFSETS, 8)));
        assert!(ProdRing::<u64>::new(r.clone(), &TEST_OFFSETS, 6).is_err());
        assert!(ProdRing::<u64>::new(r.clone(), &TEST_OFFSETS, 16).is_err());
        let skew = RingOffset {
            desc: 196,
            ..TEST_OFFSETS
        };
        assert!(ProdRing::<u64>::new(r.clone(), &skew, 4).is_err());
        let past = RingOffset {
            flags: r.len() as u64,
            ..TEST_OFFSETS
        };
        assert!(ConsRing::<u64>::new(r.clone(), &past, 8).is_err());
        assert!(ConsRing::<u64>::new(r, &TEST_OFFSETS, 8).is_ok());
    }

    #[test]
    fn produce_consume_and_full_ring() {
        let (_r, mut p, mut c) = pair(8);
        assert_eq!(p.free(1), 8);
        let idx = p.reserve(8).unwrap();
        assert!(p.reserve(1).is_none(), "ring is full");
        for i in 0..8 {
            p.write(idx + i, 100 + i as u64);
        }
        // Not visible until submitted.
        assert_eq!(c.peek(8).1, 0);
        p.submit();
        let (ci, n) = c.peek(3);
        assert_eq!(n, 3);
        assert_eq!(
            (0..n).map(|i| c.read(ci + i)).collect::<Vec<_>>(),
            [100, 101, 102]
        );
        // Not released yet: the producer still sees a full ring.
        assert!(p.reserve(1).is_none());
        c.release();
        assert_eq!(p.free(1), 3);
        let (ci, n) = c.peek(64);
        assert_eq!((ci, n), (3, 5));
        assert_eq!(c.read(ci + 4), 107);
        c.release();
        assert_eq!(p.free(8), 8);
    }

    #[test]
    fn indices_wrap_around_u32() {
        let r = Arc::new(Region::heap(ring_bytes::<XdpDesc>(&TEST_OFFSETS, 4)));
        let start = u32::MAX - 1;
        set_index(&r, TEST_OFFSETS.producer, start);
        set_index(&r, TEST_OFFSETS.consumer, start);
        let mut p = ProdRing::<XdpDesc>::new(r.clone(), &TEST_OFFSETS, 4).unwrap();
        let mut c = ConsRing::<XdpDesc>::new(r.clone(), &TEST_OFFSETS, 4).unwrap();
        for round in 0..5u32 {
            let idx = p.reserve(3).unwrap();
            for i in 0..3 {
                p.write(
                    idx.wrapping_add(i),
                    XdpDesc {
                        addr: (round * 10 + i) as u64,
                        len: i,
                        options: 0,
                    },
                );
            }
            p.submit();
            let (ci, n) = c.peek(4);
            assert_eq!(n, 3);
            for i in 0..3 {
                assert_eq!(c.read(ci.wrapping_add(i)).addr, (round * 10 + i) as u64);
            }
            c.release();
        }
        assert_eq!(
            p.probe().indices(),
            (start.wrapping_add(15), start.wrapping_add(15))
        );
    }

    #[test]
    fn corrupt_producer_is_clamped() {
        let (r, _p, mut c) = pair(4);
        set_index(&r, TEST_OFFSETS.producer, 1000);
        let (_, n) = c.peek(u32::MAX);
        assert_eq!(n, 4, "never more than the ring holds");
    }

    #[test]
    fn need_wakeup_flag() {
        let (r, p, c) = pair(4);
        assert!(!p.needs_wakeup() && !c.needs_wakeup());
        set_index(&r, TEST_OFFSETS.flags, XDP_RING_NEED_WAKEUP);
        assert!(p.needs_wakeup() && c.needs_wakeup());
    }
}
