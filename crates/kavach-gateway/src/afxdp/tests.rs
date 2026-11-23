//! Mode negotiation, socket setup, ring bookkeeping and the watchdog, against a mocked kernel.

use std::collections::VecDeque;
use std::io;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use super::ring::{TEST_OFFSETS, ring_bytes};
use super::sys::*;
use super::*;

// ---------------------------------------------------------------------------------------------
// Mock kernel
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    Socket(RawFd),
    UmemReg {
        len: u64,
        chunk: u32,
    },
    RingSize(i32, u32),
    Bind {
        flags: u16,
        ifindex: u32,
        queue: u32,
    },
}

#[derive(Debug)]
struct MockSys {
    next_fd: AtomicI32,
    /// One entry per bind call: `Some(errno)` fails it. Missing entries succeed.
    bind_errs: Mutex<VecDeque<Option<i32>>>,
    /// What `XDP_OPTIONS` reports after a zero-copy bind.
    zc_confirmed: bool,
    calls: Mutex<Vec<Call>>,
    rings: Mutex<Vec<(RawFd, u64, Arc<Region>)>>,
    umems: Mutex<Vec<Arc<Region>>>,
    closed: Mutex<Vec<RawFd>>,
    tx_kicks: AtomicU32,
    start: Instant,
}

impl MockSys {
    fn new(bind_errs: &[Option<i32>]) -> Arc<Self> {
        Arc::new(Self {
            next_fd: AtomicI32::new(100),
            bind_errs: Mutex::new(bind_errs.iter().copied().collect()),
            zc_confirmed: true,
            calls: Mutex::new(vec![]),
            rings: Mutex::new(vec![]),
            umems: Mutex::new(vec![]),
            closed: Mutex::new(vec![]),
            tx_kicks: AtomicU32::new(0),
            start: Instant::now(),
        })
    }

    fn binds(&self) -> Vec<u16> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter_map(|c| match c {
                Call::Bind { flags, .. } => Some(*flags),
                _ => None,
            })
            .collect()
    }

    fn ring(&self, fd: RawFd, pgoff: u64) -> Arc<Region> {
        self.rings
            .lock()
            .unwrap()
            .iter()
            .find(|(f, p, _)| *f == fd && *p == pgoff)
            .map(|(_, _, r)| r.clone())
            .expect("ring mapped")
    }
}

impl Sys for MockSys {
    fn socket(&self) -> io::Result<RawFd> {
        let fd = self.next_fd.fetch_add(1, Ordering::SeqCst);
        self.calls.lock().unwrap().push(Call::Socket(fd));
        Ok(fd)
    }
    fn close(&self, fd: RawFd) {
        self.closed.lock().unwrap().push(fd);
    }
    fn set_umem_reg(&self, _fd: RawFd, reg: &UmemReg) -> io::Result<()> {
        self.calls.lock().unwrap().push(Call::UmemReg {
            len: reg.len,
            chunk: reg.chunk_size,
        });
        Ok(())
    }
    fn set_ring_size(&self, _fd: RawFd, opt: i32, entries: u32) -> io::Result<()> {
        self.calls
            .lock()
            .unwrap()
            .push(Call::RingSize(opt, entries));
        Ok(())
    }
    fn mmap_offsets(&self, _fd: RawFd) -> io::Result<MmapOffsets> {
        Ok(MmapOffsets {
            rx: TEST_OFFSETS,
            tx: TEST_OFFSETS,
            fr: TEST_OFFSETS,
            cr: TEST_OFFSETS,
        })
    }
    fn map_ring(&self, fd: RawFd, pgoff: u64, len: usize) -> io::Result<Arc<Region>> {
        let r = Arc::new(Region::heap(len));
        self.rings.lock().unwrap().push((fd, pgoff, r.clone()));
        Ok(r)
    }
    fn alloc_umem(&self, len: usize) -> io::Result<Arc<Region>> {
        let r = Arc::new(Region::heap(len));
        self.umems.lock().unwrap().push(r.clone());
        Ok(r)
    }
    fn bind(&self, _fd: RawFd, a: &SockaddrXdp) -> io::Result<()> {
        assert_eq!(a.family, AF_XDP as u16);
        self.calls.lock().unwrap().push(Call::Bind {
            flags: a.flags,
            ifindex: a.ifindex,
            queue: a.queue_id,
        });
        match self.bind_errs.lock().unwrap().pop_front().flatten() {
            Some(errno) => Err(io::Error::from_raw_os_error(errno)),
            None => Ok(()),
        }
    }
    fn options(&self, _fd: RawFd) -> io::Result<u32> {
        let zc = self.binds().last().is_some_and(|f| f & XDP_ZEROCOPY != 0);
        Ok(if zc && self.zc_confirmed {
            XDP_OPTIONS_ZEROCOPY
        } else {
            0
        })
    }
    fn statistics(&self, _fd: RawFd) -> io::Result<XdpStatistics> {
        Ok(XdpStatistics::default())
    }
    fn wake_rx(&self, _fd: RawFd) -> io::Result<()> {
        Ok(())
    }
    fn kick_tx(&self, _fd: RawFd) -> io::Result<()> {
        self.tx_kicks.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn poll_in(&self, _fd: RawFd, _timeout_ms: i32) -> io::Result<bool> {
        std::thread::sleep(Duration::from_millis(1));
        Ok(true)
    }
    fn ifindex(&self, name: &str) -> io::Result<u32> {
        if name == "eth0" {
            Ok(7)
        } else {
            Err(io::Error::from_raw_os_error(libc::ENODEV))
        }
    }
    fn now_boot_ns(&self) -> u64 {
        1_000_000_000 + self.start.elapsed().as_nanos() as u64
    }
}

const RING: u32 = 8;
const FS: u32 = 2048;

fn params(queue: u32) -> SocketParams {
    SocketParams {
        ifindex: 7,
        queue,
        ring_size: RING,
        frame_size: FS,
    }
}

/// The kernel's side of one socket's rings.
struct KernelSim {
    umem: Arc<Region>,
    fill: ConsRing<u64>,
    rx: ProdRing<XdpDesc>,
    tx: ConsRing<XdpDesc>,
    comp: ProdRing<u64>,
}

impl KernelSim {
    fn new(sys: &MockSys, fd: RawFd, umem: Arc<Region>) -> Self {
        let o = TEST_OFFSETS;
        Self {
            umem,
            fill: ConsRing::new(sys.ring(fd, XDP_UMEM_PGOFF_FILL_RING), &o, RING).unwrap(),
            rx: ProdRing::new(sys.ring(fd, XDP_PGOFF_RX_RING), &o, RING).unwrap(),
            tx: ConsRing::new(sys.ring(fd, XDP_PGOFF_TX_RING), &o, RING).unwrap(),
            comp: ProdRing::new(sys.ring(fd, XDP_UMEM_PGOFF_COMPLETION_RING), &o, RING).unwrap(),
        }
    }

    /// Receive one frame: take a fill buffer, copy `data` in, post it on RX. Returns its addr.
    fn deliver(&mut self, data: &[u8]) -> Option<u64> {
        let (i, n) = self.fill.peek(1);
        if n == 0 {
            return None;
        }
        let addr = self.fill.read(i);
        self.fill.release();
        self.umem.write_at(addr as usize, data);
        self.post_rx(addr, data.len() as u32);
        Some(addr)
    }

    fn post_rx(&mut self, addr: u64, len: u32) {
        let r = self.rx.reserve(1).expect("rx ring room");
        self.rx.write(
            r,
            XdpDesc {
                addr,
                len,
                options: 0,
            },
        );
        self.rx.submit();
    }

    /// Fill buffers currently posted (consumed by the sim).
    fn take_fill(&mut self) -> Vec<u64> {
        let mut v = vec![];
        loop {
            // Like the kernel, the sim refreshes the producer only once its cache runs dry.
            let (i, n) = self.fill.peek(u32::MAX);
            if n == 0 {
                return v;
            }
            v.extend((0..n).map(|k| self.fill.read(i + k)));
            self.fill.release();
        }
    }

    /// Transmit everything on TX and complete it.
    fn transmit_all(&mut self) -> Vec<(u64, Vec<u8>)> {
        let (i, n) = self.tx.peek(u32::MAX);
        let mut out = vec![];
        for k in 0..n {
            let d = self.tx.read(i + k);
            out.push((d.addr, self.umem.read_at(d.addr as usize, d.len as usize)));
        }
        self.tx.release();
        if n > 0 {
            let c = self.comp.reserve(n).unwrap();
            for (k, (a, _)) in out.iter().enumerate() {
                self.comp.write(c + k as u32, *a);
            }
            self.comp.submit();
        }
        out
    }
}

fn open_one(
    sys: &Arc<MockSys>,
    attach: XdpAttach,
) -> Result<(BindMode, XskSocket<MockSys>), NegotiateError> {
    negotiate("eth0", 0, attach, |m| {
        XskSocket::open(sys.clone(), &params(0), m)
    })
}

// ---------------------------------------------------------------------------------------------
// Negotiation
// ---------------------------------------------------------------------------------------------

#[test]
fn native_prefers_zerocopy() {
    let sys = MockSys::new(&[]);
    let (mode, s) = open_one(&sys, XdpAttach::Native).unwrap();
    assert_eq!(mode, BindMode::ZeroCopy);
    assert_eq!(s.mode(), BindMode::ZeroCopy);
    assert_eq!(sys.binds(), [XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP]);
}

#[test]
fn zerocopy_unsupported_falls_back_to_copy_on_a_fresh_socket() {
    let sys = MockSys::new(&[Some(libc::EOPNOTSUPP)]);
    let (mode, s) = open_one(&sys, XdpAttach::Native).unwrap();
    assert_eq!(mode, BindMode::Copy);
    assert_eq!(
        sys.binds(),
        [
            XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP,
            XDP_COPY | XDP_USE_NEED_WAKEUP
        ]
    );
    // The failed attempt's socket was closed; the live one is the second.
    assert_eq!(*sys.closed.lock().unwrap(), [100]);
    assert_eq!(s.fd().raw(), 101);
}

#[test]
fn zerocopy_bind_that_silently_copies_is_not_reported_as_zerocopy() {
    let sys = Arc::new(MockSys {
        zc_confirmed: false,
        ..Arc::into_inner(MockSys::new(&[])).unwrap()
    });
    let (mode, _s) = open_one(&sys, XdpAttach::Unknown).unwrap();
    assert_eq!(mode, BindMode::Copy);
    assert_eq!(sys.binds().len(), 2);
}

#[test]
fn generic_xdp_binds_skb_mode_only() {
    let sys = MockSys::new(&[]);
    let (mode, _s) = open_one(&sys, XdpAttach::Generic).unwrap();
    assert_eq!(mode, BindMode::Skb);
    assert_eq!(sys.binds(), [XDP_COPY | XDP_USE_NEED_WAKEUP]);
}

#[test]
fn non_mode_errors_stop_the_ladder() {
    let sys = MockSys::new(&[Some(libc::EBUSY)]);
    let e = open_one(&sys, XdpAttach::Native).unwrap_err();
    assert_eq!(e.attempts.len(), 1);
    assert_eq!(
        sys.binds().len(),
        1,
        "copy mode not attempted for a busy queue"
    );
    assert!(e.to_string().contains("not a mode problem"), "{e}");
}

#[test]
fn exhausted_ladder_suggests_generic_xdp() {
    let sys = MockSys::new(&[Some(libc::EOPNOTSUPP), Some(libc::EINVAL)]);
    let e = open_one(&sys, XdpAttach::Native).unwrap_err();
    assert_eq!(
        e.attempts.iter().map(|a| a.0).collect::<Vec<_>>(),
        [BindMode::ZeroCopy, BindMode::Copy]
    );
    assert!(e.to_string().contains("xdp_mode = \"skb\""), "{e}");
    assert_eq!(sys.closed.lock().unwrap().len(), 2, "both sockets released");
}

#[test]
fn attach_labels() {
    assert_eq!(XdpAttach::from_label("native"), XdpAttach::Native);
    assert_eq!(XdpAttach::from_label("generic"), XdpAttach::Generic);
    assert_eq!(XdpAttach::from_label("replaced"), XdpAttach::Unknown);
}

// ---------------------------------------------------------------------------------------------
// Socket setup and ring bookkeeping
// ---------------------------------------------------------------------------------------------

#[test]
fn setup_order_and_initial_fill() {
    let sys = MockSys::new(&[]);
    let s = XskSocket::open(sys.clone(), &params(3), BindMode::Copy).unwrap();
    let calls = sys.calls.lock().unwrap().clone();
    assert_eq!(
        calls,
        [
            Call::Socket(100),
            Call::UmemReg {
                len: (2 * RING * FS) as u64,
                chunk: FS
            },
            Call::RingSize(XDP_UMEM_FILL_RING, RING),
            Call::RingSize(XDP_UMEM_COMPLETION_RING, RING),
            Call::RingSize(XDP_RX_RING, RING),
            Call::RingSize(XDP_TX_RING, RING),
            Call::Bind {
                flags: XDP_COPY | XDP_USE_NEED_WAKEUP,
                ifindex: 7,
                queue: 3
            },
        ]
    );
    // Every RX frame was posted before bind; the TX half stays free.
    let p = s.probe().sample();
    assert_eq!((p.fill_prod, p.fill_cons), (RING, 0));
    assert_eq!(s.free_tx(), RING as usize);
    let mut k = KernelSim::new(&sys, 100, s.umem_region());
    let fill = k.take_fill();
    assert_eq!(fill, (0..RING).map(|i| (i * FS) as u64).collect::<Vec<_>>());
    drop(s);
    assert_eq!(*sys.closed.lock().unwrap(), [100]);
}

#[test]
fn rejects_bad_geometry() {
    let sys = MockSys::new(&[]);
    for (ring_size, frame_size) in [(6, 2048), (8, 1500), (1, 2048)] {
        let p = SocketParams {
            ring_size,
            frame_size,
            ..params(0)
        };
        assert!(XskSocket::open(sys.clone(), &p, BindMode::Copy).is_err());
    }
    assert!(
        sys.calls.lock().unwrap().is_empty(),
        "rejected before any syscall"
    );
}

#[test]
fn rx_frames_are_handled_recycled_and_transmitted() {
    let sys = MockSys::new(&[]);
    let mut s = XskSocket::open(sys.clone(), &params(0), BindMode::Copy).unwrap();
    let mut k = KernelSim::new(&sys, 100, s.umem_region());

    let a0 = k.deliver(b"first").unwrap();
    let a1 = k.deliver(b"second").unwrap();
    let a2 = k.deliver(b"bounce").unwrap();
    let seen = Arc::new(Mutex::new(vec![]));
    let mut h = {
        let seen = seen.clone();
        move |q: u32, f: &mut [u8]| {
            seen.lock().unwrap().push((q, f.to_vec()));
            if f == b"bounce" {
                f[0] = b'B';
                RxAction::Transmit
            } else {
                RxAction::Consume
            }
        }
    };
    assert_eq!(s.process_rx(64, &mut h), 3);
    assert_eq!(
        *seen.lock().unwrap(),
        [
            (0, b"first".to_vec()),
            (0, b"second".to_vec()),
            (0, b"bounce".to_vec())
        ]
    );
    let p = s.probe().sample();
    assert_eq!((p.rx_prod, p.rx_cons), (3, 3), "RX released");
    assert_eq!(
        p.fill_prod,
        RING + 3,
        "three buffers returned to the fill ring"
    );

    // The two consumed frames come back as is; the transmitted one is replaced by a TX spare.
    let mut refilled = k.take_fill();
    // The sim already consumed the first three initial buffers; drop the untouched rest.
    refilled.drain(..(RING - 3) as usize);
    assert_eq!(&refilled[..2], &[a0, a1]);
    assert!(refilled[2] >= (RING * FS) as u64, "spare from the TX half");
    assert_eq!(s.free_tx(), RING as usize - 1);

    let sent = k.transmit_all();
    assert_eq!(sent, [(a2, b"Bounce".to_vec())]);
    assert_eq!(
        sys.tx_kicks.load(Ordering::SeqCst),
        1,
        "copy mode always kicks TX"
    );

    // Completion returns the bounced frame to the TX free list.
    assert_eq!(s.process_rx(64, &mut h), 0);
    assert_eq!(s.free_tx(), RING as usize);
    let st = s.stats();
    assert_eq!((st.rx_frames, st.tx_frames, st.tx_dropped), (3, 1, 0));
    assert_eq!(st.rx_bytes, 5 + 6 + 6);
}

#[test]
fn budget_limits_a_batch() {
    let sys = MockSys::new(&[]);
    let mut s = XskSocket::open(sys.clone(), &params(0), BindMode::Copy).unwrap();
    let mut k = KernelSim::new(&sys, 100, s.umem_region());
    for _ in 0..5 {
        k.deliver(b"x").unwrap();
    }
    let mut h = |_: u32, _: &mut [u8]| RxAction::Consume;
    assert_eq!(s.process_rx(2, &mut h), 2);
    assert_eq!(s.probe().sample().rx_cons, 2);
    assert_eq!(s.process_rx(64, &mut h), 3);
}

#[test]
fn invalid_descriptors_are_skipped() {
    let sys = MockSys::new(&[]);
    let mut s = XskSocket::open(sys.clone(), &params(0), BindMode::Copy).unwrap();
    let mut k = KernelSim::new(&sys, 100, s.umem_region());
    let _ = k.take_fill();
    k.post_rx(FS as u64, FS + 1); // crosses into the next frame: ours, recycled
    k.post_rx(1 << 40, 10); // outside the UMEM: never posted back
    let calls = Arc::new(AtomicU32::new(0));
    let mut h = {
        let calls = calls.clone();
        move |_: u32, _: &mut [u8]| {
            calls.fetch_add(1, Ordering::SeqCst);
            RxAction::Consume
        }
    };
    assert_eq!(s.process_rx(64, &mut h), 2);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(s.stats().invalid_descs, 2);
    assert_eq!(k.take_fill(), [FS as u64]);
}

#[test]
fn transmit_without_a_tx_buffer_is_dropped_not_leaked() {
    let sys = MockSys::new(&[]);
    let mut s = XskSocket::open(sys.clone(), &params(0), BindMode::Copy).unwrap();
    let mut k = KernelSim::new(&sys, 100, s.umem_region());
    let mut h = |_: u32, _: &mut [u8]| RxAction::Transmit;
    // RING transmits exhaust both the TX ring and the free list (nothing completes).
    for _ in 0..RING {
        k.deliver(b"t").unwrap();
    }
    assert_eq!(s.process_rx(64, &mut h), RING);
    assert_eq!(s.free_tx(), 0);
    // The fill ring now holds the TX spares; the kernel receives into one of them.
    let spares = k.take_fill();
    assert!(spares.iter().all(|a| *a >= (RING * FS) as u64));
    k.post_rx(spares[0], 1);
    assert_eq!(s.process_rx(64, &mut h), 1);
    assert_eq!(s.stats().tx_dropped, 1);
    assert_eq!(
        k.take_fill(),
        [spares[0]],
        "dropped transmit recycles its frame"
    );
}

#[test]
fn ring_helpers() {
    assert_eq!(ring_bytes::<XdpDesc>(&TEST_OFFSETS, 4), 192 + 64);
}

// ---------------------------------------------------------------------------------------------
// Watchdog
// ---------------------------------------------------------------------------------------------

const MS: u64 = 1_000_000;

fn sample(fill_prod: u32, rx_prod: u32, rx_cons: u32) -> ProbeSample {
    ProbeSample {
        fill_prod,
        fill_cons: 0,
        rx_prod,
        rx_cons,
    }
}

#[test]
fn idle_queue_never_detaches() {
    let mut w = Watchdog::new(100, 0, sample(8, 0, 0));
    for t in 1..100 {
        // Fill ring empty (zero-copy driver holding all buffers) is not pending work.
        let s = ProbeSample {
            fill_cons: 8,
            ..sample(8, 5, 5)
        };
        assert_eq!(w.observe(t * 50 * MS, s), WatchdogAction::Renew);
    }
}

#[test]
fn progressing_queue_never_detaches() {
    let mut w = Watchdog::new(100, 0, sample(8, 0, 0));
    for t in 1..100u32 {
        // Frames always pending, but the consumer keeps refilling.
        let s = sample(8 + t, t + 3, t);
        assert_eq!(w.observe(t as u64 * 60 * MS, s), WatchdogAction::Renew);
    }
}

#[test]
fn stall_with_pending_frames_detaches_then_recovers() {
    let mut w = Watchdog::new(100, 0, sample(8, 0, 0));
    assert_eq!(w.observe(10 * MS, sample(8, 3, 0)), WatchdogAction::Renew);
    assert_eq!(w.observe(60 * MS, sample(8, 4, 0)), WatchdogAction::Renew);
    // Last progress (idle) was at 0 ms: the stall is declared at 100 ms.
    assert_eq!(w.observe(99 * MS, sample(8, 4, 0)), WatchdogAction::Renew);
    assert_eq!(w.observe(100 * MS, sample(8, 4, 0)), WatchdogAction::Detach);
    assert!(w.detached());
    // Still stuck: hold. An idle-looking sample is not proof of life.
    assert_eq!(w.observe(200 * MS, sample(8, 4, 0)), WatchdogAction::Hold);
    // Consumer read the frames (RX consumer moved): re-arm.
    assert_eq!(
        w.observe(300 * MS, sample(8, 4, 4)),
        WatchdogAction::Reattach
    );
    assert!(!w.detached());
    assert_eq!(w.observe(350 * MS, sample(12, 4, 4)), WatchdogAction::Renew);
}

#[test]
fn wrapping_indices_count_as_progress() {
    let mut w = Watchdog::new(10, 0, sample(u32::MAX, 0, 0));
    assert_eq!(w.observe(50 * MS, sample(0, 1, 0)), WatchdogAction::Renew);
    assert_eq!(w.observe(100 * MS, sample(0, 1, 0)), WatchdogAction::Detach);
}

// ---------------------------------------------------------------------------------------------
// Backend (threads + watchdog against recorded map updates)
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MapOp {
    Set(u32, RawFd),
    Clear(u32),
    Alive(u32, bool),
}

#[derive(Clone, Default)]
struct RecMaps(Arc<Mutex<Vec<MapOp>>>);

impl RecMaps {
    fn ops(&self) -> Vec<MapOp> {
        self.0.lock().unwrap().clone()
    }
    fn wait_for(&self, op: MapOp, after: usize) -> usize {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(i) = self.ops().iter().skip(after).position(|o| *o == op) {
                return after + i;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {op:?}: {:?}",
                self.ops()
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

impl RedirectMaps for RecMaps {
    fn set_socket(&mut self, queue: u32, fd: RawFd) -> io::Result<()> {
        self.0.lock().unwrap().push(MapOp::Set(queue, fd));
        Ok(())
    }
    fn clear_socket(&mut self, queue: u32) -> io::Result<()> {
        self.0.lock().unwrap().push(MapOp::Clear(queue));
        Ok(())
    }
    fn set_alive_until(&mut self, queue: u32, until_ns: u64) -> io::Result<()> {
        self.0
            .lock()
            .unwrap()
            .push(MapOp::Alive(queue, until_ns != 0));
        Ok(())
    }
}

fn cfg(queues: Vec<u32>) -> AfXdpConfig {
    AfXdpConfig {
        enabled: true,
        iface: "eth0".into(),
        queues,
        ports: vec!["8443".parse().unwrap()],
        watchdog_ms: 20,
        ring_size: 64,
        frame_size: 2048,
    }
}

#[test]
fn backend_detaches_a_hung_consumer_and_reattaches_on_recovery() {
    let sys = MockSys::new(&[Some(libc::EOPNOTSUPP)]);
    let maps = RecMaps::default();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let release_rx = Arc::new(Mutex::new(release_rx));
    let b = Backend::start(
        sys.clone(),
        &cfg(vec![0]),
        XdpAttach::Native,
        maps.clone(),
        {
            let rx = release_rx.clone();
            move |_q| {
                let rx = rx.clone();
                move |_: u32, f: &mut [u8]| {
                    if f == b"hang" {
                        let _ = rx.lock().unwrap().recv_timeout(Duration::from_secs(10));
                    }
                    RxAction::Consume
                }
            }
        },
    )
    .unwrap();
    assert_eq!(b.modes(), [(0, BindMode::Copy)]);
    let fd = 101;
    assert_eq!(&maps.ops()[..2], [MapOp::Set(0, fd), MapOp::Alive(0, true)]);

    let umem = sys.umems.lock().unwrap().last().unwrap().clone();
    let o = TEST_OFFSETS;
    let mut fill = ConsRing::<u64>::new(sys.ring(fd, XDP_UMEM_PGOFF_FILL_RING), &o, 64).unwrap();
    let mut rx = ProdRing::<XdpDesc>::new(sys.ring(fd, XDP_PGOFF_RX_RING), &o, 64).unwrap();
    let mut deliver = |data: &[u8]| {
        let (i, n) = fill.peek(1);
        assert_eq!(n, 1);
        let a = fill.read(i);
        fill.release();
        umem.write_at(a as usize, data);
        let r = rx.reserve(1).unwrap();
        rx.write(
            r,
            XdpDesc {
                addr: a,
                len: data.len() as u32,
                options: 0,
            },
        );
        rx.submit();
    };
    deliver(b"hang");
    deliver(b"queued");
    // The consumer is stuck in the handler with RX unreleased: detach within ~watchdog_ms.
    let i = maps.wait_for(MapOp::Clear(0), 0);
    assert!(maps.ops()[..i].contains(&MapOp::Alive(0, true)));
    assert_eq!(maps.ops().get(i - 1), Some(&MapOp::Alive(0, false)));
    // Recover: the consumer drains and refills, and the watchdog re-arms the queue.
    release_tx.send(()).unwrap();
    let j = maps.wait_for(MapOp::Set(0, fd), i);
    assert!(j > i);
    drop(b);
    let ops = maps.ops();
    assert_eq!(
        &ops[ops.len() - 2..],
        [MapOp::Alive(0, false), MapOp::Clear(0)]
    );
    assert!(
        sys.closed.lock().unwrap().contains(&fd),
        "socket closed on stop"
    );
}

#[test]
fn backend_publishes_nothing_unless_every_queue_binds() {
    // Queue 0 binds; queue 1 is busy.
    let sys = MockSys::new(&[None, Some(libc::EBUSY)]);
    let maps = RecMaps::default();
    let e = Backend::start(
        sys.clone(),
        &cfg(vec![0, 1]),
        XdpAttach::Native,
        maps.clone(),
        |_| |_: u32, _: &mut [u8]| RxAction::Consume,
    )
    .unwrap_err();
    assert!(matches!(e, BackendError::Bind(_)), "{e}");
    assert!(
        maps.ops().is_empty(),
        "no redirect published: {:?}",
        maps.ops()
    );
    assert_eq!(sys.closed.lock().unwrap().len(), 2, "both sockets closed");
}

#[test]
fn backend_refuses_disabled_or_invalid_config() {
    let sys = MockSys::new(&[]);
    let h = |_| |_: u32, _: &mut [u8]| RxAction::Consume;
    let off = AfXdpConfig::default();
    assert!(matches!(
        Backend::start(sys.clone(), &off, XdpAttach::Native, RecMaps::default(), h),
        Err(BackendError::Config(_))
    ));
    let bad_if = AfXdpConfig {
        iface: "nope0".into(),
        ..cfg(vec![0])
    };
    assert!(matches!(
        Backend::start(
            sys.clone(),
            &bad_if,
            XdpAttach::Native,
            RecMaps::default(),
            h
        ),
        Err(BackendError::Io(..))
    ));
    assert!(sys.calls.lock().unwrap().is_empty());
}

// ---------------------------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------------------------

#[test]
fn config_parses_and_defaults_off() {
    let d: AfXdpConfig = toml::from_str("").unwrap();
    assert_eq!(d, AfXdpConfig::default());
    assert!(!d.enabled);
    assert!(d.validate().is_ok(), "disabled config is always valid");

    let c: AfXdpConfig = toml::from_str(
        r#"
enabled = true
iface = "eth0"
queues = [0, 2]
ports = [8443, "443/udp", "9000/tcp"]
watchdog_ms = 100
"#,
    )
    .unwrap();
    c.validate().unwrap();
    assert_eq!(
        c.ports,
        [
            PortSpec {
                proto: KV_PROTO_TCP,
                port: 8443
            },
            PortSpec {
                proto: KV_PROTO_UDP,
                port: 443
            },
            PortSpec {
                proto: KV_PROTO_TCP,
                port: 9000
            },
        ]
    );
    assert_eq!(c.ports[1].to_string(), "443/udp");
    assert_eq!(c.ports[0].key(), (6 << 16) | 8443);
    assert_eq!(c.port_keys().len(), 3);
    assert!(toml::from_str::<AfXdpConfig>(r#"ports = ["80/sctp"]"#).is_err());
    assert!(toml::from_str::<AfXdpConfig>(r#"ports = ["x"]"#).is_err());
    assert!(toml::from_str::<AfXdpConfig>("bogus = 1").is_err());
}

#[test]
fn config_validation() {
    let ok = cfg(vec![0]);
    ok.validate().unwrap();
    let bad = |f: &dyn Fn(&mut AfXdpConfig), needle: &str| {
        let mut c = ok.clone();
        f(&mut c);
        let e = c.validate().unwrap_err();
        assert!(e.contains(needle), "{e}");
    };
    bad(&|c| c.iface.clear(), "iface");
    bad(&|c| c.queues.clear(), "queues");
    bad(&|c| c.queues = vec![1, 1], "twice");
    bad(&|c| c.queues = vec![64], ">=");
    bad(&|c| c.ports.clear(), "ports");
    bad(&|c| c.ports = vec!["22".parse().unwrap()], "SSH");
    bad(&|c| c.ports = vec!["0/udp".parse().unwrap()], "port 0");
    bad(&|c| c.watchdog_ms = 5, "watchdog_ms");
    bad(&|c| c.ring_size = 100, "ring_size");
    bad(&|c| c.frame_size = 1500, "frame_size");
    // 22/udp is not SSH.
    let mut c = ok.clone();
    c.ports = vec!["22/udp".parse().unwrap()];
    c.validate().unwrap();
}
