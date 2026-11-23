//! WebSocket (RFC 6455) framing for the gateway.
//!
//! Client→server frames are parsed strictly and every text message is reassembled (bounded) and
//! inspected before any of its frames are forwarded; the original frames then go upstream byte
//! for byte, so the client's masking is preserved. Server→client frames are only *tracked*
//! ([`FrameTracker`]) so the gateway knows when it may inject its own frame (a JSON-RPC denial)
//! without splitting a frame or a fragmented message.
//!
//! Compression extensions are stripped from the handshake, so any RSV bit is an error. Binary
//! messages carry no JSON-RPC and are refused (fail closed).

use std::fmt;

/// Continuation frame.
pub const OP_CONT: u8 = 0x0;
/// Text frame.
pub const OP_TEXT: u8 = 0x1;
/// Binary frame.
pub const OP_BINARY: u8 = 0x2;
/// Close frame.
pub const OP_CLOSE: u8 = 0x8;
/// Ping frame.
pub const OP_PING: u8 = 0x9;
/// Pong frame.
pub const OP_PONG: u8 = 0xA;

/// Most frames one fragmented message may span.
pub const MAX_FRAGMENTS: usize = 1024;

/// Why a client frame was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsError {
    /// RSV bits set (no extension was negotiated).
    Reserved,
    /// Reserved or unknown opcode.
    BadOpcode,
    /// Client frame without a mask.
    Unmasked,
    /// Control frame fragmented or longer than 125 bytes.
    BadControl,
    /// Length not minimally encoded, or the 64-bit length has its top bit set.
    BadLength,
    /// Continuation without a message, or a new message inside one.
    BadFragmentation,
    /// Message larger than the frame limit, or too many fragments.
    TooLarge,
}

impl fmt::Display for WsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for WsError {}

impl WsError {
    /// Close code to send to the client.
    pub fn close_code(self) -> u16 {
        match self {
            WsError::TooLarge => 1009,
            _ => 1002,
        }
    }
}

/// A frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// FIN bit.
    pub fin: bool,
    /// RSV1..3 as the low three bits.
    pub rsv: u8,
    /// Opcode.
    pub opcode: u8,
    /// Masking key, if the MASK bit is set.
    pub mask: Option<[u8; 4]>,
    /// Payload length.
    pub len: u64,
    /// Header length in bytes (2..=14).
    pub header_len: usize,
    /// The length used the shortest encoding.
    pub minimal: bool,
}

impl FrameHeader {
    /// Whether this is a control frame (close, ping, pong).
    pub fn is_control(&self) -> bool {
        self.opcode & 0x8 != 0
    }
}

/// Parse a frame header; `Ok(None)` means more bytes are needed.
pub fn parse_frame_header(buf: &[u8]) -> Option<FrameHeader> {
    let (&b0, &b1) = (buf.first()?, buf.get(1)?);
    let masked = b1 & 0x80 != 0;
    let (len, mut n, minimal) = match b1 & 0x7f {
        126 => {
            let l = u16::from_be_bytes([*buf.get(2)?, *buf.get(3)?]);
            (u64::from(l), 4, l >= 126)
        }
        127 => {
            let b: [u8; 8] = buf.get(2..10)?.try_into().ok()?;
            let l = u64::from_be_bytes(b);
            (l, 10, l > u64::from(u16::MAX) && l >> 63 == 0)
        }
        l => (u64::from(l), 2, true),
    };
    let mask = if masked {
        let m: [u8; 4] = buf.get(n..n + 4)?.try_into().ok()?;
        n += 4;
        Some(m)
    } else {
        None
    };
    Some(FrameHeader {
        fin: b0 & 0x80 != 0,
        rsv: (b0 >> 4) & 0x7,
        opcode: b0 & 0x0f,
        mask,
        len,
        header_len: n,
        minimal,
    })
}

/// Validate a client→server frame header.
pub fn validate_client(h: &FrameHeader) -> Result<(), WsError> {
    if h.rsv != 0 {
        return Err(WsError::Reserved);
    }
    if !matches!(
        h.opcode,
        OP_CONT | OP_TEXT | OP_BINARY | OP_CLOSE | OP_PING | OP_PONG
    ) {
        return Err(WsError::BadOpcode);
    }
    if h.mask.is_none() {
        return Err(WsError::Unmasked);
    }
    if !h.minimal {
        return Err(WsError::BadLength);
    }
    if h.is_control() && (!h.fin || h.len > 125) {
        return Err(WsError::BadControl);
    }
    Ok(())
}

/// XOR `data` with `mask`, where `data` starts `offset` bytes into the payload.
pub fn unmask(data: &mut [u8], mask: [u8; 4], offset: usize) {
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= mask[(offset + i) % 4];
    }
}

/// Encode an unmasked (server→client) frame.
pub fn encode_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 10);
    out.push(0x80 | opcode);
    match payload.len() {
        n if n < 126 => out.push(n as u8),
        n if n <= usize::from(u16::MAX) => {
            out.push(126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            out.push(127);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    out.extend_from_slice(payload);
    out
}

/// Encode a close frame with `code` and a short reason (truncated to fit 125 bytes).
pub fn close_frame(code: u16, reason: &str) -> Vec<u8> {
    let mut p = code.to_be_bytes().to_vec();
    let mut r = reason.len().min(123);
    while !reason.is_char_boundary(r) {
        r -= 1;
    }
    p.extend_from_slice(&reason.as_bytes()[..r]);
    encode_frame(OP_CLOSE, &p)
}

/// What a complete client frame means for the relay.
#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    /// Control frame: forward these raw bytes now.
    Control {
        /// The opcode (close, ping or pong).
        opcode: u8,
        /// The frame as received.
        raw: Vec<u8>,
    },
    /// Part of a message; nothing to do yet.
    Pending,
    /// A complete text message.
    Text {
        /// The unmasked payload.
        text: Vec<u8>,
        /// Every frame of the message as received.
        raw: Vec<u8>,
    },
    /// A complete binary message (refused by the gateway).
    Binary,
}

/// Reassembles fragmented client messages, bounded by `max` payload bytes.
#[derive(Debug)]
pub struct Assembler {
    max: usize,
    opcode: Option<u8>,
    text: Vec<u8>,
    raw: Vec<u8>,
    fragments: usize,
}

impl Assembler {
    /// New assembler for messages of at most `max` bytes.
    pub fn new(max: usize) -> Self {
        Self {
            max,
            opcode: None,
            text: Vec::new(),
            raw: Vec::new(),
            fragments: 0,
        }
    }

    /// Bytes of payload the next data frame may still carry.
    pub fn remaining(&self) -> usize {
        self.max.saturating_sub(self.text.len())
    }

    /// Check a validated header against fragmentation state and limits before its payload is
    /// read, so an oversized frame is refused without buffering it.
    pub fn admit(&self, h: &FrameHeader) -> Result<(), WsError> {
        if h.is_control() {
            return Ok(());
        }
        match (h.opcode, self.opcode) {
            (OP_CONT, None) => return Err(WsError::BadFragmentation),
            (OP_TEXT | OP_BINARY, Some(_)) => return Err(WsError::BadFragmentation),
            _ => {}
        }
        if h.len > self.remaining() as u64 || self.fragments >= MAX_FRAGMENTS {
            return Err(WsError::TooLarge);
        }
        Ok(())
    }

    /// Push one complete frame (`raw` = header + masked payload) that passed [`Self::admit`].
    pub fn push(&mut self, h: &FrameHeader, raw: Vec<u8>) -> Result<Step, WsError> {
        self.admit(h)?;
        let mut payload = raw[h.header_len..].to_vec();
        if let Some(m) = h.mask {
            unmask(&mut payload, m, 0);
        }
        if h.is_control() {
            return Ok(Step::Control {
                opcode: h.opcode,
                raw,
            });
        }
        if self.opcode.is_none() {
            self.opcode = Some(h.opcode);
        }
        self.fragments += 1;
        self.text.extend_from_slice(&payload);
        self.raw.extend_from_slice(&raw);
        if !h.fin {
            return Ok(Step::Pending);
        }
        let op = self.opcode.take();
        self.fragments = 0;
        let text = std::mem::take(&mut self.text);
        let raw = std::mem::take(&mut self.raw);
        Ok(if op == Some(OP_BINARY) {
            Step::Binary
        } else {
            Step::Text { text, raw }
        })
    }
}

/// Follows a frame stream byte by byte to know when a frame (and a fragmented message) ends.
/// Used on the server→client direction, which is forwarded unbuffered.
#[derive(Debug, Default)]
pub struct FrameTracker {
    header: Vec<u8>,
    remaining: u64,
    in_message: bool,
    pending_fin: bool,
    pending_control: bool,
}

impl FrameTracker {
    /// Observe bytes forwarded in order.
    pub fn observe(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            if self.remaining > 0 {
                let n = (data.len() as u64).min(self.remaining);
                self.remaining -= n;
                data = &data[n as usize..];
                if self.remaining == 0 {
                    self.frame_done();
                }
                continue;
            }
            self.header.push(data[0]);
            data = &data[1..];
            if let Some(h) = parse_frame_header(&self.header) {
                self.header.clear();
                self.remaining = h.len;
                self.pending_fin = h.fin;
                self.pending_control = h.is_control();
                if !self.pending_control {
                    self.in_message = true;
                }
                if h.len == 0 {
                    self.frame_done();
                }
            }
        }
    }

    fn frame_done(&mut self) {
        if !self.pending_control && self.pending_fin {
            self.in_message = false;
        }
    }

    /// Whether a new frame may be injected here.
    pub fn at_boundary(&self) -> bool {
        self.header.is_empty() && self.remaining == 0 && !self.in_message
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn masked(opcode: u8, fin: bool, payload: &[u8]) -> Vec<u8> {
        let mask = [1, 2, 3, 4];
        let mut f = vec![(u8::from(fin) << 7) | opcode];
        match payload.len() {
            n if n < 126 => f.push(0x80 | n as u8),
            n => {
                f.push(0x80 | 126);
                f.extend_from_slice(&(n as u16).to_be_bytes());
            }
        }
        f.extend_from_slice(&mask);
        let mut p = payload.to_vec();
        unmask(&mut p, mask, 0);
        f.extend_from_slice(&p);
        f
    }

    #[test]
    fn header_lengths() {
        let h = parse_frame_header(&encode_frame(OP_TEXT, &[0; 5])).unwrap();
        assert_eq!((h.len, h.header_len, h.fin, h.mask), (5, 2, true, None));
        let h = parse_frame_header(&encode_frame(OP_TEXT, &[0; 300])).unwrap();
        assert_eq!((h.len, h.header_len), (300, 4));
        let h = parse_frame_header(&encode_frame(OP_BINARY, &vec![0; 70_000])).unwrap();
        assert_eq!((h.len, h.header_len), (70_000, 10));
        assert!(parse_frame_header(&[0x81]).is_none());
        assert!(parse_frame_header(&[0x81, 0xfe, 0]).is_none());
        // non-minimal length
        let h = parse_frame_header(&[0x81, 0x80 | 126, 0, 5, 1, 2, 3, 4]).unwrap();
        assert_eq!(validate_client(&h), Err(WsError::BadLength));
    }

    #[test]
    fn client_rules() {
        let v = |f: &[u8]| validate_client(&parse_frame_header(f).unwrap());
        assert_eq!(v(&masked(OP_TEXT, true, b"x")), Ok(()));
        assert_eq!(v(&encode_frame(OP_TEXT, b"x")), Err(WsError::Unmasked));
        let mut f = masked(OP_TEXT, true, b"x");
        f[0] |= 0x40;
        assert_eq!(v(&f), Err(WsError::Reserved));
        assert_eq!(v(&masked(0x3, true, b"x")), Err(WsError::BadOpcode));
        assert_eq!(v(&masked(OP_PING, false, b"x")), Err(WsError::BadControl));
        assert_eq!(
            v(&masked(OP_PING, true, &[0; 126])),
            Err(WsError::BadControl)
        );
    }

    #[test]
    fn reassembles_with_interleaved_control() {
        let mut a = Assembler::new(100);
        let f1 = masked(OP_TEXT, false, b"{\"a\":");
        let p = masked(OP_PING, true, b"hi");
        let f2 = masked(OP_CONT, true, b"1}");
        let push = |a: &mut Assembler, f: &[u8]| {
            let h = parse_frame_header(f).unwrap();
            a.push(&h, f.to_vec())
        };
        assert_eq!(push(&mut a, &f1), Ok(Step::Pending));
        assert_eq!(
            push(&mut a, &p),
            Ok(Step::Control {
                opcode: OP_PING,
                raw: p.clone()
            })
        );
        let Ok(Step::Text { text, raw }) = push(&mut a, &f2) else {
            panic!()
        };
        assert_eq!(text, b"{\"a\":1}");
        assert_eq!(raw, [f1, f2].concat());
        assert_eq!(
            push(&mut a, &masked(OP_CONT, true, b"x")),
            Err(WsError::BadFragmentation)
        );
        assert_eq!(
            push(&mut a, &masked(OP_BINARY, true, b"x")),
            Ok(Step::Binary)
        );
        assert_eq!(
            push(&mut a, &masked(OP_TEXT, true, &[b'a'; 101])),
            Err(WsError::TooLarge)
        );
        assert_eq!(
            push(&mut a, &masked(OP_TEXT, false, b"x")),
            Ok(Step::Pending)
        );
        assert_eq!(
            push(&mut a, &masked(OP_TEXT, true, b"x")),
            Err(WsError::BadFragmentation)
        );
    }

    #[test]
    fn tracker_boundaries() {
        let mut t = FrameTracker::default();
        assert!(t.at_boundary());
        let f = encode_frame(OP_TEXT, b"hello");
        t.observe(&f[..3]);
        assert!(!t.at_boundary());
        t.observe(&f[3..]);
        assert!(t.at_boundary());
        // fragmented message with a ping in the middle
        let mut first = encode_frame(OP_TEXT, b"ab");
        first[0] &= 0x7f;
        t.observe(&first);
        assert!(!t.at_boundary());
        t.observe(&encode_frame(OP_PING, b""));
        assert!(!t.at_boundary());
        t.observe(&encode_frame(OP_CONT, b"cd"));
        assert!(t.at_boundary());
        let big = encode_frame(OP_BINARY, &vec![7; 70_000]);
        for c in big.chunks(999) {
            t.observe(c);
        }
        assert!(t.at_boundary());
    }

    #[test]
    fn close_frame_truncates_reason() {
        let f = close_frame(1008, &"é".repeat(100));
        let h = parse_frame_header(&f).unwrap();
        assert!(h.len <= 125);
        assert!(std::str::from_utf8(&f[h.header_len + 2..]).is_ok());
    }
}
