//! QUIC client Initial packets: unprotect, decrypt, reassemble CRYPTO, parse the ClientHello.
//!
//! QUIC (RFC 9000) carries the TLS ClientHello in CRYPTO frames inside the client's first
//! Initial packet. That packet is encrypted, but only with keys derived from its own Destination
//! Connection ID and a public, version-specific salt (RFC 9001 §5.2, RFC 9369 §3.3.1), so any
//! on-path observer can read it. This module does exactly that, for QUIC v1 and v2:
//!
//! 1. parse the long header (version, connection IDs, token, length);
//! 2. derive the client Initial key/IV/header-protection key (HKDF-SHA256);
//! 3. remove header protection (AES-128-ECB mask over a 16-byte ciphertext sample);
//! 4. decrypt and authenticate the payload (AES-128-GCM);
//! 5. walk frames (PADDING, PING, ACK, CRYPTO; anything else is rejected) and reassemble CRYPTO
//!    data, including out-of-order offsets, into a fixed [`MAX_CRYPTO`]-byte buffer;
//! 6. hand the reassembled handshake bytes to [`ClientHello::parse`].
//!
//! Everything works in a caller-provided [`Scratch`]; there is no allocation. Only the first QUIC
//! packet of a datagram is examined (coalesced packets after it are ignored). A ClientHello that
//! does not fit in this one Initial packet (e.g. a large post-quantum key share spread over two
//! datagrams) is reported as [`Error::Truncated`], as for TLS over TCP.
//!
//! The AEAD tag is the real validity check: arbitrary bytes that merely look like a long header
//! fail authentication and come back as [`Error::Invalid`].

use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes_gcm::{AeadInPlace, Aes128Gcm};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::cursor::Cursor;
use crate::ja4::{self, Ja4, Transport};
use crate::tls::ClientHello;
use crate::{Error, Result};

/// Largest QUIC packet (header + payload) that is decrypted; larger ones are [`Error::Limit`].
pub const MAX_PACKET: usize = 4096;
/// Size of the CRYPTO reassembly buffer: CRYPTO data beyond this offset is [`Error::Limit`].
pub const MAX_CRYPTO: usize = 4096;
/// Hard cap on CRYPTO frames in one packet.
pub const MAX_CRYPTO_FRAMES: usize = 32;
/// Hard cap on non-PADDING frames in one packet.
pub const MAX_FRAMES: usize = 64;
/// Hard cap on additional ACK ranges in one ACK frame.
pub const MAX_ACK_RANGES: u64 = 64;

/// RFC 9000 §17.2: connection IDs are at most 20 bytes in QUIC v1 and v2.
const MAX_CID_LEN: usize = 20;
const TAG_LEN: usize = 16;
const SAMPLE_LEN: usize = 16;
/// The header-protection sample starts 4 bytes after the packet number offset (RFC 9001 §5.4.2).
const SAMPLE_OFFSET: usize = 4;

const SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

/// Frame types (RFC 9000 §19) that may appear in an Initial packet.
mod frame {
    pub const PADDING: u64 = 0x00;
    pub const PING: u64 = 0x01;
    pub const ACK: u64 = 0x02;
    pub const ACK_ECN: u64 = 0x03;
    pub const CRYPTO: u64 = 0x06;
    pub const CONNECTION_CLOSE: u64 = 0x1c;
}

/// A QUIC version whose Initial packets this module can decrypt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    /// QUIC version 1 (RFC 9000), wire value `0x00000001`.
    V1,
    /// QUIC version 2 (RFC 9369), wire value `0x6b3343cf`.
    V2,
}

impl Version {
    /// Map a wire version number to a supported version.
    pub fn from_wire(v: u32) -> Option<Self> {
        match v {
            0x0000_0001 => Some(Version::V1),
            0x6b33_43cf => Some(Version::V2),
            _ => None,
        }
    }

    /// The wire version number.
    pub fn wire(self) -> u32 {
        match self {
            Version::V1 => 0x0000_0001,
            Version::V2 => 0x6b33_43cf,
        }
    }

    /// Long-header packet type bits that mean "Initial" (RFC 9369 §3.2 swaps them in v2).
    fn initial_type(self) -> u8 {
        match self {
            Version::V1 => 0b00,
            Version::V2 => 0b01,
        }
    }

    fn salt(self) -> &'static [u8; 20] {
        match self {
            Version::V1 => &SALT_V1,
            Version::V2 => &SALT_V2,
        }
    }

    /// HKDF-Expand-Label labels for key, IV and header-protection key.
    fn labels(self) -> (&'static [u8], &'static [u8], &'static [u8]) {
        match self {
            Version::V1 => (b"quic key", b"quic iv", b"quic hp"),
            Version::V2 => (b"quicv2 key", b"quicv2 iv", b"quicv2 hp"),
        }
    }
}

/// Fixed-size working memory for [`parse_initial`]: one packet copy and the CRYPTO buffer.
///
/// About 8 KiB; reuse one per thread/flow rather than putting it on a small stack.
pub struct Scratch {
    packet: [u8; MAX_PACKET],
    crypto: [u8; MAX_CRYPTO],
}

impl Scratch {
    /// Zeroed scratch space.
    pub const fn new() -> Self {
        Self {
            packet: [0; MAX_PACKET],
            crypto: [0; MAX_CRYPTO],
        }
    }
}

impl Default for Scratch {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for Scratch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Scratch { .. }")
    }
}

/// A decrypted client Initial packet. Header fields borrow the datagram (`'d`); the CRYPTO data
/// and the ClientHello borrow the [`Scratch`] (`'s`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Initial<'d, 's> {
    /// QUIC version.
    pub version: Version,
    /// Destination Connection ID (the Initial keys are derived from it).
    pub dcid: &'d [u8],
    /// Source Connection ID.
    pub scid: &'d [u8],
    /// Address-validation token (empty unless the client received a Retry/NEW_TOKEN).
    pub token: &'d [u8],
    /// Truncated packet number as sent (1..=4 bytes); Initial packet numbers start at 0.
    pub packet_number: u32,
    /// CRYPTO stream bytes contiguous from offset 0.
    pub crypto: &'s [u8],
    /// The ClientHello parsed from [`Initial::crypto`].
    pub client_hello: ClientHello<'s>,
}

impl Initial<'_, '_> {
    /// JA4 fingerprint of the ClientHello, with the QUIC (`q`) transport marker.
    pub fn ja4(&self) -> Ja4 {
        ja4::ja4(&self.client_hello, Transport::Quic)
    }

    /// SNI as UTF-8, if present and valid.
    pub fn server_name(&self) -> Option<&str> {
        self.client_hello.server_name()
    }
}

/// Initial packet protection keys for one direction (RFC 9001 §5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Keys {
    pub(crate) key: [u8; 16],
    pub(crate) iv: [u8; 12],
    pub(crate) hp: [u8; 16],
}

/// Derive the client's Initial keys from the client-chosen Destination Connection ID.
pub(crate) fn client_initial_keys(version: Version, dcid: &[u8]) -> Result<Keys> {
    let (_, initial) = Hkdf::<Sha256>::extract(Some(version.salt()), dcid);
    let mut secret = [0u8; 32];
    expand_label(&initial, b"client in", &mut secret)?;
    let client = Hkdf::<Sha256>::from_prk(&secret).map_err(|_| Error::Invalid)?;
    let (key_label, iv_label, hp_label) = version.labels();
    let mut keys = Keys {
        key: [0; 16],
        iv: [0; 12],
        hp: [0; 16],
    };
    expand_label(&client, key_label, &mut keys.key)?;
    expand_label(&client, iv_label, &mut keys.iv)?;
    expand_label(&client, hp_label, &mut keys.hp)?;
    Ok(keys)
}

/// TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1) with an empty context.
fn expand_label(hk: &Hkdf<Sha256>, label: &[u8], out: &mut [u8]) -> Result<()> {
    const PREFIX: &[u8] = b"tls13 ";
    let mut info = [0u8; 32];
    let full = PREFIX.len() + label.len();
    let len = u16::try_from(out.len()).map_err(|_| Error::Invalid)?;
    let full_u8 = u8::try_from(full).map_err(|_| Error::Invalid)?;
    let n = 2 + 1 + full + 1;
    let dst = info.get_mut(..n).ok_or(Error::Invalid)?;
    dst[..2].copy_from_slice(&len.to_be_bytes());
    dst[2] = full_u8;
    dst[3..3 + PREFIX.len()].copy_from_slice(PREFIX);
    dst[3 + PREFIX.len()..3 + full].copy_from_slice(label);
    dst[3 + full] = 0; // empty context
    hk.expand(&info[..n], out).map_err(|_| Error::Invalid)
}

/// AES-128-ECB of the 16-byte sample: the header-protection mask (RFC 9001 §5.4.3).
pub(crate) fn hp_mask(hp: &[u8; 16], sample: &[u8; SAMPLE_LEN]) -> [u8; 16] {
    let cipher = Aes128::new(&GenericArray::from(*hp));
    let mut block = GenericArray::from(*sample);
    cipher.encrypt_block(&mut block);
    block.into()
}

/// The AEAD nonce: IV XOR the packet number, left-padded to 12 bytes (RFC 9001 §5.3).
pub(crate) fn nonce(iv: &[u8; 12], pn: u64) -> [u8; 12] {
    let mut n = *iv;
    for (d, p) in n[4..].iter_mut().zip(pn.to_be_bytes()) {
        *d ^= p;
    }
    n
}

/// QUIC variable-length integer (RFC 9000 §16).
fn varint(c: &mut Cursor<'_>) -> Result<u64> {
    let b0 = c.u8()?;
    let len = 1usize << (b0 >> 6);
    let mut v = u64::from(b0 & 0x3f);
    for _ in 1..len {
        v = (v << 8) | u64::from(c.u8()?);
    }
    Ok(v)
}

fn to_usize(v: u64) -> Result<usize> {
    usize::try_from(v).map_err(|_| Error::Limit)
}

/// Decrypt the first packet of `datagram` as a QUIC v1/v2 client Initial and parse its
/// ClientHello.
///
/// Errors: [`Error::Unsupported`] for short-header, Version Negotiation, unknown-version or
/// non-Initial packets, and for an Initial that only closes the connection; [`Error::Invalid`]
/// for malformed headers, failed authentication or forbidden frames; [`Error::Truncated`] when
/// the datagram is cut short or the ClientHello continues beyond this packet; [`Error::Limit`]
/// when a cap ([`MAX_PACKET`], [`MAX_CRYPTO`], frame counts) is hit.
pub fn parse_initial<'d, 's>(
    datagram: &'d [u8],
    scratch: &'s mut Scratch,
) -> Result<Initial<'d, 's>> {
    let mut c = Cursor::new(datagram);
    let first = c.u8()?;
    if first & 0x80 == 0 {
        return Err(Error::Unsupported); // short header: not an Initial
    }
    let version = Version::from_wire(c.u32()?).ok_or(Error::Unsupported)?;
    if (first >> 4) & 0b11 != version.initial_type() {
        return Err(Error::Unsupported); // 0-RTT, Handshake or Retry
    }
    let mut dcid = c.vec8()?;
    let mut scid = c.vec8()?;
    if dcid.remaining() > MAX_CID_LEN || scid.remaining() > MAX_CID_LEN {
        return Err(Error::Invalid);
    }
    let (dcid, scid) = (dcid.rest(), scid.rest());
    let token_len = to_usize(varint(&mut c)?)?;
    let token = c.bytes(token_len)?;
    let length = to_usize(varint(&mut c)?)?;
    let pn_offset = c.pos();
    // Room for the largest packet number plus the sample guarantees >= 16 bytes of ciphertext.
    if length < SAMPLE_OFFSET + SAMPLE_LEN {
        return Err(Error::Invalid);
    }
    let packet_len = pn_offset.checked_add(length).ok_or(Error::Limit)?;
    if packet_len > datagram.len() {
        return Err(Error::Truncated);
    }
    if packet_len > MAX_PACKET {
        return Err(Error::Limit);
    }

    let keys = client_initial_keys(version, dcid)?;
    let Scratch { packet, crypto } = scratch;
    let pkt = &mut packet[..packet_len];
    pkt.copy_from_slice(&datagram[..packet_len]);

    // Remove header protection.
    let sample_at = pn_offset + SAMPLE_OFFSET;
    let mut sample = [0u8; SAMPLE_LEN];
    sample.copy_from_slice(&pkt[sample_at..sample_at + SAMPLE_LEN]);
    let mask = hp_mask(&keys.hp, &sample);
    pkt[0] ^= mask[0] & 0x0f;
    let pn_len = usize::from(pkt[0] & 0x03) + 1;
    let mut pn = 0u32;
    for i in 0..pn_len {
        pkt[pn_offset + i] ^= mask[1 + i];
        pn = (pn << 8) | u32::from(pkt[pn_offset + i]);
    }

    // Decrypt and authenticate. The header (with packet number) is the associated data.
    let (header, body) = pkt.split_at_mut(pn_offset + pn_len);
    let (ciphertext, tag) = body.split_at_mut(body.len() - TAG_LEN);
    let mut tag_arr = [0u8; TAG_LEN];
    tag_arr.copy_from_slice(tag);
    Aes128Gcm::new(&GenericArray::from(keys.key))
        .decrypt_in_place_detached(
            &GenericArray::from(nonce(&keys.iv, u64::from(pn))),
            header,
            ciphertext,
            &GenericArray::from(tag_arr),
        )
        .map_err(|_| Error::Invalid)?;
    // Reserved bits are protected; once authenticated, non-zero is a protocol violation.
    if header[0] & 0x0c != 0 {
        return Err(Error::Invalid);
    }

    let n = reassemble_crypto(ciphertext, crypto)?;
    let crypto: &'s [u8] = &crypto[..n];
    let client_hello = ClientHello::parse(crypto)?;
    Ok(Initial {
        version,
        dcid,
        scid,
        token,
        packet_number: pn,
        crypto,
        client_hello,
    })
}

/// Walk the frames of a decrypted Initial payload and reassemble its CRYPTO data into `out`.
///
/// Returns how many bytes are contiguous from offset 0. CRYPTO frames may arrive in any order
/// and may overlap (later frames win). Frames other than PADDING, PING, ACK and CRYPTO are
/// rejected: CONNECTION_CLOSE as [`Error::Unsupported`], anything else as [`Error::Invalid`]
/// (RFC 9000 §17.2.2 forbids them in Initial packets).
pub fn reassemble_crypto(payload: &[u8], out: &mut [u8; MAX_CRYPTO]) -> Result<usize> {
    if payload.is_empty() {
        return Err(Error::Invalid); // a packet with no frames is a protocol violation
    }
    let mut ranges = [(0usize, 0usize); MAX_CRYPTO_FRAMES];
    let mut nranges = 0;
    let mut frames = 0;
    let mut c = Cursor::new(payload);
    while !c.is_empty() {
        let ty = varint(&mut c)?;
        if ty == frame::PADDING {
            continue; // one byte each; bounded by the payload length
        }
        frames += 1;
        if frames > MAX_FRAMES {
            return Err(Error::Limit);
        }
        match ty {
            frame::PING => {}
            frame::ACK | frame::ACK_ECN => {
                varint(&mut c)?; // largest acknowledged
                varint(&mut c)?; // ack delay
                let count = varint(&mut c)?;
                varint(&mut c)?; // first ack range
                if count > MAX_ACK_RANGES {
                    return Err(Error::Limit);
                }
                for _ in 0..count {
                    varint(&mut c)?; // gap
                    varint(&mut c)?; // ack range length
                }
                if ty == frame::ACK_ECN {
                    for _ in 0..3 {
                        varint(&mut c)?; // ECT0, ECT1, ECN-CE counts
                    }
                }
            }
            frame::CRYPTO => {
                let offset = varint(&mut c)?;
                let len = to_usize(varint(&mut c)?)?;
                let data = c.bytes(len)?;
                let start = to_usize(offset)?;
                let end = start.checked_add(len).ok_or(Error::Limit)?;
                if end > MAX_CRYPTO {
                    return Err(Error::Limit);
                }
                if len == 0 {
                    continue;
                }
                if nranges == MAX_CRYPTO_FRAMES {
                    return Err(Error::Limit);
                }
                out[start..end].copy_from_slice(data);
                ranges[nranges] = (start, end);
                nranges += 1;
            }
            frame::CONNECTION_CLOSE => return Err(Error::Unsupported),
            _ => return Err(Error::Invalid),
        }
    }
    // Contiguous prefix: each pass extends it or stops, so at most `nranges` passes.
    let mut covered = 0;
    for _ in 0..nranges {
        let before = covered;
        for &(s, e) in &ranges[..nranges] {
            if s <= covered && e > covered {
                covered = e;
            }
        }
        if covered == before {
            break;
        }
    }
    Ok(covered)
}

#[cfg(test)]
mod tests {
    use super::*;

    const V1_PACKET: &str = include_str!("../testdata/rfc9001_client_initial.hex");
    const V2_PACKET: &str = include_str!("../testdata/rfc9369_client_initial.hex");
    /// The CRYPTO frame both RFC client Initials carry (before PADDING).
    const CRYPTO_FRAME: &str = include_str!("../testdata/client_initial_crypto_frame.hex");
    const DCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

    fn hex<const N: usize>(s: &str) -> ([u8; N], usize) {
        let s = s.trim().as_bytes();
        let mut out = [0u8; N];
        assert!(s.len().is_multiple_of(2) && s.len() / 2 <= N);
        let nib = |c: u8| (c as char).to_digit(16).unwrap() as u8;
        for (i, p) in s.chunks(2).enumerate() {
            out[i] = (nib(p[0]) << 4) | nib(p[1]);
        }
        (out, s.len() / 2)
    }

    fn hex16(s: &str) -> [u8; 16] {
        hex::<16>(s).0
    }

    /// Protect a client Initial with an 8-byte DCID, empty SCID/token, 4-byte packet number.
    /// Returns the packet length. Mirrors RFC 9001 §5 so the RFC vector checks it.
    fn seal(version: Version, pn: u32, payload: &[u8], out: &mut [u8; 2048]) -> usize {
        let keys = client_initial_keys(version, &DCID).unwrap();
        let first = 0xc0 | (version.initial_type() << 4) | 0x03;
        let length = (4 + payload.len() + TAG_LEN) as u16;
        let mut n = 0;
        let mut put = |b: &[u8], n: &mut usize| {
            out[*n..*n + b.len()].copy_from_slice(b);
            *n += b.len();
        };
        put(&[first], &mut n);
        put(&version.wire().to_be_bytes(), &mut n);
        put(&[DCID.len() as u8], &mut n);
        put(&DCID, &mut n);
        put(&[0, 0], &mut n); // SCID len, token len
        put(&(0x4000 | length).to_be_bytes(), &mut n);
        let pn_offset = n;
        put(&pn.to_be_bytes(), &mut n);
        put(payload, &mut n);
        let (header, body) = out[..n].split_at_mut(pn_offset + 4);
        let tag = Aes128Gcm::new(&GenericArray::from(keys.key))
            .encrypt_in_place_detached(
                &GenericArray::from(nonce(&keys.iv, u64::from(pn))),
                header,
                body,
            )
            .unwrap();
        out[n..n + TAG_LEN].copy_from_slice(&tag);
        n += TAG_LEN;
        let mut sample = [0u8; 16];
        sample.copy_from_slice(&out[pn_offset + 4..pn_offset + 20]);
        let mask = hp_mask(&keys.hp, &sample);
        out[0] ^= mask[0] & 0x0f;
        for i in 0..4 {
            out[pn_offset + i] ^= mask[1 + i];
        }
        n
    }

    /// The RFC's unprotected payload: the CRYPTO frame padded to 1162 bytes.
    fn rfc_payload() -> [u8; 1162] {
        let (frame, n) = hex::<512>(CRYPTO_FRAME);
        let mut p = [0u8; 1162];
        p[..n].copy_from_slice(&frame[..n]);
        p
    }

    #[test]
    fn rfc9001_a1_keys() {
        let k = client_initial_keys(Version::V1, &DCID).unwrap();
        assert_eq!(k.key, hex16("1f369613dd76d5467730efcbe3b1a22d"));
        assert_eq!(k.iv, hex::<12>("fa044b2f42a3fd3b46fb255c").0);
        assert_eq!(k.hp, hex16("9f50449e04a0e810283a1e9933adedd2"));
        let mask = hp_mask(&k.hp, &hex16("d1b1c98dd7689fb8ec11d242b123dc9b"));
        assert_eq!(&mask[..5], &hex::<5>("437b9aec36").0);
    }

    #[test]
    fn rfc9369_a1_keys() {
        let k = client_initial_keys(Version::V2, &DCID).unwrap();
        assert_eq!(k.key, hex16("8b1a0bc121284290a29e0971b5cd045d"));
        assert_eq!(k.iv, hex::<12>("91f73e2351d8fa91660e909f").0);
        assert_eq!(k.hp, hex16("45b95e15235d6f45a6b19cbcb0294ba9"));
        let mask = hp_mask(&k.hp, &hex16("ffe67b6abcdb4298b485dd04de806071"));
        assert_eq!(&mask[..5], &hex::<5>("94a0c95e80").0);
    }

    fn check_rfc_vector(packet_hex: &str, version: Version) {
        let (pkt, n) = hex::<1200>(packet_hex);
        assert_eq!(n, 1200);
        let mut s = Scratch::new();
        let init = parse_initial(&pkt, &mut s).unwrap();
        assert_eq!(init.version, version);
        assert_eq!(init.dcid, &DCID);
        assert!(init.scid.is_empty() && init.token.is_empty());
        assert_eq!(init.packet_number, 2);
        // CRYPTO frame header is 06 00 40f1: offset 0, 241 bytes of ClientHello.
        let (frame, fl) = hex::<512>(CRYPTO_FRAME);
        assert_eq!(init.crypto, &frame[4..fl]);
        let h = init.client_hello;
        assert_eq!(init.server_name(), Some("example.com"));
        let alpn: [&[u8]; 1] = [b"alpn"];
        assert!(h.alpn_protocols().eq(alpn.iter().copied()));
        assert_eq!(h.max_version(), 0x0304);
        let ja4 = init.ja4();
        assert_eq!(ja4.as_str().as_bytes()[0], b'q');
        assert_eq!(&ja4.as_str()[..10], "q13d0211an");
    }

    #[test]
    fn rfc9001_a2_client_initial() {
        check_rfc_vector(V1_PACKET, Version::V1);
    }

    #[test]
    fn rfc9369_a2_client_initial() {
        check_rfc_vector(V2_PACKET, Version::V2);
    }

    #[test]
    fn seal_reproduces_rfc_vectors() {
        for (v, hexpkt) in [(Version::V1, V1_PACKET), (Version::V2, V2_PACKET)] {
            let (want, wn) = hex::<1200>(hexpkt);
            let mut out = [0u8; 2048];
            let n = seal(v, 2, &rfc_payload(), &mut out);
            assert_eq!(&out[..n], &want[..wn], "{v:?}");
        }
    }

    #[test]
    fn coalesced_trailing_bytes_are_ignored() {
        let (pkt, _) = hex::<1200>(V1_PACKET);
        let mut d = [0xffu8; 1300];
        d[..1200].copy_from_slice(&pkt);
        let mut s = Scratch::new();
        assert!(parse_initial(&d, &mut s).is_ok());
    }

    #[test]
    fn out_of_order_crypto_frames_with_ping_and_ack() {
        let (frame, fl) = hex::<512>(CRYPTO_FRAME);
        let hello = &frame[4..fl]; // 241 bytes
        let (a, b) = hello.split_at(100);
        let mut p = [0u8; 1200];
        let mut n = 0;
        let mut put = |x: &[u8], n: &mut usize| {
            p[*n..*n + x.len()].copy_from_slice(x);
            *n += x.len();
        };
        put(&[0x01], &mut n); // PING
        put(&[0x02, 0x05, 0x00, 0x01, 0x00, 0x01, 0x02], &mut n); // ACK w/ one extra range
        put(&[0x06, 0x40, 100, 0x40, b.len() as u8], &mut n); // second half first
        put(b, &mut n);
        put(&[0x00, 0x00], &mut n); // PADDING between
        put(&[0x06, 0x00, 0x40, a.len() as u8], &mut n);
        put(a, &mut n);
        let mut out = [0u8; 2048];
        let len = seal(Version::V1, 0, &p[..1150], &mut out);
        let mut s = Scratch::new();
        let init = parse_initial(&out[..len], &mut s).unwrap();
        assert_eq!(init.crypto, hello);
        assert_eq!(init.server_name(), Some("example.com"));
        assert_eq!(init.packet_number, 0);
    }

    #[test]
    fn gap_in_crypto_is_truncated() {
        let (frame, fl) = hex::<512>(CRYPTO_FRAME);
        let hello = &frame[4..fl];
        let mut p = [0u8; 1162];
        p[..4].copy_from_slice(&[0x06, 0x40, 10, 0x40]);
        p[4] = (hello.len() - 10) as u8;
        p[5..5 + hello.len() - 10].copy_from_slice(&hello[10..]);
        let mut out = [0u8; 2048];
        let len = seal(Version::V2, 0, &p, &mut out);
        let mut s = Scratch::new();
        assert_eq!(
            parse_initial(&out[..len], &mut s).unwrap_err(),
            Error::Truncated
        );
    }

    #[test]
    fn forbidden_and_close_frames() {
        let mut buf = [0u8; MAX_CRYPTO];
        // STREAM frame (0x08) is not allowed in Initial packets.
        assert_eq!(
            reassemble_crypto(&[0x08, 0, 0], &mut buf),
            Err(Error::Invalid)
        );
        assert_eq!(
            reassemble_crypto(&[0x1c, 0, 0, 0], &mut buf),
            Err(Error::Unsupported)
        );
        assert_eq!(reassemble_crypto(&[], &mut buf), Err(Error::Invalid));
        // CRYPTO beyond the reassembly buffer
        assert_eq!(
            reassemble_crypto(&[0x06, 0x50, 0x00, 0x01, 0xaa], &mut buf),
            Err(Error::Limit)
        );
        // only PADDING: valid, no CRYPTO data
        assert_eq!(reassemble_crypto(&[0; 10], &mut buf), Ok(0));
    }

    #[test]
    fn tampering_fails_authentication() {
        let (mut pkt, _) = hex::<1200>(V1_PACKET);
        pkt[600] ^= 1;
        let mut s = Scratch::new();
        assert_eq!(parse_initial(&pkt, &mut s).unwrap_err(), Error::Invalid);
        // A v1 packet relabelled as v2 derives different keys.
        let (mut pkt, _) = hex::<1200>(V1_PACKET);
        pkt[0] = (pkt[0] & 0xcf) | 0x10;
        pkt[1..5].copy_from_slice(&Version::V2.wire().to_be_bytes());
        assert_eq!(parse_initial(&pkt, &mut s).unwrap_err(), Error::Invalid);
    }

    #[test]
    fn rejects_non_initial_headers() {
        let (pkt, _) = hex::<1200>(V1_PACKET);
        let mut s = Scratch::new();
        let mut p = pkt;
        p[0] &= 0x7f; // short header
        assert_eq!(parse_initial(&p, &mut s), Err(Error::Unsupported));
        let mut p = pkt;
        p[1..5].copy_from_slice(&[0, 0, 0, 0]); // version negotiation
        assert_eq!(parse_initial(&p, &mut s), Err(Error::Unsupported));
        let mut p = pkt;
        p[0] |= 0x20; // v1 Handshake packet type
        assert_eq!(parse_initial(&p, &mut s), Err(Error::Unsupported));
        let mut p = pkt;
        p[5] = 21; // DCID too long
        assert_eq!(parse_initial(&p, &mut s), Err(Error::Invalid));
    }

    #[test]
    fn every_truncation_is_an_error_not_a_panic() {
        let (pkt, _) = hex::<1200>(V2_PACKET);
        let mut s = Scratch::new();
        for cut in 0..pkt.len() {
            assert!(parse_initial(&pkt[..cut], &mut s).is_err(), "cut at {cut}");
        }
    }

    proptest::proptest! {
        #[test]
        fn never_panics(data in proptest::collection::vec(proptest::num::u8::ANY, 0..1500)) {
            let mut s = Scratch::new();
            let _ = parse_initial(&data, &mut s);
        }

        #[test]
        fn frames_never_panic(data in proptest::collection::vec(proptest::num::u8::ANY, 0..1500)) {
            let mut out = [0u8; MAX_CRYPTO];
            if let Ok(n) = reassemble_crypto(&data, &mut out) {
                proptest::prop_assert!(n <= MAX_CRYPTO);
                let _ = ClientHello::parse(&out[..n]);
            }
        }

        #[test]
        fn mutated_header_never_panics(pos in 0usize..64, val in proptest::num::u8::ANY) {
            let (mut pkt, _) = hex::<1200>(V1_PACKET);
            pkt[pos] = val;
            let mut s = Scratch::new();
            let _ = parse_initial(&pkt, &mut s);
        }
    }
}
