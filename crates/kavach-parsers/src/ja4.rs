//! JA4 TLS client fingerprint (FoxIO JA4 spec), computed without allocation.
//!
//! `JA4 = a_b_c`
//! * `a` = transport (`t`/`q`) ‖ TLS version (`13`, `12`, …) ‖ `d` (SNI present) or `i`
//!   ‖ 2-digit cipher count ‖ 2-digit extension count ‖ first+last char of the first ALPN.
//! * `b` = first 12 hex of SHA-256 over the sorted cipher list (`"1301,1302,…"`).
//! * `c` = first 12 hex of SHA-256 over the sorted extension list without SNI/ALPN, then `_`
//!   and the signature algorithms in wire order.
//!
//! GREASE values are ignored everywhere.

use sha2::{Digest, Sha256};

use crate::tls::{ClientHello, ext, is_grease, pairs};

/// Transport the ClientHello arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// TLS over TCP.
    Tcp,
    /// QUIC (ClientHello in a CRYPTO frame).
    Quic,
}

/// A JA4 fingerprint: always 36 ASCII bytes, e.g. `t13d1516h2_8daaf6152771_e5627efa2ab1`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ja4(pub [u8; 36]);

impl Ja4 {
    /// The fingerprint as a string.
    pub fn as_str(&self) -> &str {
        // Only ASCII is ever written into the buffer.
        core::str::from_utf8(&self.0).unwrap_or("")
    }
}

impl core::fmt::Debug for Ja4 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl core::fmt::Display for Ja4 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";
const MAX_LIST: usize = 128;

/// Compute JA4 for a parsed ClientHello.
pub fn ja4(h: &ClientHello<'_>, transport: Transport) -> Ja4 {
    let mut out = [b'0'; 36];
    out[0] = if transport == Transport::Tcp {
        b't'
    } else {
        b'q'
    };
    let v = match h.max_version() {
        0x0304 => *b"13",
        0x0303 => *b"12",
        0x0302 => *b"11",
        0x0301 => *b"10",
        0x0300 => *b"s3",
        0xfeff => *b"d1",
        0xfefd => *b"d2",
        0xfefc => *b"d3",
        _ => *b"00",
    };
    out[1..3].copy_from_slice(&v);
    out[3] = if h.sni.is_some() { b'd' } else { b'i' };

    let (mut ciphers, nc) = collect(h.ciphers());
    let (mut exts, ne) = collect(h.extension_types());
    two_digits(&mut out[4..6], nc);
    two_digits(&mut out[6..8], ne);
    match h.alpn_protocols().next() {
        Some(a) if !a.is_empty() => {
            let (f, l) = (a[0], a[a.len() - 1]);
            if f.is_ascii_alphanumeric() && l.is_ascii_alphanumeric() {
                out[8] = f;
                out[9] = l;
            } else {
                out[8] = HEX[(f >> 4) as usize];
                out[9] = HEX[(l & 0xf) as usize];
            }
        }
        _ => {}
    }
    out[10] = b'_';
    out[23] = b'_';

    // b: sorted ciphers
    ciphers[..nc].sort_unstable();
    if nc == 0 {
        out[11..23].copy_from_slice(b"000000000000");
    } else {
        let mut hs = Sha256::new();
        hash_list(&mut hs, &ciphers[..nc]);
        trunc_hex(&mut out[11..23], hs);
    }

    // c: sorted extensions without SNI/ALPN, then signature algorithms in wire order
    let mut n = 0;
    for i in 0..ne {
        if exts[i] != ext::SERVER_NAME && exts[i] != ext::ALPN {
            exts[n] = exts[i];
            n += 1;
        }
    }
    exts[..n].sort_unstable();
    if ne == 0 {
        out[24..36].copy_from_slice(b"000000000000");
    } else {
        let mut hs = Sha256::new();
        hash_list(&mut hs, &exts[..n]);
        if let Some(sa) = h.signature_algorithms {
            let (sigs, ns) = collect(pairs(sa));
            if ns > 0 {
                hs.update(b"_");
                hash_list(&mut hs, &sigs[..ns]);
            }
        }
        trunc_hex(&mut out[24..36], hs);
    }
    Ja4(out)
}

fn collect(it: impl Iterator<Item = u16>) -> ([u16; MAX_LIST], usize) {
    let mut a = [0u16; MAX_LIST];
    let mut n = 0;
    for v in it.filter(|v| !is_grease(*v)) {
        if n == MAX_LIST {
            break;
        }
        a[n] = v;
        n += 1;
    }
    (a, n)
}

fn two_digits(dst: &mut [u8], n: usize) {
    let n = n.min(99);
    dst[0] = b'0' + (n / 10) as u8;
    dst[1] = b'0' + (n % 10) as u8;
}

fn hash_list(h: &mut Sha256, vals: &[u16]) {
    for (i, v) in vals.iter().enumerate() {
        if i > 0 {
            h.update(b",");
        }
        let b = v.to_be_bytes();
        h.update([
            HEX[(b[0] >> 4) as usize],
            HEX[(b[0] & 0xf) as usize],
            HEX[(b[1] >> 4) as usize],
            HEX[(b[1] & 0xf) as usize],
        ]);
    }
}

fn trunc_hex(dst: &mut [u8], h: Sha256) {
    let d = h.finalize();
    for i in 0..6 {
        dst[2 * i] = HEX[(d[i] >> 4) as usize];
        dst[2 * i + 1] = HEX[(d[i] & 0xf) as usize];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha12(s: &str) -> [u8; 12] {
        let d = Sha256::digest(s.as_bytes());
        let mut o = [0u8; 12];
        trunc_hex_bytes(&mut o, &d);
        o
    }
    fn trunc_hex_bytes(dst: &mut [u8], d: &[u8]) {
        for i in 0..6 {
            dst[2 * i] = HEX[(d[i] >> 4) as usize];
            dst[2 * i + 1] = HEX[(d[i] & 0xf) as usize];
        }
    }

    #[test]
    fn matches_spec_construction() {
        let mut b = [0u8; 512];
        let n = crate::tls::tests::sample(&mut b);
        let h = ClientHello::parse(&b[..n]).unwrap();
        let j = ja4(&h, Transport::Tcp);
        // 3 real ciphers, 5 non-GREASE extensions, ALPN h2
        assert_eq!(&j.as_str()[..11], "t13d0305h2_");
        assert_eq!(&j.0[11..23], &sha12("1301,1302,c02b"));
        assert_eq!(&j.0[24..36], &sha12("000a,000d,002b_0403,0804,0401"));
        assert_eq!(ja4(&h, Transport::Quic).as_str().as_bytes()[0], b'q');
    }

    #[test]
    fn no_sni_no_alpn() {
        let mut b = [0u8; 512];
        let n = crate::tls::tests::sample(&mut b);
        let mut h = ClientHello::parse(&b[..n]).unwrap();
        h.sni = None;
        h.alpn = None;
        let j = ja4(&h, Transport::Tcp);
        assert_eq!(&j.as_str()[3..4], "i");
        assert_eq!(&j.as_str()[8..10], "00");
    }
}
