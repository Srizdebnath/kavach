//! TLS ClientHello parsing: SNI, ALPN, versions, and the raw lists JA4 needs.
//!
//! Accepts either a full TLS record (`0x16 …`) or a bare handshake message (`0x01 …`, as found
//! in a QUIC CRYPTO frame). Only the first record is parsed; a ClientHello split across records
//! is reported as [`Error::Truncated`] so the caller can buffer more bytes.

use crate::cursor::Cursor;
use crate::{Error, Result};

/// Extension type numbers used here.
pub mod ext {
    /// server_name (RFC 6066)
    pub const SERVER_NAME: u16 = 0x0000;
    /// signature_algorithms (RFC 8446)
    pub const SIGNATURE_ALGORITHMS: u16 = 0x000d;
    /// application_layer_protocol_negotiation (RFC 7301)
    pub const ALPN: u16 = 0x0010;
    /// supported_versions (RFC 8446)
    pub const SUPPORTED_VERSIONS: u16 = 0x002b;
}

/// Hard cap on extensions we walk (real clients send < 30).
pub const MAX_EXTENSIONS: usize = 64;

/// RFC 8701 GREASE values: `0x?a?a` with equal bytes.
pub fn is_grease(v: u16) -> bool {
    (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff)
}

/// A parsed ClientHello. All slices borrow from the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientHello<'a> {
    /// `legacy_version` from the hello body.
    pub legacy_version: u16,
    /// Raw cipher suite list (pairs of bytes, wire order).
    pub cipher_suites: &'a [u8],
    /// Raw extensions block (type, len, data …), wire order.
    pub extensions: &'a [u8],
    /// Host name from server_name, if present and well formed.
    pub sni: Option<&'a [u8]>,
    /// Raw ALPN protocol list (u8-length-prefixed entries), if present.
    pub alpn: Option<&'a [u8]>,
    /// Raw supported_versions list (pairs of bytes), if present.
    pub supported_versions: Option<&'a [u8]>,
    /// Raw signature_algorithms list (pairs of bytes), if present.
    pub signature_algorithms: Option<&'a [u8]>,
}

impl<'a> ClientHello<'a> {
    /// Parse a TLS record or bare handshake message containing a ClientHello.
    pub fn parse(input: &'a [u8]) -> Result<Self> {
        let mut c = Cursor::new(input);
        let first = *input.first().ok_or(Error::Truncated)?;
        let mut hs = if first == 0x16 {
            // TLS record: content type, legacy record version 3.x, u16 length
            c.u8()?;
            if c.u16()? >> 8 != 0x03 {
                return Err(Error::Invalid);
            }
            c.vec16()?
        } else {
            c
        };
        if hs.u8()? != 0x01 {
            return Err(Error::Unsupported);
        }
        let len = hs.u24()? as usize;
        let mut body = Cursor::new(hs.bytes(len)?);

        let legacy_version = body.u16()?;
        body.bytes(32)?; // random
        let sid = body.vec8()?;
        if sid.remaining() > 32 {
            return Err(Error::Invalid);
        }
        let mut cs = body.vec16()?;
        if cs.remaining() % 2 != 0 || cs.is_empty() {
            return Err(Error::Invalid);
        }
        let cipher_suites = cs.rest();
        let comp = body.vec8()?;
        if comp.is_empty() {
            return Err(Error::Invalid);
        }
        let mut hello = ClientHello {
            legacy_version,
            cipher_suites,
            extensions: &[],
            sni: None,
            alpn: None,
            supported_versions: None,
            signature_algorithms: None,
        };
        if body.is_empty() {
            return Ok(hello); // pre-TLS1.2 hello without extensions
        }
        let mut exts = body.vec16()?;
        hello.extensions = {
            let mut copy = exts;
            copy.rest()
        };
        let mut n = 0;
        while !exts.is_empty() {
            n += 1;
            if n > MAX_EXTENSIONS {
                return Err(Error::Limit);
            }
            let ty = exts.u16()?;
            let mut data = exts.vec16()?;
            match ty {
                ext::SERVER_NAME => hello.sni = parse_sni(&mut data)?,
                ext::ALPN => {
                    let mut list = data.vec16()?;
                    let raw = {
                        let mut copy = list;
                        copy.rest()
                    };
                    // validate entries
                    while !list.is_empty() {
                        if list.vec8()?.is_empty() {
                            return Err(Error::Invalid);
                        }
                    }
                    hello.alpn = Some(raw);
                }
                ext::SUPPORTED_VERSIONS => {
                    let mut v = data.vec8()?;
                    if v.remaining() % 2 != 0 {
                        return Err(Error::Invalid);
                    }
                    hello.supported_versions = Some(v.rest());
                }
                ext::SIGNATURE_ALGORITHMS => {
                    let mut v = data.vec16()?;
                    if v.remaining() % 2 != 0 {
                        return Err(Error::Invalid);
                    }
                    hello.signature_algorithms = Some(v.rest());
                }
                _ => {}
            }
        }
        Ok(hello)
    }

    /// Iterate extension type numbers in wire order.
    pub fn extension_types(&self) -> impl Iterator<Item = u16> + 'a {
        let mut c = Cursor::new(self.extensions);
        core::iter::from_fn(move || {
            if c.is_empty() {
                return None;
            }
            let ty = c.u16().ok()?;
            c.vec16().ok()?;
            Some(ty)
        })
        .take(MAX_EXTENSIONS)
    }

    /// Cipher suites in wire order.
    pub fn ciphers(&self) -> impl Iterator<Item = u16> + 'a {
        pairs(self.cipher_suites)
    }

    /// ALPN protocols in wire order.
    pub fn alpn_protocols(&self) -> impl Iterator<Item = &'a [u8]> + 'a {
        let mut c = Cursor::new(self.alpn.unwrap_or(&[]));
        core::iter::from_fn(move || {
            if c.is_empty() {
                return None;
            }
            let mut e = c.vec8().ok()?;
            Some(e.rest())
        })
    }

    /// Highest non-GREASE version offered (supported_versions, else legacy_version).
    pub fn max_version(&self) -> u16 {
        match self.supported_versions {
            Some(v) => pairs(v)
                .filter(|v| !is_grease(*v))
                .max()
                .unwrap_or(self.legacy_version),
            None => self.legacy_version,
        }
    }

    /// SNI as UTF-8, if it is valid.
    pub fn server_name(&self) -> Option<&'a str> {
        core::str::from_utf8(self.sni?).ok()
    }
}

pub(crate) fn pairs(b: &[u8]) -> impl Iterator<Item = u16> + '_ {
    b.as_chunks::<2>().0.iter().map(|p| u16::from_be_bytes(*p))
}

fn parse_sni<'a>(data: &mut Cursor<'a>) -> Result<Option<&'a [u8]>> {
    let mut list = data.vec16()?;
    while !list.is_empty() {
        let ty = list.u8()?;
        let mut name = list.vec16()?;
        let name = name.rest();
        if ty == 0 {
            // RFC 6066: no trailing dot, LDH + '.', 1..=255 bytes.
            if name.is_empty() || name.len() > 255 || !name.iter().all(|b| b.is_ascii_graphic()) {
                return Err(Error::Invalid);
            }
            return Ok(Some(name));
        }
    }
    Ok(None)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A Chrome-like ClientHello (synthetic but structurally exact), returned with its length.
    pub(crate) fn sample(buf: &mut [u8; 512]) -> usize {
        let mut w = W { b: buf, n: 0 };
        // record header patched later
        w.put(&[0x16, 0x03, 0x01, 0, 0]);
        w.put(&[0x01, 0, 0, 0]); // handshake header, len patched
        let hs_start = w.n;
        w.put(&[0x03, 0x03]);
        w.put(&[0x11; 32]);
        w.put(&[0x00]); // empty session id
        let ciphers: [u16; 4] = [0x0a0a, 0x1301, 0x1302, 0xc02b];
        w.put(&((ciphers.len() * 2) as u16).to_be_bytes());
        for c in ciphers {
            w.put(&c.to_be_bytes());
        }
        w.put(&[0x01, 0x00]); // compression: null
        let ext_len_at = w.n;
        w.put(&[0, 0]);
        let ext_start = w.n;
        // GREASE ext
        w.put(&[0x1a, 0x1a, 0, 0]);
        // SNI "example.com"
        let host = b"example.com";
        w.put(&ext::SERVER_NAME.to_be_bytes());
        w.put(&((host.len() + 5) as u16).to_be_bytes());
        w.put(&((host.len() + 3) as u16).to_be_bytes());
        w.put(&[0]);
        w.put(&(host.len() as u16).to_be_bytes());
        w.put(host);
        // supported groups (opaque to us)
        w.put(&[0x00, 0x0a, 0, 4, 0, 2, 0x00, 0x1d]);
        // ALPN h2, http/1.1
        w.put(&ext::ALPN.to_be_bytes());
        w.put(&14u16.to_be_bytes());
        w.put(&12u16.to_be_bytes());
        w.put(&[2, b'h', b'2', 8]);
        w.put(b"http/1.1");
        // signature algorithms
        w.put(&ext::SIGNATURE_ALGORITHMS.to_be_bytes());
        w.put(&8u16.to_be_bytes());
        w.put(&6u16.to_be_bytes());
        w.put(&[0x04, 0x03, 0x08, 0x04, 0x04, 0x01]);
        // supported versions: GREASE, 1.3, 1.2
        w.put(&ext::SUPPORTED_VERSIONS.to_be_bytes());
        w.put(&7u16.to_be_bytes());
        w.put(&[6, 0x3a, 0x3a, 0x03, 0x04, 0x03, 0x03]);
        let ext_len = (w.n - ext_start) as u16;
        w.b[ext_len_at..ext_len_at + 2].copy_from_slice(&ext_len.to_be_bytes());
        let hs_len = (w.n - hs_start) as u32;
        w.b[6..9].copy_from_slice(&hs_len.to_be_bytes()[1..]);
        let rec_len = (w.n - 5) as u16;
        w.b[3..5].copy_from_slice(&rec_len.to_be_bytes());
        w.n
    }

    struct W<'a> {
        b: &'a mut [u8; 512],
        n: usize,
    }
    impl W<'_> {
        fn put(&mut self, s: &[u8]) {
            self.b[self.n..self.n + s.len()].copy_from_slice(s);
            self.n += s.len();
        }
    }

    #[test]
    fn parses_sni_alpn_versions() {
        let mut b = [0u8; 512];
        let n = sample(&mut b);
        let h = ClientHello::parse(&b[..n]).unwrap();
        assert_eq!(h.server_name(), Some("example.com"));
        let alpn: [&[u8]; 2] = [b"h2", b"http/1.1"];
        assert!(h.alpn_protocols().eq(alpn.iter().copied()));
        assert_eq!(h.max_version(), 0x0304);
        assert_eq!(h.ciphers().count(), 4);
        assert_eq!(h.extension_types().count(), 6);
        // the bare handshake (QUIC CRYPTO frame form) parses identically
        assert_eq!(ClientHello::parse(&b[5..n]).unwrap(), h);
    }

    #[test]
    fn every_truncation_is_an_error_not_a_panic() {
        let mut b = [0u8; 512];
        let n = sample(&mut b);
        for cut in 0..n {
            assert!(ClientHello::parse(&b[..cut]).is_err(), "cut at {cut}");
        }
    }

    #[test]
    fn rejects_non_hello() {
        assert_eq!(
            ClientHello::parse(&[0x02, 0, 0, 0]),
            Err(Error::Unsupported)
        );
        assert_eq!(
            ClientHello::parse(&[0x16, 0x04, 0x00, 0, 0]),
            Err(Error::Invalid)
        );
    }

    proptest::proptest! {
        #[test]
        fn never_panics(data in proptest::collection::vec(proptest::num::u8::ANY, 0..600)) {
            let _ = ClientHello::parse(&data);
        }

        #[test]
        fn mutated_hello_never_panics(pos in 0usize..300, val in proptest::num::u8::ANY) {
            let mut b = [0u8; 512];
            let n = sample(&mut b);
            b[pos % n] = val;
            if let Ok(h) = ClientHello::parse(&b[..n]) {
                let _ = crate::ja4::ja4(&h, crate::ja4::Transport::Tcp);
            }
        }
    }
}
