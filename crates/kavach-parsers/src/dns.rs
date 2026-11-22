//! DNS message parsing (RFC 1035) for answer snooping and FQDN policy.
//!
//! Name decompression is bounded: at most [`MAX_JUMPS`] pointers, every pointer must point
//! strictly backwards (so a loop is impossible even below the cap), and decoded names are capped
//! at 255 bytes.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::cursor::Cursor;
use crate::{Error, Result};

/// Maximum compression pointers followed while decoding one name.
pub const MAX_JUMPS: usize = 16;
/// Maximum resource records walked per section.
pub const MAX_RECORDS: u16 = 256;

/// Record types we interpret.
pub mod rtype {
    /// IPv4 address
    pub const A: u16 = 1;
    /// Canonical name
    pub const CNAME: u16 = 5;
    /// IPv6 address
    pub const AAAA: u16 = 28;
}

/// A decoded domain name: lowercase, dot-separated, no trailing dot (root = empty).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Name {
    buf: [u8; 255],
    len: u8,
}

impl Name {
    /// The name as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }
    /// The name as a str (labels are validated to printable ASCII).
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes()).unwrap_or("")
    }
    /// Case-insensitive comparison with a dotted name (a trailing dot is ignored).
    pub fn eq_ignore_case(&self, other: &str) -> bool {
        self.as_bytes()
            .eq_ignore_ascii_case(other.trim_end_matches('.').as_bytes())
    }
}

impl core::fmt::Debug for Name {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self.as_str())
    }
}

/// Fixed DNS header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Transaction id.
    pub id: u16,
    /// Flags word (QR, opcode, AA, TC, RD, RA, rcode).
    pub flags: u16,
    /// Question count.
    pub qdcount: u16,
    /// Answer count.
    pub ancount: u16,
    /// Authority count.
    pub nscount: u16,
    /// Additional count.
    pub arcount: u16,
}

impl Header {
    /// True for responses.
    pub fn is_response(&self) -> bool {
        self.flags & 0x8000 != 0
    }
    /// Response code (0 = NOERROR).
    pub fn rcode(&self) -> u8 {
        (self.flags & 0xf) as u8
    }
    /// Truncated (TC) bit.
    pub fn truncated(&self) -> bool {
        self.flags & 0x0200 != 0
    }
}

/// One question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Question {
    /// Queried name.
    pub name: Name,
    /// QTYPE.
    pub qtype: u16,
    /// QCLASS.
    pub qclass: u16,
}

/// One resource record from the answer section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record<'a> {
    /// Owner name.
    pub name: Name,
    /// TYPE.
    pub rtype: u16,
    /// CLASS.
    pub class: u16,
    /// TTL in seconds.
    pub ttl: u32,
    /// Raw RDATA.
    pub rdata: &'a [u8],
    /// Offset of RDATA in the message (for decoding compressed names inside it).
    rdata_off: usize,
}

impl Record<'_> {
    /// The address for A/AAAA records.
    pub fn addr(&self) -> Option<IpAddr> {
        match (self.rtype, self.rdata.len()) {
            (rtype::A, 4) => Some(IpAddr::V4(Ipv4Addr::new(
                self.rdata[0],
                self.rdata[1],
                self.rdata[2],
                self.rdata[3],
            ))),
            (rtype::AAAA, 16) => {
                let mut b = [0u8; 16];
                b.copy_from_slice(self.rdata);
                Some(IpAddr::V6(Ipv6Addr::from(b)))
            }
            _ => None,
        }
    }
}

/// A parsed DNS message (header + first question); answers are iterated lazily.
#[derive(Debug, Clone, Copy)]
pub struct Message<'a> {
    msg: &'a [u8],
    /// Header.
    pub header: Header,
    /// First question, if any.
    pub question: Option<Question>,
    answers_at: usize,
}

impl<'a> Message<'a> {
    /// Parse the header and the question section.
    pub fn parse(msg: &'a [u8]) -> Result<Self> {
        let mut c = Cursor::new(msg);
        let header = Header {
            id: c.u16()?,
            flags: c.u16()?,
            qdcount: c.u16()?,
            ancount: c.u16()?,
            nscount: c.u16()?,
            arcount: c.u16()?,
        };
        if header.qdcount > 4 {
            return Err(Error::Limit); // real resolvers send exactly one
        }
        let mut question = None;
        let mut pos = c.pos();
        for _ in 0..header.qdcount {
            let (name, next) = read_name(msg, pos)?;
            let mut q = Cursor::new(msg.get(next..).ok_or(Error::Truncated)?);
            let qtype = q.u16()?;
            let qclass = q.u16()?;
            question.get_or_insert(Question {
                name,
                qtype,
                qclass,
            });
            pos = next + 4;
        }
        Ok(Self {
            msg,
            header,
            question,
            answers_at: pos,
        })
    }

    /// Iterate the answer section. Stops (yielding an `Err` once) on malformed records.
    pub fn answers(&self) -> impl Iterator<Item = Result<Record<'a>>> + '_ {
        let mut pos = self.answers_at;
        let mut left = self.header.ancount.min(MAX_RECORDS);
        let mut failed = false;
        core::iter::from_fn(move || {
            if left == 0 || failed {
                return None;
            }
            left -= 1;
            match read_record(self.msg, pos) {
                Ok((r, next)) => {
                    pos = next;
                    Some(Ok(r))
                }
                Err(e) => {
                    failed = true;
                    Some(Err(e))
                }
            }
        })
    }

    /// Decode the target of a CNAME record from this message.
    pub fn cname_target(&self, r: &Record<'_>) -> Result<Name> {
        if r.rtype != rtype::CNAME {
            return Err(Error::Unsupported);
        }
        Ok(read_name(self.msg, r.rdata_off)?.0)
    }
}

fn read_record(msg: &[u8], pos: usize) -> Result<(Record<'_>, usize)> {
    let (name, next) = read_name(msg, pos)?;
    let mut c = Cursor::new(msg.get(next..).ok_or(Error::Truncated)?);
    let rtype = c.u16()?;
    let class = c.u16()?;
    let ttl = c.u32()?;
    let rdlen = c.u16()? as usize;
    let rdata_off = next + 10;
    let rdata = c.bytes(rdlen)?;
    Ok((
        Record {
            name,
            rtype,
            class,
            ttl,
            rdata,
            rdata_off,
        },
        rdata_off + rdlen,
    ))
}

/// Decode a (possibly compressed) name at `pos`. Returns the name and the offset just past it
/// in the original (uncompressed) position.
fn read_name(msg: &[u8], mut pos: usize) -> Result<(Name, usize)> {
    let mut name = Name {
        buf: [0; 255],
        len: 0,
    };
    let mut jumps = 0;
    let mut end = None;
    // Every pointer must target an offset strictly before the label sequence it was found in.
    let mut floor = pos;
    loop {
        let len = *msg.get(pos).ok_or(Error::Truncated)?;
        match len & 0xc0 {
            0x00 => {
                if len == 0 {
                    return Ok((name, end.unwrap_or(pos + 1)));
                }
                let label = msg
                    .get(pos + 1..pos + 1 + len as usize)
                    .ok_or(Error::Truncated)?;
                let need = label.len() + usize::from(name.len > 0);
                if name.len as usize + need > 255 {
                    return Err(Error::Limit);
                }
                if name.len > 0 {
                    name.buf[name.len as usize] = b'.';
                    name.len += 1;
                }
                for &b in label {
                    if !b.is_ascii_graphic() || b == b'.' {
                        return Err(Error::Invalid);
                    }
                    name.buf[name.len as usize] = b.to_ascii_lowercase();
                    name.len += 1;
                }
                pos += 1 + len as usize;
            }
            0xc0 => {
                let lo = *msg.get(pos + 1).ok_or(Error::Truncated)?;
                let target = (((len & 0x3f) as usize) << 8) | lo as usize;
                jumps += 1;
                if jumps > MAX_JUMPS {
                    return Err(Error::Limit);
                }
                if target >= floor {
                    return Err(Error::Invalid); // forward or self pointer: possible loop
                }
                end.get_or_insert(pos + 2);
                floor = target;
                pos = target;
            }
            _ => return Err(Error::Invalid), // 0x40/0x80 label types are obsolete
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Response for `www.Example.com A` with a CNAME and A + AAAA answers, using compression.
    fn response() -> ([u8; 128], usize) {
        let mut b = [0u8; 128];
        let mut n = 0;
        let mut put = |s: &[u8], n: &mut usize| {
            b[*n..*n + s.len()].copy_from_slice(s);
            *n += s.len();
        };
        put(&[0x12, 0x34, 0x81, 0x80, 0, 1, 0, 3, 0, 0, 0, 0], &mut n);
        put(b"\x03www\x07Example\x03com\x00", &mut n); // offset 12
        put(&[0, 1, 0, 1], &mut n);
        // CNAME www -> edge.example.com (pointer to "example.com" at 16)
        put(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 7], &mut n);
        put(b"\x04edge\xc0\x10", &mut n);
        // A for edge.example.com (pointer to the CNAME rdata at offset 45)
        let edge = 45u8;
        put(
            &[
                0xc0, edge, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4, 93, 184, 216, 34,
            ],
            &mut n,
        );
        // AAAA
        put(&[0xc0, edge, 0, 28, 0, 1, 0, 0, 0, 30, 0, 16], &mut n);
        put(
            &[
                0x26, 0x06, 0x28, 0, 0x02, 0x20, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x01,
            ],
            &mut n,
        );
        (b, n)
    }

    #[test]
    fn parses_answers_with_compression() {
        let (b, n) = response();
        let m = Message::parse(&b[..n]).unwrap();
        assert!(m.header.is_response());
        let q = m.question.unwrap();
        assert_eq!(q.name.as_str(), "www.example.com");
        assert!(q.name.eq_ignore_case("WWW.example.com."));
        let mut it = m.answers();
        let cname = it.next().unwrap().unwrap();
        assert_eq!(m.cname_target(&cname).unwrap().as_str(), "edge.example.com");
        let a = it.next().unwrap().unwrap();
        assert_eq!(a.name.as_str(), "edge.example.com");
        assert_eq!(a.ttl, 300);
        assert_eq!(a.addr(), Some("93.184.216.34".parse().unwrap()));
        let aaaa = it.next().unwrap().unwrap();
        assert_eq!(aaaa.addr(), Some("2606:2800:220:1::1".parse().unwrap()));
        assert!(it.next().is_none());
    }

    #[test]
    fn compression_loops_are_rejected() {
        // header + a name that is a pointer to itself
        let mut m = [0u8; 18];
        m[5] = 1;
        m[12] = 0xc0;
        m[13] = 12;
        assert_eq!(Message::parse(&m).unwrap_err(), Error::Invalid);
        // two pointers pointing at each other
        let mut m2 = [0u8; 20];
        m2[5] = 1;
        m2[12..14].copy_from_slice(&[0xc0, 14]);
        m2[14..16].copy_from_slice(&[0xc0, 12]);
        assert!(Message::parse(&m2).is_err());
    }

    #[test]
    fn overlong_names_are_rejected() {
        let mut m = [0u8; 12 + 5 * 64 + 1 + 4];
        m[5] = 1;
        let mut p = 12;
        for _ in 0..5 {
            m[p] = 63;
            for x in &mut m[p + 1..p + 64] {
                *x = b'a';
            }
            p += 64;
        }
        assert_eq!(Message::parse(&m).unwrap_err(), Error::Limit);
    }

    #[test]
    fn every_truncation_is_an_error_not_a_panic() {
        let (b, n) = response();
        for cut in 0..n {
            if let Ok(m) = Message::parse(&b[..cut]) {
                let ok = m.answers().all(|r| r.is_ok());
                assert!(
                    !ok || m.header.ancount == 0 || cut == n,
                    "cut at {cut} parsed fully"
                );
            }
        }
    }

    proptest::proptest! {
        #[test]
        fn never_panics(data in proptest::collection::vec(proptest::num::u8::ANY, 0..512)) {
            if let Ok(m) = Message::parse(&data) {
                for r in m.answers().flatten() {
                    let _ = r.addr();
                    let _ = m.cname_target(&r);
                }
            }
        }
    }
}
