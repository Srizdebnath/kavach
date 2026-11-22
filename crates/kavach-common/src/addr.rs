//! Address normalisation helpers. Every address in Kavach maps is 16 bytes; IPv4 addresses are
//! stored IPv4-mapped (`::ffff:a.b.c.d`) so one LPM trie serves both families.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::abi::{AddrKey, BlockKey, KV_RATE_V6_PREFIX, SrcKey};

/// Bits of prefix contributed by the `::ffff:` mapping.
pub const V4_MAPPED_PREFIX_BITS: u32 = 96;

/// Normalise an address to its 16-byte form.
pub const fn to_mapped(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// Inverse of [`to_mapped`]: IPv4-mapped addresses come back as IPv4.
pub fn from_mapped(addr: [u8; 16]) -> IpAddr {
    let v6 = Ipv6Addr::from(addr);
    match v6.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(v6),
    }
}

/// Convert a CIDR prefix length to the 128-bit space (IPv4 /24 → 120).
pub const fn mapped_prefix(ip: IpAddr, len: u8) -> u32 {
    match ip {
        IpAddr::V4(_) => V4_MAPPED_PREFIX_BITS + len as u32,
        IpAddr::V6(_) => len as u32,
    }
}

/// Zero host bits beyond `prefix` (in the 128-bit space).
pub fn mask_addr(mut addr: [u8; 16], prefix: u32) -> [u8; 16] {
    for (i, b) in addr.iter_mut().enumerate() {
        let bit = (i as u32) * 8;
        if bit >= prefix {
            *b = 0;
        } else if prefix - bit < 8 {
            *b &= 0xffu8 << (8 - (prefix - bit));
        }
    }
    addr
}

impl BlockKey {
    /// Build a blocklist key from a CIDR. Host bits are cleared.
    pub fn from_cidr(ip: IpAddr, len: u8) -> Self {
        let prefixlen = mapped_prefix(ip, len);
        Self {
            prefixlen,
            addr: mask_addr(to_mapped(ip), prefixlen),
        }
    }
    /// Full-length key used to look up a single address.
    pub fn host(ip: IpAddr) -> Self {
        Self {
            prefixlen: 128,
            addr: to_mapped(ip),
        }
    }
}

impl AddrKey {
    /// Bits used by the always-exact `slot` prefix.
    pub const HEADER_BITS: u32 = 32;

    pub fn from_cidr(slot: u32, ip: IpAddr, len: u8) -> Self {
        let p = mapped_prefix(ip, len);
        Self {
            prefixlen: Self::HEADER_BITS + p,
            slot,
            addr: mask_addr(to_mapped(ip), p),
        }
    }
    pub fn host(slot: u32, addr: [u8; 16]) -> Self {
        Self {
            prefixlen: Self::HEADER_BITS + 128,
            slot,
            addr,
        }
    }
}

impl SrcKey {
    /// Rate-limit key: IPv4 /32, IPv6 /64.
    pub fn for_source(ip: IpAddr) -> Self {
        let m = to_mapped(ip);
        match ip {
            IpAddr::V4(_) => Self { addr: m },
            IpAddr::V6(_) => Self {
                addr: mask_addr(m, KV_RATE_V6_PREFIX),
            },
        }
    }
}

/// Convert a 16-byte address to the `[u32; 4]` layout used in `FlowKey` (bytes preserved).
pub fn to_words(addr: [u8; 16]) -> [u32; 4] {
    let mut w = [0u32; 4];
    for (i, chunk) in addr.as_chunks::<4>().0.iter().enumerate() {
        w[i] = u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    w
}

/// Inverse of [`to_words`].
pub fn from_words(w: [u32; 4]) -> [u8; 16] {
    let mut a = [0u8; 16];
    for (i, word) in w.iter().enumerate() {
        a[i * 4..i * 4 + 4].copy_from_slice(&word.to_ne_bytes());
    }
    a
}

/// `true` for 127.0.0.0/8 and ::1 (in mapped form).
pub fn is_loopback(addr: [u8; 16]) -> bool {
    match from_mapped(addr) {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

/// Convenience for tests and tooling.
pub const fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_mapped_roundtrip() {
        let ip = v4(10, 1, 2, 3);
        let m = to_mapped(ip);
        assert_eq!(&m[..12], &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]);
        assert_eq!(from_mapped(m), ip);
    }

    #[test]
    fn cidr_masks_host_bits() {
        let k = BlockKey::from_cidr(v4(192, 168, 7, 99), 20);
        assert_eq!(k.prefixlen, 116);
        assert_eq!(from_mapped(k.addr), v4(192, 168, 0, 0));
    }

    #[test]
    fn v6_prefix() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let k = BlockKey::from_cidr(ip, 32);
        assert_eq!(k.prefixlen, 32);
        assert_eq!(from_mapped(k.addr), "2001:db8::".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn words_roundtrip() {
        let a = to_mapped(v4(1, 2, 3, 4));
        assert_eq!(from_words(to_words(a)), a);
    }

    #[test]
    fn rate_key_v6_is_slash64() {
        let a = SrcKey::for_source("2001:db8:1:2:aaaa:bbbb:cccc:dddd".parse().unwrap());
        let b = SrcKey::for_source("2001:db8:1:2::1".parse().unwrap());
        assert_eq!(a, b);
    }

    #[test]
    fn addr_key_prefix() {
        let k = AddrKey::from_cidr(1, v4(10, 0, 0, 0), 8);
        assert_eq!(k.prefixlen, 32 + 96 + 8);
        assert_eq!(k.slot, 1);
    }

    #[test]
    fn loopback() {
        assert!(is_loopback(to_mapped(v4(127, 0, 0, 53))));
        assert!(is_loopback(to_mapped("::1".parse().unwrap())));
        assert!(!is_loopback(to_mapped(v4(8, 8, 8, 8))));
    }
}
