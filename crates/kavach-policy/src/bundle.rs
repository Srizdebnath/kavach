//! Signed policy bundles (`.kvb`), FR-POL-5 / SR-3.
//!
//! ```text
//! magic "KVB1" | u16 format | u16 flags | u64 serial | u64 created_unix | u64 not_after_unix
//! | [u8; 8] key_id | [u8; 32] fleet | u32 payload_len | payload (postcard CompiledPolicy)
//! | [u8; 64] signature
//!
//! signature = Ed25519(sk, "kavach-bundle-v1\0" || header || payload)   (pure Ed25519)
//! key_id    = SHA-256(public key)[..8]
//! ```
//!
//! Verification order: size caps → header → trusted key → revocation → signature → fleet →
//! anti-rollback serial → expiry → decode. Nothing attacker-controlled is decoded before the
//! signature is checked.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::compile::CompiledPolicy;

pub const MAGIC: &[u8; 4] = b"KVB1";
pub const FORMAT: u16 = 1;
pub const DOMAIN: &[u8] = b"kavach-bundle-v1\0";
pub const HEADER_LEN: usize = 4 + 2 + 2 + 8 + 8 + 8 + 8 + 32 + 4;
pub const SIG_LEN: usize = 64;
/// Hard cap on payload size, checked before anything else.
pub const MAX_PAYLOAD: usize = 4 << 20;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BundleError {
    #[error("bundle truncated or oversized")]
    Size,
    #[error("not a Kavach bundle (bad magic)")]
    Magic,
    #[error("unsupported bundle format {0}")]
    Format(u16),
    #[error("signing key {0} is not trusted")]
    UntrustedKey(String),
    #[error("signing key {0} has been revoked")]
    RevokedKey(String),
    #[error("signature verification failed")]
    Signature,
    #[error("bundle is for fleet {got:?}, this host is in fleet {want:?}")]
    Fleet { got: String, want: String },
    #[error("serial {got} is not newer than the active serial {active} (rollback refused)")]
    Rollback { got: u64, active: u64 },
    #[error("bundle expired at unix time {0}")]
    Expired(u64),
    #[error("payload decode failed: {0}")]
    Decode(String),
    #[error("payload encode failed: {0}")]
    Encode(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleHeader {
    pub flags: u16,
    pub serial: u64,
    pub created_unix: u64,
    /// 0 = never expires. Past expiry the host keeps enforcing but alerts (never fails open).
    pub not_after_unix: u64,
    pub key_id: [u8; 8],
    pub fleet: String,
}

impl BundleHeader {
    fn encode(&self, payload_len: u32) -> [u8; HEADER_LEN] {
        let mut h = [0u8; HEADER_LEN];
        let mut o = 0;
        let mut put = |b: &[u8]| {
            h[o..o + b.len()].copy_from_slice(b);
            o += b.len();
        };
        put(MAGIC);
        put(&FORMAT.to_le_bytes());
        put(&self.flags.to_le_bytes());
        put(&self.serial.to_le_bytes());
        put(&self.created_unix.to_le_bytes());
        put(&self.not_after_unix.to_le_bytes());
        put(&self.key_id);
        let mut fleet = [0u8; 32];
        let fb = self.fleet.as_bytes();
        fleet[..fb.len().min(32)].copy_from_slice(&fb[..fb.len().min(32)]);
        put(&fleet);
        put(&payload_len.to_le_bytes());
        h
    }

    fn decode(h: &[u8]) -> Result<(Self, u32), BundleError> {
        if h.len() < HEADER_LEN {
            return Err(BundleError::Size);
        }
        if &h[0..4] != MAGIC {
            return Err(BundleError::Magic);
        }
        let u16le = |o: usize| u16::from_le_bytes([h[o], h[o + 1]]);
        let u64le = |o: usize| u64::from_le_bytes(h[o..o + 8].try_into().unwrap());
        let format = u16le(4);
        if format != FORMAT {
            return Err(BundleError::Format(format));
        }
        let fleet_raw = &h[40..72];
        let end = fleet_raw.iter().position(|b| *b == 0).unwrap_or(32);
        let hdr = Self {
            flags: u16le(6),
            serial: u64le(8),
            created_unix: u64le(16),
            not_after_unix: u64le(24),
            key_id: h[32..40].try_into().unwrap(),
            fleet: String::from_utf8_lossy(&fleet_raw[..end]).into_owned(),
        };
        let len = u32::from_le_bytes(h[72..76].try_into().unwrap());
        Ok((hdr, len))
    }
}

pub fn key_id(vk: &VerifyingKey) -> [u8; 8] {
    Sha256::digest(vk.as_bytes())[..8].try_into().unwrap()
}

pub fn key_id_hex(vk: &VerifyingKey) -> String {
    hex::encode(key_id(vk))
}

/// Generate a fresh signing key from the OS CSPRNG.
pub fn generate_key() -> SigningKey {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("OS RNG unavailable");
    let sk = SigningKey::from_bytes(&seed);
    seed.fill(0);
    sk
}

fn signed_message(header: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(DOMAIN.len() + header.len() + payload.len());
    m.extend_from_slice(DOMAIN);
    m.extend_from_slice(header);
    m.extend_from_slice(payload);
    m
}

/// Serialise and sign a compiled policy.
pub fn sign(
    policy: &CompiledPolicy,
    sk: &SigningKey,
    serial: u64,
    not_after_unix: u64,
    fleet: &str,
) -> Result<Vec<u8>, BundleError> {
    if fleet.len() > 32 {
        return Err(BundleError::Encode("fleet id longer than 32 bytes".into()));
    }
    let payload = postcard::to_allocvec(policy).map_err(|e| BundleError::Encode(e.to_string()))?;
    if payload.len() > MAX_PAYLOAD {
        return Err(BundleError::Size);
    }
    let hdr = BundleHeader {
        flags: 0,
        serial,
        created_unix: policy.created_unix,
        not_after_unix,
        key_id: key_id(&sk.verifying_key()),
        fleet: fleet.to_owned(),
    }
    .encode(payload.len() as u32);
    let sig = sk.sign(&signed_message(&hdr, &payload));
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len() + SIG_LEN);
    out.extend_from_slice(&hdr);
    out.extend_from_slice(&payload);
    out.extend_from_slice(&sig.to_bytes());
    Ok(out)
}

/// What a host requires of a bundle.
#[derive(Debug, Clone, Default)]
pub struct TrustPolicy {
    pub trusted: Vec<VerifyingKey>,
    pub revoked: Vec<[u8; 8]>,
    pub fleet: String,
    /// Serial of the active bundle; a new bundle must be strictly greater.
    pub active_serial: u64,
    pub now_unix: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedBundle {
    pub header: BundleHeader,
    pub policy: CompiledPolicy,
    /// True when `not_after` has passed: the caller keeps enforcing and raises an alert.
    pub expired: bool,
}

/// Parse the header without trusting anything (for `kavachctl verify` display).
pub fn peek_header(bytes: &[u8]) -> Result<BundleHeader, BundleError> {
    BundleHeader::decode(bytes).map(|(h, _)| h)
}

/// Verify and decode a bundle under `trust`. Strict mode rejects expired bundles; non-strict
/// (used when re-loading the active bundle at boot) returns them flagged `expired`.
pub fn verify(
    bytes: &[u8],
    trust: &TrustPolicy,
    strict_expiry: bool,
) -> Result<VerifiedBundle, BundleError> {
    if bytes.len() < HEADER_LEN + SIG_LEN || bytes.len() > HEADER_LEN + MAX_PAYLOAD + SIG_LEN {
        return Err(BundleError::Size);
    }
    let (header, len) = BundleHeader::decode(&bytes[..HEADER_LEN])?;
    let len = len as usize;
    if len > MAX_PAYLOAD || bytes.len() != HEADER_LEN + len + SIG_LEN {
        return Err(BundleError::Size);
    }
    let kid = hex::encode(header.key_id);
    if trust.revoked.contains(&header.key_id) {
        return Err(BundleError::RevokedKey(kid));
    }
    let vk = trust
        .trusted
        .iter()
        .find(|k| key_id(k) == header.key_id)
        .ok_or_else(|| BundleError::UntrustedKey(kid.clone()))?;
    let payload = &bytes[HEADER_LEN..HEADER_LEN + len];
    let sig = Signature::from_bytes(bytes[HEADER_LEN + len..].try_into().unwrap());
    vk.verify(&signed_message(&bytes[..HEADER_LEN], payload), &sig)
        .map_err(|_| BundleError::Signature)?;
    // Authenticated from here on.
    if header.fleet != trust.fleet {
        return Err(BundleError::Fleet {
            got: header.fleet,
            want: trust.fleet.clone(),
        });
    }
    if header.serial <= trust.active_serial {
        return Err(BundleError::Rollback {
            got: header.serial,
            active: trust.active_serial,
        });
    }
    let expired = header.not_after_unix != 0 && trust.now_unix >= header.not_after_unix;
    if expired && strict_expiry {
        return Err(BundleError::Expired(header.not_after_unix));
    }
    let policy: CompiledPolicy =
        postcard::from_bytes(payload).map_err(|e| BundleError::Decode(e.to_string()))?;
    Ok(VerifiedBundle {
        header,
        policy,
        expired,
    })
}
