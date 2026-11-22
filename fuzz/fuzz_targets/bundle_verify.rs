#![no_main]
use kavach_policy::bundle;
use libfuzzer_sys::fuzz_target;

// Arbitrary bytes must never verify and never panic; header peeking is total.
fuzz_target!(|data: &[u8]| {
    let _ = bundle::peek_header(data);
    let vk = kavach_policy::SigningKey::from_bytes(&[7u8; 32]).verifying_key();
    let trust = bundle::TrustPolicy { trusted: vec![vk], revoked: vec![], fleet: "default".into(), active_serial: 0, now_unix: 0 };
    assert!(bundle::verify(data, &trust, true).is_err());
});
