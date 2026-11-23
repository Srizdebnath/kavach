#![no_main]
use kavach_parsers::quic::{self, Scratch};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Whole-packet path: almost always stops at the AEAD tag, but exercises header parsing,
    // key derivation and header-protection removal on arbitrary input.
    let mut scratch = Scratch::new();
    if let Ok(init) = quic::parse_initial(data, &mut scratch) {
        let _ = init.server_name();
        assert_eq!(init.ja4().as_str().len(), 36);
    }
    // Post-decryption path: treat the input as a decrypted Initial payload.
    let mut crypto = [0u8; quic::MAX_CRYPTO];
    if let Ok(n) = quic::reassemble_crypto(data, &mut crypto) {
        assert!(n <= quic::MAX_CRYPTO);
        let _ = kavach_parsers::tls::ClientHello::parse(&crypto[..n]);
    }
});
