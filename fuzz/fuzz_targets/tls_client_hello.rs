#![no_main]
use kavach_parsers::{ja4, tls::ClientHello};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(h) = ClientHello::parse(data) {
        let _ = h.server_name();
        let _ = h.alpn_protocols().count();
        let j = ja4::ja4(&h, ja4::Transport::Tcp);
        assert_eq!(j.as_str().len(), 36);
    }
});
