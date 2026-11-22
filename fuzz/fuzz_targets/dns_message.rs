#![no_main]
use kavach_parsers::dns::Message;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = Message::parse(data) {
        for r in m.answers().flatten() {
            assert!(r.name.as_bytes().len() <= 255);
            let _ = r.addr();
            let _ = m.cname_target(&r);
        }
    }
});
