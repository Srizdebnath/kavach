#![no_main]
use libfuzzer_sys::fuzz_target;

// The daemon parses one JSON line per request from local clients.
fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<kavach_api::Request>(data);
});
