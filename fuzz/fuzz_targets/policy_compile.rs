#![no_main]
use libfuzzer_sys::fuzz_target;

// Compiling must never panic, and anything it accepts must lower to a kernel table.
fuzz_target!(|data: &[u8]| {
    let Ok(src) = std::str::from_utf8(data) else { return };
    if let Ok(out) = kavach_policy::compile(src, 1_700_000_000) {
        let clocks = kavach_policy::kernel::Clocks { unix_ns: 1_700_000_000_000_000_000, boot_ns: 1 };
        let t = out.policy.to_kernel(1, 1, clocks);
        assert!(t.hdr.n_rules as usize <= t.rules.len());
        let _ = kavach_policy::kernel::flatten_sets(&out.policy.static_set_entries());
    }
});
