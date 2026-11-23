#![no_main]
use kavach_policy::bundle;
use libfuzzer_sys::fuzz_target;

// Compiling must never panic, and anything it accepts must lower to a kernel table, keep its
// gateway references in range, and survive a sign → verify round trip unchanged.
fuzz_target!(|data: &[u8]| {
    let Ok(src) = std::str::from_utf8(data) else { return };
    if let Ok(out) = kavach_policy::compile(src, 1_700_000_000) {
        let p = out.policy;
        let clocks = kavach_policy::kernel::Clocks { unix_ns: 1_700_000_000_000_000_000, boot_ns: 1 };
        let t = p.to_kernel(1, 1, clocks);
        assert!(t.hdr.n_rules as usize <= t.rules.len());
        let _ = kavach_policy::kernel::flatten_sets(&p.static_set_entries());
        for r in &p.rules {
            assert_eq!(r.gateway == 0, p.rule_gateway(r).is_none());
        }
        let sk = kavach_policy::SigningKey::from_bytes(&[7u8; 32]);
        let Ok(b) = bundle::sign(&p, &sk, 2, 0, "default") else { return }; // oversized
        let want = if p.uses_gateways() { bundle::FORMAT } else { bundle::FORMAT_V2 };
        assert_eq!(bundle::peek_format(&b), Ok(want));
        let trust = bundle::TrustPolicy { trusted: vec![sk.verifying_key()], revoked: vec![], fleet: "default".into(), active_serial: 0, now_unix: 0 };
        assert_eq!(bundle::verify(&b, &trust, true).expect("own bundle verifies").policy, p);
    }
});
