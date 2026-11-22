use kavach_common::abi::*;
use kavach_common::addr::{to_mapped, v4};
use kavach_core::{FlowQuery, Snapshot, Tables};

use crate::bundle::{self, BundleError, TrustPolicy};
use crate::compile::{compile, parse_duration, Severity};
use crate::kernel::{flatten_sets, Clocks, Facts, OfflineTables};

const SHA_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

const EXAMPLE: &str = r#"
version = 1

[defaults]
egress = "drop"
ingress = "drop"
fail = "closed"

[sets]
payments = ["203.0.113.0/24", "api.stripe.com"]

[[rule]]
id    = "stripe-egress"
who   = { binary = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", user = "svc-pay" }
allow = { to = "@payments", port = 443, proto = "tcp" }
ttl   = "30d"

[[rule]]
id    = "dns"
allow = { to = ["1.1.1.1", "9.9.9.9"], port = 53, proto = "udp" }

[[rule]]
id    = "ssh-in"
direction = "ingress"
allow = { from = "10.0.0.0/8", port = 22, proto = "tcp" }

[[rule]]
id   = "web-ports"
who  = { user = 1000 }
log  = { port = [80, "8000-8999"], proto = "tcp" }

[[agent]]
id = "support-bot"
mcp.tools = ["kb.search", "ticket.create"]
budget = { calls_per_min = 60, usd_per_day = 5.0 }
"#;

fn errors(src: &str) -> Vec<String> {
    match compile(src, 1_000) {
        Ok(_) => vec![],
        Err(d) => d.into_iter().filter(|d| d.severity == Severity::Error).map(|d| d.to_string()).collect(),
    }
}

#[test]
fn compiles_example() {
    let out = compile(EXAMPLE, 1_000_000).expect("compiles");
    let p = out.policy;
    assert_eq!(p.selectors.len(), 2);
    assert_eq!(p.sets.len(), 3); // @payments, dns pair, 10/8
    assert_eq!(p.sets[0].name, "@payments");
    assert_eq!(p.sets[0].fqdns, vec!["api.stripe.com"]);
    // web-ports expands into two port ranges sharing the same id
    assert_eq!(p.rules.len(), 5);
    assert_eq!(p.rules[3].port_lo, 80);
    assert_eq!((p.rules[4].port_lo, p.rules[4].port_hi), (8000, 8999));
    assert_eq!(p.rules[3].id, p.rules[4].id);
    assert_eq!(p.rules[0].not_after_unix, 1_000_000 + 30 * 86_400);
    assert_eq!(p.agents.len(), 1);
    assert!(out.warnings.iter().any(|w| w.message.contains("agent")));
}

#[test]
fn rejects_unknown_keys() {
    let e = errors("version = 1\n[[rule]]\nid='x'\nallow={}\nbogus=1\n");
    assert!(e[0].contains("unknown field"), "{e:?}");
}

#[test]
fn rejects_duplicates_and_bad_values() {
    let src = r#"
version = 1
[[rule]]
id = "a"
allow = { to = "not a host!", port = "90-80" }
[[rule]]
id = "a"
deny = { to = "1.2.3.4", proto = "sctp" }
[[rule]]
id = "c"
allow = {}
deny = {}
"#;
    let e = errors(src).join("\n");
    assert!(e.contains("duplicate rule id"));
    assert!(e.contains("not a CIDR"));
    assert!(e.contains("reversed"));
    assert!(e.contains("unknown proto"));
    assert!(e.contains("exactly one of"));
}

#[test]
fn require_ttl_enforced() {
    let e = errors("version = 1\n[defaults]\nrequire_ttl = true\n[[rule]]\nid='x'\nallow={ to='1.1.1.1' }\n");
    assert!(e.iter().any(|m| m.contains("ttl is required")));
}

#[test]
fn detects_contradiction_and_shadowing() {
    let src = r#"
version = 1
[[rule]]
id = "allow-all-https"
allow = { port = 443, proto = "tcp" }
[[rule]]
id = "block-evil"
deny = { to = "198.51.100.0/24", port = 443, proto = "tcp" }
"#;
    let e = errors(src).join("\n");
    assert!(e.contains("[block-evil]") && e.contains("contradicts"), "{e}");

    let src = r#"
version = 1
[[rule]]
id = "wide"
allow = { to = "10.0.0.0/8" }
[[rule]]
id = "narrow"
allow = { to = "10.1.0.0/16", port = 22, proto = "tcp" }
"#;
    assert!(errors(src).join("\n").contains("shadowed by earlier rule \"wide\""));
    let relaxed = src.replace("version = 1", "version = 1\n[defaults]\nallow_shadowed = true");
    let out = compile(&relaxed, 0).expect("warning only");
    assert!(out.warnings.iter().any(|w| w.message.contains("redundant")));

    // Narrow-before-wide is the correct ordering and is accepted.
    let ok = r#"
version = 1
[[rule]]
id = "narrow-deny"
deny = { to = "10.1.0.0/16" }
[[rule]]
id = "wide-allow"
allow = { to = "10.0.0.0/8" }
"#;
    assert!(errors(ok).is_empty());
}

#[test]
fn ingress_who_and_v04_selectors_rejected() {
    let e = errors("version=1\n[[rule]]\nid='i'\ndirection='ingress'\nwho={user=0}\nallow={from='1.1.1.1'}\n");
    assert!(e[0].contains("v0.4"));
    let e = errors("version=1\n[[rule]]\nid='k'\nwho={k8s='app=db'}\ndeny={}\n");
    assert!(e[0].contains("v0.4"));
}

#[test]
fn interpreter_warning() {
    let out = compile("version=1\n[[rule]]\nid='py'\nwho={exe='/usr/bin/python3'}\nallow={}\n", 0).unwrap();
    assert!(out.warnings.iter().any(|w| w.message.contains("interpreter")));
}

#[test]
fn durations() {
    assert_eq!(parse_duration("90s"), Ok(90));
    assert_eq!(parse_duration("2h"), Ok(7200));
    assert_eq!(parse_duration("1w"), Ok(604_800));
    assert!(parse_duration("5y").is_err());
    assert!(parse_duration("0d").is_err());
}

#[test]
fn flatten_unions_covering_sets() {
    let entries = vec![
        (1, "10.0.0.0/8".parse().unwrap()),
        (2, "10.1.0.0/16".parse().unwrap()),
        (3, "10.1.0.0/16".parse().unwrap()),
        (4, "2001:db8::/32".parse().unwrap()),
    ];
    let flat = flatten_sets(&entries);
    assert_eq!(flat.len(), 3);
    let p16 = flat.iter().find(|p| p.prefix == 96 + 16).unwrap();
    assert_eq!(p16.bitmap, 0b0111);
    let p8 = flat.iter().find(|p| p.prefix == 96 + 8).unwrap();
    assert_eq!(p8.bitmap, 0b0001);
}

#[test]
fn kernel_lowering_and_offline_explain() {
    let p = compile(EXAMPLE, 0).unwrap().policy;
    let clocks = Clocks { unix_ns: 0, boot_ns: 5 };
    let k = p.to_kernel(7, 42, clocks);
    assert_eq!(k.hdr.n_rules, 5);
    assert_eq!(k.hdr.generation, 7);
    assert_eq!(k.hdr.sel_used, 0b11);
    // selector 0 constrains exe+uid, selector 1 (uid 1000) only uid
    assert_eq!(k.hdr.wild_exe & 0b11, 0b10);
    assert_eq!(k.hdr.wild_uid & 0b11, 0b00);
    assert_eq!(k.hdr.wild_cgroup & 0b11, 0b11);
    assert_eq!(k.rules[0].not_after_ns, 5 + 30 * 86_400 * 1_000_000_000);

    let sha: [u8; 32] = [0xaa; 32];
    let facts = Facts { sha256: Some(sha), user_name: Some("svc-pay"), ..Default::default() };
    let t = OfflineTables::new(&p, &facts, &[], 1);
    assert_eq!(t.mask, 0b01);
    let snap = Snapshot::new(&k, 7).unwrap(); // gen 7 → slot 1
    let mask = kavach_core::identity_mask(&t, &snap, &t.who());
    assert_eq!(mask, 0b01);
    let q = FlowQuery {
        dir: KV_DIR_EGRESS,
        mask,
        remote: to_mapped(v4(203, 0, 113, 9)),
        port: 443,
        proto: KV_PROTO_TCP,
    };
    let d = kavach_core::evaluate(&t, &snap, &q, 0);
    assert_eq!((d.verdict, d.rule_id), (Verdict::Allow, 1));
    // Same flow from someone else → default drop.
    let q2 = FlowQuery { mask: 0, ..q };
    assert_eq!(kavach_core::evaluate(&t, &snap, &q2, 0).verdict, Verdict::Drop);
    assert!(t.remote_sets(0, &q.remote) == 0, "slot isolation");
    let _ = SHA_A;
}

fn trust(vk: crate::VerifyingKey) -> TrustPolicy {
    TrustPolicy { trusted: vec![vk], revoked: vec![], fleet: "prod".into(), active_serial: 1, now_unix: 100 }
}

#[test]
fn bundle_roundtrip_and_rejections() {
    let p = compile(EXAMPLE, 50).unwrap().policy;
    let sk = bundle::generate_key();
    let b = bundle::sign(&p, &sk, 2, 1_000, "prod").unwrap();
    let v = bundle::verify(&b, &trust(sk.verifying_key()), true).unwrap();
    assert_eq!(v.policy, p);
    assert_eq!(v.header.serial, 2);

    // tamper with the payload
    let mut bad = b.clone();
    bad[bundle::HEADER_LEN + 3] ^= 1;
    assert_eq!(bundle::verify(&bad, &trust(sk.verifying_key()), true), Err(BundleError::Signature));
    // tamper with the header serial (signed too)
    let mut bad = b.clone();
    bad[8] ^= 1;
    assert_eq!(bundle::verify(&bad, &trust(sk.verifying_key()), true), Err(BundleError::Signature));
    // wrong key
    let other = bundle::generate_key();
    assert!(matches!(
        bundle::verify(&b, &trust(other.verifying_key()), true),
        Err(BundleError::UntrustedKey(_))
    ));
    // revoked
    let mut t = trust(sk.verifying_key());
    t.revoked.push(bundle::key_id(&sk.verifying_key()));
    assert!(matches!(bundle::verify(&b, &t, true), Err(BundleError::RevokedKey(_))));
    // rollback
    let mut t = trust(sk.verifying_key());
    t.active_serial = 2;
    assert!(matches!(bundle::verify(&b, &t, true), Err(BundleError::Rollback { .. })));
    // fleet
    let mut t = trust(sk.verifying_key());
    t.fleet = "staging".into();
    assert!(matches!(bundle::verify(&b, &t, true), Err(BundleError::Fleet { .. })));
    // expiry: strict refuses, non-strict flags
    let mut t = trust(sk.verifying_key());
    t.now_unix = 5_000;
    assert!(matches!(bundle::verify(&b, &t, true), Err(BundleError::Expired(1_000))));
    assert!(bundle::verify(&b, &t, false).unwrap().expired);
    // truncation
    assert_eq!(bundle::verify(&b[..b.len() - 1], &trust(sk.verifying_key()), true), Err(BundleError::Size));
}

#[test]
fn diff_reports_changes() {
    let a = compile(EXAMPLE, 0).unwrap().policy;
    let src_b = EXAMPLE.replace("port = 53", "port = 5353").replace(
        "[[agent]]",
        "[[rule]]\nid = \"new\"\ndeny = { to = \"192.0.2.1\" }\n\n[[agent]]",
    );
    let b = compile(&src_b, 0).unwrap().policy;
    let d: Vec<String> = crate::diff::diff(&a, &b).iter().map(ToString::to_string).collect();
    assert!(d.contains(&"~ rule dns".to_string()), "{d:?}");
    assert!(d.contains(&"+ rule new".to_string()), "{d:?}");
}
