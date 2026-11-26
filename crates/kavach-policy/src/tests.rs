use kavach_common::abi::*;
use kavach_common::addr::{to_mapped, v4};
use kavach_core::{FlowQuery, Snapshot, Tables};

use crate::bundle::{self, BundleError, TrustPolicy};
use crate::compile::{Severity, compile, parse_duration};
use crate::kernel::{Clocks, Facts, OfflineTables, flatten_sets};

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
        Err(d) => d
            .into_iter()
            .filter(|d| d.severity == Severity::Error)
            .map(|d| d.to_string())
            .collect(),
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
    let e = errors(
        "version = 1\n[defaults]\nrequire_ttl = true\n[[rule]]\nid='x'\nallow={ to='1.1.1.1' }\n",
    );
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
    assert!(
        e.contains("[block-evil]") && e.contains("contradicts"),
        "{e}"
    );

    let src = r#"
version = 1
[[rule]]
id = "wide"
allow = { to = "10.0.0.0/8" }
[[rule]]
id = "narrow"
allow = { to = "10.1.0.0/16", port = 22, proto = "tcp" }
"#;
    assert!(
        errors(src)
            .join("\n")
            .contains("shadowed by earlier rule \"wide\"")
    );
    let relaxed = src.replace(
        "version = 1",
        "version = 1\n[defaults]\nallow_shadowed = true",
    );
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
fn ingress_who_rejected() {
    let e = errors(
        "version=1\n[[rule]]\nid='i'\ndirection='ingress'\nwho={user=0}\nallow={from='1.1.1.1'}\n",
    );
    assert!(e[0].contains("v0.4"));
    let e = errors(
        "version=1\n[[rule]]\nid='i'\ndirection='ingress'\nwho={k8s='app=db'}\nallow={from='1.1.1.1'}\n",
    );
    assert!(e[0].contains("v0.4"));
}

#[test]
fn interpreter_warning() {
    let out = compile(
        "version=1\n[[rule]]\nid='py'\nwho={exe='/usr/bin/python3'}\nallow={}\n",
        0,
    )
    .unwrap();
    assert!(
        out.warnings
            .iter()
            .any(|w| w.message.contains("interpreter"))
    );
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
    let clocks = Clocks {
        unix_ns: 0,
        boot_ns: 5,
    };
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
    let facts = Facts {
        sha256: Some(sha),
        user_name: Some("svc-pay"),
        ..Default::default()
    };
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
    assert_eq!(
        kavach_core::evaluate(&t, &snap, &q2, 0).verdict,
        Verdict::Drop
    );
    assert!(t.remote_sets(0, &q.remote) == 0, "slot isolation");
    let _ = SHA_A;
}

fn trust(vk: crate::VerifyingKey) -> TrustPolicy {
    TrustPolicy {
        trusted: vec![vk],
        revoked: vec![],
        fleet: "prod".into(),
        active_serial: 1,
        now_unix: 100,
    }
}

#[test]
fn format_v1_bundles_still_verify_and_strict_mode_compiles() {
    let p = compile(EXAMPLE, 50).unwrap().policy;
    let v1 = crate::compile::CompiledPolicyV1 {
        version: p.version,
        created_unix: p.created_unix,
        source_sha256: p.source_sha256,
        defaults: crate::compile::CompiledDefaultsV1 {
            egress: p.defaults.egress,
            ingress: p.defaults.ingress,
            strict_ingress: p.defaults.strict_ingress,
            loopback_bypass: p.defaults.loopback_bypass,
        },
        selectors: p.selectors.clone(),
        sets: p.sets.clone(),
        rules: p.rules.iter().map(Into::into).collect(),
        agents: p.agents.clone(),
    };
    let sk = bundle::generate_key();
    let b = bundle::sign_v1(&v1, &sk, 2, 1_000, "prod").unwrap();
    let v = bundle::verify(&b, &trust(sk.verifying_key()), true).unwrap();
    assert_eq!(v.policy, p, "a format-1 bundle decodes to the same policy");
    assert!(!v.policy.defaults.unclassified_deny);

    let strict = EXAMPLE.replacen("[defaults]", "[defaults]\nunclassified = \"deny\"", 1);
    let s = compile(&strict, 50).unwrap().policy;
    assert!(s.defaults.unclassified_deny);
    let table = s.to_kernel(
        2,
        1,
        crate::kernel::Clocks {
            unix_ns: 0,
            boot_ns: 0,
        },
    );
    assert!(table.hdr.flags & KV_POL_F_UNCLASSIFIED_DENY != 0);
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
    assert_eq!(
        bundle::verify(&bad, &trust(sk.verifying_key()), true),
        Err(BundleError::Signature)
    );
    // tamper with the header serial (signed too)
    let mut bad = b.clone();
    bad[8] ^= 1;
    assert_eq!(
        bundle::verify(&bad, &trust(sk.verifying_key()), true),
        Err(BundleError::Signature)
    );
    // wrong key
    let other = bundle::generate_key();
    assert!(matches!(
        bundle::verify(&b, &trust(other.verifying_key()), true),
        Err(BundleError::UntrustedKey(_))
    ));
    // revoked
    let mut t = trust(sk.verifying_key());
    t.revoked.push(bundle::key_id(&sk.verifying_key()));
    assert!(matches!(
        bundle::verify(&b, &t, true),
        Err(BundleError::RevokedKey(_))
    ));
    // rollback
    let mut t = trust(sk.verifying_key());
    t.active_serial = 2;
    assert!(matches!(
        bundle::verify(&b, &t, true),
        Err(BundleError::Rollback { .. })
    ));
    // fleet
    let mut t = trust(sk.verifying_key());
    t.fleet = "staging".into();
    assert!(matches!(
        bundle::verify(&b, &t, true),
        Err(BundleError::Fleet { .. })
    ));
    // expiry: strict refuses, non-strict flags
    let mut t = trust(sk.verifying_key());
    t.now_unix = 5_000;
    assert!(matches!(
        bundle::verify(&b, &t, true),
        Err(BundleError::Expired(1_000))
    ));
    assert!(bundle::verify(&b, &t, false).unwrap().expired);
    // truncation
    assert_eq!(
        bundle::verify(&b[..b.len() - 1], &trust(sk.verifying_key()), true),
        Err(BundleError::Size)
    );
}

#[test]
fn diff_reports_changes() {
    let a = compile(EXAMPLE, 0).unwrap().policy;
    let src_b = EXAMPLE.replace("port = 53", "port = 5353").replace(
        "[[agent]]",
        "[[rule]]\nid = \"new\"\ndeny = { to = \"192.0.2.1\" }\n\n[[agent]]",
    );
    let b = compile(&src_b, 0).unwrap().policy;
    let d: Vec<String> = crate::diff::diff(&a, &b)
        .iter()
        .map(ToString::to_string)
        .collect();
    assert!(d.contains(&"~ rule dns".to_string()), "{d:?}");
    assert!(d.contains(&"+ rule new".to_string()), "{d:?}");
}

// ---------------------------------------------------------------------------------------------
// L7 gateway policies
// ---------------------------------------------------------------------------------------------

const GATEWAY: &str = r#"
version = 1

[defaults]
egress = "drop"

[gateway.github-agent]
allow_tools     = ["github.*", "search"]
deny_tools      = ["github.delete_*"]
allow_resources = ["repo://acme/*"]
tls             = "deny"

[gateway.support]
allow_tools          = ["kb.search"]
allow_agent_messages = true
tls                  = "allow"

[[rule]]
id    = "dns"
allow = { to = "1.1.1.1", port = 53, proto = "udp" }

[[rule]]
id   = "github-mcp"
who  = { user = 1000 }
punt = { to = "203.0.113.0/24", port = 443, proto = "tcp", gateway = "github-agent" }

[[rule]]
id   = "support-mcp"
who  = { user = 1001 }
punt = { to = "198.51.100.7", port = [443, 8443], proto = "tcp", gateway = "support" }
"#;

fn warnings(src: &str) -> Vec<String> {
    compile(src, 1_000)
        .expect("compiles")
        .warnings
        .iter()
        .map(ToString::to_string)
        .collect()
}

fn with_gateway(body: &str) -> String {
    format!(
        "version = 1\n[gateway.g]\n{body}\n[[rule]]\nid = 'p'\npunt = {{ port = 443, proto = 'tcp', gateway = 'g' }}\n"
    )
}

#[test]
fn gateway_policies_compile_and_rules_reference_them() {
    let out = compile(GATEWAY, 0).expect("compiles");
    assert!(out.warnings.is_empty(), "{:?}", out.warnings);
    let p = out.policy;
    // sorted by name; 1-based index on each compiled punt rule (port lists share it)
    let names: Vec<_> = p.gateways.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(names, ["github-agent", "support"]);
    let gw: Vec<_> = p
        .rules
        .iter()
        .map(|r| (r.name.as_str(), r.gateway))
        .collect();
    assert_eq!(
        gw,
        [
            ("dns", 0),
            ("github-mcp", 1),
            ("support-mcp", 2),
            ("support-mcp", 2)
        ]
    );
    let gh = p.gateway("github-agent").unwrap();
    assert_eq!(gh.allow_resources, ["repo://acme/"], "trailing * dropped");
    assert_eq!(gh.tls, crate::schema::GatewayTls::Deny);
    assert_eq!(p.rule_gateway(&p.rules[1]), Some(gh));
    assert_eq!(p.rule_gateway(&p.rules[0]), None);
    assert_eq!(p.gateway_for_rule_id(3).unwrap().name, "support");
    assert_eq!(p.gateway_for_rule_id(1), None);
    assert_eq!(p.gateway_for_rule_id(99), None);
    assert!(p.uses_gateways() && p.to_v2().is_none());
}

#[cfg(feature = "gateway")]
#[test]
fn gateway_policies_convert_to_tool_policies() {
    use kavach_gateway::{Action, Decision, TlsMode};
    let p = compile(GATEWAY, 0).unwrap().policy;
    let m = p.tool_policies();
    assert_eq!(m.len(), 2);
    let gh = &m["github-agent"];
    assert_eq!(gh.tls, TlsMode::Deny);
    assert_eq!(m["support"].tls, TlsMode::Allow);
    let call = |t: &str| Action::ToolCall { tool: t.into() };
    assert_eq!(gh.decide(&call("github.create_issue")), Decision::Allow);
    assert_eq!(gh.decide(&call("github.delete_repo")), Decision::Deny);
    let read = Action::ResourceRead {
        uri: "repo://acme/kavach/README.md".into(),
    };
    assert_eq!(gh.decide(&read), Decision::Allow);
    assert_eq!(gh.decide(&Action::AgentMessage), Decision::Deny);
    assert_eq!(m["support"].decide(&Action::AgentMessage), Decision::Allow);
}

#[test]
fn gateway_reference_errors() {
    let e = errors(&GATEWAY.replace("gateway = \"support\"", "gateway = \"nope\"")).join("\n");
    assert!(e.contains("[support-mcp]: unknown gateway \"nope\""), "{e}");
    let e = errors(&with_gateway("allow_tools = ['a']").replace("punt", "allow")).join("\n");
    assert!(e.contains("only valid on `punt` rules"), "{e}");
    let e = errors("version = 1\n[gateway.'bad name']\nallow_tools = ['a']\n").join("\n");
    assert!(e.contains("[gateway.bad name]: gateway names"), "{e}");
    // unknown keys are errors, as everywhere else
    let e = errors(&with_gateway("allow_tools = ['a']\nallow_tool = ['b']")).join("\n");
    assert!(e.contains("unknown field `allow_tool`"), "{e}");
    let e = errors(&with_gateway("tls = 'inspect'")).join("\n");
    assert!(e.contains("unknown variant"), "{e}");
    // defaults still cannot be punt
    let e = errors("version = 1\n[defaults]\negress = 'punt'\n").join("\n");
    assert!(e.contains("defaults cannot be `punt`"), "{e}");
}

#[test]
fn gateway_pattern_syntax() {
    for (body, want) in [
        (
            "allow_tools = ['git*hub']",
            "`*` is only allowed as the last character",
        ),
        (
            "allow_tools = ['a**']",
            "`*` is only allowed as the last character",
        ),
        (
            "deny_tools = ['*.delete']",
            "`*` is only allowed as the last character",
        ),
        ("allow_tools = ['']", "allow_tools: empty tool pattern"),
        ("allow_tools = ['a b']", "whitespace"),
        ("allow_resources = ['file:///*/x']", "`*` is only allowed"),
        ("allow_resources = ['']", "empty resource prefix"),
    ] {
        let e = errors(&with_gateway(body)).join("\n");
        assert!(e.contains(want), "{body}: {e}");
    }
    // multi-byte characters are fine (and must not panic)
    assert!(errors(&with_gateway("allow_tools = ['wiki.é', 'ü*']")).is_empty());
    assert!(errors(&with_gateway("allow_tools = ['*']")).is_empty());
}

#[test]
fn gateway_warnings() {
    // unused gateway
    let w = warnings("version = 1\n[gateway.idle]\nallow_tools = ['a']\n").join("\n");
    assert!(w.contains("warning[gateway.idle]: unused"), "{w}");
    // empty allow list
    let w = warnings(&with_gateway("allow_resources = ['file:///w/']")).join("\n");
    assert!(w.contains("allow_tools is empty"), "{w}");
    let w = warnings(&with_gateway("deny_tools = ['x']")).join("\n");
    assert!(w.contains("deny_tools has no effect"), "{w}");
    // duplicates and redundant entries
    let w = warnings(&with_gateway(
        "allow_tools = ['a.x', 'a.x', 'a.*', 'b']\nallow_resources = ['file:///w/', 'file:///w/*', 'file:///w/sub/']",
    ))
    .join("\n");
    assert!(w.contains("allow_tools: duplicate entry \"a.x\""), "{w}");
    assert!(
        w.contains("\"a.x\" is redundant, \"a.*\" already covers it"),
        "{w}"
    );
    assert!(
        w.contains("allow_resources: duplicate entry \"file:///w/*\""),
        "{w}"
    );
    assert!(w.contains("\"file:///w/sub/\" is redundant"), "{w}");
    // a punt rule without a gateway still compiles (fail mode decides) but says so
    let w = warnings("version = 1\n[[rule]]\nid = 'p'\npunt = { port = 443, proto = 'tcp' }\n")
        .join("\n");
    assert!(w.contains("[p]: punt rule has no `gateway`"), "{w}");
}

#[test]
fn gateway_shadowed_tool_patterns() {
    let src =
        with_gateway("allow_tools = ['github.create_issue', 'search']\ndeny_tools = ['github.*']");
    let e = errors(&src).join("\n");
    assert!(
        e.contains(
            "[gateway.g]: allow_tools pattern \"github.create_issue\" can never match: \
             deny_tools pattern \"github.*\" covers it"
        ),
        "{e}"
    );
    // a narrower deny inside a wider allow is the intended shape
    assert!(
        errors(&with_gateway(
            "allow_tools = ['github.*']\ndeny_tools = ['github.delete_*', 'github.admin']"
        ))
        .is_empty()
    );
    let e = errors(&with_gateway("allow_tools = ['x']\ndeny_tools = ['*']")).join("\n");
    assert!(e.contains("can never match"), "{e}");
    // allow_shadowed downgrades it to a warning, like rule shadowing
    let relaxed = src.replace(
        "version = 1",
        "version = 1\n[defaults]\nallow_shadowed = true",
    );
    assert!(warnings(&relaxed).join("\n").contains("can never match"));
}

#[test]
fn tool_pattern_cover_semantics() {
    use crate::compile::tool_pattern_covers as c;
    assert!(c("*", "anything"));
    assert!(c("git*", "github.*"));
    assert!(c("git*", "git"));
    assert!(!c("git*", "gi*"));
    assert!(!c("github.x", "github.*"));
    assert!(c("github.x", "github.x"));
}

#[test]
fn gateway_bundles_are_format_3_and_round_trip() {
    let p = compile(GATEWAY, 50).unwrap().policy;
    let sk = bundle::generate_key();
    let b = bundle::sign(&p, &sk, 2, 0, "prod").unwrap();
    assert_eq!(bundle::peek_format(&b), Ok(bundle::FORMAT));
    assert_eq!(bundle::FORMAT, 3);
    let v = bundle::verify(&b, &trust(sk.verifying_key()), true).unwrap();
    assert_eq!(v.policy, p);
    assert_eq!(
        v.policy.gateway("support").unwrap().allow_tools,
        ["kb.search"]
    );

    // gateway-free policies keep the format-2 wire layout hosts before format 3 understand
    let plain = compile(EXAMPLE, 50).unwrap().policy;
    let b2 = bundle::sign(&plain, &sk, 2, 0, "prod").unwrap();
    assert_eq!(bundle::peek_format(&b2), Ok(bundle::FORMAT_V2));
    assert_eq!(
        b2[bundle::HEADER_LEN..b2.len() - bundle::SIG_LEN],
        postcard::to_allocvec(&plain.to_v2().unwrap()).unwrap()[..]
    );
    assert_eq!(
        bundle::verify(&b2, &trust(sk.verifying_key()), true)
            .unwrap()
            .policy,
        plain
    );
}

#[test]
fn signed_bundle_with_dangling_gateway_index_is_refused() {
    let mut p = compile(GATEWAY, 50).unwrap().policy;
    p.rules[1].gateway = 9;
    let sk = bundle::generate_key();
    let b = bundle::sign(&p, &sk, 2, 0, "prod").unwrap();
    assert!(matches!(
        bundle::verify(&b, &trust(sk.verifying_key()), true),
        Err(BundleError::Decode(m)) if m.contains("gateway #9")
    ));
}

/// Format-3 policy with only the workload-selector section.
const WORKLOADS_ONLY: &str = r#"
version = 1

[defaults]
egress = "drop"

[[rule]]
id    = "db-egress"
who   = { k8s = "app=db,ns=prod" }
allow = { to = "10.0.0.0/8", port = 5432, proto = "tcp" }

[[rule]]
id    = "mesh"
who   = { spiffe = "spiffe://cluster.local/ns/prod/*" }
fail  = "open"
allow = { to = "10.1.0.0/16", port = 443, proto = "tcp" }
"#;

/// Format-3 policy with both sections: a fail-closed k8s rule punted to a gateway.
const GATEWAYS_AND_WORKLOADS: &str = r#"
version = 1

[defaults]
egress = "drop"

[gateway.mcp]
allow_tools = ["search"]

[[rule]]
id    = "dns"
allow = { to = "1.1.1.1", port = 53, proto = "udp" }

[[rule]]
id   = "agent-mcp"
who  = { k8s = "app=agent" }
punt = { to = "203.0.113.0/24", port = 443, proto = "tcp", gateway = "mcp" }
"#;

#[test]
fn format_3_carries_gateways_workloads_or_both() {
    let sk = bundle::generate_key();
    let t = trust(sk.verifying_key());
    for (name, src, gateways, workloads) in [
        ("gateways only", GATEWAY, true, false),
        ("workloads only", WORKLOADS_ONLY, false, true),
        ("both", GATEWAYS_AND_WORKLOADS, true, true),
    ] {
        let p = compile(src, 50).unwrap().policy;
        assert_eq!(p.uses_gateways(), gateways, "{name}");
        assert_eq!(p.uses_workloads(), workloads, "{name}");
        assert!(p.needs_format_3() && p.to_v2().is_none(), "{name}");

        let b = bundle::sign(&p, &sk, 2, 0, "prod").unwrap();
        assert_eq!(bundle::peek_format(&b), Ok(bundle::FORMAT), "{name}");
        // one payload layout for every format-3 bundle: the unused section is an empty list
        assert_eq!(
            b[bundle::HEADER_LEN..b.len() - bundle::SIG_LEN],
            postcard::to_allocvec(&p).unwrap()[..],
            "{name}"
        );
        let v = bundle::verify(&b, &t, true).unwrap();
        assert_eq!(v.policy, p, "{name} round-trips");
        assert_eq!(!v.policy.gateways.is_empty(), gateways, "{name}");
        assert_eq!(!v.policy.workloads.is_empty(), workloads, "{name}");

        // any change to the signed bytes is refused
        let mut bad = b.clone();
        let last = bad.len() - bundle::SIG_LEN - 1;
        bad[last] ^= 1;
        assert!(matches!(
            bundle::verify(&bad, &t, true),
            Err(BundleError::Signature)
        ));
    }

    // Both sections: the fail-closed workload rule's unknown-identity twin drops and never
    // names a gateway; the rule itself keeps its gateway.
    let p = compile(GATEWAYS_AND_WORKLOADS, 50).unwrap().policy;
    let punt: Vec<_> = p.rules.iter().filter(|r| r.name == "agent-mcp").collect();
    assert_eq!(punt.len(), 2, "{punt:?}");
    assert_eq!((punt[0].verdict, punt[0].gateway), (Verdict::Drop as u8, 0));
    assert_eq!((punt[1].verdict, punt[1].gateway), (Verdict::Punt as u8, 1));
    assert_eq!(p.rule_gateway(punt[1]).unwrap().name, "mcp");
    assert_eq!(p.workloads.len(), 2, "selector + unknown-identity twin");
}

#[test]
fn readers_reject_newer_formats_at_the_header() {
    // A v0.3.x host accepts formats 1 and 2 only, so it refuses a format-3 bundle exactly as
    // this build refuses a format-4 one: at the header, before any key, signature or payload
    // work (the real v0.3.1 reader was checked the same way).
    let p = compile(GATEWAYS_AND_WORKLOADS, 50).unwrap().policy;
    let sk = bundle::generate_key();
    let t = trust(sk.verifying_key());
    let mut b = bundle::sign(&p, &sk, 2, 0, "prod").unwrap();
    b[4..6].copy_from_slice(&(bundle::FORMAT + 1).to_le_bytes());
    assert!(matches!(
        bundle::verify(&b, &t, true),
        Err(BundleError::Format(4))
    ));
    assert!(matches!(
        bundle::peek_header(&b),
        Err(BundleError::Format(4))
    ));
    // and a format-3 bundle cannot be relabelled as format 2 for an older host: the format is
    // signed, so the relabelled bundle fails verification.
    b[4..6].copy_from_slice(&bundle::FORMAT_V2.to_le_bytes());
    assert!(matches!(
        bundle::verify(&b, &t, true),
        Err(BundleError::Signature)
    ));
}

#[test]
fn signed_bundle_with_dangling_workload_selector_is_refused() {
    let mut p = compile(WORKLOADS_ONLY, 50).unwrap().policy;
    p.workloads[0].sel = 40;
    let sk = bundle::generate_key();
    let b = bundle::sign(&p, &sk, 2, 0, "prod").unwrap();
    assert!(matches!(
        bundle::verify(&b, &trust(sk.verifying_key()), true),
        Err(BundleError::Decode(m)) if m.contains("selector #40")
    ));
}

/// Source of `testdata/format{1,2}.kvb`, signed by kavach-policy 0.3.1 (before gateway
/// policies) with key `[7; 32]`, serial 2, fleet "prod", created 50.
const GOLDEN_SRC: &str = r#"version = 1

[defaults]
egress = "drop"

[[rule]]
id    = "dns"
allow = { to = ["1.1.1.1", "9.9.9.9"], port = 53, proto = "udp" }

[[rule]]
id    = "agent-mcp"
who   = { user = 1000 }
punt  = { to = "203.0.113.0/24", port = 443, proto = "tcp" }
fail  = "open"
"#;

#[test]
fn bundles_signed_before_gateways_still_verify() {
    let vk = crate::SigningKey::from_bytes(&[7u8; 32]).verifying_key();
    let want = compile(GOLDEN_SRC, 50).unwrap().policy;
    for (bytes, format) in [
        (
            &include_bytes!("../testdata/format1.kvb")[..],
            bundle::FORMAT_V1,
        ),
        (
            &include_bytes!("../testdata/format2.kvb")[..],
            bundle::FORMAT_V2,
        ),
    ] {
        assert_eq!(bundle::peek_format(bytes), Ok(format));
        let v = bundle::verify(bytes, &trust(vk), true).expect("old bundle verifies");
        assert_eq!(v.header.serial, 2);
        assert_eq!(v.policy, want, "format {format} decodes to today's compile");
        assert!(v.policy.gateways.is_empty());
        assert!(v.policy.rules.iter().all(|r| r.gateway == 0));
        assert_eq!(v.policy.rules[1].verdict, Verdict::Punt as u8);
    }
    // and re-signing today's compile of the same source reproduces the format-2 bytes
    let sk = crate::SigningKey::from_bytes(&[7u8; 32]);
    assert_eq!(
        bundle::sign(&want, &sk, 2, 0, "prod").unwrap(),
        include_bytes!("../testdata/format2.kvb")
    );
}

#[test]
fn diff_reports_gateway_changes() {
    let a = compile(GATEWAY, 0).unwrap().policy;
    let b = compile(
        &GATEWAY
            .replace("\"search\"]", "\"search\", \"code.*\"]")
            .replace("[gateway.support]", "[gateway.support2]")
            .replace("gateway = \"support\"", "gateway = \"support2\""),
        0,
    )
    .unwrap()
    .policy;
    let d: Vec<String> = crate::diff::diff(&a, &b)
        .iter()
        .map(ToString::to_string)
        .collect();
    assert!(d.contains(&"~ gateway github-agent".to_string()), "{d:?}");
    assert!(d.contains(&"- gateway support".to_string()), "{d:?}");
    assert!(d.contains(&"+ gateway support2".to_string()), "{d:?}");
    assert!(d.contains(&"~ rule support-mcp".to_string()), "{d:?}");
    assert!(crate::diff::diff(&a, &a).is_empty());
}
