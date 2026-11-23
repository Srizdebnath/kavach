#![no_main]
//! The gateway's framing parsers: HTTP/1.1 heads, chunked bodies (strict and lenient, whole
//! and byte-split), WebSocket frames and reassembly, and per-frame JSON-RPC inspection.
use kavach_gateway::ToolPolicy;
use kavach_gateway::proxy::http::{self, ChunkedDecoder, Limits};
use kavach_gateway::proxy::{jsonrpc, ws};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = Limits {
        max_head: 4096,
        max_headers: 32,
        max_body: 1 << 16,
    };
    if let Ok(h) = http::parse_request_head(data, &limits) {
        assert!(h.head_len <= data.len());
        // The forwarded head must itself parse, with the same request line.
        let fwd = h.forward(0);
        let again = http::parse_request_head(
            &fwd,
            &Limits {
                max_head: 1 << 16,
                max_headers: 64,
                ..limits
            },
        )
        .expect("forwarded head re-parses");
        assert_eq!((again.method, again.target), (h.method, h.target));
    }
    if let Ok(r) = http::parse_response_head(data, &limits, false) {
        assert!(r.head_len <= data.len());
        let _ = r.forward();
    }

    // Chunked: feeding all at once and in two pieces must agree.
    let mid = data.len() / 2;
    for mut d in [ChunkedDecoder::strict(1 << 16), ChunkedDecoder::lenient()] {
        let mut whole = d.clone();
        let mut a = Vec::new();
        let ra = whole.decode(data, &mut a);
        let mut b = Vec::new();
        let rb = d.decode(&data[..mid], &mut b).and_then(|n| {
            if n == mid {
                d.decode(&data[mid..], &mut b).map(|m| n + m)
            } else {
                Ok(n)
            }
        });
        match (ra, rb) {
            (Ok(x), Ok(y)) => {
                assert_eq!(x, y);
                assert_eq!(a, b);
                assert_eq!(whole.is_done(), d.is_done());
            }
            (Err(_), Err(_)) => {}
            (x, y) => panic!("split disagreement {x:?} {y:?}"),
        }
    }

    // WebSocket: parse frames back to back through the assembler and the tracker.
    let mut asm = ws::Assembler::new(1 << 16);
    let mut tracker = ws::FrameTracker::default();
    let mut rest = data;
    while let Some(h) = ws::parse_frame_header(rest) {
        let Some(total) = usize::try_from(h.len)
            .ok()
            .and_then(|l| l.checked_add(h.header_len))
        else {
            break;
        };
        if total > rest.len() {
            break;
        }
        tracker.observe(&rest[..total]);
        if ws::validate_client(&h).and_then(|()| asm.admit(&h)).is_ok() {
            let _ = asm.push(&h, rest[..total].to_vec());
        }
        rest = &rest[total..];
    }

    let p = ToolPolicy {
        allow_tools: vec!["a*".into()],
        ..Default::default()
    };
    let i = jsonrpc::inspect(Some(&p), data, 1 << 16);
    let _ = jsonrpc::error_reply(&i, "g", 1);
});
