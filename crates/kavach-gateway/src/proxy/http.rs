//! Strict HTTP/1.1 head parsing and body framing.
//!
//! The gateway sits between an agent and an upstream server it does not control, so any
//! disagreement between this parser and the upstream's about where a request ends is a policy
//! bypass (request smuggling). The rules here are therefore deliberately narrower than RFC 9112:
//!
//! * every line ends in CRLF; a bare LF or a stray CR anywhere in the head is an error;
//! * no obs-fold, no whitespace between a field name and its colon, no control bytes in values;
//! * at most one `Content-Length` (even two identical ones are refused), digits only;
//! * `Transfer-Encoding` only as a single `chunked`, never together with `Content-Length`;
//! * request chunk sizes are bare hex: no extensions, no trailers;
//! * request bodies are capped *before* they are read.
//!
//! Whatever is forwarded is re-framed by the gateway (`Content-Length` it computed itself), so the
//! upstream only ever sees bytes that were inspected. Everything here is synchronous and pure so
//! it can be fuzzed directly.

use std::fmt;

/// Limits applied while parsing a head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Largest head (request line + fields + blank line) in bytes.
    pub max_head: usize,
    /// Most header fields.
    pub max_headers: usize,
    /// Largest request body accepted (checked against `Content-Length` up front).
    pub max_body: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_head: 16 * 1024,
            max_headers: 64,
            max_body: crate::MAX_FRAME,
        }
    }
}

/// Why a head or body was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpError {
    /// More bytes are needed (not an error yet).
    Incomplete,
    /// Head larger than [`Limits::max_head`].
    HeadTooLarge,
    /// More than [`Limits::max_headers`] fields.
    TooManyHeaders,
    /// Malformed request line.
    BadRequestLine,
    /// Malformed status line.
    BadStatusLine,
    /// Not HTTP/1.1 (requests) or HTTP/1.x (responses).
    BadVersion,
    /// Method outside the allowed set (`CONNECT`, `TRACE`, extension methods).
    MethodNotAllowed,
    /// LF without a preceding CR, or CR not followed by LF.
    BareLineEnding,
    /// Obsolete line folding.
    ObsFold,
    /// Field name empty, not a token, or followed by whitespace.
    BadHeaderName,
    /// Control byte in a field value.
    BadHeaderValue,
    /// More than one `Content-Length` field.
    DuplicateContentLength,
    /// `Content-Length` not a plain decimal number.
    BadContentLength,
    /// Both `Content-Length` and `Transfer-Encoding`.
    ContentLengthWithTransferEncoding,
    /// A `Transfer-Encoding` other than one `chunked`.
    UnsupportedTransferEncoding,
    /// `Host` missing or repeated.
    BadHost,
    /// `Expect` other than `100-continue`.
    UnsupportedExpect,
    /// WebSocket upgrade request that is malformed or carries a body.
    BadUpgrade,
    /// Malformed chunked encoding.
    BadChunk,
    /// Body larger than [`Limits::max_body`].
    BodyTooLarge,
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for HttpError {}

impl HttpError {
    /// Status code the gateway answers with.
    pub fn status(self) -> (u16, &'static str) {
        match self {
            HttpError::HeadTooLarge | HttpError::TooManyHeaders => {
                (431, "Request Header Fields Too Large")
            }
            HttpError::BodyTooLarge => (413, "Content Too Large"),
            HttpError::MethodNotAllowed => (405, "Method Not Allowed"),
            HttpError::UnsupportedExpect => (417, "Expectation Failed"),
            HttpError::UnsupportedTransferEncoding => (501, "Not Implemented"),
            _ => (400, "Bad Request"),
        }
    }
}

/// One header field. The value is raw bytes with surrounding whitespace removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Field name as sent.
    pub name: String,
    /// Field value (may contain obs-text, never CR/LF/NUL).
    pub value: Vec<u8>,
}

impl Header {
    fn is(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name)
    }
}

/// How a message body is delimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// No body.
    None,
    /// Exactly this many bytes.
    Length(u64),
    /// `Transfer-Encoding: chunked`.
    Chunked,
    /// Until the connection closes (responses only).
    CloseDelimited,
}

/// Methods the gateway forwards. `CONNECT` would open a tunnel past inspection.
pub const METHODS: &[&str] = &["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];

/// Fields never forwarded as-is: hop-by-hop fields, framing (re-computed), and
/// `Sec-WebSocket-Extensions` (a compressed frame could not be inspected).
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authorization",
    "proxy-authenticate",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "expect",
    "sec-websocket-extensions",
];

fn is_hop_by_hop(name: &str) -> bool {
    HOP_BY_HOP.iter().any(|h| name.eq_ignore_ascii_case(h))
}

/// A parsed request head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHead {
    /// Request method (one of [`METHODS`]).
    pub method: String,
    /// Request target, visible ASCII only.
    pub target: String,
    /// Header fields in order.
    pub headers: Vec<Header>,
    /// Body framing.
    pub framing: Framing,
    /// `Expect: 100-continue` was sent.
    pub expect_continue: bool,
    /// `Connection: close` was sent.
    pub close: bool,
    /// A well-formed WebSocket upgrade (`GET`, `Upgrade: websocket`, key, version 13).
    pub websocket: bool,
    /// Bytes consumed by the head, blank line included.
    pub head_len: usize,
}

/// A parsed response head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseHead {
    /// Status code.
    pub status: u16,
    /// The status line without CRLF.
    pub status_line: String,
    /// Header fields in order.
    pub headers: Vec<Header>,
    /// Body framing (already accounting for HEAD / 1xx / 204 / 304).
    pub framing: Framing,
    /// The connection must close after this response.
    pub close: bool,
    /// The response carries a `Content-Type: text/event-stream`.
    pub event_stream: bool,
    /// Bytes consumed by the head.
    pub head_len: usize,
}

fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Split the head into lines, enforcing CRLF. Returns the lines (without CRLF) and the length
/// consumed through the blank line.
fn split_head<'a>(buf: &'a [u8], limits: &Limits) -> Result<(Vec<&'a [u8]>, usize), HttpError> {
    let mut lines = Vec::new();
    let mut start = 0;
    let scan = &buf[..buf.len().min(limits.max_head)];
    let mut i = 0;
    while i < scan.len() {
        match scan[i] {
            b'\n' => {
                if i == 0 || scan[i - 1] != b'\r' || i - 1 < start {
                    return Err(HttpError::BareLineEnding);
                }
                let line = &scan[start..i - 1];
                start = i + 1;
                if line.is_empty() {
                    if lines.is_empty() {
                        // A leading empty line: RFC 9112 lets servers skip it; we do not.
                        return Err(HttpError::BadRequestLine);
                    }
                    return Ok((lines, start));
                }
                if lines.len() > limits.max_headers {
                    return Err(HttpError::TooManyHeaders);
                }
                lines.push(line);
            }
            b'\r' if i + 1 < scan.len() && scan[i + 1] != b'\n' => {
                return Err(HttpError::BareLineEnding);
            }
            _ => {}
        }
        i += 1;
    }
    if buf.len() >= limits.max_head {
        Err(HttpError::HeadTooLarge)
    } else {
        Err(HttpError::Incomplete)
    }
}

fn parse_fields(lines: &[&[u8]]) -> Result<Vec<Header>, HttpError> {
    let mut out = Vec::with_capacity(lines.len());
    for line in lines {
        if matches!(line.first(), Some(b' ' | b'\t')) {
            return Err(HttpError::ObsFold);
        }
        let colon = line
            .iter()
            .position(|&b| b == b':')
            .ok_or(HttpError::BadHeaderName)?;
        let name = &line[..colon];
        if name.is_empty() || !name.iter().all(|&b| is_tchar(b)) {
            return Err(HttpError::BadHeaderName);
        }
        let value = trim_ows(&line[colon + 1..]);
        if value.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f) {
            return Err(HttpError::BadHeaderValue);
        }
        out.push(Header {
            // tchar is ASCII, so this cannot fail.
            name: String::from_utf8_lossy(name).into_owned(),
            value: value.to_vec(),
        });
    }
    Ok(out)
}

fn trim_ows(v: &[u8]) -> &[u8] {
    let s = v
        .iter()
        .position(|&b| b != b' ' && b != b'\t')
        .unwrap_or(v.len());
    let e = v
        .iter()
        .rposition(|&b| b != b' ' && b != b'\t')
        .map_or(s, |e| e + 1);
    &v[s..e.max(s)]
}

fn tokens(v: &[u8]) -> impl Iterator<Item = &[u8]> {
    v.split(|&b| b == b',')
        .map(trim_ows)
        .filter(|t| !t.is_empty())
}

fn content_length(v: &[u8]) -> Result<u64, HttpError> {
    if v.is_empty() || v.len() > 19 || !v.iter().all(u8::is_ascii_digit) {
        return Err(HttpError::BadContentLength);
    }
    // ≤ 19 ASCII digits always fits in u64.
    Ok(v.iter().fold(0u64, |n, &d| n * 10 + u64::from(d - b'0')))
}

/// Framing fields shared by requests and responses.
struct FramingFields {
    content_length: Option<u64>,
    chunked: bool,
    close: bool,
    keep_alive: bool,
    conn_upgrade: bool,
}

fn framing_fields(headers: &[Header]) -> Result<FramingFields, HttpError> {
    let mut f = FramingFields {
        content_length: None,
        chunked: false,
        close: false,
        keep_alive: false,
        conn_upgrade: false,
    };
    let mut te_seen = false;
    for h in headers {
        if h.is("content-length") {
            if f.content_length.is_some() {
                return Err(HttpError::DuplicateContentLength);
            }
            f.content_length = Some(content_length(&h.value)?);
        } else if h.is("transfer-encoding") {
            if te_seen || !h.value.eq_ignore_ascii_case(b"chunked") {
                return Err(HttpError::UnsupportedTransferEncoding);
            }
            te_seen = true;
            f.chunked = true;
        } else if h.is("connection") {
            for t in tokens(&h.value) {
                f.close |= t.eq_ignore_ascii_case(b"close");
                f.keep_alive |= t.eq_ignore_ascii_case(b"keep-alive");
                f.conn_upgrade |= t.eq_ignore_ascii_case(b"upgrade");
            }
        }
    }
    if f.chunked && f.content_length.is_some() {
        return Err(HttpError::ContentLengthWithTransferEncoding);
    }
    Ok(f)
}

/// Parse a request head from the start of `buf`.
pub fn parse_request_head(buf: &[u8], limits: &Limits) -> Result<RequestHead, HttpError> {
    let (lines, head_len) = split_head(buf, limits)?;
    let mut parts = lines[0].split(|&b| b == b' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(HttpError::BadRequestLine);
    };
    if method.is_empty() || !method.iter().all(|&b| is_tchar(b)) {
        return Err(HttpError::BadRequestLine);
    }
    if target.is_empty() || !target.iter().all(|&b| (0x21..0x7f).contains(&b)) {
        return Err(HttpError::BadRequestLine);
    }
    if version != b"HTTP/1.1" {
        return Err(HttpError::BadVersion);
    }
    let method = String::from_utf8_lossy(method).into_owned();
    if !METHODS.contains(&method.as_str()) {
        return Err(HttpError::MethodNotAllowed);
    }
    let headers = parse_fields(&lines[1..])?;
    let ff = framing_fields(&headers)?;

    let mut host = 0;
    let mut expect_continue = false;
    let mut upgrade_ws = false;
    let mut ws_key = false;
    let mut ws_version = false;
    for h in &headers {
        if h.is("host") {
            host += 1;
        } else if h.is("expect") {
            if !h.value.eq_ignore_ascii_case(b"100-continue") {
                return Err(HttpError::UnsupportedExpect);
            }
            expect_continue = true;
        } else if h.is("upgrade") {
            upgrade_ws = tokens(&h.value).any(|t| t.eq_ignore_ascii_case(b"websocket"));
        } else if h.is("sec-websocket-key") {
            ws_key = !h.value.is_empty();
        } else if h.is("sec-websocket-version") {
            ws_version = h.value == b"13";
        }
    }
    if host != 1 {
        return Err(HttpError::BadHost);
    }

    let framing = if ff.chunked {
        Framing::Chunked
    } else {
        match ff.content_length {
            Some(n) if n > limits.max_body as u64 => return Err(HttpError::BodyTooLarge),
            Some(0) | None => Framing::None,
            Some(n) => Framing::Length(n),
        }
    };

    let websocket = upgrade_ws && ff.conn_upgrade;
    if websocket && (method != "GET" || !ws_key || !ws_version || framing != Framing::None) {
        return Err(HttpError::BadUpgrade);
    }

    Ok(RequestHead {
        method,
        target: String::from_utf8_lossy(target).into_owned(),
        headers,
        framing,
        expect_continue,
        close: ff.close,
        websocket,
        head_len,
    })
}

impl RequestHead {
    /// The head to send upstream: end-to-end fields only, framed with `body_len`.
    pub fn forward(&self, body_len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(self.method.as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.target.as_bytes());
        out.extend_from_slice(b" HTTP/1.1\r\n");
        for h in self.headers.iter().filter(|h| !is_hop_by_hop(&h.name)) {
            push_field(&mut out, &h.name, &h.value);
        }
        if self.websocket {
            out.extend_from_slice(b"Connection: Upgrade\r\nUpgrade: websocket\r\n");
        } else {
            if body_len > 0 || matches!(self.method.as_str(), "POST" | "PUT" | "PATCH") {
                push_field(&mut out, "Content-Length", body_len.to_string().as_bytes());
            }
            if self.close {
                out.extend_from_slice(b"Connection: close\r\n");
            }
        }
        out.extend_from_slice(b"\r\n");
        out
    }

    /// The value of the first field named `name`.
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|h| h.is(name))
            .map(|h| h.value.as_slice())
    }
}

fn push_field(out: &mut Vec<u8>, name: &str, value: &[u8]) {
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(b": ");
    out.extend_from_slice(value);
    out.extend_from_slice(b"\r\n");
}

/// Parse a response head. `head_request` is true when it answers a `HEAD`.
pub fn parse_response_head(
    buf: &[u8],
    limits: &Limits,
    head_request: bool,
) -> Result<ResponseHead, HttpError> {
    let (lines, head_len) = split_head(buf, limits).map_err(|e| match e {
        HttpError::BadRequestLine => HttpError::BadStatusLine,
        e => e,
    })?;
    let line = lines[0];
    let (version, rest) = match line.iter().position(|&b| b == b' ') {
        Some(i) => (&line[..i], &line[i + 1..]),
        None => return Err(HttpError::BadStatusLine),
    };
    let http10 = match version {
        b"HTTP/1.1" => false,
        b"HTTP/1.0" => true,
        _ => return Err(HttpError::BadVersion),
    };
    if rest.len() < 3
        || !rest[..3].iter().all(u8::is_ascii_digit)
        || (rest.len() > 3 && rest[3] != b' ')
    {
        return Err(HttpError::BadStatusLine);
    }
    if line.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f) {
        return Err(HttpError::BadStatusLine);
    }
    let status = rest[..3]
        .iter()
        .fold(0u16, |n, &d| n * 10 + u16::from(d - b'0'));
    if !(100..=599).contains(&status) {
        return Err(HttpError::BadStatusLine);
    }
    let headers = parse_fields(&lines[1..])?;
    let ff = framing_fields(&headers)?;
    let event_stream = headers.iter().any(|h| {
        h.is("content-type")
            && h.value.len() >= 17
            && h.value[..17].eq_ignore_ascii_case(b"text/event-stream")
    });

    let framing = if head_request || (100..200).contains(&status) || status == 204 || status == 304
    {
        Framing::None
    } else if ff.chunked {
        Framing::Chunked
    } else if let Some(n) = ff.content_length {
        Framing::Length(n)
    } else {
        Framing::CloseDelimited
    };
    let close = ff.close
        || (http10 && !ff.keep_alive)
        || (framing == Framing::CloseDelimited && status != 101);
    Ok(ResponseHead {
        status,
        status_line: String::from_utf8_lossy(line).into_owned(),
        headers,
        framing,
        close,
        event_stream,
        head_len,
    })
}

impl ResponseHead {
    /// The head to send to the client: end-to-end fields only, re-framed.
    pub fn forward(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(self.status_line.as_bytes());
        out.extend_from_slice(b"\r\n");
        for h in self.headers.iter().filter(|h| !is_hop_by_hop(&h.name)) {
            push_field(&mut out, &h.name, &h.value);
        }
        match self.framing {
            Framing::Length(n) => push_field(&mut out, "Content-Length", n.to_string().as_bytes()),
            Framing::Chunked => out.extend_from_slice(b"Transfer-Encoding: chunked\r\n"),
            Framing::None | Framing::CloseDelimited => {}
        }
        if self.status == 101 {
            out.extend_from_slice(b"Connection: Upgrade\r\nUpgrade: websocket\r\n");
        } else if self.close {
            out.extend_from_slice(b"Connection: close\r\n");
        }
        out.extend_from_slice(b"\r\n");
        out
    }

    /// The value of the first field named `name`.
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|h| h.is(name))
            .map(|h| h.value.as_slice())
    }
}

/// Longest chunk-size or trailer line accepted.
const MAX_CHUNK_LINE: usize = 1024;
/// Most trailer bytes skipped in lenient (response) mode.
const MAX_TRAILERS: usize = 8 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChunkState {
    Size,
    Data(u64),
    DataCr,
    DataLf,
    Trailer,
    Done,
}

/// Incremental `Transfer-Encoding: chunked` decoder.
///
/// Strict mode (requests): bare hex sizes, no extensions, no trailers, total capped.
/// Lenient mode (responses): extensions ignored, trailers skipped (bounded); no total cap,
/// because an SSE stream is unbounded by design and is streamed, not buffered.
#[derive(Debug, Clone)]
pub struct ChunkedDecoder {
    state: ChunkState,
    line: Vec<u8>,
    strict: bool,
    max_total: Option<u64>,
    total: u64,
    trailer_bytes: usize,
}

impl ChunkedDecoder {
    /// Decoder for request bodies, capped at `max_total` decoded bytes.
    pub fn strict(max_total: usize) -> Self {
        Self::new(true, Some(max_total as u64))
    }

    /// Decoder for response bodies.
    pub fn lenient() -> Self {
        Self::new(false, None)
    }

    fn new(strict: bool, max_total: Option<u64>) -> Self {
        Self {
            state: ChunkState::Size,
            line: Vec::new(),
            strict,
            max_total,
            total: 0,
            trailer_bytes: 0,
        }
    }

    /// Whether the terminating chunk and trailers have been consumed.
    pub fn is_done(&self) -> bool {
        self.state == ChunkState::Done
    }

    /// Feed bytes; decoded data is appended to `out`. Returns how many input bytes were used.
    /// Stops right after the end of the body, leaving any following bytes unconsumed.
    pub fn decode(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<usize, HttpError> {
        let mut i = 0;
        while i < input.len() {
            match self.state {
                ChunkState::Done => break,
                ChunkState::Data(rem) => {
                    let n = (input.len() - i).min(usize::try_from(rem).unwrap_or(usize::MAX));
                    out.extend_from_slice(&input[i..i + n]);
                    i += n;
                    let rem = rem - n as u64;
                    self.state = if rem == 0 {
                        ChunkState::DataCr
                    } else {
                        ChunkState::Data(rem)
                    };
                }
                ChunkState::DataCr => {
                    if input[i] != b'\r' {
                        return Err(HttpError::BadChunk);
                    }
                    i += 1;
                    self.state = ChunkState::DataLf;
                }
                ChunkState::DataLf => {
                    if input[i] != b'\n' {
                        return Err(HttpError::BadChunk);
                    }
                    i += 1;
                    self.state = ChunkState::Size;
                }
                ChunkState::Size | ChunkState::Trailer => {
                    let b = input[i];
                    i += 1;
                    if b != b'\n' {
                        if self.line.len() >= MAX_CHUNK_LINE {
                            return Err(HttpError::BadChunk);
                        }
                        self.line.push(b);
                        continue;
                    }
                    if self.line.pop() != Some(b'\r') || self.line.contains(&b'\r') {
                        return Err(HttpError::BadChunk);
                    }
                    let line = std::mem::take(&mut self.line);
                    if self.state == ChunkState::Size {
                        self.size_line(&line)?;
                    } else {
                        self.trailer_line(&line)?;
                    }
                }
            }
        }
        Ok(i)
    }

    fn size_line(&mut self, line: &[u8]) -> Result<(), HttpError> {
        let hex_end = line
            .iter()
            .position(|b| !b.is_ascii_hexdigit())
            .unwrap_or(line.len());
        let (hex, ext) = line.split_at(hex_end);
        if hex.is_empty() || hex.len() > 15 {
            return Err(HttpError::BadChunk);
        }
        if !ext.is_empty() {
            let ext = trim_ows(ext);
            if self.strict
                || ext.first() != Some(&b';')
                || ext.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f)
            {
                return Err(HttpError::BadChunk);
            }
        }
        let size = hex.iter().fold(0u64, |n, &d| {
            n * 16 + u64::from((d as char).to_digit(16).unwrap_or(0))
        });
        self.total = self.total.saturating_add(size);
        if self.max_total.is_some_and(|m| self.total > m) {
            return Err(HttpError::BodyTooLarge);
        }
        self.state = if size == 0 {
            ChunkState::Trailer
        } else {
            ChunkState::Data(size)
        };
        Ok(())
    }

    fn trailer_line(&mut self, line: &[u8]) -> Result<(), HttpError> {
        if line.is_empty() {
            self.state = ChunkState::Done;
            return Ok(());
        }
        self.trailer_bytes += line.len();
        if self.strict || self.trailer_bytes > MAX_TRAILERS {
            return Err(HttpError::BadChunk);
        }
        Ok(())
    }
}

/// Encode one chunk (empty input encodes nothing; use [`LAST_CHUNK`] to finish).
pub fn encode_chunk(data: &[u8], out: &mut Vec<u8>) {
    if data.is_empty() {
        return;
    }
    out.extend_from_slice(format!("{:x}\r\n", data.len()).as_bytes());
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
}

/// The terminating chunk with no trailers.
pub const LAST_CHUNK: &[u8] = b"0\r\n\r\n";

/// A complete response generated by the gateway itself.
pub fn simple_response(
    status: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
    close: bool,
) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\n{}\r\n",
        body.len(),
        if close { "Connection: close\r\n" } else { "" }
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(s: &str) -> Result<RequestHead, HttpError> {
        parse_request_head(s.as_bytes(), &Limits::default())
    }

    const POST: &str = "POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n";

    #[test]
    fn parses_a_plain_post() {
        let h = req(&format!("{POST}Content-Length: 5\r\n\r\nhello")).unwrap();
        assert_eq!(h.method, "POST");
        assert_eq!(h.target, "/mcp");
        assert_eq!(h.framing, Framing::Length(5));
        assert_eq!(h.head_len, POST.len() + "Content-Length: 5\r\n\r\n".len());
        assert!(!h.websocket && !h.close);
        let fwd = String::from_utf8(h.forward(5)).unwrap();
        assert!(fwd.starts_with("POST /mcp HTTP/1.1\r\nHost: x\r\n"));
        assert!(fwd.contains("Content-Length: 5\r\n"));
    }

    #[test]
    fn incomplete_until_blank_line() {
        assert_eq!(
            req("POST /mcp HTTP/1.1\r\nHost: x\r\n"),
            Err(HttpError::Incomplete)
        );
        assert_eq!(
            req("POST /mcp HTTP/1.1\r\nHost: x\r"),
            Err(HttpError::Incomplete)
        );
    }

    #[test]
    fn refuses_smuggling_shapes() {
        let cases: &[(&str, HttpError)] = &[
            (
                "Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
                HttpError::ContentLengthWithTransferEncoding,
            ),
            (
                "Transfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n",
                HttpError::ContentLengthWithTransferEncoding,
            ),
            (
                "Content-Length: 5\r\nContent-Length: 5\r\n\r\n",
                HttpError::DuplicateContentLength,
            ),
            ("Content-Length: 5, 5\r\n\r\n", HttpError::BadContentLength),
            ("Content-Length: +5\r\n\r\n", HttpError::BadContentLength),
            ("Content-Length: 0x5\r\n\r\n", HttpError::BadContentLength),
            (
                "Transfer-Encoding: chunked, identity\r\n\r\n",
                HttpError::UnsupportedTransferEncoding,
            ),
            (
                "Transfer-Encoding: xchunked\r\n\r\n",
                HttpError::UnsupportedTransferEncoding,
            ),
            (
                "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
                HttpError::UnsupportedTransferEncoding,
            ),
            (
                "Transfer-Encoding : chunked\r\n\r\n",
                HttpError::BadHeaderName,
            ),
            (" Transfer-Encoding: chunked\r\n\r\n", HttpError::ObsFold),
            (
                "X: a\r\n\tTransfer-Encoding: chunked\r\n\r\n",
                HttpError::ObsFold,
            ),
            ("Content-Length: 5\n\r\n", HttpError::BareLineEnding),
            ("X: a\rb\r\n\r\n", HttpError::BareLineEnding),
            ("X: a\x00b\r\n\r\n", HttpError::BadHeaderValue),
            ("Host: y\r\n\r\n", HttpError::BadHost),
            ("Expect: 200-ok\r\n\r\n", HttpError::UnsupportedExpect),
        ];
        for (extra, want) in cases {
            assert_eq!(req(&format!("{POST}{extra}")), Err(*want), "{extra:?}");
        }
        assert_eq!(
            req("GET / HTTP/1.1\nHost: x\n\n"),
            Err(HttpError::BareLineEnding)
        );
        assert_eq!(
            req("GET /  HTTP/1.1\r\nHost: x\r\n\r\n"),
            Err(HttpError::BadRequestLine)
        );
        assert_eq!(
            req("GET / HTTP/1.0\r\nHost: x\r\n\r\n"),
            Err(HttpError::BadVersion)
        );
        assert_eq!(
            req("CONNECT a:443 HTTP/1.1\r\nHost: a\r\n\r\n"),
            Err(HttpError::MethodNotAllowed)
        );
        assert_eq!(
            req("\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n"),
            Err(HttpError::BadRequestLine)
        );
        assert_eq!(
            req("GET /\x7f HTTP/1.1\r\nHost: x\r\n\r\n"),
            Err(HttpError::BadRequestLine)
        );
    }

    #[test]
    fn caps_body_and_head() {
        let big = crate::MAX_FRAME + 1;
        assert_eq!(
            req(&format!("{POST}Content-Length: {big}\r\n\r\n")),
            Err(HttpError::BodyTooLarge)
        );
        let l = Limits {
            max_head: 64,
            ..Limits::default()
        };
        let long = format!("{POST}X: {}\r\n\r\n", "a".repeat(100));
        assert_eq!(
            parse_request_head(long.as_bytes(), &l),
            Err(HttpError::HeadTooLarge)
        );
        let l = Limits {
            max_headers: 2,
            ..Limits::default()
        };
        let many = format!("{POST}A: 1\r\nB: 2\r\nC: 3\r\n\r\n");
        assert_eq!(
            parse_request_head(many.as_bytes(), &l),
            Err(HttpError::TooManyHeaders)
        );
    }

    #[test]
    fn strips_hop_by_hop_and_extensions() {
        let h = req("GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Key: abc\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate\r\nProxy-Authorization: x\r\n\r\n").unwrap();
        assert!(h.websocket);
        let fwd = String::from_utf8(h.forward(0)).unwrap();
        assert!(!fwd.to_ascii_lowercase().contains("permessage"));
        assert!(!fwd.contains("Proxy-Authorization"));
        assert!(!fwd.contains("keep-alive"));
        assert!(fwd.contains("Upgrade: websocket\r\n"));
        assert!(fwd.contains("Sec-WebSocket-Key: abc\r\n"));
        assert_eq!(
            req(
                "POST /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: abc\r\nSec-WebSocket-Version: 13\r\n\r\n"
            ),
            Err(HttpError::BadUpgrade)
        );
        // An Upgrade that is not a WebSocket is simply dropped (h2c, etc).
        let h = req("GET / HTTP/1.1\r\nHost: x\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n")
            .unwrap();
        assert!(!h.websocket);
        assert!(!String::from_utf8(h.forward(0)).unwrap().contains("h2c"));
    }

    #[test]
    fn strict_chunked() {
        let mut d = ChunkedDecoder::strict(100);
        let mut out = Vec::new();
        let body = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\nNEXT";
        let used = d.decode(body, &mut out).unwrap();
        assert!(d.is_done());
        assert_eq!(out, b"hello world");
        assert_eq!(&body[used..], b"NEXT");

        // byte at a time gives the same result
        let mut d = ChunkedDecoder::strict(100);
        let mut out = Vec::new();
        for b in &body[..body.len() - 4] {
            assert_eq!(d.decode(std::slice::from_ref(b), &mut out).unwrap(), 1);
        }
        assert!(d.is_done());
        assert_eq!(out, b"hello world");

        for bad in [
            &b"5;ext=1\r\nhello\r\n0\r\n\r\n"[..],
            b"5\nhello\r\n0\r\n\r\n",
            b"5\r\nhelloX\r\n0\r\n\r\n",
            b"-5\r\nhello\r\n0\r\n\r\n",
            b" 5\r\nhello\r\n0\r\n\r\n",
            b"0\r\nX-Trailer: 1\r\n\r\n",
            b"ffffffffffffffffff\r\n",
            b"\r\n",
        ] {
            let mut d = ChunkedDecoder::strict(100);
            assert!(d.decode(bad, &mut Vec::new()).is_err(), "{bad:?}");
        }
        let mut d = ChunkedDecoder::strict(10);
        assert_eq!(
            d.decode(b"b\r\n", &mut Vec::new()),
            Err(HttpError::BodyTooLarge)
        );
        let mut d = ChunkedDecoder::strict(10);
        assert_eq!(
            d.decode(b"6\r\nabcdef\r\n5\r\n", &mut Vec::new()),
            Err(HttpError::BodyTooLarge)
        );
    }

    #[test]
    fn lenient_chunked_allows_extensions_and_trailers() {
        let mut d = ChunkedDecoder::lenient();
        let mut out = Vec::new();
        d.decode(b"5;name=v\r\nhello\r\n0\r\nX-T: 1\r\n\r\n", &mut out)
            .unwrap();
        assert!(d.is_done());
        assert_eq!(out, b"hello");
        let mut enc = Vec::new();
        encode_chunk(b"hello", &mut enc);
        assert_eq!(enc, b"5\r\nhello\r\n");
    }

    #[test]
    fn response_framing() {
        let l = Limits::default();
        let r = parse_response_head(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n",
            &l,
            false,
        )
        .unwrap();
        assert_eq!(r.framing, Framing::Chunked);
        assert!(r.event_stream && !r.close);
        let r = parse_response_head(b"HTTP/1.1 200 OK\r\n\r\n", &l, false).unwrap();
        assert_eq!(r.framing, Framing::CloseDelimited);
        assert!(r.close);
        assert!(
            String::from_utf8(r.forward())
                .unwrap()
                .contains("Connection: close")
        );
        let r = parse_response_head(b"HTTP/1.1 204 No Content\r\n\r\n", &l, false).unwrap();
        assert_eq!(r.framing, Framing::None);
        let r =
            parse_response_head(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n", &l, true).unwrap();
        assert_eq!(r.framing, Framing::None);
        let r = parse_response_head(b"HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\n", &l, false)
            .unwrap();
        assert!(r.close);
        assert_eq!(
            parse_response_head(
                b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n",
                &l,
                false
            ),
            Err(HttpError::ContentLengthWithTransferEncoding)
        );
        assert_eq!(
            parse_response_head(b"HTTP/1.1 2000 OK\r\n\r\n", &l, false),
            Err(HttpError::BadStatusLine)
        );
        assert_eq!(
            parse_response_head(b"HTTP/2 200 OK\r\n\r\n", &l, false),
            Err(HttpError::BadVersion)
        );
    }
}
