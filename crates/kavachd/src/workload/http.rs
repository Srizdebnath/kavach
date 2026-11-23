//! A deliberately small blocking HTTP/1.1 GET client for the kubelet and the API server:
//! rustls (ring provider) against a CA bundle file, bearer-token auth, `Content-Length`,
//! chunked or close-delimited bodies. No redirects, no keep-alive, bounded sizes.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail, ensure};
use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};

/// Responses larger than this are refused (a big node lists a few MiB of pods).
pub const MAX_BODY: usize = 64 << 20;
const MAX_HEADER: usize = 64 << 10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub tls: bool,
    pub host: String,
    pub port: u16,
    /// Path and query, starting with `/`.
    pub path: String,
}

impl Url {
    pub fn parse(s: &str) -> Result<Self> {
        let (tls, rest) = if let Some(r) = s.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = s.strip_prefix("http://") {
            (false, r)
        } else {
            bail!("URL {s:?} must start with https:// (or http:// for a loopback proxy)");
        };
        let (auth, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        ensure!(!auth.contains('@'), "URL {s:?}: userinfo is not supported");
        let (host, port) = if let Some(v6) = auth.strip_prefix('[') {
            let (h, p) = v6
                .split_once(']')
                .ok_or_else(|| anyhow!("URL {s:?}: bad IPv6 host"))?;
            (h, p.strip_prefix(':'))
        } else {
            match auth.rsplit_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (auth, None),
            }
        };
        ensure!(!host.is_empty(), "URL {s:?} has no host");
        let port = match port {
            Some(p) => p.parse().with_context(|| format!("URL {s:?}: bad port"))?,
            None if tls => 443,
            None => 80,
        };
        Ok(Self {
            tls,
            host: host.to_owned(),
            port,
            path: path.to_owned(),
        })
    }

    fn is_loopback(&self) -> bool {
        self.host == "localhost"
            || self
                .host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    }
}

/// TLS client configuration trusting exactly the certificates in `ca_pem` (a PEM bundle).
pub fn tls_config(ca_pem: &[u8]) -> Result<Arc<rustls::ClientConfig>> {
    let mut roots = rustls::RootCertStore::empty();
    let mut n = 0;
    for cert in CertificateDer::pem_slice_iter(ca_pem) {
        roots
            .add(cert.context("parsing CA certificate")?)
            .context("adding CA certificate")?;
        n += 1;
    }
    ensure!(n > 0, "CA bundle contains no certificates");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

trait Conn: Read + Write {}
impl<T: Read + Write> Conn for T {}

/// `GET url` with an optional bearer token. Returns the body of a 2xx response.
pub fn get(
    url: &Url,
    bearer: Option<&str>,
    tls: Option<&Arc<rustls::ClientConfig>>,
    timeout: Duration,
) -> Result<Vec<u8>> {
    // Never send a credential in clear text off the host.
    ensure!(
        bearer.is_none() || url.tls || url.is_loopback(),
        "refusing to send the token over plain http to {}",
        url.host
    );
    let addr = (url.host.as_str(), url.port)
        .to_socket_addrs()
        .with_context(|| format!("resolving {}", url.host))?
        .next()
        .ok_or_else(|| anyhow!("{} has no address", url.host))?;
    let tcp = TcpStream::connect_timeout(&addr, timeout)
        .with_context(|| format!("connecting to {}:{}", url.host, url.port))?;
    tcp.set_read_timeout(Some(timeout))?;
    tcp.set_write_timeout(Some(timeout))?;
    let mut stream: Box<dyn Conn> = if url.tls {
        let cfg = tls.ok_or_else(|| anyhow!("https needs a CA bundle"))?;
        let name = ServerName::try_from(url.host.clone())
            .map_err(|_| anyhow!("{:?} is not a valid TLS server name", url.host))?;
        let conn = rustls::ClientConnection::new(cfg.clone(), name)?;
        Box::new(rustls::StreamOwned::new(conn, tcp))
    } else {
        Box::new(tcp)
    };
    let mut req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nUser-Agent: kavachd\r\nConnection: close\r\n",
        url.path, url.host
    );
    if let Some(t) = bearer {
        req.push_str(&format!("Authorization: Bearer {}\r\n", t.trim()));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes())?;
    stream.flush()?;
    read_response(BufReader::new(stream))
}

/// Parse an HTTP/1.1 response; the body of a 2xx, or an error carrying status and a snippet.
pub fn read_response<R: BufRead>(mut r: R) -> Result<Vec<u8>> {
    let mut line = String::new();
    let mut header_bytes = 0;
    let mut read_line = |r: &mut R, line: &mut String| -> Result<()> {
        line.clear();
        let n = r.by_ref().take(8192).read_line(line)?;
        header_bytes += n;
        ensure!(n > 0, "connection closed in the response header");
        ensure!(header_bytes <= MAX_HEADER, "response header too large");
        Ok(())
    };
    read_line(&mut r, &mut line)?;
    let status: u16 = line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("bad status line {:?}", line.trim_end()))?;
    let (mut len, mut chunked) = (None, false);
    loop {
        read_line(&mut r, &mut line)?;
        let h = line.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            let v = v.trim();
            if k.eq_ignore_ascii_case("content-length") {
                len = Some(v.parse::<usize>().context("bad Content-Length")?);
            } else if k.eq_ignore_ascii_case("transfer-encoding") {
                chunked = v.to_ascii_lowercase().contains("chunked");
            }
        }
    }
    let body = if chunked {
        read_chunked(&mut r)?
    } else if let Some(n) = len {
        ensure!(n <= MAX_BODY, "response body too large ({n} bytes)");
        let mut b = vec![0; n];
        r.read_exact(&mut b)?;
        b
    } else {
        let mut b = Vec::new();
        r.take(MAX_BODY as u64 + 1).read_to_end(&mut b)?;
        ensure!(b.len() <= MAX_BODY, "response body too large");
        b
    };
    if !(200..300).contains(&status) {
        let snippet = String::from_utf8_lossy(&body[..body.len().min(300)]).into_owned();
        bail!("HTTP {status}: {}", snippet.trim());
    }
    Ok(body)
}

fn read_chunked<R: BufRead>(r: &mut R) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut line = String::new();
    loop {
        line.clear();
        ensure!(
            r.by_ref().take(1024).read_line(&mut line)? > 0,
            "truncated chunked body"
        );
        let size = line.trim().split(';').next().unwrap_or("");
        let n =
            usize::from_str_radix(size, 16).with_context(|| format!("bad chunk size {size:?}"))?;
        if n == 0 {
            // trailers until the blank line (or EOF)
            loop {
                line.clear();
                if r.by_ref().take(8192).read_line(&mut line)? == 0 || line.trim().is_empty() {
                    return Ok(out);
                }
            }
        }
        ensure!(out.len() + n <= MAX_BODY, "response body too large");
        let start = out.len();
        out.resize(start + n, 0);
        r.read_exact(&mut out[start..])?;
        let mut crlf = [0u8; 2];
        r.read_exact(&mut crlf)?;
        ensure!(&crlf == b"\r\n", "chunk not terminated by CRLF");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        let u = Url::parse("https://10.0.0.1:6443/api/v1/pods?x=y").unwrap();
        assert_eq!(
            u,
            Url {
                tls: true,
                host: "10.0.0.1".into(),
                port: 6443,
                path: "/api/v1/pods?x=y".into()
            }
        );
        let u = Url::parse("https://[fd00::1]:10250").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.path.as_str()),
            ("fd00::1", 10250, "/")
        );
        assert_eq!(Url::parse("https://node-1").unwrap().port, 443);
        assert_eq!(Url::parse("http://127.0.0.1").unwrap().port, 80);
        assert!(Url::parse("ftp://x").is_err());
        assert!(Url::parse("https://u:p@x/").is_err());
        assert!(Url::parse("https://:1/").is_err());
    }

    #[test]
    fn responses() {
        let ok = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello trailing";
        assert_eq!(read_response(&ok[..]).unwrap(), b"hello");
        let chunked =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\n\r\n";
        assert_eq!(read_response(&chunked[..]).unwrap(), b"hello world");
        let close = b"HTTP/1.0 200 OK\r\n\r\nall of it";
        assert_eq!(read_response(&close[..]).unwrap(), b"all of it");
        let denied = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\n\r\nforbidden";
        let e = read_response(&denied[..]).unwrap_err().to_string();
        assert!(e.contains("403") && e.contains("forbidden"), "{e}");
        assert!(read_response(&b"garbage\r\n\r\n"[..]).is_err());
        assert!(
            read_response(&b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n"[..])
                .is_err()
        );
        let huge = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY + 1
        );
        assert!(read_response(huge.as_bytes()).is_err());
    }

    #[test]
    fn plain_http_get_against_a_local_server() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let srv = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut req = Vec::new();
            let mut buf = [0u8; 1024];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = s.read(&mut buf).unwrap();
                req.extend_from_slice(&buf[..n]);
            }
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                .unwrap();
            String::from_utf8(req).unwrap()
        });
        let u = Url::parse(&format!("http://127.0.0.1:{port}/pods")).unwrap();
        let body = get(&u, Some("tok\n"), None, Duration::from_secs(5)).unwrap();
        assert_eq!(body, b"{}");
        let req = srv.join().unwrap();
        assert!(req.starts_with("GET /pods HTTP/1.1\r\n"), "{req}");
        assert!(req.contains("Authorization: Bearer tok\r\n"), "{req}");
        // tokens never go over plain http to a non-loopback host
        let u = Url::parse("http://192.0.2.1:1/pods").unwrap();
        let e = get(&u, Some("t"), None, Duration::from_millis(1)).unwrap_err();
        assert!(e.to_string().contains("refusing"), "{e}");
    }

    #[test]
    fn tls_config_needs_certificates() {
        assert!(tls_config(b"").is_err());
        assert!(
            tls_config(b"-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n").is_err()
        );
    }
}
