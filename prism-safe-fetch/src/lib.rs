// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Fail-closed HTTP GET for Prism's server-side proxy boundary.
//!
//! Every hop is checked independently. Domain answers are validated as a set,
//! then pinned into a no-proxy Reqwest client with redirects disabled. Body
//! limits are enforced as chunks arrive, not after buffering the whole body.
//! This crate is native-only by workspace membership and must not be added to
//! wasm32 targets.

use prism_common::ssrf::{is_non_public_ip, validate_proxy_url};
use reqwest::header::LOCATION;
use reqwest::{Client, StatusCode};
use std::collections::HashSet;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::time::Duration;
use url::{Host, Url};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DNS_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub enum SafeFetchError {
    Policy(String),
    Request(String),
    TooLarge,
}

impl std::fmt::Display for SafeFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Policy(message) | Self::Request(message) => f.write_str(message),
            Self::TooLarge => f.write_str("response exceeds configured byte limit"),
        }
    }
}

impl std::error::Error for SafeFetchError {}

#[derive(Debug)]
pub struct FetchedResponse {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
    pub final_url: Url,
}

/// Validate a set of DNS answers and return pinned socket addresses.
///
/// Empty sets and mixed public/private sets fail closed. Port zero is
/// intentional: Reqwest's resolve_to_addrs API lets the URL's explicit port,
/// or the scheme's default port, remain authoritative.
pub fn pinned_addrs_from_ips<I>(addresses: I) -> Result<Vec<SocketAddr>, SafeFetchError>
where
    I: IntoIterator<Item = IpAddr>,
{
    let mut unique = HashSet::new();
    let mut pinned = Vec::new();

    for ip in addresses {
        if is_non_public_ip(ip) {
            return Err(SafeFetchError::Policy(
                "hostname resolved to a non-public address".into(),
            ));
        }
        if unique.insert(ip) {
            pinned.push(SocketAddr::new(ip, 0));
        }
    }

    if pinned.is_empty() {
        return Err(SafeFetchError::Policy(
            "hostname did not resolve to any addresses".into(),
        ));
    }

    Ok(pinned)
}

/// Resolve a hostname once and return only a fully public, pinned address set.
async fn resolve_public_host(host: &str, port: u16) -> Result<Vec<SocketAddr>, SafeFetchError> {
    let resolved = tokio::time::timeout(DNS_TIMEOUT, tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| SafeFetchError::Policy("hostname resolution timed out".into()))?
        .map_err(|_| SafeFetchError::Policy("hostname resolution failed".into()))?;

    pinned_addrs_from_ips(resolved.map(|address| address.ip()))
}

/// Build a client with a caller-provided address pin for a domain URL.
///
/// This small seam lets the local-socket regression test prove that Reqwest
/// connects through its address override rather than resolving the domain a
/// second time. Production callers must only pass results returned by
/// `resolve_public_host`.
fn client_for_url_with_pinned_addrs(
    url: &Url,
    user_agent: &str,
    timeout: Duration,
    pinned_addrs: Option<&[SocketAddr]>,
) -> Result<Client, SafeFetchError> {
    let mut builder = Client::builder()
        .user_agent(user_agent)
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        // Never let environment proxy settings route around the validated
        // origin-to-address pinning.
        .no_proxy();

    if let Some(Host::Domain(host)) = url.host() {
        let pinned = pinned_addrs.ok_or_else(|| {
            SafeFetchError::Policy("domain request requires validated DNS pins".into())
        })?;
        if pinned.is_empty() {
            return Err(SafeFetchError::Policy(
                "domain request cannot use an empty DNS pin set".into(),
            ));
        }
        builder = builder.resolve_to_addrs(host, pinned);
    }

    builder
        .build()
        .map_err(|_| SafeFetchError::Request("HTTP client initialization failed".into()))
}

/// Resolve, validate, and pin the current URL's domain before building a
/// client. A fresh client is intentionally used for every redirect hop.
type ResolveFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>, SafeFetchError>> + Send + 'a>>;

/// Resolution is injectable only inside this crate so the production path can
/// be exercised with deterministic local fixtures. Production uses
/// `SystemHostResolver`, which always applies the public-address policy.
trait HostResolver: Send + Sync {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> ResolveFuture<'a>;
}

struct SystemHostResolver;

impl HostResolver for SystemHostResolver {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> ResolveFuture<'a> {
        Box::pin(resolve_public_host(host, port))
    }
}

async fn client_for_url(
    url: &Url,
    user_agent: &str,
    timeout: Duration,
    resolver: &dyn HostResolver,
) -> Result<Client, SafeFetchError> {
    let pinned = if let Some(Host::Domain(host)) = url.host() {
        let port = url
            .port_or_known_default()
            .ok_or_else(|| SafeFetchError::Policy("URL has no usable port".into()))?;
        Some(resolver.resolve(host, port).await?)
    } else {
        None
    };

    client_for_url_with_pinned_addrs(url, user_agent, timeout, pinned.as_deref())
}

/// Canonicalize domain spelling before both resolution and Reqwest's DNS override.
/// In particular, removing a trailing root dot avoids a mismatch between the
/// hostname key used for pinning and the hostname key used by a resolver.
fn normalize_domain_host(mut url: Url) -> Result<Url, SafeFetchError> {
    let domain = match url.host() {
        Some(Host::Domain(host)) => Some(host.to_string()),
        _ => None,
    };
    if let Some(domain) = domain {
        let canonical = domain.trim_end_matches('.').to_ascii_lowercase();
        if canonical.is_empty() {
            return Err(SafeFetchError::Policy("URL has an empty hostname".into()));
        }
        if canonical != domain {
            url.set_host(Some(&canonical))
                .map_err(|_| SafeFetchError::Policy("invalid hostname".into()))?;
        }
    }
    Ok(url)
}

/// Resolve a Location header relative to its current URL and apply the URL
/// policy before any connection is attempted.
pub fn validate_redirect_target(current: &Url, location: &str) -> Result<Url, SafeFetchError> {
    let joined = current
        .join(location)
        .map_err(|_| SafeFetchError::Policy("invalid redirect target".into()))?;
    let next = validate_proxy_url(joined.as_str())
        .map_err(|reason| SafeFetchError::Policy(reason.to_string()))?;
    let next = normalize_domain_host(next)?;

    if current.scheme() == "https" && next.scheme() == "http" {
        return Err(SafeFetchError::Policy(
            "HTTPS-to-HTTP redirect downgrade is forbidden".into(),
        ));
    }

    Ok(next)
}

fn is_redirect(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    )
}

fn validate_content_length(
    content_length: Option<u64>,
    max_bytes: usize,
) -> Result<(), SafeFetchError> {
    if content_length.is_some_and(|length| length > max_bytes as u64) {
        return Err(SafeFetchError::TooLarge);
    }
    Ok(())
}

fn append_limited_chunk(
    body: &mut Vec<u8>,
    chunk: &[u8],
    max_bytes: usize,
) -> Result<(), SafeFetchError> {
    if body.len().saturating_add(chunk.len()) > max_bytes {
        return Err(SafeFetchError::TooLarge);
    }
    body.extend_from_slice(chunk);
    Ok(())
}

/// Read a response under a strict cap, checking declared length first and
/// enforcing the same limit on every chunk for chunked/decompressed bodies.
pub async fn read_limited_body(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, SafeFetchError> {
    validate_content_length(response.content_length(), max_bytes)?;

    let initial_capacity = response
        .content_length()
        .map(|length| length.min(max_bytes as u64) as usize)
        .unwrap_or(0);
    let mut body = Vec::with_capacity(initial_capacity);

    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| SafeFetchError::Request("failed while reading response body".into()))?
    {
        append_limited_chunk(&mut body, &chunk, max_bytes)?;
    }

    Ok(body)
}

/// Fetch a public HTTP(S) resource with validated DNS, pinned destinations,
/// manual redirect checks, and bounded memory use.
pub async fn fetch_public_get(
    initial_url: Url,
    user_agent: &str,
    timeout: Duration,
    max_bytes: usize,
    max_redirects: usize,
) -> Result<FetchedResponse, SafeFetchError> {
    fetch_public_get_with_resolver(
        initial_url,
        user_agent,
        timeout,
        max_bytes,
        max_redirects,
        &SystemHostResolver,
    )
    .await
}

/// Same fetch state machine as the production API, with a private resolver
/// seam so integration-style unit tests can use local sockets and deterministic
/// hostname-to-address mappings without contacting DNS or public hosts.
async fn fetch_public_get_with_resolver(
    initial_url: Url,
    user_agent: &str,
    timeout: Duration,
    max_bytes: usize,
    max_redirects: usize,
    resolver: &dyn HostResolver,
) -> Result<FetchedResponse, SafeFetchError> {
    let validated = validate_proxy_url(initial_url.as_str())
        .map_err(|reason| SafeFetchError::Policy(reason.to_string()))?;
    let mut current = normalize_domain_host(validated)?;

    for hop in 0..=max_redirects {
        let client = client_for_url(&current, user_agent, timeout, resolver).await?;
        let response = client
            .get(current.clone())
            .send()
            .await
            .map_err(|_| SafeFetchError::Request("upstream request failed".into()))?;

        if is_redirect(response.status()) {
            if hop == max_redirects {
                return Err(SafeFetchError::Policy(
                    "redirect hop limit exceeded".into(),
                ));
            }
            let location = response
                .headers()
                .get(LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| {
                    SafeFetchError::Policy("redirect response lacked a valid Location".into())
                })?
                .to_string();
            current = validate_redirect_target(&current, &location)?;
            // Drop this response without reading its body; the next hop gets
            // a newly resolved and pinned client before any outbound request.
            drop(response);
            continue;
        }

        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string();
        let body = read_limited_body(response, max_bytes).await?;

        return Ok(FetchedResponse {
            status,
            content_type,
            body,
            final_url: current,
        });
    }

    Err(SafeFetchError::Policy(
        "redirect hop limit exceeded".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct FixtureResolver {
        pins: HashMap<String, Vec<SocketAddr>>,
        seen: Arc<Mutex<Vec<(String, u16)>>>,
    }

    impl FixtureResolver {
        fn new(pins: HashMap<String, Vec<SocketAddr>>) -> Self {
            Self {
                pins,
                seen: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn seen(&self) -> Vec<(String, u16)> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl HostResolver for FixtureResolver {
        fn resolve<'a>(&'a self, host: &'a str, port: u16) -> ResolveFuture<'a> {
            Box::pin(async move {
                self.seen.lock().unwrap().push((host.to_owned(), port));
                self.pins.get(host).cloned().ok_or_else(|| {
                    SafeFetchError::Policy(format!("unexpected fixture hostname: {host}"))
                })
            })
        }
    }

    async fn read_fixture_headers(socket: &mut tokio::net::TcpStream) -> String {
        use tokio::io::AsyncReadExt;

        let request = tokio::time::timeout(Duration::from_secs(2), async {
            let mut request = Vec::new();
            let mut chunk = [0; 512];
            loop {
                let count = socket.read(&mut chunk).await.unwrap();
                assert_ne!(count, 0, "client closed before sending full headers");
                request.extend_from_slice(&chunk[..count]);
                assert!(request.len() <= 4096, "request headers exceeded test bound");
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break request;
                }
            }
        })
        .await
        .expect("request headers must arrive within the test bound");
        String::from_utf8_lossy(&request).into_owned()
    }

    fn loopback_pin() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0)
    }

    #[tokio::test]
    async fn request_uses_the_pinned_address_override() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // The hostname is deliberately unrelated to the loopback listener.
        // The request can succeed only if the shared client builder pins
        // example.com to the supplied test address instead of looking up DNS.
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let request = tokio::time::timeout(Duration::from_secs(2), async {
                let mut request = Vec::new();
                let mut chunk = [0; 512];
                loop {
                    let count = socket.read(&mut chunk).await.unwrap();
                    assert_ne!(count, 0, "client closed before sending full headers");
                    request.extend_from_slice(&chunk[..count]);
                    assert!(request.len() <= 4096, "request headers exceeded test bound");
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break request;
                    }
                }
            })
            .await
            .expect("client must connect through the pin");
            let request = String::from_utf8_lossy(&request);
            assert!(request.starts_with("GET /pinned HTTP/1.1"));
            assert!(request.lines().any(|line| {
                line.eq_ignore_ascii_case(&format!("host: example.com:{}", address.port()))
            }));
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                )
                .await
                .unwrap();
        });

        let url = Url::parse(&format!("http://example.com:{}/pinned", address.port())).unwrap();
        let pinned = [SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0)];
        let client = client_for_url_with_pinned_addrs(
            &url,
            "prism-safe-fetch-test",
            Duration::from_secs(2),
            Some(&pinned),
        )
        .unwrap();
        let response = tokio::time::timeout(Duration::from_secs(2), client.get(url).send())
            .await
            .expect("request must complete through the pin")
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.text().await.unwrap(), "ok");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn fetch_revalidates_and_pins_each_redirect_hop() {
        use tokio::io::AsyncWriteExt;

        let origin_listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        let target_listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();

        let origin_server = tokio::spawn(async move {
            let (mut socket, _) = tokio::time::timeout(
                Duration::from_secs(2),
                origin_listener.accept(),
            )
            .await
            .expect("origin request must arrive")
            .unwrap();
            let request = read_fixture_headers(&mut socket).await;
            assert!(request.starts_with("GET /start HTTP/1.1"));
            socket.write_all(
                format!(
                    "HTTP/1.1 302 Found\r\nLocation: http://target.example.com:{}/final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    target_addr.port()
                ).as_bytes()
            ).await.unwrap();
        });

        let target_server = tokio::spawn(async move {
            let (mut socket, _) = tokio::time::timeout(
                Duration::from_secs(2),
                target_listener.accept(),
            )
            .await
            .expect("redirect target request must arrive")
            .unwrap();
            let request = read_fixture_headers(&mut socket).await;
            assert!(request.starts_with("GET /final HTTP/1.1"));
            assert!(request.lines().any(|line| {
                line.eq_ignore_ascii_case(&format!("host: target.example.com:{}", target_addr.port()))
            }));
            socket.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
            ).await.unwrap();
        });

        let resolver = FixtureResolver::new(HashMap::from([
            ("origin.example.com".to_string(), vec![loopback_pin()]),
            ("target.example.com".to_string(), vec![loopback_pin()]),
        ]));
        let initial = Url::parse(&format!(
            "http://origin.example.com:{}/start",
            origin_addr.port()
        )).unwrap();
        let response = fetch_public_get_with_resolver(
            initial,
            "prism-safe-fetch-test",
            Duration::from_secs(2),
            32,
            2,
            &resolver,
        ).await.unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"ok");
        assert_eq!(response.final_url.host_str(), Some("target.example.com"));
        let seen = resolver.seen();
        assert_eq!(
            seen,
            vec![
                ("origin.example.com".to_string(), origin_addr.port()),
                ("target.example.com".to_string(), target_addr.port()),
            ],
            "each redirect hostname must be resolved and pinned independently"
        );
        origin_server.await.unwrap();
        target_server.await.unwrap();
    }

    #[tokio::test]
    async fn fetch_rejects_oversized_chunked_body_without_content_length() {
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let _request = read_fixture_headers(&mut socket).await;
            socket.write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n"
            ).await.unwrap();
        });
        let resolver = FixtureResolver::new(HashMap::from([(
            "body.example.com".to_string(),
            vec![loopback_pin()],
        )]));
        let initial = Url::parse(&format!(
            "http://body.example.com:{}/body",
            address.port()
        )).unwrap();
        let result = fetch_public_get_with_resolver(
            initial,
            "prism-safe-fetch-test",
            Duration::from_secs(2),
            4,
            0,
            &resolver,
        ).await;

        assert!(matches!(result, Err(SafeFetchError::TooLarge)));
        assert_eq!(resolver.seen().len(), 1);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn fetch_blocks_loopback_redirect_before_connecting() {
        use tokio::io::AsyncWriteExt;

        let origin_listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        let private_listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let private_addr = private_listener.local_addr().unwrap();

        let origin_server = tokio::spawn(async move {
            let (mut socket, _) = tokio::time::timeout(
                Duration::from_secs(2),
                origin_listener.accept(),
            )
            .await
            .expect("origin request must arrive")
            .unwrap();
            let request = read_fixture_headers(&mut socket).await;
            assert!(request.starts_with("GET /start HTTP/1.1"));
            socket.write_all(
                format!(
                    "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{}/metadata\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    private_addr.port()
                )
                .as_bytes(),
            ).await.unwrap();
        });

        let resolver = FixtureResolver::new(HashMap::from([(
            "origin.example.com".to_string(),
            vec![loopback_pin()],
        )]));
        let initial = Url::parse(&format!(
            "http://origin.example.com:{}/start",
            origin_addr.port()
        )).unwrap();
        let result = fetch_public_get_with_resolver(
            initial,
            "prism-safe-fetch-test",
            Duration::from_secs(2),
            32,
            2,
            &resolver,
        ).await;

        assert!(
            matches!(result, Err(SafeFetchError::Policy(_))),
            "a public origin must not redirect the proxy to loopback"
        );
        assert_eq!(
            resolver.seen(),
            vec![("origin.example.com".to_string(), origin_addr.port())],
            "the blocked loopback target must not be resolved as a follow-up hop"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(250), private_listener.accept())
                .await
                .is_err(),
            "the private redirect target must receive no connection"
        );
        origin_server.await.unwrap();
    }

    #[test]
    fn domain_client_requires_a_nonempty_pin_set() {
        let url = Url::parse("http://example.com/").unwrap();
        assert!(matches!(
            client_for_url_with_pinned_addrs(
                &url,
                "prism-safe-fetch-test",
                Duration::from_secs(1),
                None,
            ),
            Err(SafeFetchError::Policy(_))
        ));
        assert!(matches!(
            client_for_url_with_pinned_addrs(
                &url,
                "prism-safe-fetch-test",
                Duration::from_secs(1),
                Some(&[]),
            ),
            Err(SafeFetchError::Policy(_))
        ));
    }

    #[test]
    fn declared_body_length_accepts_exact_limit_and_missing_length() {
        assert!(validate_content_length(Some(10), 10).is_ok());
        assert!(validate_content_length(None, 10).is_ok());
    }

    #[test]
    fn declared_body_length_rejects_oversized_body_before_reading() {
        assert!(matches!(
            validate_content_length(Some(11), 10),
            Err(SafeFetchError::TooLarge)
        ));
    }

    #[test]
    fn streamed_body_limit_is_exact_and_fail_closed() {
        let mut body = Vec::new();
        append_limited_chunk(&mut body, b"123", 5).unwrap();
        append_limited_chunk(&mut body, b"45", 5).unwrap();
        assert_eq!(body.as_slice(), b"12345");
        assert!(matches!(
            append_limited_chunk(&mut body, b"6", 5),
            Err(SafeFetchError::TooLarge)
        ));
        assert_eq!(body.as_slice(), b"12345");
    }

    #[test]
    fn rejects_empty_dns_answers() {
        assert!(matches!(
            pinned_addrs_from_ips(Vec::<IpAddr>::new()),
            Err(SafeFetchError::Policy(_))
        ));
    }

    #[test]
    fn rejects_mixed_public_and_private_dns_answers() {
        let answers = vec![
            "1.1.1.1".parse().unwrap(),
            "127.0.0.1".parse().unwrap(),
        ];
        assert!(matches!(
            pinned_addrs_from_ips(answers),
            Err(SafeFetchError::Policy(_))
        ));
    }

    #[test]
    fn pins_unique_public_answers_only() {
        let answers = vec![
            "1.1.1.1".parse().unwrap(),
            "2606:4700:4700::1111".parse().unwrap(),
            "1.1.1.1".parse().unwrap(),
        ];
        let pinned = pinned_addrs_from_ips(answers).unwrap();
        assert_eq!(pinned.len(), 2);
        assert!(pinned.iter().all(|address| address.port() == 0));
    }

    #[test]
    fn canonicalizes_trailing_dot_before_pinning() {
        let url = Url::parse("https://Example.com./path").unwrap();
        let canonical = normalize_domain_host(url).unwrap();
        assert_eq!(canonical.host_str(), Some("example.com"));
    }

    #[test]
    fn redirect_target_resolves_relative_locations() {
        let current = Url::parse("https://example.com/a/b").unwrap();
        let next = validate_redirect_target(&current, "../c").unwrap();
        assert_eq!(next.as_str(), "https://example.com/c");
    }

    #[test]
    fn redirect_target_rejects_private_ip_literals() {
        let current = Url::parse("https://example.com/start").unwrap();
        for location in [
            "http://127.0.0.1/admin",
            "http://[::1]/",
            "http://169.254.169.254/latest/meta-data",
            "http://service.internal/",
        ] {
            assert!(
                validate_redirect_target(&current, location).is_err(),
                "must reject {location}"
            );
        }
    }

    #[test]
    fn redirect_target_rejects_https_downgrade() {
        let current = Url::parse("https://example.com/start").unwrap();
        assert!(matches!(
            validate_redirect_target(&current, "http://example.com/next"),
            Err(SafeFetchError::Policy(_))
        ));
    }

    #[test]
    fn redirect_target_rejects_userinfo() {
        let current = Url::parse("https://example.com/start").unwrap();
        assert!(validate_redirect_target(&current, "https://user:pass@other.example/path").is_err());
    }
}
