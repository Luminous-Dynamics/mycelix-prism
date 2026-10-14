// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root

//! CORS proxy for Prism.
//!
//! Fetches external URLs on behalf of the WASM app and returns
//! responses with permissive CORS headers.
//!
//! Usage: cargo run -p prism-proxy
//! Listens on http://127.0.0.1:8131
//!
//! WASM app requests: GET /proxy?url=https://example.com

mod quota_middleware;

use axum::{
    Router,
    extract::{DefaultBodyLimit, Query},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
};
use prism_common::client_quota::{ClientQuotaState, parse_trusted_proxy_ips};
use prism_common::proxy_limits::MAX_REQUEST_TARGET_BYTES;
use prism_common::ssrf::validate_proxy_url;
use prism_safe_fetch::{SafeFetchError, fetch_public_get, read_limited_body};
use std::net::SocketAddr;
use std::time::Duration;
use tower_http::cors::{AllowOrigin, CorsLayer};

const MAX_RESPONSE_SIZE: usize = 10 * 1024 * 1024; // 10 MiB
const MAX_PROVIDER_REQUEST_SIZE: usize = 1024 * 1024; // 1 MiB

async fn reject_oversized_request_target(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let uri = request.uri();
    let path_and_query_bytes = uri
        .path_and_query()
        .map(|path_and_query| path_and_query.as_str().len())
        .unwrap_or(0);
    let authority_bytes = uri
        .authority()
        .map(|authority| authority.as_str().len())
        .unwrap_or(0);
    let prefix_bytes = if uri.scheme_str().is_some() {
        uri.scheme_str().map(str::len).unwrap_or(0) + 3
    } else if uri.authority().is_some() {
        2
    } else {
        0
    };
    let target_bytes = path_and_query_bytes + authority_bytes + prefix_bytes;

    if target_bytes > MAX_REQUEST_TARGET_BYTES {
        return (StatusCode::URI_TOO_LONG, "Request target too long").into_response();
    }

    next.run(request).await
}

// SSRF validation (`validate_proxy_url` / `is_private_ipv4`) lives in
// `prism_common::ssrf` so `prism-proxy` and `prism-serve` share a single
// implementation — see that module for rationale and tests.

fn build_client(user_agent: &str, timeout_secs: u64) -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent(user_agent)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .build()
        .expect("HTTP client TLS init failed")
}

fn internal_error_response() -> axum::response::Response<axum::body::Body> {
    let mut resp = axum::response::Response::new(axum::body::Body::from("Internal error"));
    *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    resp
}

fn json_response(
    status: u16,
    body: axum::body::Bytes,
) -> axum::response::Response<axum::body::Body> {
    axum::response::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|_| internal_error_response())
}

#[derive(serde::Deserialize)]
struct ProxyParams {
    url: String,
}

async fn proxy_handler(Query(params): Query<ProxyParams>) -> impl IntoResponse {
    let validated = match validate_proxy_url(&params.url) {
        Ok(url) => url,
        Err(reason) => {
            log::warn!("Blocked proxy destination: {}", reason);
            return (StatusCode::FORBIDDEN, reason.to_string()).into_response();
        }
    };
    let host = validated.host_str().unwrap_or("<unknown>");
    log::info!("Proxy request for host {}", host);

    match fetch_public_get(
        validated,
        "Prism/0.1 (proxy; +https://luminousdynamics.org)",
        std::time::Duration::from_secs(15),
        MAX_RESPONSE_SIZE,
        5,
    )
    .await
    {
        Ok(fetched) => {
            let response_bytes = fetched.body.len();
            log::info!(
                "Proxy fetch completed: status={} response_bytes={} redirects={}",
                fetched.status,
                response_bytes,
                fetched.redirect_count
            );
            axum::response::Response::builder()
                .status(fetched.status)
                .header("content-type", fetched.content_type)
                .header("x-prism-proxied", "true")
                .body(axum::body::Body::from(fetched.body))
                .unwrap_or_else(|_| internal_error_response())
                .into_response()
        }
        Err(SafeFetchError::TooLarge) => {
            log::warn!("Proxy fetch failed: reason=response_too_large");
            (StatusCode::PAYLOAD_TOO_LARGE, "Response too large").into_response()
        }
        Err(SafeFetchError::Policy(_)) => {
            log::warn!("Proxy fetch blocked: reason=destination_policy");
            (StatusCode::FORBIDDEN, "Destination blocked by proxy policy").into_response()
        }
        Err(SafeFetchError::RedirectRejected { hop }) => {
            log::warn!("Proxy redirect rejected: reason=policy hop={}", hop);
            (StatusCode::FORBIDDEN, "Redirect rejected by proxy policy").into_response()
        }
        Err(SafeFetchError::Timeout) => {
            log::warn!("Proxy fetch failed: reason=upstream_timeout");
            (StatusCode::GATEWAY_TIMEOUT, "Upstream request timed out").into_response()
        }
        Err(SafeFetchError::Request(_)) => {
            log::warn!("Proxy fetch failed: reason=upstream_transport");
            (StatusCode::BAD_GATEWAY, "Upstream request failed").into_response()
        }
    }
}

/// DuckDuckGo Instant Answer proxy — bypasses CORS.
#[derive(serde::Deserialize)]
struct DdgParams {
    q: String,
}

async fn ddg_handler(Query(params): Query<DdgParams>) -> impl IntoResponse {
    // Let Reqwest percent-encode query data; never splice user input into URL syntax.
    let url = "https://api.duckduckgo.com/";
    log::info!("DuckDuckGo proxy request");

    let client = build_client("Prism/0.2 (ddg-proxy)", 10);

    match client
        .get(url)
        .query(&[
            ("q", params.q.as_str()),
            ("format", "json"),
            ("no_html", "1"),
            ("skip_disambig", "1"),
        ])
        .send()
        .await
    {
        Ok(resp) => {
            if resp.status().is_redirection() {
                log::warn!("Provider redirect blocked: class=search reason=redirect_blocked");
                return (
                    StatusCode::BAD_GATEWAY,
                    "Unexpected provider redirect blocked",
                )
                    .into_response();
            }
            match read_limited_body(resp, MAX_RESPONSE_SIZE).await {
                Ok(body) => json_response(200, axum::body::Bytes::from(body)).into_response(),
                Err(SafeFetchError::TooLarge) => {
                    log::warn!("Provider response failed: class=search reason=response_too_large");
                    (StatusCode::PAYLOAD_TOO_LARGE, "Provider response too large").into_response()
                }
                Err(SafeFetchError::Timeout) => {
                    log::warn!("Provider response failed: class=search reason=timeout");
                    (StatusCode::GATEWAY_TIMEOUT, "Provider response timed out").into_response()
                }
                Err(_) => {
                    log::warn!("Provider response failed: class=search reason=read_failure");
                    (StatusCode::BAD_GATEWAY, "Failed to read provider response").into_response()
                }
            }
        }
        Err(error) if error.is_timeout() => {
            log::warn!("Provider request failed: class=search reason=timeout");
            (StatusCode::GATEWAY_TIMEOUT, "Provider request timed out").into_response()
        }
        Err(_) => {
            log::warn!("Provider request failed: class=search reason=transport");
            (StatusCode::BAD_GATEWAY, "DuckDuckGo request failed").into_response()
        }
    }
}

/// Brave Search proxy — reads API key from X-Brave-Key header, forwards as auth.
#[derive(serde::Deserialize)]
struct BraveParams {
    q: String,
}

async fn brave_handler(
    headers: axum::http::HeaderMap,
    Query(params): Query<BraveParams>,
) -> impl IntoResponse {
    let api_key = headers
        .get("X-Brave-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if api_key.is_empty() {
        return (StatusCode::UNAUTHORIZED, "Missing X-Brave-Key header").into_response();
    }

    // Query serialization prevents '&' or '#' in user input from changing URL structure.
    let url = "https://api.search.brave.com/res/v1/web/search";
    log::info!("Brave proxy request");

    let client = build_client("Prism/0.2 (brave-proxy)", 15);

    match client
        .get(url)
        .query(&[("q", params.q.as_str())])
        .header("X-Subscription-Token", api_key)
        .header("Accept", "application/json")
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status().as_u16();
            if resp.status().is_redirection() {
                log::warn!("Provider redirect blocked: class=search reason=redirect_blocked");
                return (
                    StatusCode::BAD_GATEWAY,
                    "Unexpected provider redirect blocked",
                )
                    .into_response();
            }
            match read_limited_body(resp, MAX_RESPONSE_SIZE).await {
                Ok(body) => json_response(status, axum::body::Bytes::from(body)).into_response(),
                Err(SafeFetchError::TooLarge) => {
                    log::warn!("Provider response failed: class=search reason=response_too_large");
                    (StatusCode::PAYLOAD_TOO_LARGE, "Provider response too large").into_response()
                }
                Err(SafeFetchError::Timeout) => {
                    log::warn!("Provider response failed: class=search reason=timeout");
                    (StatusCode::GATEWAY_TIMEOUT, "Provider response timed out").into_response()
                }
                Err(_) => {
                    log::warn!("Provider response failed: class=search reason=read_failure");
                    (StatusCode::BAD_GATEWAY, "Failed to read provider response").into_response()
                }
            }
        }
        Err(error) if error.is_timeout() => {
            log::warn!("Provider request failed: class=search reason=timeout");
            (StatusCode::GATEWAY_TIMEOUT, "Provider request timed out").into_response()
        }
        Err(_) => {
            log::warn!("Provider request failed: class=search reason=transport");
            (StatusCode::BAD_GATEWAY, "Brave request failed").into_response()
        }
    }
}

/// Perplexity proxy — reads API key from custom header, forwards as Bearer token.
async fn perplexity_handler(
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let api_key = headers
        .get("X-Perplexity-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if api_key.is_empty() {
        return (StatusCode::UNAUTHORIZED, "Missing X-Perplexity-Key header").into_response();
    }

    log::info!("Perplexity proxy request");

    let client = build_client("Prism/0.2 (perplexity-proxy)", 30);

    match client
        .post("https://api.perplexity.ai/chat/completions")
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .body(body.to_vec())
        .send()
        .await
    {
        Ok(resp) => {
            if resp.status().is_redirection() {
                log::warn!("Provider redirect blocked: class=provider reason=redirect_blocked");
                return (
                    StatusCode::BAD_GATEWAY,
                    "Unexpected provider redirect blocked",
                )
                    .into_response();
            }
            let status = resp.status().as_u16();
            match read_limited_body(resp, MAX_RESPONSE_SIZE).await {
                Ok(body) => json_response(status, axum::body::Bytes::from(body)).into_response(),
                Err(SafeFetchError::TooLarge) => {
                    log::warn!(
                        "Provider response failed: class=provider reason=response_too_large"
                    );
                    (StatusCode::PAYLOAD_TOO_LARGE, "Provider response too large").into_response()
                }
                Err(SafeFetchError::Timeout) => {
                    log::warn!("Provider response failed: class=provider reason=timeout");
                    (StatusCode::GATEWAY_TIMEOUT, "Provider response timed out").into_response()
                }
                Err(_) => {
                    log::warn!("Provider response failed: class=provider reason=read_failure");
                    (StatusCode::BAD_GATEWAY, "Failed to read provider response").into_response()
                }
            }
        }
        Err(error) if error.is_timeout() => {
            log::warn!("Provider request failed: class=provider reason=timeout");
            (StatusCode::GATEWAY_TIMEOUT, "Provider request timed out").into_response()
        }
        Err(_) => {
            log::warn!("Provider request failed: class=provider reason=transport");
            (StatusCode::BAD_GATEWAY, "Perplexity request failed").into_response()
        }
    }
}

async fn health() -> &'static str {
    "Prism proxy OK"
}

macro_rules! route_limit_layer {
    ($class:literal, $capacity:expr, $timeout:expr) => {
        tower::ServiceBuilder::new()
            .layer(axum::error_handling::HandleErrorLayer::new(
                |_: axum::BoxError| async {
                    log::warn!(
                        "Proxy route unavailable: class={} reason=capacity_or_deadline",
                        $class
                    );
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Route capacity reached; retry shortly",
                    )
                },
            ))
            .load_shed()
            .concurrency_limit($capacity)
            .timeout($timeout)
    };
}

fn build_app() -> Router {
    build_app_with_quota(ClientQuotaState::default())
}

fn build_app_with_quota(quota_state: ClientQuotaState) -> Router {
    let allowed_origins = AllowOrigin::list([
        "http://localhost:8130"
            .parse()
            .expect("hardcoded CORS origin literal is malformed"),
        "https://prism.mycelix.net"
            .parse()
            .expect("hardcoded CORS origin literal is malformed"),
        "https://prism.luminousdynamics.io"
            .parse()
            .expect("hardcoded CORS origin literal is malformed"),
        "https://app.mycelix.net"
            .parse()
            .expect("hardcoded CORS origin literal is malformed"),
    ]);

    let cors = CorsLayer::new()
        .allow_origin(allowed_origins)
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
        .allow_headers(tower_http::cors::Any);

    let generic_proxy_route = Router::new()
        .route("/proxy", get(proxy_handler))
        .layer(axum::middleware::from_fn_with_state(
            quota_state.clone(),
            quota_middleware::enforce_client_quota,
        ))
        .layer(route_limit_layer!(
            "generic_proxy",
            12,
            Duration::from_secs(20)
        ));

    let search_routes = Router::new()
        .route("/api/ddg", get(ddg_handler))
        .route("/api/brave", get(brave_handler))
        .layer(axum::middleware::from_fn_with_state(
            quota_state.clone(),
            quota_middleware::enforce_client_quota,
        ))
        .layer(route_limit_layer!("search", 12, Duration::from_secs(20)));

    let provider_route = Router::new()
        .route("/api/perplexity", axum::routing::post(perplexity_handler))
        .layer(axum::middleware::from_fn_with_state(
            quota_state.clone(),
            quota_middleware::enforce_client_quota,
        ))
        .layer(route_limit_layer!("provider", 3, Duration::from_secs(35)));

    let app = Router::new()
        .merge(generic_proxy_route)
        .merge(search_routes)
        .merge(provider_route)
        .route("/health", get(health))
        .layer(tower::limit::ConcurrencyLimitLayer::new(50))
        .layer(DefaultBodyLimit::max(MAX_PROVIDER_REQUEST_SIZE))
        .layer(axum::middleware::from_fn(reject_oversized_request_target))
        .layer(cors);

    app
}

fn quota_state_from_env() -> Result<ClientQuotaState, String> {
    let raw = std::env::var("PRISM_TRUSTED_PROXY_IPS").unwrap_or_default();
    if raw.trim().is_empty() {
        return Ok(ClientQuotaState::default());
    }
    parse_trusted_proxy_ips(&raw).map(ClientQuotaState::new)
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let quota_state = quota_state_from_env().unwrap_or_else(|error| {
        log::error!("{}", error);
        std::process::exit(2);
    });
    let app = build_app_with_quota(quota_state);

    // prism-proxy intentionally remains loopback-only. Public deployment belongs
    // behind the explicitly configured ingress in front of prism-serve.
    let addr: SocketAddr = "127.0.0.1:8131".parse().expect("constant socket address");
    log::info!("Prism proxy listening on http://{}", addr);
    println!("Prism CORS proxy on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind port 8131");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("Server error");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_localhost() {
        assert!(validate_proxy_url("http://localhost:8080").is_err());
        assert!(validate_proxy_url("http://127.0.0.1:5432").is_err());
        assert!(validate_proxy_url("http://[::1]:80").is_err());
        assert!(validate_proxy_url("http://0.0.0.0").is_err());
    }

    #[test]
    fn rejects_private_ips() {
        assert!(validate_proxy_url("http://10.0.0.1").is_err());
        assert!(validate_proxy_url("http://172.16.0.1").is_err());
        assert!(validate_proxy_url("http://192.168.1.1").is_err());
    }

    #[test]
    fn rejects_cloud_metadata() {
        assert!(validate_proxy_url("http://169.254.169.254/latest/meta-data/").is_err());
        assert!(validate_proxy_url("http://metadata.google.internal").is_err());
    }

    #[test]
    fn rejects_non_http_schemes() {
        assert!(validate_proxy_url("file:///etc/passwd").is_err());
        assert!(validate_proxy_url("ftp://example.com").is_err());
        assert!(validate_proxy_url("gopher://evil.com").is_err());
    }

    #[test]
    fn rejects_ipv4_mapped_ipv6() {
        // ::ffff:127.0.0.1 — loopback disguised as IPv6
        assert!(validate_proxy_url("http://[::ffff:127.0.0.1]").is_err());
        // ::ffff:192.168.1.1 — private IP disguised as IPv6
        assert!(validate_proxy_url("http://[::ffff:192.168.1.1]").is_err());
        // ::ffff:169.254.169.254 — cloud metadata disguised as IPv6
        assert!(validate_proxy_url("http://[::ffff:169.254.169.254]").is_err());
        // ::ffff:10.0.0.1 — private range disguised as IPv6
        assert!(validate_proxy_url("http://[::ffff:10.0.0.1]").is_err());
    }

    #[test]
    fn rejects_ipv6_link_local_and_ula() {
        // fe80:: — link-local
        assert!(validate_proxy_url("http://[fe80::1]").is_err());
        // fc00:: — unique-local address
        assert!(validate_proxy_url("http://[fc00::1]").is_err());
        // fd00:: — also unique-local
        assert!(validate_proxy_url("http://[fd12::1]").is_err());
    }

    #[test]
    fn allows_valid_external_urls() {
        assert!(validate_proxy_url("https://example.com").is_ok());
        assert!(validate_proxy_url("https://api.duckduckgo.com/?q=test").is_ok());
        assert!(validate_proxy_url("http://en.wikipedia.org/wiki/Rust").is_ok());
    }

    #[tokio::test]
    async fn per_client_rate_limit_rejects_the_31st_generic_proxy_request() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let app = build_app();
        for index in 0..31 {
            let response = app
                .clone()
                .oneshot(
                    Request::get("/proxy?url=http%3A%2F%2F127.0.0.1")
                        .header("origin", "http://localhost:8130")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            if index < 30 {
                assert_eq!(response.status(), StatusCode::FORBIDDEN);
            } else {
                assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
                assert_eq!(
                    response
                        .headers()
                        .get("retry-after")
                        .and_then(|v| v.to_str().ok()),
                    Some("60")
                );
                assert_eq!(
                    response
                        .headers()
                        .get("access-control-allow-origin")
                        .and_then(|v| v.to_str().ok()),
                    Some("http://localhost:8130")
                );
            }
        }
    }

    #[tokio::test]
    async fn per_client_in_flight_cap_sheds_excess_and_recovers_after_completion() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let app = Router::new()
            .route(
                "/proxy",
                get(|| async {
                    tokio::time::sleep(Duration::from_millis(40)).await;
                    "ok"
                }),
            )
            .layer(axum::middleware::from_fn_with_state(
                ClientQuotaState::default(),
                quota_middleware::enforce_client_quota,
            ));
        let request = || Request::get("/proxy").body(Body::empty()).unwrap();

        let (first, second, third) = tokio::join!(
            app.clone().oneshot(request()),
            app.clone().oneshot(request()),
            app.clone().oneshot(request()),
        );
        let responses = [first.unwrap(), second.unwrap(), third.unwrap()];
        assert_eq!(
            responses
                .iter()
                .filter(|response| response.status() == StatusCode::OK)
                .count(),
            2,
            "two generic-proxy requests from one client should hold permits"
        );
        let rejected = responses
            .iter()
            .find(|response| response.status() == StatusCode::TOO_MANY_REQUESTS)
            .expect("third concurrent request should be shed");
        assert_eq!(
            rejected
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok()),
            Some("1")
        );

        let recovered = app.oneshot(request()).await.unwrap();
        assert_eq!(recovered.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn oversized_content_length_is_rejected_before_body_read() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let app = build_app();
        let response = app
            .oneshot(
                Request::post("/api/perplexity")
                    .header("origin", "http://localhost:8130")
                    .header("content-type", "application/json")
                    .header(
                        "content-length",
                        (prism_common::client_quota::MAX_PROXY_REQUEST_BODY_BYTES + 1).to_string(),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-origin")
                .and_then(|value| value.to_str().ok()),
            Some("http://localhost:8130")
        );
    }

    #[tokio::test]
    async fn oversized_provider_body_is_rejected_before_handler_execution() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let app = build_app();
        let body = vec![b'x'; prism_common::client_quota::MAX_PROXY_REQUEST_BODY_BYTES + 1];
        let response = app
            .oneshot(
                Request::post("/api/perplexity")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn accepts_request_target_at_limit() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let app = build_app();
        let prefix = "/health?q=";
        let uri = format!(
            "{}{}",
            prefix,
            "x".repeat(MAX_REQUEST_TARGET_BYTES - prefix.len())
        );
        assert_eq!(uri.len(), MAX_REQUEST_TARGET_BYTES);
        let response = app
            .oneshot(Request::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn rejects_oversized_request_target_before_route_handling() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let app = build_app();
        let uri = format!("/health?q={}", "x".repeat(MAX_REQUEST_TARGET_BYTES));
        let response = app
            .oneshot(
                Request::get(uri)
                    .header("origin", "http://localhost:8130")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::URI_TOO_LONG);
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-origin")
                .and_then(|value| value.to_str().ok()),
            Some("http://localhost:8130"),
            "CORS headers should remain present on URI-too-long responses"
        );
    }
}
