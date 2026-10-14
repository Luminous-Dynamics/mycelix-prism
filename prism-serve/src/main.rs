// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root

//! Unified Prism server: static files + CORS proxy on a single port.
//!
//! Serves the WASM app from dist/ and proxies external API requests,
//! eliminating the need for a separate proxy service and port.

mod quota_middleware;

use axum::Router;
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::StatusCode;
use axum::http::header::HeaderValue;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use prism_common::client_quota::{ClientQuotaState, parse_trusted_proxy_ips};
use prism_common::proxy_limits::MAX_REQUEST_TARGET_BYTES;
use prism_common::ssrf::validate_proxy_url;
use prism_safe_fetch::{
    PROXY_CONTENT_DISPOSITION, PROXY_CONTENT_SECURITY_POLICY, SafeFetchError,
    fetch_public_get, proxy_content_requires_attachment, read_limited_body,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tower_http::compression::CompressionLayer;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;

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

// ═══════════════════════════════════════════════════════════════
// SSRF PROTECTION
// ═══════════════════════════════════════════════════════════════
//
// `validate_proxy_url` / `is_private_ipv4` live in `prism_common::ssrf` so
// `prism-proxy` and `prism-serve` share a single implementation — see that
// module for rationale and tests.

// ═══════════════════════════════════════════════════════════════
// HTTP CLIENT
// ═══════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════
// PROXY HANDLERS
// ═══════════════════════════════════════════════════════════════

#[derive(serde::Deserialize)]
struct ProxyParams {
    url: String,
}

fn proxy_response(
    status: u16,
    content_type: String,
    body: Vec<u8>,
) -> axum::response::Response {
    // The proxy shares Prism's origin. Apply a restrictive document policy to
    // every upstream response; active formats also download on top-level navigation.
    let requires_attachment = proxy_content_requires_attachment(&content_type);
    let mut response = axum::response::Response::builder()
        .status(status)
        .header("content-type", content_type)
        .header("x-prism-proxied", "true")
        .header("x-content-type-options", "nosniff")
        .header("content-security-policy", PROXY_CONTENT_SECURITY_POLICY)
        .header("cache-control", "no-store")
        .header("referrer-policy", "no-referrer")
        .header("x-frame-options", "DENY");

    if requires_attachment {
        response = response.header("content-disposition", PROXY_CONTENT_DISPOSITION);
    }

    response
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|_| internal_error_response())
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
        "Prism/0.3 (proxy; +https://mycelix.net)",
        Duration::from_secs(15),
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
            proxy_response(fetched.status, fetched.content_type, fetched.body).into_response()
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

#[derive(serde::Deserialize)]
struct DdgParams {
    q: String,
}

async fn ddg_handler(Query(params): Query<DdgParams>) -> impl IntoResponse {
    // Let Reqwest percent-encode query data; never splice user input into URL syntax.
    let url = "https://api.duckduckgo.com/";
    let client = build_client("Prism/0.3 (ddg-proxy)", 10);
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
                Ok(body) => axum::response::Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(body))
                    .unwrap_or_else(|_| internal_error_response())
                    .into_response(),
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
    let client = build_client("Prism/0.3 (brave-proxy)", 15);
    match client
        .get(url)
        .query(&[("q", params.q.as_str())])
        .header("X-Subscription-Token", api_key)
        .header("Accept", "application/json")
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
            let status = resp.status().as_u16();
            match read_limited_body(resp, MAX_RESPONSE_SIZE).await {
                Ok(body) => axum::response::Response::builder()
                    .status(status)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(body))
                    .unwrap_or_else(|_| internal_error_response())
                    .into_response(),
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
    let client = build_client("Prism/0.3 (perplexity-proxy)", 30);
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
                Ok(body) => axum::response::Response::builder()
                    .status(status)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(body))
                    .unwrap_or_else(|_| internal_error_response())
                    .into_response(),
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

// ═══════════════════════════════════════════════════════════════
// SYMTHAEA BRIDGE
// ═══════════════════════════════════════════════════════════════
//
// Forwards a query to the Symthaea Service Daemon (a separate systemd
// service, see /srv/luminous-dynamics/symthaea/nix/modules/
// symthaea-service.nix) over its Unix socket. This is the opt-in "Ask
// Symthaea" action — deliberately not wired into every search (see
// Part 2 of /home/tstoltz/.claude/plans/fuzzy-beaming-brook.md) — so
// volume stays low/high-signal and the daemon (which has no rate
// limiting of its own) isn't exposed to raw request volume.
//
// The daemon has none of its own rate limiting, so this route applies
// its own ConcurrencyLimitLayer + LoadShedLayer + TimeoutLayer (wired in
// build_app) sized to the daemon's single-mutex-serialized capacity.

const SYMTHAEA_MAX_QUERY_CHARS: usize = 2000;

const SYMTHAEA_MAX_RESPONSE_LINE_BYTES: usize = 1024 * 1024; // 1 MiB

/// Read one newline-delimited daemon response without allowing an unbounded
/// String allocation if the local service misbehaves or is compromised.
async fn read_bounded_line<R>(reader: &mut R, max_bytes: usize) -> Result<String, String>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    let mut bytes = Vec::with_capacity(max_bytes.min(4096));
    let mut terminated = false;
    loop {
        let (take, has_newline) = {
            let available = reader
                .fill_buf()
                .await
                .map_err(|_| "failed to read Symthaea response".to_string())?;
            if available.is_empty() {
                break;
            }

            let newline = available.iter().position(|byte| *byte == b'\n');
            let take = newline.map_or(available.len(), |index| index + 1);
            if bytes.len().saturating_add(take) > max_bytes {
                return Err("Symthaea response line exceeds size limit".to_string());
            }
            bytes.extend_from_slice(&available[..take]);
            (take, newline.is_some())
        };
        reader.consume(take);
        if has_newline {
            terminated = true;
            break;
        }
    }

    if !terminated {
        return Err("Symthaea response line is not newline-terminated".to_string());
    }

    String::from_utf8(bytes).map_err(|_| "Symthaea response is not valid UTF-8".to_string())
}

/// Concurrency-limit + load-shed + timeout stack for the Symthaea route.
/// A macro rather than a function because the ServiceBuilder stack's type
/// is awkward to name explicitly; HandleErrorLayer is mandatory here —
/// axum's Router::layer requires an Infallible service error, but
/// LoadShed/Timeout produce a boxed error without it (compile error
/// otherwise: "the trait bound `Infallible: From<Box<dyn Error...>>` is
/// not satisfied").
macro_rules! symthaea_rate_limit_layer {
    ($timeout_duration:expr) => {
        tower::ServiceBuilder::new()
            .layer(axum::error_handling::HandleErrorLayer::new(
                |_: axum::BoxError| async {
                    log::warn!("Symthaea route unavailable: reason=capacity_or_deadline");
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Symthaea is busy, try again shortly",
                    )
                },
            ))
            .load_shed()
            .concurrency_limit(3)
            .timeout($timeout_duration)
    };
}

/// Config for reaching the Symthaea daemon. `None` (e.g. in tests, or a
/// deploy that hasn't set the env vars) makes the route return 503 rather
/// than panicking — this bridge is optional, additive functionality.
#[derive(Clone)]
struct SymthaeaConfig {
    socket_path: String,
    bearer_token: String,
}

impl SymthaeaConfig {
    fn from_env() -> Option<Self> {
        let socket_path = std::env::var("SYMTHAEA_SOCKET_PATH").ok()?;
        let bearer_token = std::env::var("SYMTHAEA_SERVICE_BEARER_TOKEN").ok()?;
        if bearer_token.trim().is_empty() {
            return None;
        }
        Some(Self {
            socket_path,
            bearer_token,
        })
    }
}

#[derive(serde::Deserialize)]
struct SymthaeaQueryRequest {
    content: String,
}

#[derive(serde::Serialize)]
struct SymthaeaQueryResponse {
    content: String,
    confidence: f32,
    safe: bool,
    phi: f32,
    processing_time_ms: u64,
}

/// Parse the daemon's successful response without manufacturing defaults for
/// missing fields or allowing non-finite/out-of-range numeric values.
fn parse_symthaea_response(
    parsed: &serde_json::Value,
) -> Result<SymthaeaQueryResponse, &'static str> {
    if parsed.get("type").and_then(serde_json::Value::as_str) != Some("response") {
        return Err("unexpected_response_type");
    }

    let content = parsed
        .get("content")
        .and_then(serde_json::Value::as_str)
        .ok_or("missing_or_invalid_content")?
        .to_string();
    if content.trim().is_empty() {
        return Err("empty_content");
    }

    let confidence = parsed
        .get("confidence")
        .and_then(serde_json::Value::as_f64)
        .ok_or("missing_or_invalid_confidence")?;
    if !confidence.is_finite() || !(0.0..=1.0).contains(&confidence) {
        return Err("confidence_out_of_range");
    }

    let safe = parsed
        .get("safe")
        .and_then(serde_json::Value::as_bool)
        .ok_or("missing_or_invalid_safety_flag")?;

    let phi = parsed
        .get("phi")
        .and_then(serde_json::Value::as_f64)
        .ok_or("missing_or_invalid_phi")?;
    if !phi.is_finite() || phi.abs() > f32::MAX as f64 {
        return Err("phi_not_finite_or_representable");
    }

    let processing_time_ms = parsed
        .get("processing_time_ms")
        .and_then(serde_json::Value::as_u64)
        .ok_or("missing_or_invalid_processing_time_ms")?;

    Ok(SymthaeaQueryResponse {
        content,
        confidence: confidence as f32,
        safe,
        phi: phi as f32,
        processing_time_ms,
    })
}

async fn symthaea_query_handler(
    State(cfg): State<Option<Arc<SymthaeaConfig>>>,
    axum::Json(req): axum::Json<SymthaeaQueryRequest>,
) -> impl IntoResponse {
    let Some(cfg) = cfg else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Symthaea bridge not configured",
        )
            .into_response();
    };

    if req.content.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "Empty query").into_response();
    }
    if req.content.chars().count() > SYMTHAEA_MAX_QUERY_CHARS {
        return (StatusCode::PAYLOAD_TOO_LARGE, "Query too long").into_response();
    }

    let wire_request = serde_json::json!({
        "type": "query",
        "content": req.content,
        "authorization": format!("Bearer {}", cfg.bearer_token),
    });
    let mut line = match serde_json::to_string(&wire_request) {
        Ok(s) => s,
        Err(_) => return internal_error_response().into_response(),
    };
    line.push('\n');

    // The daemon's own translation calls have been observed taking up to
    // ~160s under real host load (measured 2026-07-04) — this timeout is
    // generous relative to that, not the route-level TimeoutLayer (which
    // bounds the whole request including connect + write).
    let result: Result<String, String> = async {
        let mut stream = UnixStream::connect(&cfg.socket_path)
            .await
            .map_err(|e| format!("connect failed: {e}"))?;
        stream
            .write_all(line.as_bytes())
            .await
            .map_err(|e| format!("write failed: {e}"))?;
        let mut reader = BufReader::new(stream);
        read_bounded_line(&mut reader, SYMTHAEA_MAX_RESPONSE_LINE_BYTES).await
    }
    .await;

    let response_line = match result {
        Ok(line) => line,
        Err(e) => {
            log::warn!("Symthaea bridge request failed");
            return (StatusCode::BAD_GATEWAY, "Symthaea unavailable").into_response();
        }
    };

    let parsed: serde_json::Value = match serde_json::from_str(&response_line) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_GATEWAY, "Malformed Symthaea response").into_response(),
    };

    if parsed.get("type").and_then(|t| t.as_str()) == Some("error") {
        let msg = parsed
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("Symthaea error");
        log::warn!("Symthaea returned an error response");
        return (StatusCode::BAD_GATEWAY, "Symthaea error").into_response();
    }

    // Treat the daemon reply as a typed protocol contract. No missing metric
    // is silently filled with an empty string or zero.
    let out = match parse_symthaea_response(&parsed) {
        Ok(response) => response,
        Err(reason) => {
            log::warn!("Symthaea response rejected: reason={reason}");
            return (StatusCode::BAD_GATEWAY, "Malformed Symthaea response").into_response();
        }
    };

    axum::Json(out).into_response()
}

async fn health() -> &'static str {
    "Prism OK"
}

// ═══════════════════════════════════════════════════════════════
// SERVER SETUP
// ═══════════════════════════════════════════════════════════════

/// Bounded route stacks shed excess work instead of letting one expensive API
/// queue behind the entire process.
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

/// Build the unified Prism router: API proxy routes + static file serving.
///
/// `symthaea_cfg` is `None` when the bridge isn't configured (tests, or a
/// deploy that hasn't set SYMTHAEA_SOCKET_PATH/SYMTHAEA_SERVICE_BEARER_TOKEN)
/// — the route itself handles that by returning 503, so this is purely an
/// explicit opt-in rather than a hard dependency.
fn build_app(dist_path: &str, symthaea_cfg: Option<Arc<SymthaeaConfig>>) -> Router {
    build_app_with_quota(dist_path, symthaea_cfg, ClientQuotaState::default())
}

fn build_app_with_quota(
    dist_path: &str,
    symthaea_cfg: Option<Arc<SymthaeaConfig>>,
    quota_state: ClientQuotaState,
) -> Router {
    let fallback = ServeFile::new(format!("{}/index.html", dist_path));

    let symthaea_route = axum::Router::new()
        .route("/api/symthaea/query", post(symthaea_query_handler))
        .with_state(symthaea_cfg)
        // Scoped tighter than the app-wide ConcurrencyLimitLayer(100) below:
        // the daemon serializes all processing behind a single mutex, so
        // admitting more concurrent requests than it can usefully serve in
        // parallel just means they queue instead of the caller getting a
        // fast, clear "busy" response. LoadShedLayer converts
        // ConcurrencyLimitLayer's default queue-on-overflow into an
        // immediate rejection instead. HandleErrorLayer is required: axum's
        // Router::layer demands an Infallible service error, but
        // LoadShed/Timeout produce a boxed error — this converts it into an
        // actual response instead of failing to compile.
        .layer(axum::middleware::from_fn_with_state(
            quota_state.clone(),
            quota_middleware::enforce_client_quota,
        ))
        .layer(symthaea_rate_limit_layer!(Duration::from_secs(240)));

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
        .route("/api/perplexity", post(perplexity_handler))
        .layer(axum::middleware::from_fn_with_state(
            quota_state.clone(),
            quota_middleware::enforce_client_quota,
        ))
        .layer(route_limit_layer!("provider", 3, Duration::from_secs(35)));

    Router::new()
        .merge(generic_proxy_route)
        .merge(search_routes)
        .merge(provider_route)
        .route("/health", get(health))
        .merge(symthaea_route)
        // Static files with SPA fallback
        .fallback_service(ServeDir::new(dist_path).not_found_service(fallback))
        .layer(tower::limit::ConcurrencyLimitLayer::new(100))
        .layer(DefaultBodyLimit::max(MAX_PROVIDER_REQUEST_SIZE))
        .layer(axum::middleware::from_fn(reject_oversized_request_target))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::REFERRER_POLICY,
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        .layer(CompressionLayer::new())
}

fn quota_state_from_env() -> Result<ClientQuotaState, String> {
    let raw = std::env::var("PRISM_TRUSTED_PROXY_IPS").unwrap_or_default();
    if raw.trim().is_empty() {
        return Ok(ClientQuotaState::default());
    }
    parse_trusted_proxy_ips(&raw).map(ClientQuotaState::new)
}

fn validate_bind_addr(
    configured: Option<&str>,
    allow_non_loopback: bool,
) -> Result<SocketAddr, String> {
    let raw = configured.unwrap_or("127.0.0.1:8130");
    let addr: SocketAddr = raw.parse().map_err(|_| {
        "PRISM_ADDR must be an IP address and port, such as 127.0.0.1:8130".to_string()
    })?;

    if !addr.ip().is_loopback() && !allow_non_loopback {
        return Err(
            "Non-loopback PRISM_ADDR requires PRISM_ALLOW_NON_LOOPBACK_BIND=1 and trusted ingress"
                .to_string(),
        );
    }
    Ok(addr)
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let dist_path = std::env::var("PRISM_DIST").unwrap_or_else(|_| {
        "/srv/luminous-dynamics/mycelix-workspace/mycelix-prism/prism-ui/dist".to_string()
    });

    let symthaea_cfg = SymthaeaConfig::from_env().map(Arc::new);
    if symthaea_cfg.is_none() {
        log::info!(
            "Symthaea bridge not configured (SYMTHAEA_SOCKET_PATH/SYMTHAEA_SERVICE_BEARER_TOKEN unset) — /api/symthaea/query will return 503"
        );
    }

    let quota_state = quota_state_from_env().unwrap_or_else(|error| {
        log::error!("{}", error);
        std::process::exit(2);
    });
    let app = build_app_with_quota(&dist_path, symthaea_cfg, quota_state);

    let configured_addr = std::env::var("PRISM_ADDR").ok();
    let allow_non_loopback =
        std::env::var("PRISM_ALLOW_NON_LOOPBACK_BIND").is_ok_and(|value| value == "1");
    let addr = validate_bind_addr(configured_addr.as_deref(), allow_non_loopback).unwrap_or_else(
        |error| {
            log::error!("{}", error);
            std::process::exit(2);
        },
    );

    if !addr.ip().is_loopback() {
        log::warn!(
            "Non-loopback bind enabled; use trusted ingress/auth. CORS is not access control."
        );
    }
    log::info!("Prism unified server on {} (dist: {})", addr, dist_path);
    println!("Prism serving on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind Prism server address");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("Prism server error");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn symthaea_response_line_is_bounded_before_parsing() {
        use tokio::io::AsyncWriteExt;

        let (mut writer, stream) = tokio::io::duplex(64);
        writer.write_all(b"12345678901234567890\n").await.unwrap();
        drop(writer);
        let mut reader = BufReader::new(stream);

        let error = read_bounded_line(&mut reader, 8).await.unwrap_err();
        assert!(
            error.contains("size limit"),
            "oversized daemon response should fail with a bounded-read error"
        );
    }

    #[tokio::test]
    async fn symthaea_response_line_accepts_a_bounded_complete_json_line() {
        use tokio::io::AsyncWriteExt;

        let (mut writer, stream) = tokio::io::duplex(64);
        writer.write_all(b"{\"safe\":true}\n").await.unwrap();
        drop(writer);
        let mut reader = BufReader::new(stream);

        assert_eq!(
            read_bounded_line(&mut reader, 64).await.unwrap(),
            "{\"safe\":true}\n"
        );
    }

    #[tokio::test]
    async fn symthaea_response_line_rejects_valid_json_without_newline_terminator() {
        use tokio::io::AsyncWriteExt;

        let (mut writer, stream) = tokio::io::duplex(64);
        writer.write_all(b"{\"safe\":true}").await.unwrap();
        drop(writer);
        let mut reader = BufReader::new(stream);

        let error = read_bounded_line(&mut reader, 64).await.unwrap_err();
        assert!(
            error.contains("newline-terminated"),
            "EOF before the required line delimiter must be rejected"
        );
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
        let dir = test_dist_dir();
        let app = build_app(dir.path().to_str().unwrap(), None);
        let response = app
            .oneshot(
                Request::post("/api/perplexity")
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
                .get("x-content-type-options")
                .and_then(|value| value.to_str().ok()),
            Some("nosniff")
        );
    }

    #[tokio::test]
    async fn oversized_provider_body_is_rejected_before_handler_execution() {
        let dir = test_dist_dir();
        let app = build_app(dir.path().to_str().unwrap(), None);
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

    #[test]
    fn server_bind_defaults_to_loopback() {
        assert_eq!(
            validate_bind_addr(None, false).unwrap(),
            "127.0.0.1:8130".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn server_bind_rejects_non_loopback_without_explicit_opt_in() {
        for value in ["0.0.0.0:8130", "192.0.2.10:8130", "[::]:8130"] {
            assert!(
                validate_bind_addr(Some(value), false).is_err(),
                "must reject accidental public/private bind {value}"
            );
        }
    }

    #[test]
    fn server_bind_allows_non_loopback_only_with_explicit_opt_in() {
        assert_eq!(
            validate_bind_addr(Some("0.0.0.0:8130"), true).unwrap(),
            "0.0.0.0:8130".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            validate_bind_addr(Some("127.0.0.1:8130"), false).unwrap(),
            "127.0.0.1:8130".parse::<SocketAddr>().unwrap()
        );
    }

    fn test_dist_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("index.html"),
            "<html><body>Prism</body></html>",
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join("static")).unwrap();
        std::fs::write(dir.path().join("static/test.js"), "console.log('ok')").unwrap();
        dir
    }

    #[tokio::test]
    async fn serves_index_html() {
        let dir = test_dist_dir();
        let app = build_app(dir.path().to_str().unwrap(), None);
        let resp = app
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn spa_fallback_returns_index() {
        let dir = test_dist_dir();
        let app = build_app(dir.path().to_str().unwrap(), None);
        let resp = app
            .oneshot(
                Request::get("/nonexistent/path")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        assert!(
            status == StatusCode::OK || status == StatusCode::NOT_FOUND,
            "Expected 200 or 404 for SPA fallback, got {}",
            status
        );
    }

    #[tokio::test]
    async fn serves_static_files() {
        let dir = test_dist_dir();
        let app = build_app(dir.path().to_str().unwrap(), None);
        let resp = app
            .oneshot(Request::get("/static/test.js").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn security_headers_present() {
        let dir = test_dist_dir();
        let app = build_app(dir.path().to_str().unwrap(), None);
        let resp = app
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            resp.headers()
                .get("x-content-type-options")
                .map(|v| v.to_str().unwrap()),
            Some("nosniff")
        );
        assert_eq!(
            resp.headers()
                .get("x-frame-options")
                .map(|v| v.to_str().unwrap()),
            Some("DENY")
        );
        assert_eq!(
            resp.headers()
                .get("referrer-policy")
                .map(|v| v.to_str().unwrap()),
            Some("strict-origin-when-cross-origin")
        );
    }

    #[tokio::test]
    async fn health_endpoint() {
        let dir = test_dist_dir();
        let app = build_app(dir.path().to_str().unwrap(), None);
        let resp = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn rejects_localhost() {
        assert!(validate_proxy_url("http://localhost:8080").is_err());
        assert!(validate_proxy_url("http://127.0.0.1:5432").is_err());
        assert!(validate_proxy_url("http://[::1]:80").is_err());
    }

    #[test]
    fn rejects_private_ips() {
        assert!(validate_proxy_url("http://10.0.0.1").is_err());
        assert!(validate_proxy_url("http://192.168.1.1").is_err());
    }

    #[test]
    fn allows_external_urls() {
        assert!(validate_proxy_url("https://example.com").is_ok());
        assert!(validate_proxy_url("https://en.wikipedia.org/wiki/Rust").is_ok());
    }

    // ═══════════════════════════════════════════════════════════
    // SYMTHAEA BRIDGE
    // ═══════════════════════════════════════════════════════════

    #[tokio::test]
    async fn symthaea_query_returns_503_when_not_configured() {
        let dir = test_dist_dir();
        let app = build_app(dir.path().to_str().unwrap(), None);
        let resp = app
            .oneshot(
                Request::post("/api/symthaea/query")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"content":"hello"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// Spawns a fake Unix-socket daemon implementing just enough of the
    /// wire protocol to stand in for the real symthaea service: reads one
    /// newline-terminated JSON line, responds however `respond` says to.
    fn spawn_fake_daemon(
        socket_path: std::path::PathBuf,
        respond: impl Fn(serde_json::Value) -> FakeDaemonAction + Send + 'static,
    ) {
        // Bind before spawning so the socket is ready when this helper returns.
        // A fixed sleep in each test cannot guarantee listener readiness under CI load.
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => return,
                };
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                if reader.read_line(&mut line).await.is_err() || line.is_empty() {
                    continue;
                }
                let req: serde_json::Value = match serde_json::from_str(&line) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                match respond(req) {
                    FakeDaemonAction::Reply(mut s) => {
                        s.push('\n');
                        let _ = reader.get_mut().write_all(s.as_bytes()).await;
                    }
                    FakeDaemonAction::HangForever => {
                        tokio::time::sleep(Duration::from_secs(3600)).await;
                    }
                }
            }
        });
    }

    enum FakeDaemonAction {
        Reply(String),
        HangForever,
    }

    fn test_symthaea_cfg(socket_path: &std::path::Path) -> Option<Arc<SymthaeaConfig>> {
        Some(Arc::new(SymthaeaConfig {
            socket_path: socket_path.to_str().unwrap().to_string(),
            bearer_token: "test-token".to_string(),
        }))
    }

    #[test]
    fn symthaea_response_contract_rejects_missing_and_malformed_fields() {
        let valid = serde_json::json!({
            "type": "response",
            "content": "answer",
            "confidence": 0.9,
            "safe": true,
            "phi": 0.85,
            "processing_time_ms": 42
        });
        assert!(parse_symthaea_response(&valid).is_ok());

        let invalid = [
            serde_json::json!({
                "type": "other",
                "content": "answer",
                "confidence": 0.9,
                "safe": true,
                "phi": 0.85,
                "processing_time_ms": 42
            }),
            serde_json::json!({
                "type": "response",
                "confidence": 0.9,
                "safe": true,
                "phi": 0.85,
                "processing_time_ms": 42
            }),
            serde_json::json!({
                "type": "response",
                "content": "",
                "confidence": 0.9,
                "safe": true,
                "phi": 0.85,
                "processing_time_ms": 42
            }),
            serde_json::json!({
                "type": "response",
                "content": " \t\n ",
                "confidence": 0.9,
                "safe": true,
                "phi": 0.85,
                "processing_time_ms": 42
            }),
            serde_json::json!({
                "type": "response",
                "content": "answer",
                "confidence": "high",
                "safe": true,
                "phi": 0.85,
                "processing_time_ms": 42
            }),
            serde_json::json!({
                "type": "response",
                "content": "answer",
                "confidence": 1.1,
                "safe": true,
                "phi": 0.85,
                "processing_time_ms": 42
            }),
            serde_json::json!({
                "type": "response",
                "content": "answer",
                "confidence": 0.9,
                "safe": "true",
                "phi": 0.85,
                "processing_time_ms": 42
            }),
            serde_json::json!({
                "type": "response",
                "content": "answer",
                "confidence": 0.9,
                "safe": true,
                "phi": 1e100,
                "processing_time_ms": 42
            }),
            serde_json::json!({
                "type": "response",
                "content": "answer",
                "confidence": 0.9,
                "safe": true,
                "phi": 0.85,
                "processing_time_ms": "42"
            }),
        ];

        for (index, value) in invalid.iter().enumerate() {
            assert!(
                parse_symthaea_response(value).is_err(),
                "malformed response contract case {index} must fail closed"
            );
        }
    }

    #[tokio::test]
    async fn symthaea_query_round_trips_through_fake_daemon() {
        let dir = test_dist_dir();
        let socket_path = dir.path().join("fake-symthaea.sock");
        spawn_fake_daemon(socket_path.clone(), |req| {
            assert_eq!(req["type"], "query");
            assert_eq!(req["authorization"], "Bearer test-token");
            FakeDaemonAction::Reply(
                serde_json::json!({
                    "type": "response",
                    "content": "a real answer",
                    "confidence": 0.9,
                    "safe": true,
                    "phi": 0.85,
                    "phi_dyad": 1.0,
                    "steps_to_emergence": 0,
                    "processing_time_ms": 42
                })
                .to_string(),
            )
        });

        let app = build_app(
            dir.path().to_str().unwrap(),
            test_symthaea_cfg(&socket_path),
        );
        let resp = app
            .oneshot(
                Request::post("/api/symthaea/query")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"content":"what is X?"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["content"], "a real answer");
        assert_eq!(parsed["processing_time_ms"], 42);
    }

    #[tokio::test]
    async fn symthaea_query_rejects_missing_or_invalid_safety_flag() {
        let malformed_responses = [
            serde_json::json!({
                "type": "response",
                "content": "unqualified answer",
                "confidence": 0.9,
                "phi": 0.85,
                "processing_time_ms": 42
            }),
            serde_json::json!({
                "type": "response",
                "content": "unqualified answer",
                "confidence": 0.9,
                "safe": "true",
                "phi": 0.85,
                "processing_time_ms": 42
            }),
        ];

        for (index, malformed) in malformed_responses.into_iter().enumerate() {
            let dir = test_dist_dir();
            let socket_path = dir
                .path()
                .join(format!("fake-symthaea-invalid-safe-{index}.sock"));
            spawn_fake_daemon(socket_path.clone(), move |_req| {
                FakeDaemonAction::Reply(malformed.to_string())
            });

            let app = build_app(
                dir.path().to_str().unwrap(),
                test_symthaea_cfg(&socket_path),
            );
            let response = app
                .oneshot(
                    Request::post("/api/symthaea/query")
                        .header("content-type", "application/json")
                        .body(Body::from(r#"{ "content": "hello" }"#))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(
                response.status(),
                StatusCode::BAD_GATEWAY,
                "malformed safety flag case {index} must not become a successful response"
            );
            assert_eq!(
                response
                    .headers()
                    .get("x-content-type-options")
                    .and_then(|value| value.to_str().ok()),
                Some("nosniff"),
                "security headers must remain present on rejected daemon responses"
            );
        }
    }

    #[tokio::test]
    async fn symthaea_query_rejects_empty_daemon_content() {
        let dir = test_dist_dir();
        let socket_path = dir.path().join("fake-symthaea-empty-response.sock");
        spawn_fake_daemon(socket_path.clone(), |_req| {
            FakeDaemonAction::Reply(
                serde_json::json!({
                    "type": "response",
                    "content": " \t ",
                    "confidence": 0.9,
                    "safe": true,
                    "phi": 0.5,
                    "processing_time_ms": 1
                })
                .to_string(),
            )
        });

        let app = build_app(
            dir.path().to_str().unwrap(),
            test_symthaea_cfg(&socket_path),
        );
        let response = app
            .oneshot(
                Request::post("/api/symthaea/query")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{ "content": "hello" }"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            response
                .headers()
                .get("x-content-type-options")
                .and_then(|value| value.to_str().ok()),
            Some("nosniff")
        );
    }

    #[tokio::test]
    async fn symthaea_query_accepts_multibyte_content_at_character_limit() {
        let dir = test_dist_dir();
        let socket_path = dir.path().join("fake-symthaea-unicode.sock");
        spawn_fake_daemon(socket_path.clone(), |_req| {
            FakeDaemonAction::Reply(
                serde_json::json!({
                    "type": "response",
                    "content": "accepted",
                    "confidence": 0.9,
                    "safe": true,
                    "phi": 0.5,
                    "processing_time_ms": 1
                })
                .to_string(),
            )
        });

        let content = "é".repeat(SYMTHAEA_MAX_QUERY_CHARS);
        assert_eq!(content.chars().count(), SYMTHAEA_MAX_QUERY_CHARS);
        assert!(
            content.len() > SYMTHAEA_MAX_QUERY_CHARS,
            "fixture must be over the character limit in UTF-8 bytes"
        );

        let app = build_app(
            dir.path().to_str().unwrap(),
            test_symthaea_cfg(&socket_path),
        );
        let response = app
            .oneshot(
                Request::post("/api/symthaea/query")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "content": content }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "a request within the Unicode character limit must not be rejected due to UTF-8 byte length"
        );
    }

    #[tokio::test]
    async fn symthaea_query_rejects_empty_and_oversized_content() {
        let dir = test_dist_dir();
        let socket_path = dir.path().join("fake-symthaea-2.sock");
        spawn_fake_daemon(socket_path.clone(), |_req| {
            FakeDaemonAction::Reply(
                serde_json::json!({"type": "response", "content": "", "confidence": 0.9,
                    "safe": true, "phi": 0.5, "phi_dyad": 1.0, "steps_to_emergence": 0,
                    "processing_time_ms": 1})
                .to_string(),
            )
        });

        let cfg = test_symthaea_cfg(&socket_path);

        let app = build_app(dir.path().to_str().unwrap(), cfg.clone());
        let resp = app
            .oneshot(
                Request::post("/api/symthaea/query")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"content":""}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let too_long = "x".repeat(SYMTHAEA_MAX_QUERY_CHARS + 1);
        let app = build_app(dir.path().to_str().unwrap(), cfg);
        let resp = app
            .oneshot(
                Request::post("/api/symthaea/query")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "content": too_long }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn symthaea_query_times_out_on_hung_daemon() {
        let dir = test_dist_dir();
        let socket_path = dir.path().join("fake-symthaea-hang.sock");
        spawn_fake_daemon(socket_path.clone(), |_req| FakeDaemonAction::HangForever);

        // Rebuild with a short timeout for this test only — the production
        // 240s default would make this test take 4 minutes.
        let symthaea_route = axum::Router::new()
            .route("/api/symthaea/query", post(symthaea_query_handler))
            .with_state(test_symthaea_cfg(&socket_path))
            .layer(symthaea_rate_limit_layer!(Duration::from_millis(200)));

        let resp = symthaea_route
            .oneshot(
                Request::post("/api/symthaea/query")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"content":"hello"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        // TimeoutLayer maps an elapsed timeout to 503 by default in tower.
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn accepts_request_target_at_limit() {
        let dir = test_dist_dir();
        let app = build_app(dir.path().to_str().unwrap(), None);
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
        let dir = test_dist_dir();
        let app = build_app(dir.path().to_str().unwrap(), None);
        let uri = format!("/health?q={}", "x".repeat(MAX_REQUEST_TARGET_BYTES));
        let response = app
            .oneshot(Request::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::URI_TOO_LONG);
        assert_eq!(
            response
                .headers()
                .get("x-content-type-options")
                .and_then(|value| value.to_str().ok()),
            Some("nosniff")
        );
        assert_eq!(
            response
                .headers()
                .get("x-frame-options")
                .and_then(|value| value.to_str().ok()),
            Some("DENY")
        );
        assert_eq!(
            response
                .headers()
                .get("referrer-policy")
                .and_then(|value| value.to_str().ok()),
            Some("strict-origin-when-cross-origin")
        );
    }
}


#[cfg(test)]
mod proxy_response_security_tests {
    use super::proxy_response;

    #[test]
    fn upstream_html_is_attachment_and_receives_a_sandboxed_no_store_policy() {
        let response = proxy_response(
            200,
            "text/html; charset=utf-8".to_string(),
            b"<script>document.cookie</script>".to_vec(),
        );
        let headers = response.headers();

        assert_eq!(
            headers.get("content-disposition").and_then(|value| value.to_str().ok()),
            Some("attachment; filename=\"prism-proxy-content\"")
        );
        assert_eq!(
            headers.get("content-security-policy").and_then(|value| value.to_str().ok()),
            Some("default-src 'none'; sandbox")
        );
        assert_eq!(
            headers.get("x-content-type-options").and_then(|value| value.to_str().ok()),
            Some("nosniff")
        );
        assert_eq!(
            headers.get("cache-control").and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        assert_eq!(
            headers.get("referrer-policy").and_then(|value| value.to_str().ok()),
            Some("no-referrer")
        );
        assert_eq!(
            headers.get("x-frame-options").and_then(|value| value.to_str().ok()),
            Some("DENY")
        );
    }

    #[test]
    fn raster_images_remain_embeddable_but_use_restrictive_response_headers() {
        let response = proxy_response(200, "image/png".to_string(), vec![137, 80, 78, 71]);
        let headers = response.headers();

        assert_eq!(
            headers.get("content-type").and_then(|value| value.to_str().ok()),
            Some("image/png")
        );
        assert!(
            headers.get("content-disposition").is_none(),
            "ordinary raster images must remain usable in image elements"
        );
        assert_eq!(
            headers.get("content-security-policy").and_then(|value| value.to_str().ok()),
            Some("default-src 'none'; sandbox")
        );
        assert_eq!(
            headers.get("cache-control").and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
    }
}
