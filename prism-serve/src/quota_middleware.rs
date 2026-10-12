// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root

use axum::{
    body::{to_bytes, Body},
    extract::{ConnectInfo, State},
    http::{header::HeaderMap, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use prism_common::client_quota::{
    ClientQuotaState, QuotaClass, QuotaRejection, QuotaTicket,
    MAX_PROXY_REQUEST_BODY_BYTES, MAX_PROXY_RESPONSE_BODY_BYTES,
};
use std::net::{IpAddr, SocketAddr};
#[cfg(test)]
use std::net::Ipv4Addr;
use std::time::Duration;

struct InFlightGuard {
    state: ClientQuotaState,
    ticket: QuotaTicket,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.state.release_request(self.ticket);
    }
}

/// Enforce per-client rate, ingress-byte, and response-body quotas before delivery
/// starts. This middleware reads bodies with an explicit byte cap and deadline,
/// then restores the body for Axum's normal extractors.
pub async fn enforce_client_quota(
    State(state): State<ClientQuotaState>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    if request.method() == Method::OPTIONS {
        // CORS preflights do not create upstream work and should not consume
        // the browser's request allowance.
        return next.run(request).await;
    }

    let Some(class) = QuotaClass::for_path(request.uri().path()) else {
        return next.run(request).await;
    };

    // A missing socket peer must never silently collapse all production
    // clients into one localhost quota identity. Unit tests use Router::oneshot,
    // which has no ConnectInfo extension, so they get a deterministic fallback.
    let peer = match request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip())
    {
        Some(peer) => peer,
        None => {
            #[cfg(test)]
            {
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            }
            #[cfg(not(test))]
            {
                log::error!("Proxy quota middleware received a request without ConnectInfo");
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Client identity unavailable",
                )
                    .into_response();
            }
        }
    };
    let forwarded_for = bounded_forwarded_for(request.headers());
    let client = state.resolve_client_ip(peer, forwarded_for.as_deref());
    let target_bytes = request
        .uri()
        .path_and_query()
        .map(|target| target.as_str().len())
        .unwrap_or_else(|| request.uri().path().len());

    let ticket = match state.admit_request(client, class, target_bytes) {
        Ok(ticket) => ticket,
        Err(reason) => return rejection_response(reason),
    };
    // Drop always releases the slot, including every early return and task cancellation.
    let _in_flight = InFlightGuard {
        state: state.clone(),
        ticket,
    };

    let (parts, body) = request.into_parts();
    let body_bytes = match tokio::time::timeout(
        Duration::from_secs(10),
        to_bytes(body, MAX_PROXY_REQUEST_BODY_BYTES),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => {
            return (StatusCode::PAYLOAD_TOO_LARGE, "Request body too large").into_response();
        }
        Err(_) => {
            return (StatusCode::REQUEST_TIMEOUT, "Request body read timed out").into_response();
        }
    };

    if let Err(reason) = state.charge_body(ticket, body_bytes.len()) {
        return rejection_response(reason);
    }

    let response = next
        .run(axum::extract::Request::from_parts(
            parts,
            Body::from(body_bytes),
        ))
        .await;

    let (response_parts, response_body) = response.into_parts();
    let response_bytes = match tokio::time::timeout(
        Duration::from_secs(5),
        to_bytes(response_body, MAX_PROXY_RESPONSE_BODY_BYTES),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => {
            return (
                StatusCode::BAD_GATEWAY,
                "Proxy response exceeds safety limit",
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::GATEWAY_TIMEOUT,
                "Proxy response did not complete",
            )
                .into_response();
        }
    };

    if let Err(reason) = state.charge_response(client, class, response_bytes.len()) {
        return rejection_response(reason);
    }

    log::info!(
        "Proxy request completed: class={:?} status={} response_bytes={}",
        class,
        response_parts.status.as_u16(),
        response_bytes.len()
    );

    Response::from_parts(response_parts, Body::from(response_bytes))
}

fn rejection_response(reason: QuotaRejection) -> Response {
    match reason {
        QuotaRejection::RequestRate => {
            log::warn!("Proxy client quota denied: request rate");
            (
                StatusCode::TOO_MANY_REQUESTS,
                [(axum::http::header::RETRY_AFTER, "60")],
                "Client request rate exceeded",
            )
                .into_response()
        }
        QuotaRejection::IngressBytes => {
            log::warn!("Proxy client quota denied: ingress byte budget");
            (
                StatusCode::TOO_MANY_REQUESTS,
                [(axum::http::header::RETRY_AFTER, "60")],
                "Client byte budget exceeded",
            )
                .into_response()
        }
        QuotaRejection::ResponseBytes => {
            log::warn!("Proxy client quota denied: response byte budget");
            (
                StatusCode::TOO_MANY_REQUESTS,
                [(axum::http::header::RETRY_AFTER, "60")],
                "Client response byte budget exceeded",
            )
                .into_response()
        }
        QuotaRejection::InFlight => {
            log::warn!("Proxy client quota denied: in-flight request cap");
            (
                StatusCode::TOO_MANY_REQUESTS,
                [(axum::http::header::RETRY_AFTER, "1")],
                "Client in-flight request cap reached",
            )
                .into_response()
        }
        QuotaRejection::ClientTableFull | QuotaRejection::StaleTicket => {
            log::warn!("Proxy client quota unavailable");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                [(axum::http::header::RETRY_AFTER, "60")],
                "Client quota capacity unavailable",
            )
                .into_response()
        }
    }
}

/// Bound duplicate/oversized forwarding headers before parsing. Malformed
/// headers are ignored; trusted-proxy resolution then falls back to the peer.
fn bounded_forwarded_for(headers: &HeaderMap) -> Option<String> {
    let values: Vec<_> = headers.get_all("x-forwarded-for").iter().collect();
    if values.is_empty() || values.len() > 8 {
        return None;
    }

    let mut combined = String::new();
    for (index, value) in values.iter().enumerate() {
        let Ok(value) = value.to_str() else {
            return None;
        };
        if combined.len().saturating_add(value.len()) > 4096 {
            return None;
        }
        if index > 0 {
            combined.push(',');
        }
        combined.push_str(value);
    }
    Some(combined)
}
