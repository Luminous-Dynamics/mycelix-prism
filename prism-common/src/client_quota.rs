// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Bounded, deterministic per-client quotas for Prism's outbound-facing APIs.
//!
//! This module intentionally has no HTTP or async-runtime dependency so its
//! quota semantics can be tested with a supplied monotonic clock.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const WINDOW: Duration = Duration::from_secs(60);
const IDLE_TTL: Duration = Duration::from_secs(5 * 60);
const DEFAULT_MAX_CLIENTS: usize = 4_096;

/// Maximum accepted request body for proxy/provider routes (1 MiB).
pub const MAX_PROXY_REQUEST_BODY_BYTES: usize = 1024 * 1024;
/// Maximum accepted response body in one proxied request (10 MiB).
pub const MAX_PROXY_RESPONSE_BODY_BYTES: usize = 10 * 1024 * 1024;

/// Endpoint class used to keep expensive operations from sharing the cheap
/// generic-fetch allowance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuotaClass {
    /// Arbitrary public URL fetch through `/proxy`.
    GenericProxy,
    /// Search-provider calls through `/api/ddg` and `/api/brave`.
    Search,
    /// Metered/credentialed upstream calls through `/api/perplexity`.
    Provider,
    /// Local Symthaea bridge requests.
    Symthaea,
}

impl QuotaClass {
    /// Classify only routes that can create material upstream work.
    pub fn for_path(path: &str) -> Option<Self> {
        match path {
            "/proxy" => Some(Self::GenericProxy),
            "/api/ddg" | "/api/brave" => Some(Self::Search),
            "/api/perplexity" => Some(Self::Provider),
            "/api/symthaea/query" => Some(Self::Symthaea),
            _ => None,
        }
    }

    fn policy(self) -> Policy {
        match self {
            // The proxy response is separately capped at 10 MiB per request.
            Self::GenericProxy => Policy {
                requests: 30,
                in_flight: 2,
                ingress_bytes: 512 * 1024,
                response_bytes: 64 * 1024 * 1024,
            },
            Self::Search => Policy {
                requests: 30,
                in_flight: 2,
                ingress_bytes: 256 * 1024,
                response_bytes: 16 * 1024 * 1024,
            },
            Self::Provider => Policy {
                requests: 8,
                in_flight: 1,
                ingress_bytes: 2 * 1024 * 1024,
                response_bytes: 16 * 1024 * 1024,
            },
            Self::Symthaea => Policy {
                requests: 4,
                in_flight: 1,
                ingress_bytes: 128 * 1024,
                response_bytes: 4 * 1024 * 1024,
            },
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Policy {
    requests: usize,
    in_flight: usize,
    ingress_bytes: usize,
    response_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaRejection {
    /// The route's rolling one-minute request allowance is exhausted.
    RequestRate,
    /// The route's rolling one-minute ingress-byte allowance is exhausted.
    IngressBytes,
    /// The route's rolling one-minute egress-byte allowance is exhausted.
    ResponseBytes,
    /// This client has reached its in-flight request cap for the route class.
    InFlight,
    /// The bounded state table is full of active client entries.
    ClientTableFull,
    /// The original request ticket disappeared before its body could be charged.
    StaleTicket,
}

#[derive(Debug, Clone, Copy)]
struct Event {
    id: u64,
    at: Instant,
    ingress_bytes: usize,
}

#[derive(Debug, Clone, Copy)]
struct ResponseEvent {
    at: Instant,
    bytes: usize,
}

#[derive(Debug, Default)]
struct Bucket {
    events: VecDeque<Event>,
    ingress_bytes: usize,
    responses: VecDeque<ResponseEvent>,
    response_bytes: usize,
}

#[derive(Debug, Default)]
struct ClientUsage {
    last_seen: Option<Instant>,
    buckets: HashMap<QuotaClass, Bucket>,
    in_flight: HashMap<QuotaClass, usize>,
}

/// Proof that a request consumed one rate slot; middleware uses it to charge
/// the exact decoded request-body size after reading the bounded body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaTicket {
    client: IpAddr,
    class: QuotaClass,
    event_id: u64,
}

/// Sliding-window quotas keyed by client IP and route class. The table is
/// bounded and fails closed when it cannot safely track a new active client.
#[derive(Debug)]
pub struct ClientQuota {
    clients: HashMap<IpAddr, ClientUsage>,
    max_clients: usize,
    next_event_id: u64,
}

impl Default for ClientQuota {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_MAX_CLIENTS)
    }
}

impl ClientQuota {
    pub fn with_capacity(max_clients: usize) -> Self {
        Self {
            clients: HashMap::new(),
            max_clients: max_clients.max(1),
            next_event_id: 1,
        }
    }

    /// Record a request and its known byte cost (normally the target URI).
    /// Uses a true rolling 60-second window rather than a fixed-window counter,
    /// avoiding a doubled burst at the minute boundary.
    pub fn admit_request(
        &mut self,
        client: IpAddr,
        class: QuotaClass,
        known_bytes: usize,
        now: Instant,
    ) -> Result<QuotaTicket, QuotaRejection> {
        self.clients.retain(|_, usage| {
            usage.last_seen.is_some_and(|last| now.saturating_duration_since(last) < IDLE_TTL)
        });

        if !self.clients.contains_key(&client) && self.clients.len() >= self.max_clients {
            return Err(QuotaRejection::ClientTableFull);
        }

        let usage = self.clients.entry(client).or_default();
        usage.last_seen = Some(now);
        let policy = class.policy();
        if usage.in_flight.get(&class).copied().unwrap_or(0) >= policy.in_flight {
            return Err(QuotaRejection::InFlight);
        }
        let bucket = usage.buckets.entry(class).or_default();
        purge_expired(bucket, now);

        if bucket.events.len() >= policy.requests {
            return Err(QuotaRejection::RequestRate);
        }
        if known_bytes > policy.ingress_bytes.saturating_sub(bucket.ingress_bytes) {
            return Err(QuotaRejection::IngressBytes);
        }

        let event_id = self.next_event_id;
        self.next_event_id = self.next_event_id.wrapping_add(1).max(1);
        bucket.events.push_back(Event {
            id: event_id,
            at: now,
            ingress_bytes: known_bytes,
        });
        bucket.ingress_bytes = bucket.ingress_bytes.saturating_add(known_bytes);
        *usage.in_flight.entry(class).or_default() += 1;

        Ok(QuotaTicket { client, class, event_id })
    }

    /// Release a request's in-flight slot. Middleware owns an RAII guard so
    /// cancellation, timeout, and early error returns also release capacity.
    pub fn release_request(&mut self, ticket: QuotaTicket) {
        let Some(usage) = self.clients.get_mut(&ticket.client) else {
            return;
        };
        let remove_entry = if let Some(count) = usage.in_flight.get_mut(&ticket.class) {
            *count = count.saturating_sub(1);
            *count == 0
        } else {
            false
        };
        if remove_entry {
            usage.in_flight.remove(&ticket.class);
        }
    }

    /// Charge bytes read from the request body. A failed byte charge keeps the
    /// request-rate slot consumed, so oversized payload attempts still cost a
    /// request slot and cannot be replayed without limit.
    pub fn charge_body(
        &mut self,
        ticket: QuotaTicket,
        body_bytes: usize,
    ) -> Result<(), QuotaRejection> {
        let usage = self.clients.get_mut(&ticket.client).ok_or(QuotaRejection::StaleTicket)?;
        let bucket = usage.buckets.get_mut(&ticket.class).ok_or(QuotaRejection::StaleTicket)?;
        let event = bucket.events.iter_mut().find(|event| event.id == ticket.event_id)
            .ok_or(QuotaRejection::StaleTicket)?;
        let policy = ticket.class.policy();
        if body_bytes > policy.ingress_bytes.saturating_sub(bucket.ingress_bytes) {
            return Err(QuotaRejection::IngressBytes);
        }
        event.ingress_bytes = event.ingress_bytes.saturating_add(body_bytes);
        bucket.ingress_bytes = bucket.ingress_bytes.saturating_add(body_bytes);
        Ok(())
    }

    /// Charge the actual response body before it is sent to the client. This
    /// permits an over-budget response to be replaced with HTTP 429 rather than
    /// leaking a partial body; each endpoint also enforces a hard per-response cap.
    pub fn charge_response(
        &mut self,
        client: IpAddr,
        class: QuotaClass,
        response_bytes: usize,
        now: Instant,
    ) -> Result<(), QuotaRejection> {
        let usage = self.clients.get_mut(&client).ok_or(QuotaRejection::StaleTicket)?;
        usage.last_seen = Some(now);
        let bucket = usage.buckets.entry(class).or_default();
        purge_expired(bucket, now);
        let policy = class.policy();

        if response_bytes > policy.response_bytes.saturating_sub(bucket.response_bytes) {
            return Err(QuotaRejection::ResponseBytes);
        }
        bucket.responses.push_back(ResponseEvent { at: now, bytes: response_bytes });
        bucket.response_bytes = bucket.response_bytes.saturating_add(response_bytes);
        Ok(())
    }

    #[cfg(test)]
    fn active_clients(&self) -> usize {
        self.clients.len()
    }
}

fn purge_expired(bucket: &mut Bucket, now: Instant) {
    while bucket.events.front().is_some_and(|event| {
        now.saturating_duration_since(event.at) >= WINDOW
    }) {
        if let Some(event) = bucket.events.pop_front() {
            bucket.ingress_bytes = bucket.ingress_bytes.saturating_sub(event.ingress_bytes);
        }
    }
    while bucket.responses.front().is_some_and(|event| {
        now.saturating_duration_since(event.at) >= WINDOW
    }) {
        if let Some(event) = bucket.responses.pop_front() {
            bucket.response_bytes = bucket.response_bytes.saturating_sub(event.bytes);
        }
    }
}

/// Resolve a client address without trusting client-supplied forwarding headers.
///
/// `X-Forwarded-For` is consulted only when the immediate TCP peer is explicitly
/// listed in `PRISM_TRUSTED_PROXY_IPS`. Walk from right to left, skipping
/// configured trusted proxies; an invalid rightmost hop falls back to the peer
/// instead of trusting an earlier attacker-controlled value.
pub fn resolve_client_ip(
    peer: IpAddr,
    forwarded_for: Option<&str>,
    trusted_proxies: &HashSet<IpAddr>,
) -> IpAddr {
    if !trusted_proxies.contains(&peer) {
        return peer;
    }
    let Some(header) = forwarded_for else {
        return peer;
    };

    for token in header.split(',').rev() {
        let Ok(candidate) = IpAddr::from_str(token.trim()) else {
            return peer;
        };
        if !trusted_proxies.contains(&candidate) {
            return candidate;
        }
    }
    peer
}

/// Parse comma-separated exact proxy IPs. CIDRs are intentionally unsupported
/// so an accidental broad network declaration cannot establish trust.
pub fn parse_trusted_proxy_ips(raw: &str) -> Result<HashSet<IpAddr>, String> {
    let mut addresses = HashSet::new();
    for token in raw.split(',') {
        let token = token.trim();
        if token.is_empty() {
            return Err("PRISM_TRUSTED_PROXY_IPS contains an empty entry".to_string());
        }
        let address = IpAddr::from_str(token)
            .map_err(|_| format!("invalid IP address in PRISM_TRUSTED_PROXY_IPS: {token}"))?;
        addresses.insert(address);
    }
    Ok(addresses)
}

/// Shared state wrapper for HTTP middleware.
#[derive(Clone, Debug)]
pub struct ClientQuotaState {
    limiter: Arc<Mutex<ClientQuota>>,
    trusted_proxies: Arc<HashSet<IpAddr>>,
}

impl Default for ClientQuotaState {
    fn default() -> Self {
        Self::new(HashSet::new())
    }
}

impl ClientQuotaState {
    pub fn new(trusted_proxies: HashSet<IpAddr>) -> Self {
        Self {
            limiter: Arc::new(Mutex::new(ClientQuota::default())),
            trusted_proxies: Arc::new(trusted_proxies),
        }
    }

    pub fn resolve_client_ip(&self, peer: IpAddr, forwarded_for: Option<&str>) -> IpAddr {
        resolve_client_ip(peer, forwarded_for, &self.trusted_proxies)
    }

    pub fn admit_request(
        &self,
        client: IpAddr,
        class: QuotaClass,
        known_bytes: usize,
    ) -> Result<QuotaTicket, QuotaRejection> {
        self.limiter
            .lock()
            .map_err(|_| QuotaRejection::ClientTableFull)?
            .admit_request(client, class, known_bytes, Instant::now())
    }

    pub fn charge_body(
        &self,
        ticket: QuotaTicket,
        body_bytes: usize,
    ) -> Result<(), QuotaRejection> {
        self.limiter
            .lock()
            .map_err(|_| QuotaRejection::ClientTableFull)?
            .charge_body(ticket, body_bytes)
    }

    pub fn release_request(&self, ticket: QuotaTicket) {
        if let Ok(mut limiter) = self.limiter.lock() {
            limiter.release_request(ticket);
        }
    }

    pub fn charge_response(
        &self,
        client: IpAddr,
        class: QuotaClass,
        response_bytes: usize,
    ) -> Result<(), QuotaRejection> {
        self.limiter
            .lock()
            .map_err(|_| QuotaRejection::ClientTableFull)?
            .charge_response(client, class, response_bytes, Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn sliding_window_blocks_the_first_request_over_budget_and_recovers_after_sixty_seconds() {
        let start = Instant::now();
        let client = ip("192.0.2.10");
        let mut quota = ClientQuota::with_capacity(4);

        for n in 0..30 {
            assert!(
                quota
                    .admit_request(
                        client,
                        QuotaClass::GenericProxy,
                        1,
                        start + Duration::from_secs(n),
                    )
                    .is_ok()
            );
        }
        assert_eq!(
            quota.admit_request(
                client,
                QuotaClass::GenericProxy,
                1,
                start + Duration::from_secs(29),
            ),
            Err(QuotaRejection::RequestRate)
        );
        assert!(quota.admit_request(client, QuotaClass::GenericProxy, 1, start + WINDOW).is_ok());
    }

    #[test]
    fn per_client_in_flight_cap_releases_on_completion_or_cancellation() {
        let start = Instant::now();
        let client = ip("192.0.2.15");
        let mut quota = ClientQuota::with_capacity(4);
        let first = quota
            .admit_request(client, QuotaClass::GenericProxy, 0, start)
            .unwrap();
        let second = quota
            .admit_request(client, QuotaClass::GenericProxy, 0, start)
            .unwrap();

        assert_eq!(
            quota.admit_request(client, QuotaClass::GenericProxy, 0, start),
            Err(QuotaRejection::InFlight)
        );

        quota.release_request(first);
        assert!(quota
            .admit_request(client, QuotaClass::GenericProxy, 0, start)
            .is_ok());
        quota.release_request(second);
    }

    #[test]
    fn byte_budget_counts_known_target_and_actual_body_bytes() {
        let start = Instant::now();
        let client = ip("192.0.2.11");
        let mut quota = ClientQuota::with_capacity(4);
        let ticket = quota.admit_request(client, QuotaClass::Search, 10, start).unwrap();
        assert!(quota.charge_body(ticket, 256 * 1024 - 10).is_ok());
        assert_eq!(
            quota.admit_request(client, QuotaClass::Search, 1, start + Duration::from_secs(1)),
            Err(QuotaRejection::IngressBytes)
        );
    }

    #[test]
    fn response_bytes_are_charged_before_delivery_and_expire_after_sixty_seconds() {
        let start = Instant::now();
        let client = ip("192.0.2.14");
        let mut quota = ClientQuota::with_capacity(4);
        assert!(quota.admit_request(client, QuotaClass::Search, 0, start).is_ok());
        assert!(quota.charge_response(client, QuotaClass::Search, 16 * 1024 * 1024, start).is_ok());
        assert_eq!(
            quota.charge_response(client, QuotaClass::Search, 1, start + Duration::from_secs(1)),
            Err(QuotaRejection::ResponseBytes)
        );
        assert!(quota.charge_response(client, QuotaClass::Search, 1, start + WINDOW).is_ok());
    }

    #[test]
    fn clients_and_route_classes_have_independent_budgets() {
        let start = Instant::now();
        let a = ip("192.0.2.12");
        let b = ip("192.0.2.13");
        let mut quota = ClientQuota::with_capacity(4);
        for n in 0..30 {
            assert!(
                quota
                    .admit_request(
                        a,
                        QuotaClass::Search,
                        0,
                        start + Duration::from_millis(n),
                    )
                    .is_ok()
            );
        }
        assert_eq!(
            quota.admit_request(a, QuotaClass::Search, 0, start + Duration::from_secs(1)),
            Err(QuotaRejection::RequestRate)
        );
        assert!(
            quota
                .admit_request(a, QuotaClass::Provider, 0, start + Duration::from_secs(1))
                .is_ok()
        );
        assert!(
            quota
                .admit_request(b, QuotaClass::Search, 0, start + Duration::from_secs(1))
                .is_ok()
        );
    }

    #[test]
    fn active_client_table_is_bounded_and_recovers_after_idle_expiration() {
        let start = Instant::now();
        let mut quota = ClientQuota::with_capacity(1);
        assert!(quota.admit_request(ip("192.0.2.20"), QuotaClass::Search, 0, start).is_ok());
        assert_eq!(
            quota.admit_request(
                ip("192.0.2.21"),
                QuotaClass::Search,
                0,
                start + Duration::from_secs(1),
            ),
            Err(QuotaRejection::ClientTableFull)
        );
        assert!(
            quota
                .admit_request(ip("192.0.2.21"), QuotaClass::Search, 0, start + IDLE_TTL)
                .is_ok()
        );
        assert_eq!(quota.active_clients(), 1);
    }

    #[test]
    fn forwarded_headers_are_ignored_for_direct_peers() {
        let trusted = HashSet::from([ip("192.0.2.1")]);
        assert_eq!(
            resolve_client_ip(ip("198.51.100.9"), Some("203.0.113.5"), &trusted),
            ip("198.51.100.9")
        );
    }

    #[test]
    fn trusted_proxy_resolution_skips_trusted_hops_from_the_right() {
        let trusted = HashSet::from([ip("192.0.2.1"), ip("192.0.2.2")]);
        assert_eq!(
            resolve_client_ip(
                ip("192.0.2.2"),
                Some("203.0.113.10, 192.0.2.1"),
                &trusted
            ),
            ip("203.0.113.10")
        );
    }

    #[test]
    fn invalid_forwarded_suffix_fails_closed_to_the_peer() {
        let trusted = HashSet::from([ip("192.0.2.1")]);
        assert_eq!(
            resolve_client_ip(
                ip("192.0.2.1"),
                Some("198.51.100.7, attacker-controlled"),
                &trusted,
            ),
            ip("192.0.2.1")
        );
    }

    #[test]
    fn trusted_proxy_configuration_rejects_malformed_entries_and_cidrs() {
        assert!(parse_trusted_proxy_ips("192.0.2.1,2001:db8::1").is_ok());
        assert!(parse_trusted_proxy_ips("192.0.2.1,").is_err());
        assert!(parse_trusted_proxy_ips("192.0.2.0/24").is_err());
    }

    #[test]
    fn path_classification_excludes_static_and_health_routes() {
        assert_eq!(QuotaClass::for_path("/health"), None);
        assert_eq!(QuotaClass::for_path("/"), None);
        assert_eq!(QuotaClass::for_path("/proxy"), Some(QuotaClass::GenericProxy));
        assert_eq!(QuotaClass::for_path("/api/ddg"), Some(QuotaClass::Search));
        assert_eq!(QuotaClass::for_path("/api/brave"), Some(QuotaClass::Search));
        assert_eq!(QuotaClass::for_path("/api/perplexity"), Some(QuotaClass::Provider));
        assert_eq!(
            QuotaClass::for_path("/api/symthaea/query"),
            Some(QuotaClass::Symthaea)
        );
    }

    #[test]
    fn quota_defaults_support_ipv4_and_ipv6_keys() {
        let mut quota = ClientQuota::default();
        let now = Instant::now();
        assert!(
            quota
                .admit_request(IpAddr::V4(Ipv4Addr::LOCALHOST), QuotaClass::Search, 0, now)
                .is_ok()
        );
        assert!(
            quota
                .admit_request(IpAddr::V6(Ipv6Addr::LOCALHOST), QuotaClass::Search, 0, now)
                .is_ok()
        );
    }
}
