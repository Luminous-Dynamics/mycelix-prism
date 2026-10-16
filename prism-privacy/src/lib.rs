// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Three-zone privacy enforcement for Prism.
//!
//! The encoding gate is the ONLY path to the HDC encoder and DHT.
//! No code path can write to DHT without passing through this gate.
//!
//! Zones:
//! - **Private**: Never encoded, never shared. Banks, email, corporate.
//! - **Local**: HDC encoded for personal semantic memory. Never broadcast.
//! - **Public**: Encoded and offered to DHT. Requires E3+/E4 OR user consent.

use prism_common::ContentZone;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub mod grants;

/// Decision from the encoding gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodingDecision {
    /// Content must not be encoded at all.
    Deny,
    /// Content may be encoded for local semantic memory only.
    LocalOnly,
    /// Content may be encoded and shared to DHT.
    EncodeAndShare,
}

/// The encoding gate — the non-bypassable enforcement point for privacy.
///
/// This is the ONLY path to HDC encoding and DHT writes.
pub fn encoding_gate(zone: ContentZone) -> EncodingDecision {
    match zone {
        ContentZone::Private => EncodingDecision::Deny,
        ContentZone::Local => EncodingDecision::LocalOnly,
        ContentZone::Public => EncodingDecision::EncodeAndShare,
    }
}

/// Canonicalize a hostname before it is used as a privacy-policy key.
///
/// Accept ASCII DNS hostnames (including already-encoded IDNA A-labels), normalize
/// ASCII case, and remove one optional DNS root dot. Invalid, ambiguous, or
/// non-ASCII input is rejected rather than allowed to widen sharing authority.
/// Callers that parse URLs must pass the parser's canonical host, not an origin
/// string containing a scheme, port, path, or credentials.
pub(crate) fn canonical_domain(domain: &str) -> Option<String> {
    if domain.is_empty() || !domain.is_ascii() || domain.trim() != domain {
        return None;
    }

    let domain = domain.strip_suffix('.').unwrap_or(domain);
    if domain.is_empty() || domain.len() > 253 {
        return None;
    }

    let canonical = domain.to_ascii_lowercase();
    for label in canonical.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return None;
        }
        if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
            return None;
        }
        if !bytes.iter().all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-') {
            return None;
        }
    }

    Some(canonical)
}

/// Match legacy persisted values by canonical hostname, so old mixed-case or
/// root-dot entries cannot bypass current policy.
fn contains_canonical_domain(domains: &HashSet<String>, canonical: &str) -> bool {
    domains
        .iter()
        .any(|stored| canonical_domain(stored).as_deref() == Some(canonical))
}

fn remove_canonical_domain(domains: &mut HashSet<String>, canonical: &str) {
    domains.retain(|stored| canonical_domain(stored).as_deref() != Some(canonical));
}

fn canonical_domain_count(domains: &HashSet<String>) -> usize {
    domains
        .iter()
        .filter_map(|stored| canonical_domain(stored))
        .collect::<HashSet<_>>()
        .len()
}

/// Persistent store of user consent decisions (per-domain).
///
/// When a domain is approved for Public sharing, it's stored here.
/// Stored as JSON on disk for persistence across sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentStore {
    /// Domains the user has approved for Public zone (DHT sharing).
    approved_domains: HashSet<String>,
    /// Domains the user has explicitly marked as Private.
    denied_domains: HashSet<String>,
}

impl ConsentStore {
    pub fn new() -> Self {
        Self {
            approved_domains: HashSet::new(),
            denied_domains: HashSet::new(),
        }
    }

    /// Check if a domain has been approved for Public sharing.
    pub fn is_approved(&self, domain: &str) -> bool {
        let Some(canonical) = canonical_domain(domain) else {
            return false;
        };
        contains_canonical_domain(&self.approved_domains, &canonical)
            && !contains_canonical_domain(&self.denied_domains, &canonical)
    }

    /// Check if a domain has been explicitly denied.
    /// Invalid host input is treated as denied, so callers can fail closed.
    pub fn is_denied(&self, domain: &str) -> bool {
        let Some(canonical) = canonical_domain(domain) else {
            return true;
        };
        contains_canonical_domain(&self.denied_domains, &canonical)
    }

    /// Approve a domain for Public zone sharing.
    ///
    /// Invalid input is ignored. Use `try_approve_domain` when rejection must be
    /// surfaced to the caller. Existing callers keep their original API contract.
    pub fn approve_domain(&mut self, domain: String) {
        let _ = self.try_approve_domain(&domain);
    }

    /// Approve one exact hostname for Public sharing.
    ///
    /// Returns false and leaves state unchanged for an invalid hostname.
    /// Approval never extends implicitly to subdomains.
    #[must_use = "check whether the hostname was accepted by the privacy policy"]
    pub fn try_approve_domain(&mut self, domain: &str) -> bool {
        let Some(canonical) = canonical_domain(domain) else {
            return false;
        };
        remove_canonical_domain(&mut self.denied_domains, &canonical);
        remove_canonical_domain(&mut self.approved_domains, &canonical);
        self.approved_domains.insert(canonical);
        true
    }

    /// Deny a domain (force Private zone).
    ///
    /// Invalid input is ignored. Use `try_deny_domain` when rejection must be
    /// surfaced to the caller. Existing callers keep their original API contract.
    pub fn deny_domain(&mut self, domain: String) {
        let _ = self.try_deny_domain(&domain);
    }

    /// Deny one exact hostname. Invalid input is rejected without mutating policy.
    #[must_use = "check whether the hostname was accepted by the privacy policy"]
    pub fn try_deny_domain(&mut self, domain: &str) -> bool {
        let Some(canonical) = canonical_domain(domain) else {
            return false;
        };
        remove_canonical_domain(&mut self.approved_domains, &canonical);
        remove_canonical_domain(&mut self.denied_domains, &canonical);
        self.denied_domains.insert(canonical);
        true
    }

    /// Resolve zone considering user consent.
    ///
    /// If the reflex arc classified as Local, check if user has approved
    /// this domain for Public sharing.
    pub fn resolve_zone(&self, base_zone: ContentZone, domain: &str) -> ContentZone {
        // User denial always wins
        if self.is_denied(domain) {
            return ContentZone::Private;
        }

        match base_zone {
            ContentZone::Private => ContentZone::Private, // Never override Private
            ContentZone::Local => {
                if self.is_approved(domain) {
                    ContentZone::Public
                } else {
                    ContentZone::Local
                }
            }
            ContentZone::Public => ContentZone::Public,
        }
    }

    /// Number of approved domains.
    pub fn approved_count(&self) -> usize {
        self.approved_domains
            .iter()
            .filter_map(|stored| canonical_domain(stored))
            .filter(|canonical| !contains_canonical_domain(&self.denied_domains, canonical))
            .collect::<HashSet<_>>()
            .len()
    }

    /// Number of denied domains after canonicalizing persisted hostnames.
    pub fn denied_count(&self) -> usize {
        canonical_domain_count(&self.denied_domains)
    }
}

impl Default for ConsentStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_private_denies() {
        assert_eq!(encoding_gate(ContentZone::Private), EncodingDecision::Deny);
    }

    #[test]
    fn gate_local_allows_local_only() {
        assert_eq!(
            encoding_gate(ContentZone::Local),
            EncodingDecision::LocalOnly
        );
    }

    #[test]
    fn gate_public_allows_share() {
        assert_eq!(
            encoding_gate(ContentZone::Public),
            EncodingDecision::EncodeAndShare
        );
    }

    #[test]
    fn consent_approve_upgrades_local_to_public() {
        let mut store = ConsentStore::new();
        store.approve_domain("example.com".to_string());
        assert_eq!(
            store.resolve_zone(ContentZone::Local, "example.com"),
            ContentZone::Public
        );
    }

    #[test]
    fn consent_deny_downgrades_to_private() {
        let mut store = ConsentStore::new();
        store.deny_domain("evil.com".to_string());
        assert_eq!(
            store.resolve_zone(ContentZone::Local, "evil.com"),
            ContentZone::Private
        );
        assert_eq!(
            store.resolve_zone(ContentZone::Public, "evil.com"),
            ContentZone::Private
        );
    }

    #[test]
    fn consent_private_never_overridden() {
        let mut store = ConsentStore::new();
        store.approve_domain("bank.com".to_string());
        // Even with approval, Private stays Private
        assert_eq!(
            store.resolve_zone(ContentZone::Private, "bank.com"),
            ContentZone::Private
        );
    }

    #[test]
    fn consent_unapproved_stays_local() {
        let store = ConsentStore::new();
        assert_eq!(
            store.resolve_zone(ContentZone::Local, "unknown.com"),
            ContentZone::Local
        );
    }

    #[test]
    fn consent_deny_removes_approval() {
        let mut store = ConsentStore::new();
        store.approve_domain("site.com".to_string());
        assert!(store.is_approved("site.com"));
        store.deny_domain("site.com".to_string());
        assert!(!store.is_approved("site.com"));
        assert!(store.is_denied("site.com"));
    }

    #[test]
    fn subdomain_independence() {
        let mut store = ConsentStore::new();
        store.approve_domain("example.com".to_string());
        // Subdomain is independent — not automatically approved
        assert!(!store.is_approved("sub.example.com"));
        assert_eq!(
            store.resolve_zone(ContentZone::Local, "sub.example.com"),
            ContentZone::Local
        );
    }

    #[test]
    fn serialize_roundtrip() {
        let mut store = ConsentStore::new();
        store.approve_domain("wiki.org".to_string());
        store.deny_domain("evil.com".to_string());
        let json = serde_json::to_string(&store).unwrap();
        let restored: ConsentStore = serde_json::from_str(&json).unwrap();
        assert!(restored.is_approved("wiki.org"));
        assert!(restored.is_denied("evil.com"));
        assert_eq!(restored.approved_count(), 1);
        assert_eq!(restored.denied_count(), 1);
    }

    #[test]
    fn domain_approval_and_denial_are_case_and_root_dot_insensitive() {
        let mut store = ConsentStore::new();
        assert!(store.try_approve_domain("Example.COM."));
        assert!(store.is_approved("example.com"));
        assert!(store.is_approved("EXAMPLE.COM."));
        assert_eq!(
            store.resolve_zone(ContentZone::Local, "EXAMPLE.COM"),
            ContentZone::Public
        );

        assert!(store.try_deny_domain("EVIL.COM."));
        assert!(store.is_denied("evil.com"));
        assert_eq!(
            store.resolve_zone(ContentZone::Public, "eViL.CoM"),
            ContentZone::Private
        );
    }

    #[test]
    fn invalid_domains_fail_closed_and_cannot_be_approved() {
        let mut store = ConsentStore::new();
        for domain in [
            "",
            " ",
            "example..com",
            "-bad.example",
            "bad-.example",
            "example.com/path",
            "example.com:443",
            "éxample.com",
            "example.com..",
            ".",
        ] {
            assert!(!store.try_approve_domain(domain), "{domain:?}");
            assert!(!store.try_deny_domain(domain), "{domain:?}");
            assert!(store.is_denied(domain), "{domain:?}");
            assert_eq!(
                store.resolve_zone(ContentZone::Public, domain),
                ContentZone::Private,
                "{domain:?}"
            );
        }
        assert_eq!(store.approved_count(), 0);
        assert_eq!(store.denied_count(), 0);
    }

    #[test]
    fn legacy_persisted_domain_casing_cannot_bypass_policy() {
        let json = r#"{"approved_domains":["Example.COM."],"denied_domains":["EVIL.COM"]}"#;
        let mut store: ConsentStore = serde_json::from_str(json).unwrap();
        assert!(store.is_approved("example.com"));
        assert!(store.is_denied("evil.com."));
        assert_eq!(
            store.resolve_zone(ContentZone::Public, "EVIL.COM."),
            ContentZone::Private
        );

        assert!(store.try_deny_domain("example.com"));
        assert!(!store.is_approved("EXAMPLE.COM."));
        assert_eq!(store.approved_count(), 0);
        assert_eq!(store.denied_count(), 2);
    }

    #[test]
    fn conflicting_legacy_approval_and_denial_always_resolve_as_denied() {
        let json = r#"{"approved_domains":["Example.COM."],"denied_domains":["EXAMPLE.COM"]}"#;
        let mut store: ConsentStore = serde_json::from_str(json).unwrap();

        // Denial wins consistently across decisions and user-visible counts.
        assert!(store.is_denied("example.com"));
        assert!(!store.is_approved("example.com."));
        assert_eq!(store.approved_count(), 0);
        assert_eq!(store.denied_count(), 1);
        assert_eq!(
            store.resolve_zone(ContentZone::Public, "EXAMPLE.COM."),
            ContentZone::Private
        );

        // A later explicit approval resolves the conflict intentionally.
        assert!(store.try_approve_domain("example.com"));
        assert!(store.is_approved("EXAMPLE.COM."));
        assert!(!store.is_denied("example.com"));
        assert_eq!(store.approved_count(), 1);
        assert_eq!(store.denied_count(), 0);
    }

    #[test]
    fn hostname_canonicalization_preserves_exact_host_consent_scope() {
        let mut store = ConsentStore::new();
        assert!(store.try_approve_domain("example.com"));
        assert!(!store.is_approved("sub.example.com"));
        assert_eq!(
            store.resolve_zone(ContentZone::Local, "sub.example.com"),
            ContentZone::Local
        );
    }
}
