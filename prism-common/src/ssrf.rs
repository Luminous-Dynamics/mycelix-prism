// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Shared SSRF (Server-Side Request Forgery) protection for Prism's proxy layer.
//!
//! Both `prism-proxy` (standalone dev proxy) and `prism-serve` (unified
//! production server) accept a `url` query parameter and fetch it on the
//! server's behalf. Without validation, an attacker can point the proxy at
//! loopback addresses, RFC1918 private ranges, link-local addresses (incl.
//! cloud metadata endpoints like `169.254.169.254`), or other internal-only
//! schemes/hosts.
//!
//! This module is the single source of truth for that validation so a future
//! patch to one binary can't silently miss the other. It intentionally has
//! no dependency beyond `url` (already a `prism-common` dependency) so it
//! stays compilable for both native (proxy/serve) and `wasm32-unknown-unknown`
//! (prism-ui) targets that depend on `prism-common`.

/// Return true for IPv4 destinations that must not be reached by the
/// server-side proxy.
///
/// This is deliberately conservative and rejects special-purpose, private,
/// shared, documentation, benchmarking, multicast, reserved, loopback, and
/// unspecified ranges. It does not rely on nightly-only `Ipv4Addr::is_global`.
///
/// Range references: [IANA IPv4 Special-Purpose Address Space](https://www.iana.org/assignments/iana-ipv4-special-registry).
/// Re-audit this table when the registry changes; this is a proxy-denial policy,
/// not a claim that every non-public-purpose range is fully enumerated.
pub fn is_private_ipv4(ip: &std::net::Ipv4Addr) -> bool {
    let [a, b, c, _d] = ip.octets();

    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || a == 0 // "this network" / current-host special range
        || a >= 224 // multicast and reserved
        || (a == 100 && (64..=127).contains(&b)) // RFC 6598 shared address space
        || (a == 192 && b == 0 && c == 0) // IETF protocol assignments
        || (a == 192 && b == 0 && c == 2) // TEST-NET-1
        || (a == 192 && b == 88 && c == 99) // deprecated 6to4 relay anycast
        || (a == 198 && (b == 18 || b == 19)) // benchmarking
        || (a == 198 && b == 51 && c == 100) // TEST-NET-2
        || (a == 203 && b == 0 && c == 113) // TEST-NET-3
}

/// Return true unless an IP address is clearly globally routable.
///
/// IPv6 is allow-listed to global unicast (2000::/3) and then excludes the
/// IETF special-purpose, 6to4 and documentation ranges. This policy is more
/// conservative than merely testing loopback/private/link-local because some
/// translated and transition addresses can encode an IPv4 destination.
///
/// Range references: [IANA IPv6 Global Unicast Address Space](https://www.iana.org/assignments/ipv6-unicast-address-assignments)
/// and [IANA IPv6 Special-Purpose Address Space](https://www.iana.org/assignments/iana-ipv6-special-registry).
pub fn is_non_public_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => is_private_ipv4(&ip),
        std::net::IpAddr::V6(ip) => {
            let s = ip.segments();
            let is_global_unicast = (s[0] & 0xe000) == 0x2000; // 2000::/3
            let is_ietf_special = s[0] == 0x2001 && s[1] <= 0x01ff; // 2001::/23
            let is_documentation = s[0] == 0x2001 && s[1] == 0x0db8; // 2001:db8::/32
            let is_6to4 = s[0] == 0x2002; // 2002::/16 embeds IPv4
            let is_new_documentation = s[0] == 0x3fff && (s[1] & 0xfff0) == 0; // 3fff::/20
            !is_global_unicast
                || is_ietf_special
                || is_documentation
                || is_6to4
                || is_new_documentation
                || ip.is_multicast()
                || ip.is_unspecified()
                || ip.is_loopback()
        }
    }
}

/// Validate that a URL is syntactically safe for a server-side proxy.
///
/// This is only the first gate: callers must also resolve the hostname, reject
/// any non-public DNS answer, pin the HTTP client to the approved address set,
/// and validate every redirect hop. A domain passing this function alone is
/// not authorization to connect to it.
pub fn validate_proxy_url(raw: &str) -> Result<url::Url, &'static str> {
    let parsed = url::Url::parse(raw).map_err(|_| "Invalid URL")?;

    match parsed.scheme() {
        "http" | "https" => {}
        _ => return Err("Only http and https URLs are allowed"),
    }

    // The accessors catch non-empty username/password values. Also inspect
    // the serialized authority so an empty userinfo delimiter ("https://@host")
    // cannot slip through simply because both accessors appear empty.
    let serialized = parsed.as_str();
    let authority_remainder = serialized
        .split_once("://")
        .map(|(_, remainder)| remainder)
        .unwrap_or("");
    let authority_end = authority_remainder
        .find(|ch| matches!(ch, '/' | '?' | '#'))
        .unwrap_or(authority_remainder.len());
    let has_userinfo_delimiter = authority_remainder[..authority_end].contains('@');

    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || has_userinfo_delimiter
    {
        return Err("URLs containing user credentials are forbidden");
    }

    let host_str = parsed.host_str().unwrap_or("");
    let normalized_host = host_str.trim_end_matches('.').to_ascii_lowercase();
    let is_domain = matches!(parsed.host(), Some(url::Host::Domain(_)));

    if normalized_host.is_empty()
        || (is_domain && !normalized_host.contains('.'))
        || normalized_host == "localhost"
        || normalized_host.ends_with(".localhost")
        || normalized_host.ends_with(".local")
        || normalized_host.ends_with(".internal")
        || normalized_host.ends_with(".test")
        || normalized_host.ends_with(".invalid")
        || normalized_host.ends_with(".example")
        || normalized_host == "metadata.google.internal"
    {
        return Err("Access to local or reserved hostnames is forbidden");
    }

    match parsed.host() {
        Some(url::Host::Ipv4(ip)) if is_non_public_ip(std::net::IpAddr::V4(ip)) => {
            return Err("Access to private/reserved IP addresses is forbidden");
        }
        Some(url::Host::Ipv6(ip)) if is_non_public_ip(std::net::IpAddr::V6(ip)) => {
            return Err("Access to private/reserved IP addresses is forbidden");
        }
        Some(url::Host::Domain(_)) => {}
        Some(url::Host::Ipv4(_)) | Some(url::Host::Ipv6(_)) => {}
        None => return Err("URL must include a hostname"),
    }

    Ok(parsed)
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
    fn rejects_credentials_and_reserved_hostname_suffixes() {
        for url in [
            "https://user:password@example.com/",
            "https://@example.com/",
            "http://LOCALHOST./",
            "http://metadata.google.internal./",
            "http://service.local/",
            "http://printer.localhost/",
            "http://database.internal/",
            "http://testhost.test/",
            "http://fixture.example/",
            "http://database/",
            "http://metadata/",
        ] {
            assert!(validate_proxy_url(url).is_err(), "must reject {url}");
        }
    }

    #[test]
    fn rejects_noncanonical_ipv4_literal_spellings() {
        // WHATWG URL parsing accepts legacy shorthand, integer, hexadecimal,
        // and octal IPv4 forms. Ensure they are normalized to literal IPs and
        // then pass through the same destination policy as dotted-decimal IPs.
        for raw in [
            "http://127.1/",
            "http://2130706433/",
            "http://0x7f000001/",
            "http://0177.0.0.1/",
        ] {
            let parsed = url::Url::parse(raw).expect("URL fixture must parse");
            assert!(
                matches!(parsed.host(), Some(url::Host::Ipv4(_))),
                "fixture must parse as an IPv4 literal: {raw} -> {parsed}"
            );
            assert!(
                validate_proxy_url(raw).is_err(),
                "must reject noncanonical private IPv4 spelling {raw}"
            );
        }
    }

    #[test]
    fn rejects_special_purpose_ipv4_ranges() {
        for ip in [
            "0.0.0.1",
            "100.64.0.1",
            "192.0.0.8",
            "192.0.2.1",
            "192.88.99.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
        ] {
            let parsed = ip.parse().unwrap();
            assert!(is_non_public_ip(std::net::IpAddr::V4(parsed)), "must reject {ip}");
            assert!(validate_proxy_url(&format!("http://{ip}/")).is_err());
        }
    }

    #[test]
    fn rejects_non_global_ipv6_special_ranges() {
        for ip in [
            "2001:db8::1",   // documentation
            "2001::1",       // IETF protocol assignments
            "2002:7f00:1::", // 6to4 can encode loopback IPv4
            "3fff::1",       // documentation
            "ff02::1",       // multicast
            "64:ff9b::7f00:1", // NAT64 translated special destination
        ] {
            let parsed = ip.parse().unwrap();
            assert!(is_non_public_ip(std::net::IpAddr::V6(parsed)), "must reject {ip}");
            assert!(validate_proxy_url(&format!("http://[{ip}]/")).is_err());
        }
    }

    #[test]
    fn accepts_unambiguously_global_ip_literals() {
        assert!(!is_non_public_ip("1.1.1.1".parse().unwrap()));
        assert!(!is_non_public_ip("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn allows_valid_external_urls() {
        assert!(validate_proxy_url("https://example.com").is_ok());
        assert!(validate_proxy_url("https://api.duckduckgo.com/?q=test").is_ok());
        assert!(validate_proxy_url("http://en.wikipedia.org/wiki/Rust").is_ok());
    }
}
