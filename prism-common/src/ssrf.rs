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

/// Check if an IPv4 address is private/reserved and therefore unsafe to proxy to.
pub fn is_private_ipv4(ip: &std::net::Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();

    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_unspecified()
        // "This network" and shared carrier-grade NAT address space.
        || a == 0
        || (a == 100 && (64..=127).contains(&b))
        // Conservative deny of IETF protocol assignments and documentation
        // blocks. This deliberately rejects some exceptions inside 192.0.0.0/24.
        || (a == 192 && b == 0 && (c == 0 || c == 2))
        // Deprecated 6to4 relay anycast.
        || (a == 192 && b == 88 && c == 99)
        // Benchmarking and documentation ranges.
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        // Multicast and reserved/future-use ranges are not public unicast targets.
        || a >= 224
}

/// Validate that a URL is safe to proxy — reject private/reserved addresses
/// and non-HTTP schemes.
///
/// Returns the parsed `url::Url` on success, or a static error string
/// describing why the URL was rejected.
pub fn validate_proxy_url(raw: &str) -> Result<url::Url, &'static str> {
    let parsed = url::Url::parse(raw).map_err(|_| "Invalid URL")?;

    match parsed.scheme() {
        "http" | "https" => {}
        _ => return Err("Only http and https URLs are allowed"),
    }

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("URL credentials are forbidden");
    }

    let host_str = parsed.host_str().unwrap_or("");

    if host_str == "localhost" || host_str == "metadata.google.internal" {
        return Err("Access to internal addresses is forbidden");
    }

    // Use url::Host for proper IPv4/IPv6 discrimination
    match parsed.host() {
        Some(url::Host::Ipv4(ip)) => {
            if is_private_ipv4(&ip) {
                return Err("Access to private/reserved IP addresses is forbidden");
            }
        }
        Some(url::Host::Ipv6(ip)) => {
            if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
                return Err("Access to private/reserved IP addresses is forbidden");
            }

            let seg = ip.segments();

            // Documentation (2001:db8::/32 and 3fff::/20), benchmarking
            // (2001:2::/48), and deprecated 6to4 (2002::/16) are not valid
            // public unicast proxy destinations.
            if (seg[0] == 0x2001 && (seg[1] == 0x0db8 || (seg[1] == 0x0002 && seg[2] == 0)))
                || (seg[0] == 0x3fff && (seg[1] & 0xf000) == 0)
                || seg[0] == 0x2002
            {
                return Err("Access to private/reserved IP addresses is forbidden");
            }

            // Block well-known and local-use NAT64 prefixes. These can encode
            // IPv4 destinations that would otherwise bypass IPv4 literal checks.
            if (seg[0] == 0x0064
                && seg[1] == 0xff9b
                && seg[2..6].iter().all(|part| *part == 0))
                || (seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2] == 0x0001)
            {
                return Err("Access to private/reserved IP addresses is forbidden");
            }

            // IPv4-mapped IPv6 (::ffff:x.x.x.x)
            if seg[0] == 0
                && seg[1] == 0
                && seg[2] == 0
                && seg[3] == 0
                && seg[4] == 0
                && seg[5] == 0xffff
            {
                let mapped = std::net::Ipv4Addr::new(
                    (seg[6] >> 8) as u8,
                    seg[6] as u8,
                    (seg[7] >> 8) as u8,
                    seg[7] as u8,
                );
                if is_private_ipv4(&mapped) {
                    return Err("Access to private/reserved IP addresses is forbidden");
                }
            }

            // IPv6 link-local (fe80::/10)
            if (seg[0] & 0xffc0) == 0xfe80 {
                return Err("Access to private/reserved IP addresses is forbidden");
            }

            // IPv6 unique-local (fc00::/7)
            if (seg[0] & 0xfe00) == 0xfc00 {
                return Err("Access to private/reserved IP addresses is forbidden");
            }
        }
        // Hostnames pass through syntactic validation only. Connection-time DNS
        // resolution classification and address pinning are tracked separately.
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
    fn rejects_embedded_url_credentials() {
        assert!(validate_proxy_url("https://user:secret@example.com/path").is_err());
        assert!(validate_proxy_url("https://user@example.com/path").is_err());
    }

    #[test]
    fn rejects_non_http_schemes() {
        assert!(validate_proxy_url("file:///etc/passwd").is_err());
        assert!(validate_proxy_url("ftp://example.com").is_err());
        assert!(validate_proxy_url("gopher://evil.com").is_err());
    }

    #[test]
    fn rejects_ipv4_special_use_and_non_global_ranges() {
        for raw in [
            "http://0.1.2.3",
            "http://100.64.0.1",
            "http://100.127.255.254",
            "http://192.0.0.8",
            "http://192.0.2.10",
            "http://192.88.99.1",
            "http://198.18.0.1",
            "http://198.19.255.254",
            "http://198.51.100.7",
            "http://203.0.113.4",
            "http://224.0.0.1",
            "http://240.0.0.1",
        ] {
            assert!(
                validate_proxy_url(raw).is_err(),
                "special-use address accepted: {raw}"
            );
        }
    }

    #[test]
    fn rejects_ipv6_special_use_and_non_global_ranges() {
        for raw in [
            "http://[ff02::1]",
            "http://[2001:db8::1]",
            "http://[2001:2::1]",
            "http://[3fff::1]",
            "http://[2002::1]",
            "http://[64:ff9b::a00:1]",
            "http://[64:ff9b:1::a00:1]",
        ] {
            assert!(
                validate_proxy_url(raw).is_err(),
                "special-use address accepted: {raw}"
            );
        }
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
}
