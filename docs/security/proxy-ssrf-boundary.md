# Proxy SSRF boundaries and qualification plan

**Scope:** `prism-proxy`, `prism-serve`, and the shared `prism-common::ssrf` URL validator.  
**Implementation branch:** `fix/proxy-redirect-target-validation`.  
**Follow-up:** [Issue #41 — connection-time DNS validation and pinning](https://github.com/Luminous-Dynamics/mycelix-prism/issues/41).

## Finding and change

The original proxy flow validated a user-supplied initial URL and then used `reqwest::redirect::Policy::limited(5)`. The redirect policy limited hops but did not re-run Prism's URL/IP policy on redirect targets. A public URL could therefore redirect to an obvious internal destination such as loopback, a private address, or cloud metadata.

The implementation branch now:

- Re-validates every redirect target with the shared URL policy before following it.
- Delegates redirect hop/loop control to reqwest's bounded policy after the additional check.
- Restricts provider API clients carrying credentials or user query data to same-origin redirects. The general page proxy may follow a different public origin after validating that target because cross-domain navigation is a normal browser use case.
- Rejects embedded URL credentials.
- Rejects additional special-use IPv4 targets (including shared carrier-grade NAT, documentation, benchmarking, multicast and reserved ranges) and special-use IPv6 targets (including multicast, documentation, benchmarking, 6to4 and well-known/local-use NAT64 prefixes).
- Adds deterministic tests for these address classes, credentialed URLs, unsafe/allowed redirect targets, and provider same-origin comparisons.

Research grounding: [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) explicitly recommends disabling unchecked redirects as a way to avoid bypassing input validation. [reqwest's redirect policy](https://docs.rs/reqwest/latest/reqwest/redirect/struct.Policy.html) supports custom per-hop decisions and a bounded-policy delegation.

## Remaining limitation: DNS rebinding

This is not complete SSRF protection. The shared validator rejects unsafe IP literals but currently allows DNS hostnames without classifying their actual answer set. Hostnames can resolve to an internal address or change between validation and connection. Per-hop URL validation does not by itself solve that TOCTOU problem.

Do not claim the proxy cannot reach private networks until Issue #41 is implemented: resolve through an explicit resolver, reject an answer set if any result is forbidden, and ensure the socket actually connects to a validated pinned address while preserving hostname-based TLS verification. The same enforcement must apply to redirects, retries and fallback IPv4/IPv6 connections.

## Qualification targets

These are proposed release gates, not measured outcomes:

| Gate | Target | Evidence |
|---|---|---|
| Redirect SSRF | 0 forbidden targets followed | Local deterministic redirect server with redirect-chain and side-effect counters |
| Literal address classification | 100% denial for manifest-defined forbidden IPv4/IPv6 cases | Versioned positive/negative manifest and exact expected decisions |
| API data egress | 0 cross-origin redirects for provider requests carrying query data or credentials | Redirect tests across host, scheme and port changes |
| Valid navigation | Public allowed redirects remain functional | Positive-control fixture for permitted redirect chains |
| Redirect bounds | 0 loops and at most 5 followed hops | Loop and hop-limit tests |
| DNS and pinning (follow-up) | 0 connections to forbidden addresses across 10,000 seeded resolution/redirect sequences | Resolver injection, pin/connect trace and forbidden-destination counters |
| Performance | Report p50/p95/p99 redirect overhead and DNS cache-hit/miss latency before fixing thresholds | Same-host randomized/interleaved baseline vs candidate runs |

Every denial test must assert that the network-side-effect counter stays at zero. A validator's return value alone is not enough to prove a forbidden connection never occurred.

## Validation status

The changes are committed to the branch, but Rust tests and workflows have **not** been observed passing for this head. These changes have not been validated by an actual socket-level redirect integration test in this environment. The branch improves validation at redirect decisions; it does not yet implement DNS resolution pinning or prove that a prohibited network connection is impossible.
