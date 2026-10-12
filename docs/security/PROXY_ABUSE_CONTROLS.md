# Prism proxy abuse controls

**Status:** implementation proposal stacked on the DNS-pinning/redirect-validation branch; not qualified until exact-head CI and review complete.

## Deployment boundary

The unified `prism-serve` process binds to `127.0.0.1:8130` by default. A non-loopback bind requires both an explicit address, for example `PRISM_ADDR=0.0.0.0:8130`, and `PRISM_ALLOW_NON_LOOPBACK_BIND=1`. This is a deliberate deployment opt-in, not authentication. Before using it, restrict ingress with a firewall and a trusted reverse proxy or other authentication layer. **CORS is not an authorization boundary.**

The standalone `prism-proxy` remains bound to `127.0.0.1:8131`; it does not expose a public-bind switch.

When the service is behind a reverse proxy, set `PRISM_TRUSTED_PROXY_IPS` to a comma-separated list of the reverse proxy's exact peer IP addresses. CIDRs are rejected. Forwarding headers are ignored unless the immediate socket peer is explicitly trusted. The resolver walks `X-Forwarded-For` from right to left and skips configured trusted proxies; a malformed suffix falls back to the immediate peer. Do not add client-controlled hosts to the trusted list. Direct deployments can leave this variable unset.

Rate limits are IP-based, not account identity. Users sharing NAT may share a quota; clients that can change their public IP may obtain separate quotas. These controls reduce accidental and single-source abuse but are not a replacement for authenticated ingress, network-level defenses, or provider billing controls.

## Rolling one-minute budgets

Every applicable route uses an independent, per-client sliding 60-second budget. Requests are charged before handler/upstream work; bounded request bodies are then charged by their actual byte length. Response bodies are bounded and counted before delivery to the client; the budget counts the application response body before the outer HTTP compression layer.

| Route class | Routes | Requests/minute per client | In-flight requests per client | Ingress bytes/minute | Response-body bytes/minute (before HTTP compression) |
|---|---|---:|---:|---:|
| Generic proxy | `/proxy` | 30 | 2 | 512 KiB | 64 MiB |
| Search | `/api/ddg`, `/api/brave` | 30 | 2 | 256 KiB | 16 MiB |
| Metered provider | `/api/perplexity` | 8 | 1 | 2 MiB | 16 MiB |
| Symthaea bridge | `/api/symthaea/query` | 4 | 1 | 128 KiB | 4 MiB |

The global request-body cap is 1 MiB. The proxy middleware caps a single response body at 10 MiB and bounds body reading by a deadline. The response-byte budget is separate from that per-response hard cap. The Symthaea Unix-socket bridge additionally caps one newline-delimited daemon response at 1 MiB before JSON parsing, preventing unbounded line allocation inside the handler.

The in-memory client table is capped at 4,096 active IP keys and idle entries expire after five minutes. If it cannot safely track another active client, new tracked work fails closed with HTTP 503 rather than silently escaping quotas. This state is per process and resets on restart; horizontally scaled deployments need equivalent controls at ingress or a shared rate-limit service if a global quota is required.

## Concurrency and backpressure

| Route class | In-flight request cap (process-wide) | Route deadline |
|---|---:|---:|
| Generic proxy | 12 | 20 seconds |
| Search | 12 | 20 seconds |
| Metered provider | 3 | 35 seconds |
| Symthaea bridge | 3 | 240 seconds |

The route-level concurrency layer wraps quota middleware as well as handler execution, so bounded request-body reads and response-body accounting stay inside the per-route in-flight cap and deadline. The server also retains its process-wide concurrency cap. Excess route work is shed with HTTP 503 rather than accumulating an unbounded queue. The Symthaea bridge stays explicit and optional; these quotas do not grant it authority over Prism's trust or security decisions.

## Client-visible outcomes

- **HTTP 429 Too Many Requests:** request-rate or ingress/response byte budget exhausted (`Retry-After: 60`), or the per-client in-flight cap is reached (`Retry-After: 1`).
- **HTTP 503 Service Unavailable:** route capacity/deadline exhausted, or the bounded quota table cannot admit a new client.
- **HTTP 413 Payload Too Large:** request body exceeds the request cap.
- **HTTP 504 Gateway Timeout:** an upstream DNS/HTTP operation or upstream response-body read exceeded its deadline; the log reason is `timeout`.
- **HTTP 502 Bad Gateway:** upstream transport/read failure that was not classified as a timeout.
- **HTTP 403 Forbidden:** destination or redirect rejected by policy. Redirect rejections log a 1-based hop number but never log the Location URL.
- **HTTP 408 Request Timeout:** the client request-body stream exceeded its read deadline.

CORS preflight (`OPTIONS`) requests do not consume upstream-work quotas.

## Logs and remaining operational work

The middleware emits bounded reason codes for quota denials, missing client identity, oversized/timed-out request bodies, and oversized/timed-out upstream response bodies. Quota and body decisions include route class; route load-shed/deadline failures use the bounded `capacity_or_deadline` reason. Provider send/read failures distinguish timeouts from other transport failures and return 504 for timeouts. Completed proxied requests log route class, status, and response byte count. The generic safe-fetch handlers log the validated redirect-hop count for successful fetches, and a numeric hop plus a fixed policy reason for rejected redirects. Logs do not include raw target URLs, search terms, redirect Location values, forwarded headers, request bodies, or provider keys. Access logs at an upstream reverse proxy must be configured with the same privacy discipline.

This change establishes local request and byte budgets and emits bounded completion events with route class, response status, response-body bytes, and the validated redirect-hop count for successful generic fetches. A rejected redirect emits one bounded event with its 1-based rejected hop; a metrics endpoint and retained multi-hop trace for a rejected chain are not provided yet. Deployment-level monitoring should separately track 429/503 counts, provider spend, upstream latency/timeouts, and egress volume without recording sensitive query data.

## Qualification requirements

The implementation is a draft and must not be described as security-qualified until the exact commit has passed the repository's workflow-policy guard, formatter, locked workspace check, test suite, and MSRV lane. Deterministic local regression coverage should verify sliding-window boundaries, body and response budget exhaustion, active-client table saturation/expiry, malformed/spoofed forwarding headers, public-bind opt-in, load shedding, and that denied responses retain security headers. No unit test should require a public upstream service.
