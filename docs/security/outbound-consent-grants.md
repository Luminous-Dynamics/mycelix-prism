# Outbound consent grants: threat model and qualification gates

**Status:** implementation slice; not yet connected to every outbound runtime path.  
**Tracking:** [Issue #39](https://github.com/Luminous-Dynamics/mycelix-prism/issues/39), [PR #38 hostname canonicalization](https://github.com/Luminous-Dynamics/mycelix-prism/pull/38), [PR #4 evidence and benchmark policy](https://github.com/Luminous-Dynamics/mycelix-prism/pull/4).

## Design shift

**A domain preference is not an authority grant. Trust is evidence; consent is authority.** Reputation, classifier confidence, a source's integrity, or a Mycelix trust score must never silently widen permission to disclose content.

A grant binds one explicit choice to all of the following:

- Exact DNS destination (no wildcard or implicit subdomain inheritance).
- Typed operation.
- Stable content scope or sensitivity label.
- Declared purpose.
- Policy version.
- Opaque reference to integrity-protected evidence of the user's explicit choice.
- Validity interval, with expiry exclusive.
- Unique, non-reusable grant ID.

The authority owns the active policy version instead of trusting a request-supplied version. A monotonic policy generation invalidates older grants even if a previous version label is later reused. Each choice receipt is unique in the authority, each grant is single-use, and a grant is consumed before its commit closure runs. The decision path fails closed on private content, malformed bindings, missing grants, mismatches, unavailable clocks, backward clock readings, expiry, revocation, replay, and poisoned authority state. A Public or Local request that uses this authority still needs an explicit matching grant. This primitive is not a default-allow policy path.

## Revocation and the last responsible moment

Checking authorization when work is queued is insufficient: policy can change before the work produces an irreversible effect. The API therefore has two checks:

1. `authorize` evaluates the full request binding and returns an in-memory permit tied to the current grant epoch.
2. `commit_with` rechecks the binding, grant state, expiry, clock and epoch immediately at the commit boundary.

The commit closure is executed while holding the same mutex used by `revoke`. This defines a precise ordering for this process: a revocation acknowledgement cannot return while an earlier commit closure is still running, and a later commit cannot pass after acknowledgement. The closure must be a short, synchronous local commit such as an atomic enqueue; it must not perform a long network transfer or call back into the authority. If an enqueued operation can wait, the final sender must revalidate immediately before actual transmission.

This is deliberately narrower than claiming distributed or end-to-end revocation. A process-local mutex does not coordinate other processes or devices. In-memory grants and revocation epochs do not survive restart. Persistence, recovery semantics and a broker-owned send boundary remain required before the property can be claimed for the running browser.

## Clock and storage requirements

The caller injects time so tests are deterministic. Production integrations must read time from a trusted clock provider and pass no time when the read fails. Backward timestamps fail closed; the API cannot prove that a caller supplied an honest clock, detect every forward jump, or preserve monotonicity across restarts. Before production, use a persisted time/epoch strategy with explicit recovery behavior and test expiry against suspend/resume, wall-clock corrections, and restart.

Grant deserialization must not grant authority by itself: every loaded record must be revalidated against the current policy version and integrity-protected revocation state. The choice-receipt field is only a reference; the UI/broker integration must mint it only after an explicit user gesture and verify its integrity. Grant IDs are never reused; issuing a replacement grant must use a fresh identifier.

## Qualification gates

The following are **proposed targets**, not measured results or claims about current runtime behavior. Record the exact commit, toolchain, hardware, workload, raw samples, and test manifest for every campaign.

| Gate | Proposed criterion | Evidence required |
|---|---|---|
| Private-data noninterference | 0 Private requests invoke a commit closure | Unit/property tests plus runtime side-effect counter |
| Authorization precision | 100% of manifest cases match expected decisions; all negative cases have 0 commit side effects | Versioned case manifest, positive control, raw event trace |
| Scope binding | 0 successes for destination, operation, scope, purpose, or policy-version mismatch | Mutation/property corpus; retain each mismatch as a separate case |
| Consent replay | A grant can commit at most once; duplicate choice-receipt references cannot mint additional grants | Permit replay, concurrent duplicate commits, duplicate-receipt and restart tests |
| Revocation | 0 commit closures start after the revocation acknowledgement | Deterministic scheduling tests, model-checking or equivalent interleaving harness, then a 10,000-schedule soak |
| Clock failure | 100% deny on unavailable or backward clock readings | Injected fault tests and runtime clock-fault tests |
| Fail-closed behavior | 0 authorization successes after poisoned authority state or invalid persisted records | Fault injection and restart/recovery tests |
| Contention / latency | Initial screening goal: p95 in-memory authorization overhead ≤10 μs uncontended and ≤100 μs at 64 competing workers | Release-mode matched runs; report p50/p95/IQR/MAD and raw samples |
| Revocation responsiveness | Initial screening goal: p99 acknowledgement ≤50 ms when each commit closure is bounded to ≤1 ms | Saturation workload; report lock wait time separately from policy evaluation |
| Scale / soak | 100,000 grants loaded and 1,000,000 adversarial authorization attempts with 0 unauthorized commits, crashes, or state corruption | Seeded workload, deterministic replay, resource measurements |

Latency values are engineering hypotheses, not universal standards. First collect a baseline; do not turn these provisional numbers into release gates until the workload and measurement environment are agreed. Do not optimize by dropping checks or treating missing telemetry as success.

For performance comparisons, randomize/interleave candidate and baseline runs on the same machine, keep benchmark processes from overlapping, and retain raw observations. Use at least 30 matched blocks for regression screening and at least 100 for release-blocking performance claims, with confidence intervals and correction for multiple release-blocking metrics. The benchmark methodology is tracked in [PR #4](https://github.com/Luminous-Dynamics/mycelix-prism/pull/4).

## Current limitations and next gates

This change adds a grant-authority primitive; it does **not** yet demonstrate that every network, DHT, form-submit, download, export, or browser integration path routes through it. It also does not yet emit a runtime privacy evidence capsule or persist revocation state. Do not claim zero runtime egress or non-bypassability until those paths are wired and exercised with observed side-effect counters.

Next work should connect the authority to a single broker-owned outbound boundary, make enqueue and final send checks explicit, persist grants/revocation epochs atomically, and produce a capsule bound to the exact Prism commit, policy version, manifest digest, observed decisions, side-effect counts and event-trace digest. The independent checker should recompute the result rather than trusting a declared outcome.

This design is informed by the transaction-authorization principle that authorization must be checked at execution to address time-of-check/time-of-use gaps ([OWASP Transaction Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html)) and by the established token-revocation trade-off between server-side state, short lifetimes and immediate revocation ([IETF RFC 7009](https://www.rfc-editor.org/rfc/rfc7009.html)). These sources motivate the design; they do not validate this Prism implementation.

## Validation status

The Rust tests are committed with the implementation but have **not** been run in this environment. PR #38's workflow was last observed queued, with no reported status checks. The repository's current `main` lacks `Cargo.lock` while CI uses `--locked`; this known prerequisite may stop validation before the new tests execute. Queued, missing, cancelled, or blocked checks are not passes.
