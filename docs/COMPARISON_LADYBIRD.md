# Prism and Ladybird: comparison and roadmap

**Status: strategy document, not a feature-parity claim.** This comparison is based on public project descriptions and the current Prism repository structure; it is not a side-by-side runtime benchmark.

## The core distinction

Ladybird's central objective is an independent, standards-driven web browser engine. Its documented architecture includes LibWeb (HTML/CSS/DOM and web APIs), LibJS, LibWasm, and separate processes for web content, network requests, and image decoding. Ladybird maintains browser-specific rendering and web-platform tests.

Prism's plausible differentiation is broader than rendering: a Rust-first modular platform, privacy/security policy surfaces, portable WASM components, and optional integrations with Mycelix and Symthaea for knowledge workflows. Those integrations can make Prism distinctive, but they do not replace the need for a correct HTML/CSS engine, JavaScript, networking, media, accessibility, and process isolation.

## Recommended relationship: Ladybird first, engine boundary by design

**Working decision:** Ladybird is Prism's selected first-choice renderer. Prism will build toward using Ladybird to render web content instead of treating it only as a reference implementation. The runtime migration remains staged because a source-level `LibWebView` target does not yet prove that an independent host can build, link, package, and preserve the desired security/lifecycle boundaries. See [ADR-0002](adr/0002-ladybird-first-replaceable-engine.md); [ADR-0001](adr/0001-ladybird-reference-strategy.md) records the superseded earlier decision.

This is not a multi-browser project today. Implement and validate one real Ladybird backend first. At the same time, keep the engine-facing boundary owned by Prism so a future backend could be added if Ladybird becomes infeasible for a target or another engine creates a concrete product benefit. Future backends are an option, not a promise of feature parity or an excuse to maintain several engines in parallel.

The first integration investigation targets the pinned `LibWebView` source at `86a57aa4b0194823c6f2c8ee5b9a473c6e03e19f`. Upstream's target pulls in a meaningful internal CMake/IPC/native dependency graph; source inspection has not established a stable public embedder ABI. The [bounded feasibility protocol](ladybird-spike/README.md) therefore starts with pinned inputs and a headless local-only fixture before a visible host, capability bridge, or package migration. The current executable is not to be described as Ladybird-powered until implementation and runtime tests demonstrate that fact.

As of the September 2026 project update, Ladybird was still preparing for alpha testing and described active security hardening. Its release plans and process architecture are subject to change; this is an actively progressing dependency, not a blanket guarantee of production readiness. See the [September update](https://ladybird.org/newsletter/2026-09-30/) and consult the [current upstream repository](https://github.com/LadybirdBrowser/ladybird) before pinning a new candidate.

### Future-engine compatibility without premature abstraction

The Prism-owned boundary should initially expose only the real first vertical slice: lifecycle/health, navigation and history, URL/title/load-state events, viewport and input, a provider-owned presentation surface or frame transport, and typed user-mediated requests such as permissions and downloads. It must not leak Ladybird C++ types or object ownership into product services. Errors and unsupported capabilities are explicit.

Do not build a generic framework for every browser API. Keep core operations small, and add typed, optional capability extensions only when Prism has a concrete need. A later backend can use its own supported embedding API or a supervised process protocol while Prism retains authority over privacy, network policy, local files, credentials, and Mycelix/Symthaea access.

Standards and pinned Web Platform Tests remain normative. Ladybird informs the first implementation, comparative tests, and interoperability investigations; observed Ladybird behavior does not override a specification or test expectation. Prism's own search, provenance, privacy policy, data portability, and optional integrations remain separable from rendering.

## Evidence-based comparison

| Dimension | Ladybird | Prism today / evidence needed |
|---|---|---|
| HTML/CSS and DOM | Dedicated engine (LibWeb), with browser-specific tests | Prism has prism-dom, prism-layout, prism-ui, etc.; crate presence and compilation do not establish standards coverage. Build a WPT-backed capability report. |
| JavaScript and WebAssembly | Dedicated LibJS and LibWasm implementations | Prism's Rust/WASM tooling is not equivalent to full web JavaScript or WebAssembly engine compatibility. Inventory what is implemented versus embedded or delegated. |
| Process isolation | Documented multi-process design with sandboxed per-tab web content and out-of-process request/image services | Specify and test renderer isolation, brokered network, image/media decoding, IPC validation, sandbox policy, and crash containment. |
| Standards conformance | Ladybird publishes WPT progress; its September 2026 update reported 2,109,072 subtests, while noting upstream-added tests contributed substantially to the monthly increase | Establish a pinned WPT revision and selected test manifest. Report pass/fail/timeout/unsupported counts and revision deltas; raw totals across different WPT revisions are not apples-to-apples. |
| Security assurance | Public sandbox/process architecture; September 2026 update describes external Trail of Bits scrutiny and ongoing fixes, not a security certification | Audit unsafe Rust and FFI, especially parser lifetimes and shared state. Passing unit tests is not a security review. |
| Privacy and user sovereignty | Strong independence/no-user-monetization positioning | Opportunity for explicit data minimization, local-first storage, transparent permissions, exportability, and user-owned search/knowledge controls. These need product specs and tests. |
| AI / knowledge integration | Not its central differentiator | Prism can offer opt-in, least-privilege knowledge/search assistance via Mycelix/Symthaea. It must remain explainable, disableable, and unable to bypass browser security policy. |
| Portability | Desktop targets and platform roadmap documented by Ladybird | WASM is useful for portable components, but a browser still needs platform-specific UI, GPU, media, sandbox, and OS integration. Prove each target separately. |
| Performance | Active engine/style/layout optimization | No fair performance claim without matched hardware, sites, cold/warm runs, memory, energy, and responsiveness measurements. |
| Readiness | Publicly described as actively developing; consult current release status before adoption | Experimental. Do not claim daily-driver or drop-in replacement readiness without compatibility and security evidence. |

## Recommended strategy

### 1. Do not rewrite everything just to be independent

For a small team, the most expensive path is independently implementing all of HTML, CSS, JavaScript, WebAssembly, media, graphics, and accessibility while also building a novel product layer. Evaluate three explicit options for each subsystem:

1. Implement natively in Rust where this is a meaningful differentiator and the maintenance cost is supportable.
2. Integrate a well-isolated, permissively licensed component where that accelerates safe interoperability.
3. Defer the feature rather than shipping an unsafe or misleading partial implementation.

Do not assume Ladybird code can be copied or linked without a license and architecture review. Its repository is BSD-2-Clause, while Prism is AGPL-3.0-or-later; compatibility and distribution obligations need explicit legal review before code reuse.

### 2. Build an honest compatibility dashboard

Pin a Web Platform Tests revision and publish total selected tests, pass/fail/timeout/unsupported counts, per-area coverage, expected-failure baseline, regression delta, runner instructions, and exact commit/toolchain/dependency digests. Never summarize a narrow test subset as web compatible. Keep unit, integration, WPT, security, and real-site smoke tests as separate evidence classes.

### 3. Establish a browser security boundary before adding AI features

Define threat model and trust zones. Treat HTML, JavaScript, images, fonts, media, downloads, extensions, and remote knowledge responses as hostile. Keep privileged file access, credentials, network policy, and navigation decisions outside the content renderer. Any AI-generated suggestion must go through the same deterministic policy checks as a human-triggered action; AI must not grant itself capabilities.

Prioritize review of unsafe code, FFI, parser callbacks, DOM storage lifetimes, origin/site isolation, permissions, CSP, TLS/certificate handling, and download handling. Add fuzzing and sanitizers where applicable, and publish unresolved risks.

### 4. Make the product-layer difference concrete

A credible first differentiated release could focus on local-first, user-controlled knowledge/search; provenance for summaries and extracted claims; explicit per-origin permissions and data-flow visibility; exportable profiles and portable user data; optional Mycelix/Symthaea integration with no security-policy bypass; and a keyboard-accessible interface with reduced-motion/high-contrast support. These should be opt-in, testable capabilities—not marketing labels.

### 5. Use staged release gates

- **Gate A — reproducible build:** committed Cargo.lock, locked Nix inputs, green CI on one exact SHA.
- **Gate B — memory safety:** unsafe-code inventory, parser lifetime fix/review, fuzz corpus, sanitizers/Miri where practical, no unexplained critical findings.
- **Gate C — standards baseline:** pinned WPT subset and published baseline; regressions block merge.
- **Gate D — isolation and privacy:** tested process/capability boundaries, permission behavior, network restrictions, storage partitioning, and threat-model review.
- **Gate E — usability:** accessibility, keyboard navigation, crash recovery, download safety, and real-site smoke tests.
- **Gate F — comparative performance:** once Ladybird is integrated, run repeatable matched workloads against Prism's pre-migration Tauri/WebKitGTK and custom-shell baselines, plus a mature external browser when useful. Publish raw data and limitations; keep conformance, performance, and security evidence separate.

## Bottom line

Ladybird is Prism's chosen first renderer, and the first integration should be narrow, reproducible, and reversible. Prism should differentiate in user sovereignty, privacy, verifiable knowledge workflows, and modular deployment—not by rebuilding a full engine or implementing several browsers in parallel. A Prism-owned adapter keeps a future alternative possible, while standards tests, sandboxing, and evidence-driven releases remain mandatory.
