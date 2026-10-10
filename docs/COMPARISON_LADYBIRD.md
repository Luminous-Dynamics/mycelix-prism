# Prism and Ladybird: comparison and roadmap

**Status: strategy document, not a feature-parity claim.** This comparison is based on public project descriptions and the current Prism repository structure; it is not a side-by-side runtime benchmark.

## The core distinction

Ladybird's central objective is an independent, standards-driven web browser engine. Its documented architecture includes LibWeb (HTML/CSS/DOM and web APIs), LibJS, LibWasm, and separate processes for web content, network requests, and image decoding. Ladybird maintains browser-specific rendering and web-platform tests.

Prism's plausible differentiation is broader than rendering: a Rust-first modular platform, privacy/security policy surfaces, portable WASM components, and optional integrations with Mycelix and Symthaea for knowledge workflows. Those integrations can make Prism distinctive, but they do not replace the need for a correct HTML/CSS engine, JavaScript, networking, media, accessibility, and process isolation.

## Recommended relationship: reference first, integrate only by evidence

**Working decision:** Ladybird is Prism's primary external engine reference and comparative baseline, not a required runtime dependency at this stage. The full decision, options, licensing/security gates, and revisit criteria are recorded in [ADR-0001](adr/0001-ladybird-reference-strategy.md).

This distinction matters because, as of 2026-10-10, Ladybird's public README still labels it pre-alpha and developer-only, its process-architecture document says parts of the architecture are aspirational, and its FAQ retains a planned 2026 alpha milestone. The 2026-09-30 project newsletter says the team is still preparing for alpha testing; the GitHub Releases page showed no published release entries when checked. This is an actively progressing project, not a ready-made production dependency.

The Rust migration is substantial but still incremental. By August 2026, official updates described the style and layout systems, CSS parsing, computed-style pipeline, and paint pipeline as moved to Rust, while broader engine work continued. The September newsletter also reported a security-hardening week with Trail of Bits engineers who identified issues and built some exploit chains. That is useful evidence of active scrutiny—not a security certification or proof that all findings are resolved. The reviewed public docs still do not establish a stable, supported third-party embeddable-engine API.

Use Ladybird to compare standards behavior, selected real-site rendering, security boundaries, IPC, performance methodology, and developer diagnostics. Use WPT/specifications as the normative authority: do not reproduce a Ladybird bug merely to match its output. Contribute fixes upstream where appropriate rather than maintaining a private fork.

Do not make Ladybird a bundled/mandatory dependency until a prototype proves a stable interface, security isolation, packaging and update strategy, platform coverage, license/dependency compatibility, upstream alignment, and a measured maintenance-cost advantage. Prism's search, provenance, privacy policy, Mycelix integration, and data export should remain useful without any browser-engine dependency.

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
- **Gate F — comparative performance:** repeatable matched benchmarks against Ladybird and at least one mature browser. Publish raw data and limitations.

## Bottom line

Ladybird is the more appropriate reference for independent browser-engine engineering and standards conformance. Prism should differentiate in user sovereignty, privacy, verifiable knowledge workflows, and modular deployment—while adopting the discipline of standards tests, sandboxing, and evidence-driven releases. The ambition should not be 'more features than Ladybird' on paper; it should be a trustworthy browser platform whose claims are backed by reproducible measurements.
