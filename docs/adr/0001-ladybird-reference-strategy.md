# ADR-0001: Use Ladybird as Prism's browser-engine reference, not a runtime dependency

- **Status:** Proposed for review; recommended working decision for the current phase
- **Date:** 2026-10-10
- **Owners:** Prism maintainers
- **Scope:** Browser-engine strategy, compatibility testing, code reuse, integration boundaries

## Context

Prism is an experimental Rust-first browser and knowledge-platform workspace. Its most differentiated product work is local-first epistemic search, traceable sources, user-controlled data flows, and optional Mycelix/Symthaea integrations. Its current rendering stack is not a proven replacement for an integrated web browser engine.

Ladybird is an independent, standards-oriented browser project with LibWeb, LibJS, LibWasm, and dedicated process roles for web content, network requests, and image decoding. Its public README still describes it as pre-alpha and developer-only. Its process-architecture document says parts of the described architecture are aspirational and implementation is ongoing. The current public plan targets Linux and macOS for the 2026 alpha; its FAQ describes a beta in 2027 and stable release in 2028. These dates are plans, not guarantees.

Ladybird's February 2026 Rust announcement describes a deliberate, incremental port while the main engine continues to develop in C++. It explicitly asks contributors to coordinate proposed porting work with the core team. The public materials reviewed do not establish a stable, supported embeddable-engine API intended for third-party browser shells.

Sources checked on 2026-10-10:
- [Ladybird README and license](https://github.com/LadybirdBrowser/ladybird)
- [Ladybird process architecture](https://github.com/LadybirdBrowser/ladybird/blob/master/Documentation/ProcessArchitecture.md)
- [Ladybird FAQ and release roadmap](https://github.com/LadybirdBrowser/ladybird/blob/master/Documentation/FAQ.md)
- [Ladybird adopts Rust, 2026-02-23](https://ladybird.org/posts/adopting-rust/)
- [Ladybird project updates](https://ladybird.org/news/)
- [Web Platform Tests](https://web-platform-tests.org/)

## Decision

**Use Ladybird as Prism's primary external browser-engine reference and compatibility comparison. Do not adopt it as a required runtime dependency, fork its engine, or copy internal engine code into Prism in this phase.**

Prism's engine strategy is therefore hybrid:

1. Keep Prism's search, evidence/provenance, privacy policy, Mycelix connectivity, optional Symthaea integration, user data controls, and product-specific UI as separable modules.
2. Use web standards and the Web Platform Tests (WPT) as the normative compatibility authority; use Ladybird as a living comparison implementation, not as the definition of correctness.
3. Run Ladybird separately as an optional reference browser in desktop engineering and real-site smoke testing when practical. Its pre-alpha status means it is not a general availability or safety guarantee.
4. Keep Prism's lightweight/reader-oriented mode clearly scoped. Do not claim full browser compatibility while JavaScript, CSS, media, accessibility, site isolation, and conformance remain incomplete.
5. Prefer upstream contributions or standards-aligned fixes over maintaining a private divergent copy when a problem is within Ladybird's engine scope. Contact maintainers before proposing Rust-porting work, consistent with their published guidance.

## Options considered

### A. Ladybird as reference implementation — selected

Low coupling and immediate value. Prism can compare behavior, test against real sites, learn from process-boundary design, and use WPT without inheriting an engine build chain or release schedule. Standards remain the source of truth when results disagree.

### B. Make Ladybird a mandatory bundled engine now — rejected for now

Potentially avoids rebuilding large parts of the web platform, but there is no established supported embedding API evidenced by the reviewed project documentation. Prism would inherit a pre-alpha engine, a C++-heavy integration boundary, upstream architecture and release changes, a significant packaging/toolchain burden, and uncertain portability across Prism's intended targets. Building an adapter before proving the interface is supportable would create a second browser-integration project.

### C. Fork Ladybird and maintain a Prism engine — rejected

This would duplicate substantial maintenance and compatibility work, fragment security fixes, and divert effort from Prism's differentiated knowledge and sovereignty layers. A fork would only be justified by a concrete upstream incompatibility and a credible, funded long-term maintenance plan.

### D. Keep building the complete browser engine independently — not the default strategy

Continue only where there is a specific, measured reason. Reimplementing all of HTML, CSS, JavaScript, WebAssembly, graphics, media, accessibility, and process isolation in parallel is not the best near-term use of a small team.

## Operating model

### Use Ladybird as a reference for

- Real-site behavior and interoperability differences.
- WPT selection, reporting, and regression triage.
- Browser process roles, IPC boundaries, network brokering, image decoding, permission flows, and crash containment.
- Useful developer diagnostics, inspectability, and release evidence.
- Performance methodology, using matched workloads and hardware rather than ungrounded speed claims.

### Do not treat Ladybird as

- An oracle that overrides WHATWG/W3C standards or normative tests.
- Proof that Prism is safe because Ladybird's corresponding feature exists.
- A stable embeddable library or supported plugin API unless upstream explicitly documents and supports one.
- A blanket security guarantee: its own project is under active development and hardening.
- A reason to copy code without file-level license, dependency, provenance, and distribution review.

## Integration experiment: gates before implementation

A limited adapter/sidecar spike may be proposed only after all of the following are documented:

1. **Use case:** a concrete user outcome that Prism's current engine cannot deliver and that an external Ladybird process could deliver.
2. **Interface:** a feasible, versionable boundary supported by upstream or maintained as an explicit external process protocol. No private C++ object coupling.
3. **Security:** explicit renderer/network/filesystem capabilities, hostile-content treatment, lifecycle/crash behavior, IPC schema validation, and testable failure closure. No Mycelix or Symthaea component may bypass the browser's deterministic authorization policy.
4. **Portability:** a target matrix proving the selected platforms can build, launch, update, and sandbox the integration.
5. **Licensing and supply chain:** reviewed BSD-2-Clause notices, transitive dependencies, combined distribution, third-party assets, and the interaction with Prism's AGPL-3.0-or-later distribution. Obtain appropriate legal review where necessary; do not assume that the headline license resolves every dependency question.
6. **Upstream alignment:** discussion with Ladybird maintainers before investing in an integration that requires API or architecture changes.
7. **Measured value:** an apples-to-apples compatibility, latency, memory, startup, package-size, and operational-maintenance comparison against Prism's current path.
8. **Reversibility:** an opt-in, disableable adapter with no mandatory dependency for Prism search, data export, or local knowledge functions.

Until those gates pass, do not create a production dependency on Ladybird.

## Exit and revisit criteria

Revisit this decision when Ladybird publishes a stable integration boundary or upstream explicitly agrees to support one; its target-platform and release guarantees align with Prism's product requirements; a prototype passes the security and portability gates; and the measured maintenance cost is lower than the best realistic alternative.

Revisit the independent-engine strategy when Prism publishes a WPT baseline, safety review, and real-site compatibility report. No one test metric alone establishes browser readiness.

## Consequences

- Prism can advance search, privacy, evidence provenance, data sovereignty, and user experience without waiting for engine parity.
- The project avoids making a pre-alpha external engine a hard dependency before an integration boundary is proven.
- Prism accepts that its experimental reader/runtime is not currently a drop-in modern browser.
- The team must maintain a WPT-based capability ledger and test both standards compliance and selected Ladybird comparisons.
- Any future Ladybird code reuse or bundling receives explicit per-file and dependency license review.

## Next actions

1. Pin a WPT revision and publish an initial Prism baseline with implemented, unsupported, failing, and untested counts.
2. Add Ladybird as an optional comparison lane to a deterministic real-site smoke corpus; store exact version/commit and test environment.
3. Keep search and privacy tests independent of any browser-engine runtime.
4. Resolve Prism's documented potential parser lifetime issue before security-readiness claims.
5. Obtain a reproducible standalone Cargo.lock and passing CI on exact source commits.
