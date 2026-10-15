# ADR-0002: Make Ladybird the first renderer behind a replaceable browser-engine boundary

- **Status:** Accepted as the implementation direction; integration and release remain gated
- **Date:** 2026-10-15
- **Supersedes:** the engine-selection portion of [ADR-0001](0001-ladybird-reference-strategy.md)
- **Owners:** Prism maintainers
- **Scope:** Web rendering backend selection, engine integration boundary, future engine portability

## Context

Prism has been spending effort on a Rust-first browser/runtime of its own while needing the standards coverage of a complete web platform: HTML/CSS, JavaScript, networking, media, accessibility, and hostile-content isolation. Rebuilding those capabilities independently is a large long-term commitment, and the current Prism parser/layout/rendering path is not evidence of full browser interoperability.

The upstream Ladybird repository contains `LibWebView`, `ViewImplementation`, and `HeadlessWebView`. Source inspection at candidate commit `86a57aa4b0194823c6f2c8ee5b9a473c6e03e19f` confirms a plausible integration surface, but also shows a substantial internal CMake dependency graph and does not establish a stable, supported third-party embedding ABI. The project is still actively developing and hardening the engine. The existence of a library target is not proof that Prism can build, link, package, render, or safely maintain an integration.

Prism already has product-specific work worth preserving independently of its renderer: local-first epistemic search, provenance and evidence handling, privacy/data-zone policy, user-controlled data, safe networking, and optional Mycelix/Symthaea integration. Those services must not become coupled to one engine's object model or obtain elevated privileges through web content.

Finally, a future engine switch should be possible without requiring a multi-engine product today. Designing a small boundary now is cheaper than letting Ladybird-specific types spread throughout application logic; implementing several adapters in parallel now would be premature.

## Decision

**Ladybird is Prism's selected first-choice web renderer. Build Prism toward using Ladybird as its default rendering engine, rather than treating Ladybird merely as a reference implementation.** This is an architecture decision, not a claim that an integrated runtime already exists or has passed its build/security gates.

Adopt the following implementation policy:

1. **One real backend first:** the first full browser-engine backend will be Ladybird, pinned to an exact upstream commit for each experiment/build. Do not build simultaneous Chromium, Firefox, or WebKit alternatives now.
2. **A replaceable boundary:** define a narrow Rust-owned browser-engine interface between Prism product services/UI and the engine integration. Keep Ladybird C++ objects, internal headers, callback types, and build assumptions behind that boundary.
3. **Choose the integration mechanism by evidence:** evaluate `LibWebView` first. Use an in-process bridge only if the API/build/lifecycle contract is supportable and its unsafe/FFI surface is narrow. If it is too tightly coupled, evaluate a supervised process and versioned, bounded IPC protocol. Do not silently fall back to an unpinned or opaque WebKitGTK view and call it Ladybird.
4. **Current implementation is transitional:** Prism's existing Tauri/WebKitGTK path and custom lightweight shell may be used as development/bootstrap baselines while the Ladybird backend is built and tested. They are not the long-term default decision. Do not claim the shipped application uses Ladybird until the executable, packaging and runtime tests prove it.
5. **Future engines remain possible:** a later backend may implement the same stable Prism-facing contract using another browser's supported embedding API or a separately supervised process. Do not promise feature parity. Every backend reports explicit capabilities and unsupported operations; engine-specific extensions stay behind typed, capability-checked interfaces.
6. **Standards stay normative:** WHATWG/W3C standards and pinned WPT baselines decide correctness. Ladybird's behavior is the implementation Prism currently targets, not an oracle that overrides standards.
7. **Product authority stays in Prism:** engine content is untrusted. File access, credentials, local knowledge, search indexes, Mycelix/Symthaea operations, network policy, and permission decisions remain behind Prism's validated authorization boundary. The renderer does not get direct product-service privileges.
8. **No production claim without evidence:** build reproducibility, supported integration controls, process/crash isolation, origin and permission handling, licensing/dependency review, update strategy, supported-platform evidence, accessibility, and exact-head test evidence remain release gates.

## Engine boundary contract

The public contract is a Prism-owned interface, not a promise about any vendor's API. The initial contract should cover only operations that the first user-facing integration needs:

- lifecycle: start, orderly shutdown, health, and observable process/renderer failure;
- navigation: navigate, back, forward, reload, stop, current URL, title, and load-state events;
- viewport and input: resize, focus, keyboard, pointer, and scroll events where the selected surface supports them;
- presentation: a provider-owned render surface or frame transport, without exposing raw provider pointers outside the adapter;
- browser-mediated requests: typed events for permissions, dialogs, downloads/file selection, external URL handling and related user decisions;
- capabilities/limitations: a machine-readable list of supported operations and relevant configuration constraints for the chosen backend.

The contract must be asynchronous where work can block and must not assume one event-loop model. It must define cancellation, event ordering, ownership, size/rate limits and teardown behavior. Errors are typed and visible; unsupported behavior must not silently succeed.

Do **not** design a lowest-common-denominator abstraction for every feature any browser has. Keep the core contract small, and add optional, typed extensions only when Prism needs them and the active backend advertises them. Provider-specific controls may be exposed through a carefully scoped extension interface, but must not bypass the same authorization, logging, and origin rules.

Do not allow generic arbitrary RPC, raw C++ pointers across the boundary, direct renderer access to local files/secrets, or AI-driven grants of browser permissions. If using IPC, authenticate the local peer as appropriate, frame messages with explicit versions and bounded lengths, validate every decoded message, apply timeouts/backpressure, and fail closed on unknown commands. If using FFI, keep the C ABI surface minimal and document each unsafe invariant.

## Options considered

### A. Use Ladybird now as the target backend behind a replaceable interface — selected

This puts the product on a path to reuse a real browser engine while keeping future choices open. The integration proof remains staged and reversible. It avoids wasting effort on a second complete browser engine or a multi-backend framework before any one backend is shipped.

### B. Keep Ladybird only as an external reference — superseded

This avoids immediate integration risk, but does not satisfy the strategic aim of using Ladybird to render Prism's web content. Continue to use it as a comparison implementation and development aid, but not merely as a reference-only destination.

### C. Make Ladybird a mandatory bundled runtime immediately — rejected as premature

A decision to target Ladybird does not establish that the current source revision can be integrated safely or reproducibly. Do not make a default package depend on a prototype with an unverified ABI, runtime resources, permission UI, accessibility integration, or update pathway.

### D. Build multiple browser backends in parallel — rejected for now

It increases integration and test complexity before the first backend works. Preserve extensibility at the interface boundary, then add another backend only in response to a concrete need and with its own supported-feature and security evidence.

### E. Maintain a Prism-specific Ladybird fork — rejected by default

Avoid privately patching core engine internals or diverging security fixes. If an essential integration feature is missing, document the upstream requirement and coordinate with maintainers. A long-lived fork needs a separate explicit decision and a funded maintenance owner.

## Migration plan and acceptance gates

### Gate 0 — identify the engine actually used

Inventory current rendering paths in `prism-shell`, `prism-tauri`, tests and packaging. Document which path handles remote HTML today and which Rust parser/layout renderer is used for lightweight/reader content. Do not call the existing custom renderer a Ladybird integration.

### Gate 1 — build and consume the pinned Ladybird candidate

Pin the upstream SHA, Nix inputs and toolchain. Build the actual `LibWebView` target in a clean environment, inspect its dependency closure, and prove a minimal independent consumer can link and run without editing upstream source. A successful Ladybird browser build alone is insufficient.

### Gate 2 — local-only headless smoke test

Load deterministic local fixtures with no external-network dependency. Exercise startup/shutdown, navigation, URL/title/loading state, viewport changes, repeatable output, and bounded crash/failure behavior. Record raw logs, commands, hashes, exit status and environment.

### Gate 3 — establish the first Prism adapter

Implement the smallest vertical slice through the Prism-owned interface: create/close a view, render a local page, navigate between fixtures, update URL/title/loading state, forward resize and keyboard/pointer input, and recover observably from renderer failure. Keep product services independent from the provider implementation. Do not widen scope to every browser feature before this slice is reliable.

### Gate 4 — authority and hostile-content review

Test site/origin/process isolation, IPC/FFI validation, network permissions, downloads/file chooser, dialogs, cookies/profiles, external links, accessibility, and crash containment. Demonstrate that hostile page content cannot directly invoke privileged Prism services. Missing behavior is recorded as fail, unsupported or not tested—not assumed secure.

### Gate 5 — usability, conformance and release fit

Pin WPT and maintain a selected compatibility baseline. Test accessibility and essential keyboard flows. Measure build/package size, startup, memory, navigation and update effort against the current Tauri/WebKitGTK and custom-shell baselines on the same Linux host. Report raw results and environmental limits. Test additional platforms separately rather than extrapolating from Linux.

**Implementation go/no-go:** proceed from one gate to the next when its evidence is recorded. If the selected Ladybird API cannot be consumed sustainably, keep Ladybird as the selected engine but investigate an upstream-supported/supervised integration boundary. Do not hide failure by reverting the architecture decision or asserting the integration already works. Reconsider the engine choice only if a documented blocker makes the target infeasible or unacceptable after realistic alternatives are compared.

**Release go/no-go:** do not ship Ladybird as Prism's default runtime until the build, integration, security, compatibility, accessibility, license/dependency, platform and maintenance gates are reviewed. Architecture selection is not release authorization.

## Consequences

- Engineering effort shifts toward making Ladybird Prism's real renderer, rather than independently rebuilding general web-platform functionality.
- A thin Prism-owned adapter creates a seam for possible future browsers without a parallel multi-engine implementation today.
- The integration may initially require native C++/CMake work despite Prism's Rust-first product code; minimize and isolate that surface rather than pretending it does not exist.
- Current Tauri/WebKitGTK and custom-rendering code must be inventoried and migrated deliberately; duplicate rendering paths should not survive as undocumented defaults.
- Some Ladybird capabilities will be unsupported or costly to integrate in the first slice. State this in a capability ledger and fail explicitly for unsupported controls.
- Security, WPT, dependency, packaging and runtime evidence remain separate; no one replaces the others.

## Sources

- [Pinned Ladybird LibWebView CMake target](https://github.com/LadybirdBrowser/ladybird/blob/86a57aa4b0194823c6f2c8ee5b9a473c6e03e19f/Libraries/LibWebView/CMakeLists.txt)
- [Pinned ViewImplementation interface](https://github.com/LadybirdBrowser/ladybird/blob/86a57aa4b0194823c6f2c8ee5b9a473c6e03e19f/Libraries/LibWebView/ViewImplementation.h)
- [Pinned HeadlessWebView interface](https://github.com/LadybirdBrowser/ladybird/blob/86a57aa4b0194823c6f2c8ee5b9a473c6e03e19f/Libraries/LibWebView/HeadlessWebView.h)
- [Pinned Ladybird build instructions](https://github.com/LadybirdBrowser/ladybird/blob/86a57aa4b0194823c6f2c8ee5b9a473c6e03e19f/Documentation/BuildInstructionsLadybird.md)
- [Ladybird September 2026 security update](https://ladybird.org/newsletter/2026-09-30/)
- [Web Platform Tests](https://web-platform-tests.org/)
