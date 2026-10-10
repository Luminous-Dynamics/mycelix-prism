# Prism capability inventory — not a feature-parity claim

**Status: evidence-based snapshot, updated 2026-10-10.** This document supersedes the earlier feature-parity matrix, whose claims about browser security, memory safety, privacy enforcement, feature coverage, and binary size were not backed by comparable measurements.

This is an implementation inventory, not a runtime benchmark. A crate, enum, test, or dependency is not proof that a complete browser feature is integrated or safe. No WPT report, independent security assessment, or matched performance study has been published for the exact Prism revision described here.

## Browser engine comparison

| Area | Ladybird (public project evidence) | Prism (source evidence / current limit) |
|---|---|---|
| Project scope | Independent browser engine with dedicated HTML/CSS/DOM, JavaScript and WebAssembly implementations | Experimental Rust-first browser/platform workspace with separate DOM, layout, UI, networking, shell and search crates |
| HTML | Integrated engine with ongoing standards and real-site compatibility work | Uses html5ever 0.39 and a custom DOM adapter; this does not establish end-to-end browser compatibility or complete Web Platform Test coverage |
| CSS and layout | Dedicated style, layout, paint and rendering pipeline; implementation is still actively evolving | prism-layout and Taffy are present, but full CSS cascade, layout, painting and web API compatibility have not been established |
| JavaScript | LibJS is integrated into Ladybird's browser engine | No page JavaScript engine is integrated in the current Prism architecture. This limits compatibility with most interactive sites; it should not be marketed as a full web browser equivalent |
| WebAssembly | Dedicated LibWasm implementation in the browser engine | A wasm32 component target exists in the development environment; this is not evidence of page-level WebAssembly runtime parity |
| Process isolation | Ladybird documents separate web-content and helper processes, with sandboxing; its process-boundary work is ongoing | Prism has modular crates and broker-oriented design goals, but its end-to-end renderer/site isolation and hostile-renderer containment are not independently demonstrated |
| Parser safety | Ladybird publishes ongoing security work and external review findings | Open issue #2 records a potential unsafe lifetime concern in prism-dom's parser. It is not a confirmed exploit, but it is an explicit blocker for security-hardening claims |
| Networking | Browser-specific request, cookie, cache, permission and process boundaries are actively developed | reqwest and an SSRF guard are present. Full browser networking semantics, origin isolation, cookie policy, CSP and conformance have not been evidenced as a complete system |
| Media and graphics | Dedicated media and graphics pipelines with current work on hardware decoding and compositor performance | Workspace dependencies include graphics/UI components, but they do not demonstrate parity for browser media, GPU isolation, WebGL/WebGPU or accessibility |
| Standards evidence | Ladybird publishes ongoing Web Platform Test progress and real-site compatibility work | No pinned WPT baseline or independently reproducible real-site compatibility report is currently published |
| Performance | Monthly, revision-specific browser benchmark updates are published | No matched browser benchmark report is published. Performance superiority must not be claimed without comparable hardware, workloads and raw results |

## Prism-specific areas worth differentiating

### Local-first knowledge search

Prism's search crate encodes text into 16,384-bit BinaryHV vectors and combines semantic similarity with corpus statistics and an empirical evidence level. That is an interesting inspectable approach, but it is not yet evidence of competitive web-search quality.

The current search corpus is claim-oriented rather than a demonstrated full-web index. The project still needs an explicit source manifest, exact corpus counts, duplicate policy, retrieval timestamps and content hashes; a pinned query set with human- or rule-labeled relevance; Recall@k, MRR and nDCG measurements; and a strong lexical baseline such as BM25. Until those exist, describe the engine as experimental epistemic/claim search, not a replacement for web-scale search engines.

### User sovereignty and privacy

Prism defines Private, Local and Public content zones and defaults the enum to Local. This is a useful policy vocabulary, but a type definition alone does not prove that sensitive content cannot cross a network boundary. The product needs end-to-end data-flow tests, explicit origin permissions, inspectable data export/deletion, consent receipts, and a fail-closed boundary between local content and any peer network.

Threat heuristics and epistemic labels can help users inspect claims. They should be presented as decision support, not as proof of truth, comprehensive prompt-injection defense, or calibrated confidence. Unknown provenance must remain unknown instead of becoming a synthetic trust score.

### Portability

WebAssembly is valuable for portable, capability-limited components. It does not eliminate OS-specific work for rendering, GPU drivers, media codecs, key storage, accessibility, networking, window management or sandboxing. Support should be reported per target using an actual build and runtime test matrix; desktop Linux evidence does not establish Windows, macOS, Android, iOS, TV or embedded support.

## Evidence required before stronger claims

1. **Reproducible build:** commit Cargo.lock from the exact source tree, pin dependency inputs, and pass locked CI on one SHA.
2. **Memory safety:** resolve issue #2 with a defensible safe representation or a narrowly justified unsafe contract, plus stress and dynamic-analysis evidence where practical.
3. **Standards coverage:** pin a WPT revision, publish per-area pass/fail/timeout/unsupported counts, and prevent unexplained regressions.
4. **Security boundary:** verify renderer compromise assumptions, IPC input validation, network brokering, site isolation, permissions and local/private data non-egress.
5. **Search quality:** publish a pinned corpus and query set, a deterministic evaluator, a lexical baseline, and confidence intervals or repeated-run variance where relevant.
6. **Usability and performance:** measure keyboard/accessibility behavior, crash recovery, memory, CPU, energy, cold/warm load and interaction latency against named baselines.

## Bottom line

Ladybird is currently the stronger reference for independent browser-engine implementation, standards conformance and process isolation, with public evidence of continuing work in each area. Prism's most defensible differentiation is local-first epistemic search, explicit user-controlled data flows, and optional Mycelix/Symthaea integrations. The winning strategy is not to claim more features; it is to make fewer, more useful claims and attach reproducible evidence to each one.