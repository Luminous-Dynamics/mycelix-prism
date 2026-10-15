# Prism Engine Strategy: Ladybird First, Build Our Own Where It Matters

**Status:** Research-backed direction, 2026-10-15  
**Related decisions:** [ADR-0002 — Ladybird first behind a replaceable engine boundary](../adr/0002-ladybird-first-replaceable-engine.md)  
**Implementation track:** [Issue #36 — integrate Ladybird as Prism's first renderer](https://github.com/Luminous-Dynamics/mycelix-prism/issues/36)

## Executive decision

Prism should neither blindly bind itself to an external engine forever nor start by recreating every part of the modern web platform.

**Use Ladybird as the first intended renderer. Own the architecture around it. Build selected engine components when they deliver a measurable advantage. Preserve a path to a Prism-native engine, but make that an evidence-gated investment rather than an identity commitment.**

The strategic unit is not “browser engine versus no browser engine.” It is a set of explicit contracts across rendering, scripting, networking, storage, isolation, permissions, accessibility, policy and product services. Each contract should have one authoritative implementation at a time, machine-readable capabilities, conformance tests and a reversible replacement path where practical.

The first operational goal remains a Ladybird-backed vertical slice. The document does not claim an integrated Ladybird runtime exists today.

## Evidence-carrying architecture: the engine capability ledger

Prism now has a machine-readable [capability ledger](capability-ledger.json) and public [JSON Schema](capability-ledger.schema.json). The ledger separates three facts that are often blurred together: what upstream source/docs support, what Prism has integrated, and what an exact-revision runtime test actually demonstrated.

A separate [standard-library-only validator](../../scripts/validate_engine_capability_ledger.py), its [explicit JSON Schema keyword-subset checker](../../scripts/engine_ledger_schema.py), and [positive/negative regression tests](../../scripts/test_engine_capability_ledger.py) enforce the declared contract plus repository-specific cross-record rules. The subset checker fails closed on unknown schema keywords rather than silently ignoring constraints; CI also checks that schema enum vocabularies match the semantic validator. This is deliberately not advertised as a general JSON Schema implementation and adds no runtime dependency. The [Engine evidence ledger workflow](../../.github/workflows/engine-ledger.yml) runs this short gate independently of the expensive Nix/Cargo lanes.

The critical fail-closed rule is that a capability marked `verified` requires a passed Prism test-result artifact tied to an exact engine revision and a full Prism commit SHA. An upstream source link or a passing build alone cannot elevate it to verified. The current ledger deliberately contains **no verified browser capabilities**: this research pass did not run a Ladybird/Servo host or WPT workload.

### Reproducible result capsules

The next layer is a versioned [test-result capsule schema](test-capsule.schema.json), checked by a [semantic validator](../../scripts/validate_engine_test_capsule.py) and adversarial [regression tests](../../scripts/test_engine_test_capsule.py). A capsule binds exact Prism, engine and suite revisions to a manifest digest, environment/toolchain fingerprints, command, individual case IDs, input/output digests, and explicit `passed`, `failed`, `timeout`, `unsupported`, `skipped`, or `not_run` outcomes. The validator recomputes the summary counts, rejects duplicate case IDs and refuses to classify any skipped, unsupported or not-run case as an overall pass.

The capsule is a result contract, **not evidence that a browser test has run**. Each future run must enumerate every case declared by the pinned manifest. Hash the exact emitted artifact bytes and record that SHA-256 with its artifact location in the ledger; do not hash a separately reserialized JSON object and assume byte identity. Signed workflow attestations can establish artifact provenance, but not whether its expected behavior was correct. Raw page bodies, credentials, cookies and private browsing histories must not be included by default. See [GitHub's artifact documentation](https://docs.github.com/en/actions/concepts/workflows-and-actions/workflow-artifacts) and [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html) for related provenance and deterministic-serialization principles.

The ledger's schema now requires executable evidence to carry the artifact's SHA-256 and a declared environment/toolchain fingerprint. A source of kind `prism_test_result` must also name capsule schema version `1.0.0`. Each capability has an explicit nullable `verification_target_prism_revision`; a `verified` capability is rejected unless every referenced passing capsule names that exact Prism commit and the selected engine revision. Changing the verification target therefore exposes stale test evidence rather than silently reusing it.

These checks validate the evidence record's shape and revision consistency, not that the URL is reachable, the remote artifact is authentic, or the test's oracle is correct.

Status meanings:
- **pinned_source_reviewed / official_docs_reviewed:** upstream evidence was inspected; runtime integration is still a separate field.
- **implemented_in_source_only:** Prism source contains relevant code, but this does not establish end-to-end browser behavior.
- **not_established / not_reviewed:** no sufficient evidence was captured; do not infer support.
- **not_implemented / not_tested / partial_unqualified:** Prism-side statuses that prevent upstream claims from being presented as Prism integration results.
- **verified:** reserved for exact-revision executable test evidence. It is not a blanket security, standards-compliance or production-readiness label.

The approach is informed by Ladybird's [September 2026 security model update](https://ladybird.org/newsletter/2026-09-30/), which says renderer IPC must be treated as untrusted and privileged operations validated, and by [WASI's capability-security principles](https://github.com/WebAssembly/WASI/blob/main/docs/DesignPrinciples.md), which emphasize explicit, unforgeable capabilities and no ambient authority. These are architectural influences—not a claim that WASI itself secures native Ladybird C++ code or Prism IPC.

## What the external research changes

### Ladybird: the current target

At the [pinned candidate revision](https://github.com/LadybirdBrowser/ladybird/tree/86a57aa4b0194823c6f2c8ee5b9a473c6e03e19f), the source contains a real `LibWebView` target, but its CMake definition generates UI-process IPC and links a sizeable closure of internal browser libraries. Its view interfaces depend on internal headers. This makes integration plausible without proving the existence of a stable standalone SDK or third-party ABI.

References:
- [Pinned LibWebView target](https://github.com/LadybirdBrowser/ladybird/blob/86a57aa4b0194823c6f2c8ee5b9a473c6e03e19f/Libraries/LibWebView/CMakeLists.txt)
- [Pinned ViewImplementation API](https://github.com/LadybirdBrowser/ladybird/blob/86a57aa4b0194823c6f2c8ee5b9a473c6e03e19f/Libraries/LibWebView/ViewImplementation.h)
- [Pinned HeadlessWebView API](https://github.com/LadybirdBrowser/ladybird/blob/86a57aa4b0194823c6f2c8ee5b9a473c6e03e19f/Libraries/LibWebView/HeadlessWebView.h)
- [Pinned build requirements](https://github.com/LadybirdBrowser/ladybird/blob/86a57aa4b0194823c6f2c8ee5b9a473c6e03e19f/Documentation/BuildInstructionsLadybird.md)

**Conclusion:** try Ladybird first, but select the integration seam by building and testing it. Do not make a source-level library target synonymous with an easy or safe embed.

### Servo: a necessary comparison, not a new default

[Servo's official site](https://servo.org/) describes a Rust browser engine with an embedding-oriented `WebView`, parallel architecture and support for multiple targets. On 2026-04-13, Servo published its first library crate, `servo 0.1.0`, and announced an LTS track for embedders; the announcement explicitly says this is not a 1.0 release and routine monthly releases may break. Its [current book](https://doc.servo.org/) points embedders toward options such as `tauri-runtime-verso` and `servo-gtk`; its [embedding overview](https://book.servo.org/embedding/overview.html) still describes the integration documentation as sparse and notes that a direct Cargo build may require reproducing work normally handled by `mach`.

This improves Servo's credibility as a library to evaluate, but does not prove it is more compatible, secure, easier to package, or better aligned with Prism than Ladybird. An LTS policy mitigates upgrade churn; it does not remove integration or security work.

Useful source evidence:
- [Servo 0.1.0 crate and LTS announcement (2026-04-13)](https://servo.org/blog/2026/04/13/servo-0.1.0-release/)
- [Servo embedding API docs](https://doc.servo.org/servo/)
- [Servo WebView rendering model](https://doc.servo.org/servo/struct.WebView.html)
- [Servo embedding overview](https://book.servo.org/embedding/overview.html)
- [Servo 2026 development updates](https://servo.org/blog/)

**Conclusion:** Servo makes “Rust-based existing engine” a real comparison option. It does not by itself establish that Servo is the better fit, more secure, more compatible, or easier to package for Prism. Record what is measured and what remains unknown; do not quietly switch away from the chosen Ladybird path.

### Web Platform Tests: the external contract

The [Web Platform Tests project](https://web-platform-tests.org/) exists to measure interoperability across implementations. Prism should pin a WPT revision and a selected test manifest, save raw machine-readable results, and report pass, fail, timeout, unsupported, skipped and not-run separately. A browser engine's own output is useful differential evidence, not the definition of correctness.

## Three kinds of ownership

### 1. Own the product and policy kernel now

These are Prism differentiators and should not be entrusted to renderer-specific behavior:

- User-visible privacy and data-zone policy, explicit consent, profile separation and export/deletion.
- Permission and privileged-operation broker for local files, downloads, external handlers, local knowledge, and optional Mycelix/Symthaea services.
- Provenance and evidence presentation that distinguishes origin/source, transformations and uncertainty from engine trust.
- Search, retrieval quality evaluation and reproducible data import/index formats.
- Capability ledger, telemetry policy, crash/failure semantics and versioned engine integration contract.

An engine can emit a permission request or navigation event; it cannot authorize its own privileged operation. An AI assistant can suggest an action; it cannot grant itself access. Unknown provenance stays unknown rather than becoming a synthetic confidence score.

### 2. Own selected browser components incrementally

Prism already contains a custom DOM adapter, a layout crate based on Taffy, and a Vello/wgpu GPU-rendering shell. These are useful assets and research surfaces, but component presence does not mean standards-compliant HTML, a full CSS cascade, a browser compositor, or a complete browser engine.

The rule for each component is: **one owner, one authority, an explicit contract, and conformance tests before replacing it.**

Keep the Ladybird adapter as the first path to real web compatibility. Separately, where the product needs capabilities that an engine does not expose or cannot satisfy, prototype a component behind a narrow boundary. Examples include a deterministic privacy-policy broker, user-visible network decision ledger, local-only archive/reader pipeline, content provenance records, or an independently testable URL/origin policy module.

Do not fork or duplicate an engine subsystem just because it is interesting to implement. Each owned component needs a concrete use case, a baseline, security tests, maintenance ownership and a demonstrated benefit.

### 3. Reserve a Prism-native engine as a gated option

A complete engine means much more than HTML parsing and painting: DOM behavior, CSS syntax/cascade/computed style, layout, JavaScript and host bindings, event loops, fetch/network semantics, storage and origin rules, workers, WebAssembly, images/fonts/media, compositing, accessibility, permissions, isolation, DevTools and broad conformance.

A greenfield engine is warranted only when all of the following are true:

1. A documented required capability or product invariant cannot reasonably be met by a maintainable Ladybird integration or a justified existing alternative.
2. The team can name a tightly bounded first subsystem with measurable acceptance criteria—not merely “build a browser in Rust.”
3. A prototype has passed its supported WPT subset, memory-safety/fuzzing and differential tests, and demonstrates an advantage on a matched workload.
4. The work has a realistic maintainer/time/funding plan and does not starve immediate Prism security, build reproducibility or product work.
5. There is an incremental migration path: the new component can be evaluated behind a contract without silently taking over unsupported general-web traffic.

Until those gates are met, Ladybird remains the first intended renderer and a complete Prism-native engine remains an exploratory option—not a parallel production commitment.

## Paradigm shifts that could genuinely differentiate Prism

### Shift A — capability-oriented browser kernel, not simply “more blocking”

Traditional site permissions tend to expose coarse prompts and settings. Prism can make every privileged operation a typed request evaluated by a deterministic policy broker. Decisions should be tied to origin/context, resource, purpose, duration and user choice; unsupported or malformed requests fail closed. Provide a user-readable explanation and a revocable record. Do not mistake this policy layer for a substitute for the engine's process sandbox or web security model.

### Shift B — evidence-carrying browsing

Represent each navigation and extracted claim as provenance-bearing data: source origin, final URL, time observed, response/content digest where appropriate, transformation chain, consent context and limitations. Make derived summaries traceable to source spans or source records. Keep this optional, inspectable and privacy-preserving: by default, do not create a centralized log of every visited URL or upload page contents.

This is a product architecture opportunity, not a claim that provenance proves truth. Provenance proves where an assertion came from and how it changed; independent evidence determines whether it is well-supported.

### Shift C — conformance as a continuous engineering signal

Build an engine observatory that runs the same pinned fixture and supported WPT manifests across the selected backend and any experimental component. Preserve seeds, environment, renderer revision, screenshots/DOM outcomes when useful, timing distributions and minimized failing cases. Classify disagreement as a bug candidate, specification question or unsupported capability. Use standards/tests as authority and other engines as independent witnesses.

### Shift D — replayable, privacy-preserving bug reports

When a page misrenders or a renderer crashes, generate a local report containing engine SHA, environment, fixture or minimized reproduction, relevant capabilities and redacted diagnostic evidence. Capture is opt-in; raw URLs, cookies, credentials and page bodies are excluded unless the user explicitly chooses to attach them. Aim for a small reproducible case instead of “works on my machine” screenshots alone.

### Shift E — explicit capability maturity instead of binary feature claims

Expose a machine-readable ledger per engine revision: implemented, tested, unsupported, failing, experimental or not tested. Keep browser conformance, application security, privacy policy and product quality as separate axes. Never let “uses Ladybird,” “written in Rust,” “sandboxed,” or “has unit tests” imply the other properties.

## Proposed development protocol

1. **Now:** finish the pinned Ladybird feasibility path from [issue #36](https://github.com/Luminous-Dynamics/mycelix-prism/issues/36). No production engine switch is inferred from research alone.
2. **In parallel, low cost:** write a provider-neutral interface contract and capability schema. Keep the first actual backend Ladybird; do not build abstract factories for hypothetical features.
3. **Before a greenfield engine proposal:** run a small Servo/Ladybird capability and integration comparison using identical fixtures and explicit unknowns. This is research only, not permission to change the current default direction.
4. **Choose an owned component:** select one product-relevant module with measurable success conditions, such as navigation permission decisions or a local provenance ledger, and test it independently of rendering.
5. **Create an experimental native-engine prototype only behind a flag:** use a single subsystem and a small supported WPT manifest; fuzz inputs and run differential tests. Do not route ordinary web traffic through it until its declared support set is tested.
6. **Promote with a written gate review:** show raw results, unresolved failures, security assumptions, maintenance cost and rollback strategy. One strong demo or passing unit suite is not enough.

## Decision summary

- **Current first-choice renderer:** Ladybird.
- **First integration route to test:** pinned `LibWebView`; assess a supervised process boundary if in-process use is too coupled.
- **Future engine option:** preserve one stable Prism-owned contract; add no other backend until a concrete need exists.
- **Prism-native engine:** allowed as a future, evidence-gated program; never require a wholesale rewrite as the price of ownership.
- **Core innovation:** own the sovereignty, provenance, policy and testing architecture while steadily increasing component ownership based on proven advantage.
- **Proof standard:** standards/WPT for behavior, adversarial tests for security boundaries, matched measurements for performance, pinned commits and inputs for reproducibility.


## Benchmark targets and promotion gates

The versioned [benchmark scorecard](benchmark-scorecard.json) and [schema](benchmark-scorecard.schema.json) define what Prism should measure, when the measurement becomes applicable, and which targets are provisional versus release gates. The scorecard is not a result report and all suite statuses currently say `protocol_only` or `not_applicable_yet`. A `gate_when_activated` flag means a target becomes a gate only after its suite is implemented and activated; it does not claim the currently unavailable suite is passing or release-blocking today.

The first gates are correctness and sovereignty: deterministic supported fixtures must pass; broker negative controls must fail closed; local-only/offline tests must show zero unexpected outbound requests. These precede performance claims. WPT is a separate conformance lane and its supported-subset pass rate must be reported honestly, not represented as whole-browser parity.

Performance measurement uses two warm-ups and ten measured samples by default, reports median, p95, IQR, MAD and raw samples, and requires at least 30 valid same-environment baseline samples before activating numeric regression gates. The provisional regression signal is a greater-than-5% median or greater-than-10% p95 regression against that pinned baseline which exceeds measured noise; confirm on a repeat run before blocking. Numeric latency/resource budgets are provisional and must be recalibrated on a declared reference machine after the first Ladybird-backed vertical slice.

Target hypotheses include p95 cold-start to usable frame ≤3,000 ms, p95 small local fixture navigation-to-correct-render ≤500 ms, p95 supported input-to-visible-update ≤100 ms, p95 process-tree RSS ≤500 MiB, and ≤5% p95 host-adapter overhead against standalone Ladybird on matched workloads. These are engineering goals, **not measured results**, and should not become release gates until the scorecard's calibration criteria are satisfied.

Speedometer 3.1 measures end-to-end web-app responsiveness; its official instructions call for a clean, focused test environment and a sufficiently large viewport ([overview](https://www.browserbench.org/Speedometer3.1/about.html), [instructions](https://www.browserbench.org/Speedometer3.1/instructions.html)). JetStream 2.2 exercises JavaScript and WebAssembly and warns that scores from different JetStream versions are not interchangeable ([suite](https://browserbench.org/JetStream2.2/index.html), [version notes](https://webkit.org/blog/15378/jetstream-2-2/)). MotionMark 1.3 measures graphics/painting workloads and its score depends on display-refresh assumptions ([release notes](https://webkit.org/blog/14908/motionmark-1-3/)). All three are future industry comparators with no invented score targets. Speedometer needs realistic interactive web-app/API support, JetStream needs JavaScript/WebAssembly runtime support, and MotionMark needs relevant graphics/animation APIs. For each, report the official suite version, detailed workloads, raw outputs and environment; do not publish misleading partial scores. The WPT lane should retain the runner's machine-readable report plus run metadata ([WPT local-run documentation](https://github.com/web-platform-tests/wpt/blob/master/docs/running-tests/from-local-system.md), [wpt.fyi report format](https://github.com/web-platform-tests/wpt.fyi/blob/main/api/README.md)).
