
# Ladybird / LibWebView feasibility spike

**Status: NOT RUN.** This is a reproducible experiment protocol and a source-level integration audit, not evidence that Ladybird builds, embeds, or is secure enough for Prism. No renderer, host executable, benchmark, or end-to-end test was run while preparing this document.

## Candidate and provenance

- Upstream: [LadybirdBrowser/ladybird](https://github.com/LadybirdBrowser/ladybird)
- Candidate source commit: 86a57aa4b0194823c6f2c8ee5b9a473c6e03e19f
- Platform for this spike: Linux only
- Current Prism decision: reference-first; do not make Ladybird a mandatory runtime dependency or switch production rendering on the basis of this spike alone.
- Normative compatibility authority: the selected Web Platform Tests (WPT) revision and applicable web standards, not Ladybird's observed behavior.

The candidate SHA is intentionally fixed. Any different revision must be recorded as a new candidate with a reason, and its results must not be attributed to this revision.

## Source-audit findings at the pinned revision

These findings come from reading the pinned source and upstream build instructions. They are **not build results**.

1. **There is a real target, but not an obvious stand-alone SDK.** [Libraries/LibWebView/CMakeLists.txt](https://github.com/LadybirdBrowser/ladybird/blob/86a57aa4b0194823c6f2c8ee5b9a473c6e03e19f/Libraries/LibWebView/CMakeLists.txt) declares LibWebView through Ladybird's internal ladybird_lib helper. It generates UI-process IPC endpoints and links public internal targets LibCompositing, LibSandbox, and LibWebCommon, as well as a substantial private closure including LibCore, LibCrypto, LibDatabase, LibDevTools, LibFileSystem, LibGfx, LibHTTP, LibIPC, LibRequests, LibMedia, LibURL, LibThreading, and SDL3. Build success for this target may therefore still mean building a large portion of the browser.
2. **The apparent view abstractions are C++ internals.** [ViewImplementation.h](https://github.com/LadybirdBrowser/ladybird/blob/86a57aa4b0194823c6f2c8ee5b9a473c6e03e19f/Libraries/LibWebView/ViewImplementation.h) exposes a broad browser-control surface and includes many internal AK and Lib* headers. Symbol export annotations and a CMake target do not by themselves establish a stable, independently versioned third-party ABI or API.
3. **Headless is an initial smoke-test path, not a GUI embedding proof.** [HeadlessWebView.h](https://github.com/LadybirdBrowser/ladybird/blob/86a57aa4b0194823c6f2c8ee5b9a473c6e03e19f/Libraries/LibWebView/HeadlessWebView.h) offers a view with a viewport and theme buffer. It can help isolate engine initialization, navigation and rendering from desktop-shell integration, but it does not demonstrate that Prism can present frames in Tauri or safely route keyboard, pointer, accessibility and window lifecycle events.
4. **The header-install block is not a complete SDK declaration.** The cited CMake file's ENABLE_INSTALL_HEADERS block installs generated IPC headers from GENERATED_SOURCES; it does not establish that all headers needed to consume ViewImplementation form a supported installed public API.
5. **The full upstream build has a material toolchain footprint.** The pinned [BuildInstructionsLadybird.md](https://github.com/LadybirdBrowser/ladybird/blob/86a57aa4b0194823c6f2c8ee5b9a473c6e03e19f/Documentation/BuildInstructionsLadybird.md) calls for Qt 6.10+, CMake 3.30+, a C++23-capable compiler and Rust, plus platform packages. Determine the actual dependency set required by the selected targets from a clean configuration; do not assume every documented GUI dependency can be removed when building only LibWebView.
6. **The upstream security model creates concrete integration obligations.** Ladybird's [September 2026 security update](https://ladybird.org/newsletter/2026-09-30/) says IPC from a potentially compromised renderer must be treated as untrusted, privileged operations validated by other processes, and helper processes given minimal system access. It describes the network process handling HTTP/WebSocket cookie operations and tighter Linux helper sandboxing including Landlock. The update also distinguishes top-level site isolation from embedded-frame process isolation. These upstream statements are useful threat-model evidence, but they do not prove that a Prism host, bridge, or particular build preserves those boundaries; Stage 4 must verify the actual process graph and callback/IPC paths.
7. **Prism's current shell is not yet enough to claim reproducibility.** The investigated Prism flake.nix points at moving nixos-unstable and rust-overlay inputs and itself says to commit flake.lock before calling the shell reproducible. Pin and record the experiment's inputs before using it as evidence.

These findings lower confidence that this is a drop-in library, but do not rule out a useful, upstream-aligned integration. The experiment should answer the build-graph and lifecycle questions before implementing a large adapter.

## Experiment stages

### Stage 0 — freeze the evidence

Record the exact source revision, git status --porcelain, git diff --exit-code, submodule state, OS/kernel, architecture, Nix version, CMake and generator versions, C/C++ compiler, Rust toolchain, all resolved Nix input revisions, relevant environment variables, and the exact commands used. Commit a flake.lock for any Nix shell used by the experiment. Keep all build outputs outside the source checkout.

**Gate:** the input revision and toolchain are machine-recorded, and the source tree is unmodified. Otherwise stop: later results are not attributable to this candidate.

### Stage 1 — determine whether the target is realistically consumable

From a clean build directory, configure Ladybird using the pinned upstream instructions and inspect the generated build graph. Capture the complete configure log, target list, dependency graph for LibWebView, and the output of the targeted build. Do not patch Ladybird's source to make the first attempt succeed.

Record separately:
- configure success/failure and first actionable error;
- whether LibWebView can be built at the pinned revision;
- transitive dependencies and generated-source/IPC requirements;
- whether a consumer can link against the resulting target without relying on undocumented build-tree details;
- whether usable headers and runtime resources can be consumed without copying Ladybird internals into Prism;
- clean-build wall time, peak memory and output sizes, with commands and raw logs.

**Gate:** the target builds in a clean, pinned environment and its consumption boundary is understood. A configured target alone is not a pass; a successful build of Ladybird's own browser is not proof that an independent Prism host links.

### Stage 2 — headless, local-only engine smoke test

If Stage 1 passes, start with the smallest HeadlessWebView-based test harness that can be created using APIs available at the pinned revision. Keep it outside production Prism and avoid source edits. Use a tiny checked-in fixture corpus served from loopback by the test process. Deny or monitor external network egress so an accidentally remote resource makes the test fail.

At minimum, verify:
- initialization and orderly shutdown;
- initial fixture load and a second local navigation;
- final URL, document title and loading-completion state;
- deterministic output for the same fixture and viewport (prefer a rendered output or a verifiable DOM result available through supported APIs);
- a renderer crash or failed navigation results in a bounded, observable failure rather than a hung test;
- all test requests stay on the fixture origin.

Save raw logs, exit codes, fixture hashes, viewport, source SHA and test output. A headless pass proves only the tested headless behaviors. Do not describe it as a visible desktop embed.

### Stage 3 — visible native host, only if needed and justified

Only proceed if the headless test passes and the target can be consumed without an unmaintainable private-API dependency. Verify the input, resize, focus, frame-presentation and shutdown contracts before wiring UI. Test keyboard and pointer actions, back/forward, URL/title/loading state, resize, dialogs and renderer-crash recovery.

If the only viable design requires adding a host target to Ladybird's own build graph or maintaining a compatibility patch against internal APIs, label it **upstream-coupled** and document the maintenance owner/update process. "No modified upstream source files" does not by itself mean "independently consumable."

### Stage 4 — security boundary and Prism bridge

Do not expose Prism privileges directly to the renderer. Before any bridge experiment, write and review the command allowlist and threat model. The Rust-side broker must validate typed requests and their origin/context, enforce authorization on every operation, default-deny unknown operations, bound message size and rate, and avoid giving web content direct access to local files, browser secrets, Symthaea or Mycelix. No opaque generic RPC or raw pointer crossing the FFI boundary.

Audit the actual process tree and IPC, including site/process isolation, sandbox prerequisites and behavior if a renderer is compromised. Record permissions, downloads/file chooser, cookies/profile ownership, accessibility, DevTools, media, update policy and unsupported controls as **pass**, **fail**, **unsupported**, or **not tested**. Do not infer the security of Prism's integration from Ladybird's architecture description alone.

### Stage 5 — compare with the current Prism path

On the same Linux machine, with the same fixture corpus and test protocol, compare the candidate with Prism's current Tauri v2 / WebKitGTK path. Capture raw measurements and tool versions for:
- clean build success, total build time, peak build memory and shipped package size;
- cold and warm startup, local navigation latency and shutdown latency;
- idle and peak resident memory across the same fixture/workload;
- required behaviors and unsupported integration hooks;
- process boundaries and crash recovery;
- dependency/update complexity, including how quickly Prism can follow a new Ladybird commit without a private patch.

Report the distribution and number of samples for timings, not a single best run. Do not publish superiority claims without the raw results and comparable methods.

## Required result record

For every stage, record PASS, FAIL, UNSUPPORTED or NOT RUN, plus the exact command, commit SHA, environment, logs/artifact location, and an explanation. Unknown results must remain NOT RUN; an empty field or queued CI is not a pass. A source review is useful evidence but must never be mislabeled as an executed build or test.

## Decision rule

- **Go to a bounded prototype:** Stages 0–2 pass; the build and API boundary is understandable; no source patch is needed for the initial smoke path; security assumptions can be tested. This authorizes only a prototype, not a production engine switch.
- **Go to a visible host:** headless evidence is repeatable and the required native surface/input/lifecycle APIs are consumable with a sustainable update strategy.
- **No-go / retain as reference:** unpinned or irreproducible inputs, target build failure that cannot be resolved without a long-lived private fork, no supported way to control process/lifecycle/security boundaries, or a maintenance burden that lacks a credible upstream coordination path.
- **Production decision:** requires a separately reviewed security/threat-model report, applicable WPT evidence, exact-head regression results, supported-platform matrix, and measured cost/benefit. No spike result alone approves shipping or bundling Ladybird.

## Source references

- [Pinned LibWebView target definition](https://github.com/LadybirdBrowser/ladybird/blob/86a57aa4b0194823c6f2c8ee5b9a473c6e03e19f/Libraries/LibWebView/CMakeLists.txt)
- [Pinned ViewImplementation interface](https://github.com/LadybirdBrowser/ladybird/blob/86a57aa4b0194823c6f2c8ee5b9a473c6e03e19f/Libraries/LibWebView/ViewImplementation.h)
- [Pinned HeadlessWebView interface](https://github.com/LadybirdBrowser/ladybird/blob/86a57aa4b0194823c6f2c8ee5b9a473c6e03e19f/Libraries/LibWebView/HeadlessWebView.h)
- [Pinned build instructions](https://github.com/LadybirdBrowser/ladybird/blob/86a57aa4b0194823c6f2c8ee5b9a473c6e03e19f/Documentation/BuildInstructionsLadybird.md)
- [Ladybird September 2026 security update](https://ladybird.org/newsletter/2026-09-30/)
- [Prism experiment tracker](https://github.com/Luminous-Dynamics/mycelix-prism/issues/36)
