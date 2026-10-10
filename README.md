# Prism

Prism is an experimental Rust browser prototype from Luminous Dynamics. It explores a native Rust rendering path, reader-first presentation, privacy signals, safety analysis, and epistemic search.

**Status: early prototype, not a secure or standards-complete replacement for a mainstream browser.** The existence of a crate, protocol type, security indicator, or passing unit test does not by itself prove a feature is complete or enforced.

## What is in this repository

The workspace separates responsibilities into crates, including:

- `prism-dom`: an HTML tree and an HTML parser built on `html5ever`.
- `prism-layout`: an experimental layout and text-painting implementation.
- `prism-shell` and `prism-tauri`: native desktop-shell experiments.
- `prism-net`, `prism-proxy`, and `prism-privacy`: networking, proxy, and privacy-related components.
- `prism-reflex` and `prism-search`: page-analysis signals and epistemic/semantic search experiments.
- `prism-kernel-protocol` and `prism-attestation`: security-protocol and release-evidence work; some attestation commands and modules are scaffolds, not production security controls.

The current renderer uses a deliberately small set of hand-built style and layout rules. Parsing HTML with a standards-oriented parser is useful, but it is not the same as implementing the complete HTML, CSS, DOM, and browser API standards.

## Known limitations

The repository should not currently claim modern-web parity with browsers such as Firefox, Safari, Chromium, or Ladybird. In particular, this source tree does not yet provide a complete browser platform:

- No integrated standards-complete CSS cascade/layout engine.
- No general-purpose JavaScript engine integrated with page DOM and browser APIs.
- No demonstrated conformance result for the Web Platform Tests (WPT) suite.
- No demonstrated, end-to-end site-isolation and sandbox-enforcement story comparable to mature multi-process browser architectures.
- The `prism-attestation` crate explicitly contains scaffold commands and minimal modules; compilation is not equivalent to valid signatures, provenance, or release-admission verification.
- The standalone repository needs a committed `Cargo.lock` before the current `--locked` CI commands can be reproduced reliably. Do not treat the initial source-freeze build report as a substitute for a passing run on this repository's exact public commit.

Security labels, privacy UI, content analysis, or a protocol definition must never be treated as proof that dangerous activity is blocked. Enforcement requires independently tested controls, clear trust boundaries, and fail-closed behavior.

## Relationship to Ladybird

[Ladybird](https://github.com/LadybirdBrowser/ladybird) is a separate independent-browser project with a much more integrated web engine, including HTML/CSS/DOM behavior, JavaScript and WebAssembly implementations, a multi-process architecture, and ongoing WPT and security work. Ladybird also describes itself as pre-alpha; that is not a reason to equate its scope or maturity with this prototype.

Prism's differentiated research direction is a Rust-first, reader-oriented browser with explicit privacy/safety signals and epistemic search. The responsible path is to prove a narrow, useful slice, then expand standards support and security boundaries with measurable evidence—not to claim parity prematurely.

## Development

The repository supplies a Nix flake for Rust and native desktop dependencies. Current CI intends to run:

- Workspace compilation with `cargo check --workspace --locked`.
- Workspace tests with `cargo nextest run --workspace --locked`.
- A compatibility compilation using the flake's `msrv` development shell.

Before relying on these gates, commit the generated `Cargo.lock` and require successful CI on the exact commit under review. For browser correctness, add WPT-based tests and publish results separately from unit-test counts. For security claims, publish threat models, negative tests, sandbox observations, and independently checkable evidence.

## License and commercial permissions

The workspace declares AGPL-3.0-or-later; the complete license text is in [LICENSE](LICENSE). A separate commercial licensing program is not documented in this repository. See [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md) for that status; do not assume it grants permissions beyond the AGPL.
