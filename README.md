# Mycelix Prism

**Prism is an experimental, Rust-first browser and knowledge-platform project.** Its intended direction combines a standards-oriented web runtime with privacy/security controls, portable WebAssembly components, and optional Mycelix/Symthaea integrations.

> **Maturity statement:** Prism is not currently presented as a drop-in replacement for Ladybird, Firefox, Safari, or Chromium. A successful workspace compile and unit-test run are necessary engineering gates, not evidence of browser compatibility, security assurance, or daily-driver readiness.

**Engine strategy:** Prism's chosen first-choice renderer is [Ladybird](https://github.com/LadybirdBrowser/ladybird). Integration is underway as a staged engineering effort; the repository does not yet claim that Ladybird is wired into or shipped by the current executable. A small Prism-owned engine boundary is intended to allow a future browser backend without implementing multiple engines now. Standards and pinned Web Platform Tests remain the compatibility authority. See [ADR-0002](docs/adr/0002-ladybird-first-replaceable-engine.md), the [engine strategy and native-engine decision gates](docs/engine-strategy/README.md), the [superseded reference-first ADR](docs/adr/0001-ladybird-reference-strategy.md), and the [comparison/roadmap](docs/COMPARISON_LADYBIRD.md).

## Project goals

- Build a modular browser platform with clear separation between web content, privileged browser services, and user-facing UI.
- Prefer memory-safe Rust for new implementation work and keep unsafe code narrow, justified, and tested.
- Treat network, document parsing, extensions, and downloaded content as untrusted inputs.
- Make privacy and user control defaults explicit and auditable.
- Keep Mycelix/Symthaea integrations optional and capability-limited; browser safety must not depend on an AI component being correct or available.
- Use web-platform tests, interoperability fixtures, accessibility checks, and security review as evidence of progress.

## Current engineering gates

The repository contains a 20-crate Cargo workspace and a Nix development shell. CI is intended to run locked workspace compilation, Nextest, and a Rust 1.96.1 compatibility lane.

Before treating these as release evidence, confirm that the public repository has a committed Cargo.lock, all required GitHub Actions checks pass on the same commit, and the CI logs are linked to that exact revision. The presence of a workflow or branch-protection rule alone does not mean its checks have passed.

## Browser-engine comparison

See [the Ladybird comparison and staged roadmap](docs/COMPARISON_LADYBIRD.md). The core strategy is to learn from Ladybird's standards-driven engine and process isolation while differentiating at the platform layer—without claiming parity until comparable test evidence exists.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
