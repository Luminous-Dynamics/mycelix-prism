# Mycelix Prism

**Prism is an experimental, Rust-first browser and knowledge-platform project.** Its intended direction combines a standards-oriented web runtime with privacy/security controls, portable WebAssembly components, and optional Mycelix/Symthaea integrations.

> **Maturity statement:** Prism is not currently presented as a drop-in replacement for Ladybird, Firefox, Safari, or Chromium. A successful workspace compile and unit-test run are necessary engineering gates, not evidence of browser compatibility, security assurance, or daily-driver readiness.

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
