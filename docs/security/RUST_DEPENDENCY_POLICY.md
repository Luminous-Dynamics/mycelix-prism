# Rust Dependency Audit Policy

## Purpose

Prism must make dependency provenance and known-vulnerability checks repeatable against the exact committed dependency graph. A successful compilation does not establish that the dependency graph is free of published vulnerabilities, nor that the project's license obligations have been reviewed.

## Automated checks

The `.github/workflows/dependency-audit.yml` workflow checks the committed `Cargo.lock` after validating it with `cargo metadata --locked`.

- **RustSec advisories:** `cargo audit --file Cargo.lock` checks the lockfile against the RustSec advisory database. No advisory IDs are globally suppressed by this policy.
- **Dependency graph and sources:** `cargo deny --locked check advisories bans sources` checks advisories, reports duplicate dependency versions for review, rejects wildcard version requirements, and rejects unknown registries or unapproved Git sources.
- **Pinned Git exception:** the workspace currently consumes Symthaea from `https://github.com/Luminous-Dynamics/symthaea`; its precise revision must remain visible in `Cargo.lock`. The URL allowlist does not itself approve arbitrary revisions.
- **Build reproducibility:** metadata validation uses `--locked`, and the workflow records the SHA-256 digest of the exact lockfile it audits.

The job uses full-SHA-pinned third-party actions, a `contents: read` workflow permission baseline, a PR-head checkout, and `persist-credentials: false`.

## Review rules

1. Do not use a clean build or green test suite as a substitute for advisory review.
2. Do not silence an advisory merely to make CI green. Prefer updating/removing the affected dependency; any exception must name the advisory, reason, affected code path, compensating controls, and review/expiry date.
3. Duplicate versions currently warn rather than fail, so the first baseline can expose graph growth without pretending all duplicate versions are necessarily harmful. Review and consolidate where practical.
4. A Git URL allowlist controls source identity, not the trustworthiness of a specific commit. Inspect the exact source revision recorded in the lockfile.
5. **License approval is not yet asserted by this file.** License scanning is intentionally not enabled until Prism's full resolved license inventory has been reviewed and a deliberate allowlist/exception policy is committed. That work remains required before making a dependency-license clearance claim.
6. A passing audit applies only to the exact commit SHA, lockfile digest, and advisory-database snapshot observed by that run. A queued, skipped, or superseded run is not a pass.

## References

- RustSec Cargo audit: https://github.com/rustsec/rustsec
- cargo-deny configuration and checks: https://embarkstudios.github.io/cargo-deny/
- Cargo `--locked` behavior: https://doc.rust-lang.org/cargo/commands/cargo.html
- OWASP dependency and SSRF defense guidance where dependencies cross network trust boundaries: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

## Scope

This policy covers the current Rust lockfile's published advisories, dependency versions, registry sources, and Git sources. It does not prove that Prism is secure, that every transitive dependency is reachable in a particular binary, that all target-specific configurations have been built, or that the licenses have been cleared.
