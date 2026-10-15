# Rust Dependency Audit Policy

## Purpose

Prism audits dependency provenance and known advisories against the exact committed dependency graph. A successful build does not establish that dependencies are vulnerability-free, and a green advisory scan does not clear software licenses.

## Automated checks

The `.github/workflows/dependency-audit.yml` workflow validates the committed `Cargo.lock` with `cargo metadata --locked`, runs a manifest policy regression, then runs RustSec and cargo-deny.

- **RustSec:** `cargo audit --file Cargo.lock` checks the lockfile against the RustSec advisory database. Its diagnostics are retained even when the command exits zero; the log must not be summarized merely as “clean” when warnings are present.
- **Advisories:** `cargo deny --locked check advisories bans sources` explicitly treats unmaintained advisories and unsoundness as blocking and fails on yanked crates. No advisory IDs are ignored. Known unmaintained/unsound dependencies therefore keep this lane red until remediated or a narrow, documented exception is approved.
- **Duplicate versions:** duplicate versions warn for review instead of failing the initial baseline; graph growth is not hidden.
- **Wildcard dependency requirements:** cargo-deny's wildcard detector also labels path-only workspace dependencies with no version requirement as wildcards, so its native wildcard setting is warning-only. The independent `scripts/check_cargo_wildcard_requirements.py` guard fails on explicit wildcard version requirements such as `*`, `1.*`, or `1.x`, including in workspace, target-specific, build, dev, and ordinary dependency sections. It does not flag a path-only workspace dependency that has no `version` key.
- **Sources:** unknown registry and Git sources fail. The workspace explicitly allows the Symthaea Git URL `https://github.com/Luminous-Dynamics/symthaea`; the exact revision remains pinned in `Cargo.lock`. The URL allowlist does not approve arbitrary revisions.
- **Reproducibility:** metadata and audit use the committed lockfile with `--locked`, and the workflow records its SHA-256.

The job uses full-SHA-pinned third-party actions, a `contents: read` workflow permission baseline, PR-head checkout, and `persist-credentials: false`.

## Review rules

1. Do not use a clean build or green tests as a substitute for advisory review.
2. Do not silence an advisory merely to make CI green. Prefer updating/removing affected dependencies. Any exception must name the advisory, reason, affected code path, compensating controls, and review/expiry date.
3. A path allowlist controls source identity, not the trustworthiness of a specific revision.
4. License scanning is not yet enabled: the full resolved license inventory and an allowlist/exception policy must be reviewed before making any dependency-license clearance claim.
5. Every pass applies only to the exact commit SHA, lockfile digest, tool versions, and advisory-database snapshot used by that run. A queued, skipped, cancelled, superseded, or failed run is not a pass.

## References

- RustSec Cargo audit: https://github.com/rustsec/rustsec
- cargo-deny configuration and checks: https://embarkstudios.github.io/cargo-deny/
- Cargo `--locked` behavior: https://doc.rust-lang.org/cargo/commands/cargo.html

## Scope

This policy covers published advisories, dependency versions, registry sources, Git sources, and explicit wildcard version requirements. It does not prove Prism secure, establish exploitability for every dependency path, show that every target-specific build was tested, or clear licenses.
