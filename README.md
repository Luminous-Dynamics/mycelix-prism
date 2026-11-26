# Mycelix Prism

**A Rust workspace for privacy-aware epistemic search, claim ingestion, user-facing interfaces, and evidence-oriented release tooling.**

Prism is being developed as a sovereign user-facing client and knowledge interface in the Luminous Dynamics ecosystem. The public repository is a standalone workspace that is still under active construction. It is not yet a complete secure browser, production sandbox, or independently audited security runtime.

## What is implemented in this repository?

The root Cargo workspace currently contains 20 member crates:

| Area | Crates / modules | Current boundary |
|---|---|---|
| Knowledge representation | `prism-common`, `prism-epistemic-types`, `prism-kernel-protocol` | Shared domain types and protocols |
| Ingestion | `prism-ingest` | Curated, Mycelix, pipeline, and Wikidata claim sources with quality filtering |
| Search | `prism-search` | Binary hypervector encoding and similarity search over a seeded claim index |
| Privacy | `prism-privacy` | Private/local/public encoding decisions and an in-memory consent store |
| UI | `prism-ui`, `prism-shell`, `prism-layout`, `prism-dom` | Leptos-based UI and rendering-related components |
| Runtime and integration | `prism-proxy`, `prism-serve`, `prism-net`, `prism-knowledge-bridge`, `prism-reflex` | Integration components whose readiness is crate-specific |
| Attestation and security | `prism-attestation`, `prism-zkp`, `prism-security-tests` | Evidence, promotion, proof, and test infrastructure; some attestation modules remain stubs |
| Application boundary | `prism-node`, `prism-tauri` | Early application/runtime scaffolding |

The workspace membership and source tree are the authority for this inventory; see the root `Cargo.toml` for the current list.

## Important implementation limits

- `prism-search` currently uses deterministic word-level random indexing into binary hypervectors and searches a pre-seeded claim index. This is not a claim of SOTA semantic retrieval or an externally benchmarked search engine.
- `prism-ingest` includes curated, Mycelix, pipeline, and Wikidata-oriented ingestion code. Source adapters do not by themselves establish provenance or factual correctness of every ingested claim.
- `prism-privacy` implements a three-zone encoding decision and an in-memory consent store. This does not establish complete information-flow security, persistent consent governance, or a production privacy guarantee.
- `prism-node` explicitly identifies itself as a Phase 0 stub. In `prism-attestation`, the ceremony and incident-policy modules are documented as minimal stubs; do not infer that all release or recovery paths are complete.
- Validation notes for hardening waves distinguish structural/static checks from executable release admission. A syntactically valid receipt or passing static check is not a production security audit.

Prism's ambition is broader than its presently verified implementation. Treat each crate and integration as independently maturing; do not assume every planned subsystem is operational because it appears in the architecture or hardening documents.

## Development

The repository pins Rust 1.99.0 and provides a Nix development shell for Rust, WebAssembly, Nextest, and Tauri/WebKitGTK dependencies.

```sh
nix develop
cargo metadata --locked --format-version 1
cargo check --workspace --locked
cargo nextest run --workspace --locked
```

**Lockfile caveat (2026-11-26):** the audited default branch contains `flake.lock` but no root `Cargo.lock`. The CI's `--locked` Cargo commands therefore currently fail before compiling because Cargo cannot create a missing lockfile in locked mode. Generate and commit a reviewed `Cargo.lock` as a separate dependency-resolution change before treating these commands or the CI lock discipline as reproducible.

The Nix flake also defines an `msrv` development shell using Rust 1.96.1. The CI workflow should be checked alongside the flake before relying on that compatibility lane; the workflow currently refers to a `compat` shell name that is not the shell name exported by the flake.

## Design and governance documents

- [Repository boundary specification](PRISM_REPOSITORY_BOUNDARY_V1.md)
- [Architecture update](PRISM_ARCHITECTURE_UPDATE.md)
- [Extension architecture](PRISM_EXTENSION_ARCH.md)
- [Hardening wave records](PRISM_HARDENING_WAVE_16.md)
- [Wave 16 validation record](PRISM_HARDENING_WAVE_16_VALIDATION.md)
- [Feature comparison](FEATURE_COMPARISON.md)
- [Sovereign consent plan](SOVEREIGN_CONSENT_PLAN.md)
- [Reflex privacy integration](REFLEX_PRIVACY_INTEGRATION.md)

## Security posture

This is experimental research software. It has not received an independent security audit or external release qualification. Do not use it as a security boundary for systems or data you depend on. In particular, do not rely on the current privacy, sandbox, process-isolation, attestation, or cryptographic components without separate implementation review and threat-model validation.

## License

AGPL-3.0-or-later. See the source headers and applicable license files.
