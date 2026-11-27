# Mycelix Prism

**Prism is an experimental Rust-first, local-first knowledge reader and search client.** It explores a different client architecture: parse and sanitize content, classify privacy and threat signals, ingest source-labelled claims, and search a local epistemic index. The repository also contains early desktop, network, attestation, and knowledge-bridge crates; those areas are at mixed maturity and are not all production implementations.

Prism is part of the Luminous Dynamics ecosystem. Its intended integration boundary is evidence and data exchange with Mycelix, and local cognitive/search services from Symthaea—not embedding the Holochain conductor or the Symthaea runtime inside every Prism component.

## Repository status

| Area | What is present | Maturity boundary |
|---|---|---|
| Rust workspace | 20 declared crates, edition 2024, shared dependency versions | Workspace builds and tests on the pinned normal toolchain and MSRV lane in CI |
| DOM and reader pipeline | prism-dom uses html5ever, markup5ever and taffy; sanitization is wired through client layers | Not a full browser engine; no JavaScript engine or general web-platform implementation |
| Reflex / content signals | prism-reflex uses URL/domain rules and Aho-Corasick matching for fast pre-fetch and post-parse threat signals | Heuristic classifier; not a complete prompt-injection detector, phishing oracle, or substitute for a hardened browser sandbox |
| Privacy zones | prism-privacy models Private, Local and Public decisions plus per-domain consent state | Policy helpers are implemented and tested; repository-wide non-bypassability and native OS isolation require separate end-to-end qualification |
| Knowledge ingestion | Curated, pipeline, Mycelix and Wikidata claim loaders; quality filters and source/tag metadata | Dataset coverage, provenance and license terms vary by upstream source; see the seed-license document |
| Epistemic search | prism-search stores 16,384-bit BinaryHV vectors and uses word-level random indexing / IDF-weighted similarity | Local claim index, not a web-scale search index or independently benchmarked general-purpose semantic search service |
| Desktop and UI | prism-tauri and prism-ui packages are present | Native packaging, OS privilege isolation and release promotion require their own qualification |
| Node, attestation and security test crates | Workspace packages and some release-evidence data structures exist | prism-node is currently a stub; prism-attestation explicitly marks ceremony and incident-policy support as minimal stubs; prism-security-tests describes itself as scaffold/placeholder-only |
| DHT / evidence bridge and ZKP | Dedicated crates and client dependency boundaries exist | Do not assume a complete Holochain DHT integration, cryptographic attestation pipeline, or production ZK proof system merely from crate presence |

This is a research and development repository, not a claim of browser feature parity, certified security, clinical suitability, or production-grade isolation.

## Architecture at a glance

~~~text
Sources / user content
        |
        v
prism-dom ---- parse and construct a structured content tree
        |
        +------> prism-reflex ---- URL, header and text-pattern signals
        |
        +------> prism-privacy --- Private / Local / Public policy decisions
        |
        v
prism-ingest ---- curated + pipeline + Mycelix + Wikidata claims
        |
        v
prism-search ---- BinaryHV index and local similarity retrieval
        |
        v
prism-ui / prism-tauri ---- reader-oriented client surfaces

Evidence/data contracts:
prism-epistemic-types / prism-knowledge-bridge / prism-attestation
        |
        +---- intended integration with Mycelix and Symthaea APIs
~~~

The diagram shows intended data flow and package boundaries, not a claim that every connector or subsystem is complete. In particular, the Holochain boundary is designed around external evidence/data exchange; the Prism repository does not contain a Holochain conductor as its local node runtime.

## Build and test

The workspace pins its Rust dependency graph in Cargo.lock. The flake exports a default development shell on Rust 1.99.0 and an explicit MSRV shell on Rust 1.96.1.

Using Nix:

~~~bash
nix develop
cargo metadata --locked --format-version 1
cargo check --workspace --locked
cargo nextest run --workspace --locked
~~~

Check the declared compatibility toolchain:

~~~bash
nix develop .#msrv
cargo check --workspace --locked
cargo nextest run --workspace --locked
~~~

Focused checks for the ingestion crate:

~~~bash
cargo test -p prism-ingest --locked
cargo test -p prism-ingest --features noncommercial-seed-data --locked
~~~

The noncommercial-seed-data feature intentionally opts into the WHO and FAO seed files that the upstream data README marks CC-BY-NC-SA 3.0 IGO. They are not embedded by the default profile. Review KNOWLEDGE_SEED_DATA_LICENSES.md before enabling that feature or redistributing derived bundles. The default profile still uses GeoNames CC-BY data, which requires attribution.

The standalone lockfile bootstrap and CI configuration are being qualified in PR #47. A successful build/test run is evidence for that exact source head and toolchain only; it does not automatically qualify desktop packaging, sandbox enforcement, browser security, or release attestation.

## Design principles

- **Local-first by default:** unknown or ambiguous content should not silently become public.
- **Source-labelled knowledge:** preserve source and epistemic metadata alongside claim content.
- **Explicit policy boundaries:** privacy-zone selection, user consent, and external data exchange should be inspectable.
- **Fail closed on missing evidence:** a missing policy, unverified receipt or uncertain mutation must not be presented as a successful authorization.
- **Reproducible dependencies:** commit lockfiles and name the toolchain used for build and test evidence.

## Research directions

The strongest differentiator is not to outperform mainstream browsers on full rendering, JavaScript execution, or web compatibility. Prism should compete on a narrower and independently measurable capability: **safe, provenance-preserving transformation of external information into a local knowledge workspace**.

Useful benchmark tracks include:

1. **Content extraction quality:** article/boilerplate separation, reading-order fidelity, Unicode preservation, and source-span retention on a frozen document corpus.
2. **Threat-signal calibration:** precision/recall and false-block rates on benign, malicious and ambiguous pages; test unseen domains and adversarially rewritten content. Do not count keyword matches as proof of prompt-injection detection.
3. **Privacy-state integrity:** wrong-domain, authenticated-session, private-path, explicit-denial and consent-revocation controls; verify actual storage/network side effects, not only the classifier's returned enum.
4. **Knowledge provenance:** each claim retains a source, source version, retrieval time, license, transformation digest and evidence label. Missing lineage should fail qualification.
5. **Local search quality:** nDCG@10, recall@k, MRR, calibration and abstention on a blinded query/claim corpus, compared with BM25 and a matched embedding baseline at equal memory/latency budgets.
6. **Resource frontier:** p50/p95/p99 ingestion and query latency, index-build time, memory, storage, energy and offline cold-start time.
7. **Independent replay:** rebuild the same index from frozen inputs and verify deterministic IDs, provenance and expected query results.

A competitive target should start with a public, reproducible baseline and a held-out set—not a claimed percentage win over Chrome, Brave, or Google. Prism should first demonstrate that it produces better auditable local knowledge with fewer privacy/provenance failures at a clearly measured resource budget.

## Knowledge seed data and licensing

The compile-time knowledge seed assets are staged from the canonical [Mycelix repository snapshot](https://github.com/Luminous-Dynamics/mycelix/tree/d597dcd99ccbf1cc3c341c3442ef6a53efd0dbff/mycelix-workspace/mycelix-knowledge/seed-data/claims) at commit `d597dcd99ccbf1cc3c341c3442ef6a53efd0dbff`. CI uses a pinned sparse checkout and records SHA-256 digests; it does not fabricate or duplicate the source datasets.

The default `prism-ingest` profile embeds only public-domain and CC-BY datasets. WHO and FAO datasets identified upstream as CC-BY-NC-SA 3.0 IGO are excluded by default and available only through the explicit `noncommercial-seed-data` feature. Enabling that feature requires a separate review of the source terms and intended use.

See [Knowledge Seed Data: Source and License Boundary](docs/KNOWLEDGE_SEED_DATA_LICENSES.md) for attribution, exact source snapshot, feature behavior, and reproducible CI staging. GeoNames attribution requirements still apply to redistributions that include GeoNames-derived data.

## Licensing

The Rust workspace uses AGPL-3.0-or-later unless an individual package states otherwise. Commercial licensing information is maintained in COMMERCIAL_LICENSE.md. Embedded and staged datasets retain their own upstream licenses; repository licensing does not replace upstream dataset terms.
