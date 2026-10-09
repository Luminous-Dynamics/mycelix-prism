# PRISM REPOSITORY BOUNDARY SPECIFICATION (V1)
**Canonical Repository Ownership & Migration Governance Contract**

- **Target Repository**: `Luminous-Dynamics/mycelix-prism`
- **Specification Version**: `1.1.0`
- **Status**: `Stage 1 — Canonical Hardening & Cryptographic Manifest Active`
- **Date**: October 8, 2026

---

## 1. Architectural Core & Strategic Boundaries

Prism is the sovereign user client, desktop browser/shell, process sandbox authority, and security runtime sitting between the Mycelix socio-epistemic substrate and the Symthaea cognitive core.

Rather than treating Prism as a sub-module of `mycelix` or a monolithic folder in `luminous-dynamics`, Prism's migration path establishes a **first-class public application repository (`Luminous-Dynamics/mycelix-prism`)**.

The boundary contract explicitly establishes:
```text
                   ┌────────────────────────┐
                   │    Mycelix Protocol    │
                   │  Holochain / DKG /     │
                   │  Epistemic Evidence    │
                   └───────────┬────────────┘
                               │
                       evidence receipts
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│                    Luminous-Dynamics/mycelix-prism           │
│                                                              │
│  UI ── Renderer Authority ── Broker ── Security Kernel IPC   │
│                    │                                         │
│          ┌─────────┼──────────┐                              │
│          ▼         ▼          ▼                              │
│       Network   Sandbox    Evidence                          │
│       Authority Authority  Receipts                          │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
                       Symthaea APIs (Cognitive Core)
```

---

## 2. 10-Step Migration Sequence

To prevent multiple divergent "canonical" copies of Prism, extraction follows an explicit, cryptographically verifiable 10-step sequence:

1. ✅ **Finish Boundary Contract**: Establish `PRISM_REPOSITORY_BOUNDARY_V1.md` (Completed).
2. ✅ **Generate Cryptographic Migration Manifest**: Build automated SHA-256 tree & crate manifest generators (`generate_prism_migration_manifest.py`) (Completed).
3. ✅ **Audit 20-Crate Dependency Graph**: Run automated zero-violation dependency graph validation (`verify_prism_migration_manifest.py`) (Completed).
4. 🔄 **Continue Canonical Hardening**: Deepen security migration, Landlock/seccomp adapters, and composed renderer security state/evidence layers inside `luminous-dynamics` (Stage 1 Active).
5. ⏸️ **Freeze Exact Prism Commit**: Record exact git commit SHA and tree SHA-256 hash prior to external repository creation.
6. ⏸️ **Create Remote Repository**: Initialize `Luminous-Dynamics/mycelix-prism` on GitHub when external repo creation is executed.
7. ⏸️ **Seed Remote Repository**: Seed `Luminous-Dynamics/mycelix-prism` from the exact frozen commit/tree.
8. ⏸️ **Verify Remote Identity**: Re-verify tree SHA-256 digest against `prism_migration_manifest.json` post-push.
9. ⏸️ **Establish Standalone CI**: Configure independent Tauri desktop & Rust test GitHub Actions workflows.
10. ⏸️ **Transition Monorepo Copy**: Retain monorepo copy strictly as an explicit integration/reference environment.

---

## 3. Cryptographic Migration Manifest Invariants

The extraction is governed by `prism_migration_manifest.json`, which records:
- **Source Repository & Commit SHA**: `luminous-dynamics` HEAD commit digest.
- **Source Tree SHA-256**: Cryptographic hash of all 220+ tracked source files across Prism.
- **Per-Crate Hashes**: SHA-256 tree digests for each of the 20 Prism crates.
- **Included / Excluded Path Rules**: Explicit inclusion of source code & specs; exclusion of target/build/log artifacts.
- **Dependency Boundary Enforcement**: Prohibits circular dependencies and restricts upstream imports to data-only schemas.

---

## 4. Canonical Crate & Component Ownership

`Luminous-Dynamics/mycelix-prism` holds exclusive canonical ownership over the following 20 crates and subsystems:

| Crate / Subsystem | Primary Role & Layer Authority | Public / Private |
| :--- | :--- | :--- |
| `prism-common` | Core domain primitives, configuration, error types | Public |
| `prism-dom` | DOM manipulation, UI tree state, accessibility engine | Public |
| `prism-ingest` | Data ingestion pipeline, telemetry, document parsing | Public |
| `prism-knowledge-bridge` | Interface to decentralized knowledge graphs/stores | Public |
| `prism-layout` | Layout engine, dynamic component placement math | Public |
| `prism-net` | P2P network transport layer & connection authority | Public |
| `prism-node` | Local node daemon & background service runtime | Public |
| `prism-privacy` | Differential privacy, local encryption, data masking | Public |
| `prism-proxy` | Network proxy, Landlock/seccomp egress filter | Public |
| `prism-reflex` | Reactive signal dispatch & event bus | Public |
| `prism-search` | Local vector/HDC semantic indexer | Public |
| `prism-security-tests` | Qualification test suite & attack surface probes | Public |
| `prism-serve` | Local HTTP/gRPC API service for desktop UI | Public |
| `prism-shell` | CLI manager & process broker lifecycle orchestrator | Public |
| `prism-tauri` | Tauri v2 native app wrapper & OS windowing | Public |
| `prism-ui` | Svelte/HTML front-end UI asset bundle | Public |
| `prism-zkp` | ZKP evidence generators & verification circuits | Public |
| `prism-attestation` | Client-side attestation verification receipts | Public |
| `prism-kernel-protocol` | Inter-process wire protocol for broker ↔ kernel service | Private / Internal |
| `prism-epistemic-types` | Client-side epistemic validation data structures | Private / Internal |

---

## 5. Allowed & Forbidden Dependency Directions

### ✅ Allowed Dependency Vectors
1. `mycelix-prism` ➔ `mycelix-core-types` / `mycelix-zkp-core` (Data schemas & evidence receipt formats ONLY).
2. `mycelix-prism` ➔ `Symthaea` APIs (Via gRPC/IPC contracts for local cognitive/HDC services).
3. `mycelix` ➔ `mycelix-prism` attestations (Consumes signed client receipts as Holochain zome payload inputs).

### 🚫 Forbidden Dependency Vectors
1. `mycelix-prism` MUST NOT depend on Holochain runtime engine binaries or zome compilation toolchains directly.
2. `mycelix` MUST NOT depend on `prism-tauri`, `prism-ui`, `prism-dom`, or desktop windowing libraries.
3. `symthaea` MUST NOT depend on Prism rendering, broker, or UI layers.
4. Direct circular crate path imports between monorepo directories and `mycelix-prism` are strictly prohibited in Stage 3.

---

## 6. Security Authority Ownership

`mycelix-prism` is the sole owner of the client security boundary:
* **Broker & Process Lifecycle**: `prism-shell` and `prism-node` manage process spawn, supervision, and graceful teardown.
* **Renderer Authority**: `prism-tauri` and `prism-ui` enforce strict origin isolation and IPC privilege restriction.
* **Linux Sandbox Adapters**: Native `Landlock` filesystem restricted access rules and `seccomp-bpf` syscall filters.
* **Security Qualification Corpus**: `prism-security-tests` containing automated qualification suites for Waves 1-16.

---

## 7. Holochain Evidence-Only Boundary

Holochain serves strictly as an **evidence receipt store** and distributed hash table (DHT):
* Holochain zomes do NOT run inside the Prism UI or broker process.
* Prism communicates with Holochain exclusively via external RPC/IPC bridges.
* Evidence receipts (attestations, DKG signatures) pass into Prism as cryptographically sealed payload structures.

---

*Authored and Approved by Luminous Dynamics Core Architecture Team.*
