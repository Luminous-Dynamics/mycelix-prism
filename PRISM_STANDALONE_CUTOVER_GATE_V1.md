# PRISM Standalone Repository Cutover Gate V1

Status: Stage 1 / unqualified design gate

This document defines the conditions for creating and declaring
`Luminous-Dynamics/mycelix-prism` canonical.

## Principle

The standalone repository must be an exact, intentional extraction of a frozen
Prism tree. A successful file-copy operation is not evidence of identity.

The migration has two independent identities:

1. **source identity** — the exact Prism tree selected from the monorepo;
2. **destination identity** — the exact tree committed to the standalone repository.

Cutover is qualified only when both identities are independently recomputed and
the migration manifest agrees.

## Freeze gate

Before seeding the standalone repository:

- select one immutable source commit;
- record the source branch only as provenance, never as identity;
- record the exact Prism subpath;
- enumerate every tracked file included in the extraction;
- enumerate explicit exclusions;
- compute a deterministic source-tree digest;
- freeze the manifest in the source repository;
- verify the manifest from a clean checkout.

A moving branch name MUST NOT be used as the migration identity.

## Dependency gate

The standalone Prism tree MUST:

- contain only the declared Prism crate set;
- preserve the declared internal dependency direction;
- contain no forbidden Mycelix/Holochain runtime dependency;
- contain no accidental enclosing-workspace dependency;
- contain a standalone Cargo workspace and lockfile;
- preserve pinned security-sensitive dependency identities where required.

The Mycelix Holochain layer is an evidence/data integration boundary, not Prism
kernel authority.

## Security gate

The extraction MUST preserve the security layering:

`policy -> proof -> native adapter -> kernel -> receipt`

and:

`renderer -> broker -> kernel`

Renderer capability authority and neutral external-kernel service IPC MUST remain
distinct.

The legacy Spore-specific renderer bridge MUST NOT be reintroduced by extraction.

## Destination verification gate

After the remote repository is seeded, independently obtain its default-branch
tree and recompute the same canonical tree digest.

Qualification requires:

`destination_tree_digest == frozen_source_tree_digest`

and exact equality of the included path/file manifest.

A matching commit message, branch name, or file count is insufficient.

## Canonical cutover gate

The standalone repository may be declared canonical only when all are true:

- [ ] frozen source commit recorded;
- [ ] source manifest independently verifies;
- [ ] standalone repository exists;
- [ ] destination tree independently verifies against frozen manifest;
- [ ] standalone Cargo workspace builds/tests from a clean checkout;
- [ ] exact-head security qualification workflows execute successfully;
- [ ] release packaging is independently reproducible;
- [ ] monorepo contains no competing mutable canonical Prism implementation;
- [ ] remaining monorepo references are explicitly classified as integration,
      compatibility, migration, or archived artifacts.

Until all gates are satisfied, status MUST remain **UNQUALIFIED**.

## Evidence rule

No source-level PASS, local script PASS, or successful repository creation may be
promoted to a security qualification claim.

Each evidence record must identify:

- exact commit;
- exact workflow/test subject;
- observed result;
- environment/toolchain identity;
- relevant artifact digest;
- whether the result is source evidence, executable qualification, or scientific
  admission.

## Non-goals

This gate does not require Prism to depend on Mycelix at runtime, does not make
Holochain an enforcement oracle, and does not require importing the monorepo's
entire Cargo workspace into the standalone repository.
