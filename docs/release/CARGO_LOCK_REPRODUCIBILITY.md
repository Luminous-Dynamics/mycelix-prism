# Cargo lockfile reproducibility

Prism is a multi-crate Cargo workspace. The root `Cargo.lock` is the reviewed record of the exact third-party dependency graph and Git dependency revisions used for workspace validation.

## When to regenerate

Regenerate only after intended workspace/package manifests are frozen for the change being reviewed. Do not copy a lockfile from an earlier manifest state, construct one manually, or remove `--locked` to make CI green.

From a clean checkout of the exact candidate source revision:

```sh
nix develop --command cargo generate-lockfile
nix develop --command cargo metadata --locked --format-version 1 > /tmp/prism-cargo-metadata.json
nix develop --command cargo tree --locked -e normal
git diff --check -- Cargo.lock
```

## Review gates

Before the lock is considered accepted:

1. Inspect every new or changed package/version and each non-registry source. For Git dependencies, record the repository URL and resolved commit; do not accept moving branches as proof of reproducibility.
2. Review newly introduced dependencies for necessity, license compatibility, maintenance posture, and known security advisories. Investigate unexpected transitive dependency growth rather than hiding it.
3. Commit the generated `Cargo.lock` alongside the source/manifests that require it. Keep the PR draft while the graph is reviewed.
4. On that exact commit, run `cargo metadata --locked --format-version 1`, focused package tests, `cargo check --workspace --locked`, `cargo nextest run --workspace --locked`, and the declared MSRV check.
5. Record the exact source SHA and test results. A generated lockfile or successful metadata resolution proves dependency resolution, not code compilation, behavioral correctness, or security.

## CI behavior

The formatting job is intentionally independent of `Cargo.lock`, using the lightweight `.#fmt` Nix shell. Locked build/test/MSRV jobs fail fast if the root lock is absent. The lock-recovery path in the Prism security PR is narrowly scoped to that same-repository PR branch, writes only `Cargo.lock`, and leaves the result in the draft for review. It is not a general mechanism for silently updating dependency locks in other branches.
