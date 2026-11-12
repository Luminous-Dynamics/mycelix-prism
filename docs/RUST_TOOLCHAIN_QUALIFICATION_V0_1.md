# Prism Rust 1.99.1 qualification v0.1

**Status:** draft upgrade proposal, stacked on the committed-lock/build foundation PR #28. The intended default is Rust/Cargo 1.99.1 only after exact-head qualification succeeds. The Rust 1.96.1 MSRV lane remains unchanged.

## Why upgrade

Prism currently declares Rust 1.99.0 in `rust-toolchain.toml` and its Nix default shell. Rust 1.99.1 is a patch release with fixes for:
- x86_64 FFI `bool` return-value upper-register zero extension;
- missing `wcslen` on UEFI and embedded targets;
- macOS rust-lld `libLLVM` library lookup.

The Prism source search did not find a direct `extern "C" bool` declaration. The ABI fix is therefore general compiler correctness and forward safety, not a claim of an identified Prism defect.

## Nix toolchain pinning issue

The build foundation PR #28's flake lock pins oxalica/rust-overlay to an October 9 snapshot. Rust 1.99.1 was published October 15. The candidate Nix attribute may therefore not exist in that older overlay snapshot even though the upstream release is published.

To keep the compiler upgrade isolated from a broad Nixpkgs refresh, the qualification workflow updates **only** the `rust-overlay` input to exact commit:

`d1e30fd696e1151603aa8adaa8f6b8c604fe3eb0` (manifest update dated 2026-11-12).

The updated flake.lock is retained as a workflow artifact. It is not silently committed by CI. Review the resulting one-input lock diff and commit it explicitly after verifying the artifact. The nixpkgs input and other sources remain unchanged.

## Matched toolchain shells

The flake defines:
- `default`: Rust/Cargo 1.99.1;
- `toolchain-1-99-0`: exact 1.99.0 comparison baseline;
- `msrv`: Rust/Cargo 1.96.1 compatibility lane.

The root `rust-toolchain.toml`, Nix shell, and CI job names must agree on the default 1.99.1 release. The exact baseline shell remains available temporarily for paired comparison. The declared MSRV does not move.

## Hosted qualification gates

For both 1.99.0 and 1.99.1:
- exact rustc/Cargo identity;
- `cargo fmt --check --all`;
- `cargo check --workspace --locked`;
- `cargo nextest run --workspace --locked`.

The candidate additionally runs Clippy across all workspace targets. The MSRV shell performs a separate locked workspace check.

The workflow captures exact compiler/Cargo verbose identity, overlay commit, source SHA, kernel and updated flake lock artifact.

## Benchmark plan

This PR establishes compatibility, not a speed claim. Next, compare the exact same source/lock/overlay with:
- clean build wall time;
- `cargo check` and Nextest wall time;
- incremental compile after a scripted fixed source edit;
- peak RSS and CPU time;
- output artifact sizes;
- sccache hit/miss and speedup as a separate profile;
- build reproducibility and lockfile stability.

For compiler ecosystem comparisons, use rustc-perf. Use Cargo timing reports to separate compiler time from dependency graph, build scripts and linker. Prism-specific runtime performance (DOM/parser, layout, search/index and proxy throughput/latency) needs matched optimized binaries, fixed corpus, concurrency, hardware and warmed/cold-cache policies; compiler build time is not application runtime.

Statistical bar:
- 5+ paired runs for exploratory results;
- 30+ for ordinary latency claims;
- at least 10,000 per-condition observations or justified design for p99;
- raw trials and failures preserved; no skipped run treated as pass.

## Promotion gates

1. The Rust overlay lock update is limited to the exact reviewed rust-overlay commit; nixpkgs remains unchanged.
2. Baseline and candidate checks/tests both pass on exact source and Cargo.lock.
3. MSRV 1.96.1 remains green.
4. Candidate Clippy result is reviewed separately; no broad warning suppression.
5. Only then promote 1.99.1 as default. Do not mix dependency updates or source changes into this PR.

## References

- Rust 1.99.1 official release notes: https://blog.rust-lang.org/releases/latest/
- rust-overlay: https://github.com/oxalica/rust-overlay
- rustc-perf: https://rustc-dev-guide.rust-lang.org/tests/perf.html
- Cargo timings: https://doc.rust-lang.org/cargo/reference/timings.html
