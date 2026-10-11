# Optional Mycelix Knowledge Seed Data

Prism can be checked out and built as a standalone public repository. The
larger Mycelix workspace may provide an additional compile-time corpus from a
sibling `mycelix-knowledge/seed-data/claims` directory, but that companion data
tree is not part of this repository and must not be an implicit build
requirement.

## Standalone build (default)

The `prism-ingest` crate does not enable `workspace-seed-data` by default.
In this configuration, `mycelix_claims()` returns no claims from that optional
corpus. Other Prism ingestion sources remain available. This avoids a compiler
failure caused by unresolved `include_str!` paths and keeps public builds
reproducible without materializing a sibling checkout.

## Full-workspace build

When the companion repository and its five JSON claim files are present at the
expected sibling path, opt in explicitly:

```sh
cargo check --workspace --locked --features prism-ingest/workspace-seed-data
cargo test -p prism-ingest --locked --features workspace-seed-data
```

The feature expects these files at compile time:

- `energy-facts.json`
- `geonames-major.json`
- `who-health.json`
- `noaa-climate.json`
- `fao-agriculture.json`

This feature is intentionally explicit: do not enable it in a standalone CI
job or public release build unless the companion corpus is supplied and its
provenance/licensing has been reviewed. A default-feature build proves the
Prism source can compile on its own; it does **not** prove that the optional
companion data was included.
