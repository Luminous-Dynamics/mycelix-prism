# Prism Mycelix Knowledge Seed Data: Source and License Boundary

**Pinned upstream snapshot:** [Luminous-Dynamics/mycelix](https://github.com/Luminous-Dynamics/mycelix/tree/d597dcd99ccbf1cc3c341c3442ef6a53efd0dbff/mycelix-workspace/mycelix-knowledge/seed-data/claims) at commit `d597dcd99ccbf1cc3c341c3442ef6a53efd0dbff`.

Prism's CI stages the canonical upstream data into the sibling path required by the existing compile-time `include_str!` declarations. The data are not copied into Prism source and are not regenerated during CI. The pinned commit and staged file hashes are recorded by the seed-staging workflow.

## Default embedded profile

The default `prism-ingest` build embeds only the following source datasets:

| Dataset | Upstream attribution | License shown by upstream seed-data README | Default profile |
|---|---|---|---|
| `energy-facts.json` | U.S. EIA and USGS | Public domain | Included |
| `geonames-major.json` | GeoNames.org | CC-BY 4.0 | Included with attribution |
| `noaa-climate.json` | NOAA NCEI | Public domain | Included |

## Explicit non-commercial profile

The following files are **not embedded by default** because the upstream seed-data README identifies their licenses as CC-BY-NC-SA 3.0 IGO:

| Dataset | Attribution | License | Inclusion |
|---|---|---|---|
| `who-health.json` | World Health Organization | CC-BY-NC-SA 3.0 IGO | Only with `noncommercial-seed-data` |
| `fao-agriculture.json` | Food and Agriculture Organization | CC-BY-NC-SA 3.0 IGO | Only with `noncommercial-seed-data` |

Enable the profile explicitly for non-commercial evaluation or deployments whose legal basis has been reviewed:

```bash
cargo test -p prism-ingest --features noncommercial-seed-data --locked
cargo build -p prism-ingest --features noncommercial-seed-data --locked
```

The Cargo feature is a technical inclusion boundary, not legal advice or a substitute for checking the current source terms. Commercial products must not enable this feature unless they have obtained an appropriate separate permission or license. The default profile still includes GeoNames attribution requirements; include the attribution in any redistribution that uses those data.

## Reproduction and controls

- CI checks out the exact upstream commit above with sparse checkout.
- A staging script refuses missing/empty inputs, validates each dataset as a non-empty JSON array of claims, and refuses to overwrite an unexpected sibling path.
- SHA-256 digests are retained in the CI artifact.
- Default and explicit non-commercial feature builds are both tested.
- No generated dummy data, permissive-license substitution, or silent omission is used.

## Upstream attribution references

The upstream seed-data README lists source and license metadata for each file:

- [GeoNames](https://www.geonames.org/) — CC-BY 4.0.
- [U.S. Energy Information Administration](https://www.eia.gov/) and [U.S. Geological Survey](https://www.usgs.gov/) — public domain.
- [NOAA NCEI](https://www.ncei.noaa.gov/) — public domain.
- [World Health Organization GHO](https://www.who.int/data/gho) — CC-BY-NC-SA 3.0 IGO.
- [FAO FAOSTAT](https://www.fao.org/faostat/) — CC-BY-NC-SA 3.0 IGO.
