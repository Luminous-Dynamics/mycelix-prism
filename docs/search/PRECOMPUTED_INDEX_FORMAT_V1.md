# Prism Precomputed Search Index — Format v1

**Status:** Draft implementation specification for PR #34. This is not a release guarantee until exact-head validation and artifact migration review are complete.

## Security and compatibility contract

A version-1 index is a local precomputation artifact, not a signed statement about its source. Its BLAKE3 digest detects accidental corruption; it does not authenticate the producer. The decoder must fail closed on malformed bytes and invalid derived state.

The decoder accepts only the versioned format. Legacy raw bincode artifacts are not auto-detected or reinterpreted; regenerate them deliberately with the current encoder. Unknown versions and nonzero reserved flags are rejected.

## Header

All integer fields are little-endian. The fixed header is 52 bytes:

| Offset | Width | Field | Required value |
|---:|---:|---|---|
| 0 | 8 bytes | Magic | ASCII `PRSMIDX` followed by NUL (`0x00`) |
| 8 | 2 | Format version | `1` |
| 10 | 2 | Reserved flags | `0` |
| 12 | 8 | Payload length | Exact byte count after the 52-byte header |
| 20 | 32 | BLAKE3 digest | BLAKE3 of payload bytes only |

The decoder rejects files larger than 128 MiB, payload lengths outside the supported maximum, declared/actual length mismatches, and digest mismatches before parsing fields.

## Payload layout

Counts and string lengths are u32 little-endian. Each string is UTF-8 and encoded as `u32 byte_length` followed by exactly that many bytes.

1. **Claims:** `u32 claim_count`, maximum 50,000. Each claim contains:
   - non-empty content string, maximum 512 KiB;
   - `u32 source_count`, maximum 128, followed by source strings, maximum 16 KiB each;
   - one byte empirical level (`E0` through `E4` encode as `0` through `4`);
   - one byte normative level (`N0` through `N3` encode as `0` through `3`);
   - one byte materiality level (`M0` through `M3` encode as `0` through `3`);
   - `u32 tag_count`, maximum 256, followed by tag strings of at most 4 KiB.
2. **Vectors:** `u32 vector_count`, equal to `claim_count` and at most 50,000; each vector is exactly 2,048 bytes (16,384 bits), with no per-vector length prefix.
3. **Word document frequencies:** `u32 word_count`, maximum 250,000. Each entry contains a non-empty key string of at most 256 bytes and a u64 little-endian frequency. Keys are encoded in lexicographic order for deterministic output. Duplicate keys are rejected and each frequency must be in `1..=claim_count`.

Aggregate payload limits include counts, strings, vectors, and frequency entries. Count and string constraints are checked before allocation or copy. Checked cursor operations reject truncated fields, invalid UTF-8, invalid enum values, integer overflow, and trailing bytes.

## Semantic validation

Structural decoding alone is insufficient. Prism recomputes word document frequencies from all claims and recomputes each vector using the same IDF encoder. It rejects mismatched claim/vector cardinality, stale or fabricated document frequencies, and vectors inconsistent with the claims and corpus statistics.

The writer applies cheap count, string, and aggregate-size bounds before recomputing derived state. The decoder does not allocate a second vector array to compare vectors; it recomputes and compares one vector at a time.

## Migration

Regenerate old precomputed artifacts using `SearchEngine::to_precomputed()`. Before enabling `precomputed-index` in a release:

1. record source corpus revision, claim count, source manifest, and artifact SHA-256;
2. generate the file using the new encoder;
3. load it with `SearchEngine::try_from_precomputed()` in an exact-head build/test;
4. measure file bytes, build time, load time, and peak memory at representative and maximum supported corpus sizes;
5. publish rebuild instructions and do not silently fall back to an empty index if an embedded artifact fails validation.

## Current bounds and limitations

The implementation caps the complete file at 128 MiB, claims/vectors at 50,000, sources at 128 per claim, tags at 256 per claim, content at 512 KiB, source strings at 16 KiB, tag strings at 4 KiB, word-frequency entries at 250,000, and each word key at 256 bytes. These are defensive limits, not performance claims; benchmarks should inform future version changes.; validation also rejects claims with more than 2,048 indexed terms before recomputing vectors to bound temporary memory amplification.
