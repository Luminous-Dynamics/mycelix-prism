// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Versioned, length-bounded encoding for precomputed search indexes.
//!
//! This format uses checked primitive reads rather than a generic deserializer.
//! Collection counts and string lengths are capped before allocation, and the
//! complete payload digest is checked before parsing. The digest detects
//! corruption; it is not an authenticity signature.

use super::{ClaimEntry, SearchEngine, encode_text_idf, is_stop_word};
use crate::binary_hv::BinaryHV;
use prism_common::{EmpiricalLevel, MaterialityLevel, NormativeLevel};
use std::collections::{HashMap, HashSet};
use std::fmt;

const MAGIC: &[u8; 8] = b"PRSMIDX\0";
const FORMAT_VERSION: u16 = 1;
const HEADER_LEN: usize = 8 + 2 + 2 + 8 + 32;
const MAX_INDEX_BYTES: usize = 128 * 1024 * 1024;
const MAX_PAYLOAD_BYTES: usize = MAX_INDEX_BYTES - HEADER_LEN;

const MAX_CLAIMS: usize = 50_000;
const MAX_SOURCES_PER_CLAIM: usize = 128;
const MAX_TAGS_PER_CLAIM: usize = 256;
const MAX_WORD_DF_ENTRIES: usize = 250_000;
const MAX_CONTENT_BYTES: usize = 512 * 1024;
const MAX_SOURCE_BYTES: usize = 16 * 1024;
const MAX_TAG_BYTES: usize = 4 * 1024;
const MAX_WORD_BYTES: usize = 256;
const MAX_INDEXED_WORDS_PER_CLAIM: usize = 2_048;
const MAX_TOTAL_INDEXED_WORDS: usize = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrecomputedIndexError {
    TooLarge,
    InvalidMagic,
    UnsupportedVersion(u16),
    InvalidFlags(u16),
    LengthMismatch,
    DigestMismatch,
    Truncated,
    TrailingBytes,
    InvalidUtf8,
    InvalidCount(&'static str),
    InvalidValue(&'static str),
    InconsistentClaimVectorCount,
    InconsistentWordFrequencies,
    InconsistentVectors,
}

impl fmt::Display for PrecomputedIndexError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "precomputed index rejected: {self:?}")
    }
}

impl std::error::Error for PrecomputedIndexError {}

impl SearchEngine {
    /// Encode a search index as PRSMIDX format version 1.
    ///
    /// The writer validates derived document frequencies and vectors before
    /// emitting bytes. Raw bincode artifacts are intentionally not reinterpreted
    /// as this format; old artifacts must be rebuilt/re-encoded explicitly.
    pub fn to_precomputed(&self) -> Result<Vec<u8>, PrecomputedIndexError> {
        // Enforce cheap bounds before rebuilding corpus statistics and vectors.
        if self.claims.len() > MAX_CLAIMS || self.claims.len() != self.vectors.len() {
            return Err(PrecomputedIndexError::InconsistentClaimVectorCount);
        }
        if self.word_df.len() > MAX_WORD_DF_ENTRIES {
            return Err(PrecomputedIndexError::InvalidCount("word frequencies"));
        }

        let mut projected_payload = 4_usize; // claim count
        for claim in &self.claims {
            if claim.content.is_empty() || claim.content.len() > MAX_CONTENT_BYTES {
                return Err(PrecomputedIndexError::InvalidValue("claim content"));
            }
            if claim.sources.len() > MAX_SOURCES_PER_CLAIM {
                return Err(PrecomputedIndexError::InvalidCount("claim sources"));
            }
            if claim.tags.len() > MAX_TAGS_PER_CLAIM {
                return Err(PrecomputedIndexError::InvalidCount("claim tags"));
            }
            add_projected_size(&mut projected_payload, 4 + claim.content.len())?;
            add_projected_size(&mut projected_payload, 4 + 3 + 4)?;
            for source in &claim.sources {
                if source.len() > MAX_SOURCE_BYTES {
                    return Err(PrecomputedIndexError::InvalidValue("source"));
                }
                add_projected_size(&mut projected_payload, 4 + source.len())?;
            }
            for tag in &claim.tags {
                if tag.len() > MAX_TAG_BYTES {
                    return Err(PrecomputedIndexError::InvalidValue("tag"));
                }
                add_projected_size(&mut projected_payload, 4 + tag.len())?;
            }
        }

        add_projected_size(&mut projected_payload, 4)?; // vector count
        let vectors_size = self
            .vectors
            .len()
            .checked_mul(BinaryHV::BYTES)
            .ok_or(PrecomputedIndexError::TooLarge)?;
        add_projected_size(&mut projected_payload, vectors_size)?;
        add_projected_size(&mut projected_payload, 4)?; // word-frequency count
        for (word, frequency) in &self.word_df {
            if word.is_empty() || word.len() > MAX_WORD_BYTES {
                return Err(PrecomputedIndexError::InvalidValue("word"));
            }
            if *frequency == 0 || *frequency > self.claims.len() {
                return Err(PrecomputedIndexError::InvalidValue("word frequency"));
            }
            add_projected_size(&mut projected_payload, 4 + word.len() + 8)?;
        }

        validate_derived_state(self)?;

        let mut payload = Writer::default();
        payload.write_count(self.claims.len(), MAX_CLAIMS, "claims")?;
        for claim in &self.claims {
            payload.write_string(&claim.content, MAX_CONTENT_BYTES, "claim content", true)?;
            payload.write_count(claim.sources.len(), MAX_SOURCES_PER_CLAIM, "claim sources")?;
            for source in &claim.sources {
                payload.write_string(source, MAX_SOURCE_BYTES, "source", false)?;
            }
            payload.write_u8(empirical_to_wire(claim.empirical_level))?;
            payload.write_u8(normative_to_wire(claim.normative_level))?;
            payload.write_u8(materiality_to_wire(claim.materiality_level))?;
            payload.write_count(claim.tags.len(), MAX_TAGS_PER_CLAIM, "claim tags")?;
            for tag in &claim.tags {
                payload.write_string(tag, MAX_TAG_BYTES, "tag", false)?;
            }
        }

        payload.write_count(self.vectors.len(), MAX_CLAIMS, "vectors")?;
        for vector in &self.vectors {
            payload.write_bytes(&vector.0)?;
        }

        // HashMap order is nondeterministic; sorted keys make output reproducible.
        let mut words = self.word_df.iter().collect::<Vec<_>>();
        words.sort_unstable_by(|left, right| left.0.cmp(right.0));
        payload.write_count(words.len(), MAX_WORD_DF_ENTRIES, "word frequencies")?;
        for (word, frequency) in words {
            payload.write_string(word, MAX_WORD_BYTES, "word", true)?;
            payload.write_u64(
                u64::try_from(*frequency)
                    .map_err(|_| PrecomputedIndexError::InvalidValue("word frequency"))?,
            )?;
        }

        if payload.bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(PrecomputedIndexError::TooLarge);
        }
        let payload_len =
            u64::try_from(payload.bytes.len()).map_err(|_| PrecomputedIndexError::TooLarge)?;
        let digest = blake3::hash(&payload.bytes);

        let mut output = Vec::with_capacity(HEADER_LEN + payload.bytes.len());
        output.extend_from_slice(MAGIC);
        output.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        output.extend_from_slice(&0_u16.to_le_bytes()); // Reserved flags must stay zero.
        output.extend_from_slice(&payload_len.to_le_bytes());
        output.extend_from_slice(digest.as_bytes());
        output.extend_from_slice(&payload.bytes);
        if output.len() > MAX_INDEX_BYTES {
            return Err(PrecomputedIndexError::TooLarge);
        }
        Ok(output)
    }

    /// Decode PRSMIDX version 1 using explicit allocation and length bounds.
    ///
    /// Old unversioned bincode blobs fail closed: no legacy decoding fallback is
    /// attempted, preventing ambiguous format interpretation.
    pub fn try_from_precomputed(bytes: &[u8]) -> Result<Self, PrecomputedIndexError> {
        if bytes.len() > MAX_INDEX_BYTES {
            return Err(PrecomputedIndexError::TooLarge);
        }
        if bytes.len() < HEADER_LEN {
            return Err(PrecomputedIndexError::Truncated);
        }
        if &bytes[..8] != MAGIC {
            return Err(PrecomputedIndexError::InvalidMagic);
        }

        let version = u16::from_le_bytes([bytes[8], bytes[9]]);
        if version != FORMAT_VERSION {
            return Err(PrecomputedIndexError::UnsupportedVersion(version));
        }
        let flags = u16::from_le_bytes([bytes[10], bytes[11]]);
        if flags != 0 {
            return Err(PrecomputedIndexError::InvalidFlags(flags));
        }
        let declared_len = u64::from_le_bytes(
            bytes[12..20]
                .try_into()
                .map_err(|_| PrecomputedIndexError::Truncated)?,
        );
        if declared_len > MAX_PAYLOAD_BYTES as u64 {
            return Err(PrecomputedIndexError::TooLarge);
        }
        let actual_len = bytes.len() - HEADER_LEN;
        if usize::try_from(declared_len).ok() != Some(actual_len) {
            return Err(PrecomputedIndexError::LengthMismatch);
        }

        let payload = &bytes[HEADER_LEN..];
        let actual_digest = blake3::hash(payload);
        if !bytes[20..52]
            .iter()
            .zip(actual_digest.as_bytes().iter())
            .all(|(left, right)| left == right)
        {
            return Err(PrecomputedIndexError::DigestMismatch);
        }

        let mut cursor = Cursor::new(payload);
        let claim_count = cursor.read_count(MAX_CLAIMS, "claims", 16)?;
        let mut claims = Vec::with_capacity(claim_count);
        for _ in 0..claim_count {
            let content = cursor.read_string(MAX_CONTENT_BYTES, "claim content", true)?;
            let source_count =
                cursor.read_count(MAX_SOURCES_PER_CLAIM, "claim sources", 4)?;
            let mut sources = Vec::with_capacity(source_count);
            for _ in 0..source_count {
                sources.push(cursor.read_string(MAX_SOURCE_BYTES, "source", false)?);
            }

            let empirical_level = empirical_from_wire(cursor.read_u8()?)?;
            let normative_level = normative_from_wire(cursor.read_u8()?)?;
            let materiality_level = materiality_from_wire(cursor.read_u8()?)?;

            let tag_count = cursor.read_count(MAX_TAGS_PER_CLAIM, "claim tags", 4)?;
            let mut tags = Vec::with_capacity(tag_count);
            for _ in 0..tag_count {
                tags.push(cursor.read_string(MAX_TAG_BYTES, "tag", false)?);
            }
            claims.push(ClaimEntry {
                content,
                sources,
                empirical_level,
                normative_level,
                materiality_level,
                tags,
            });
        }

        let vector_count = cursor.read_count(MAX_CLAIMS, "vectors", BinaryHV::BYTES)?;
        if vector_count != claim_count {
            return Err(PrecomputedIndexError::InconsistentClaimVectorCount);
        }
        let mut vectors = Vec::with_capacity(vector_count);
        for _ in 0..vector_count {
            let raw = cursor.take(BinaryHV::BYTES)?;
            let mut bits = [0_u8; BinaryHV::BYTES];
            bits.copy_from_slice(raw);
            vectors.push(BinaryHV(bits));
        }

        let word_count = cursor.read_count(MAX_WORD_DF_ENTRIES, "word frequencies", 13)?;
        let mut word_df = HashMap::with_capacity(word_count);
        for _ in 0..word_count {
            let word = cursor.read_string(MAX_WORD_BYTES, "word", true)?;
            let frequency = cursor.read_u64()?;
            if frequency == 0 || frequency > claim_count as u64 {
                return Err(PrecomputedIndexError::InvalidValue("word frequency"));
            }
            let frequency = usize::try_from(frequency)
                .map_err(|_| PrecomputedIndexError::InvalidValue("word frequency"))?;
            if word_df.insert(word, frequency).is_some() {
                return Err(PrecomputedIndexError::InvalidValue("duplicate word frequency key"));
            }
        }
        if cursor.remaining() != 0 {
            return Err(PrecomputedIndexError::TrailingBytes);
        }

        let engine = Self {
            claims,
            vectors,
            word_df,
        };
        validate_derived_state(&engine)?;
        Ok(engine)
    }
}

fn add_projected_size(
    total: &mut usize,
    additional: usize,
) -> Result<(), PrecomputedIndexError> {
    *total = total
        .checked_add(additional)
        .ok_or(PrecomputedIndexError::TooLarge)?;
    if *total > MAX_PAYLOAD_BYTES {
        return Err(PrecomputedIndexError::TooLarge);
    }
    Ok(())
}

fn validate_derived_state(engine: &SearchEngine) -> Result<(), PrecomputedIndexError> {
    if engine.claims.len() != engine.vectors.len() {
        return Err(PrecomputedIndexError::InconsistentClaimVectorCount);
    }
    if engine.claims.len() > MAX_CLAIMS || engine.word_df.len() > MAX_WORD_DF_ENTRIES {
        return Err(PrecomputedIndexError::InvalidCount("index cardinality"));
    }

    let mut expected_word_df = HashMap::<String, usize>::new();
    let mut total_indexed_words = 0usize;
    for claim in &engine.claims {
        let lowered = claim.content.to_lowercase();
        let indexed_word_count = lowered
            .split(|character: char| !character.is_alphanumeric())
            .filter(|word| word.len() >= 2 && !is_stop_word(word))
            .take(MAX_INDEXED_WORDS_PER_CLAIM + 1)
            .count();
        if indexed_word_count > MAX_INDEXED_WORDS_PER_CLAIM {
            // IDF encoding materializes a full 2,048-byte hypervector for each
            // unigram and adjacent-word bigram. Bound temporary validation memory
            // independently of the raw string/file-size caps.
            return Err(PrecomputedIndexError::InvalidValue("claim indexed word count"));
        }
        total_indexed_words = total_indexed_words
            .checked_add(indexed_word_count)
            .ok_or(PrecomputedIndexError::InvalidCount("total indexed words"))?;
        if total_indexed_words > MAX_TOTAL_INDEXED_WORDS {
            return Err(PrecomputedIndexError::InvalidCount("total indexed words"));
        }
        let words: HashSet<&str> = lowered
            .split(|character: char| !character.is_alphanumeric())
            .filter(|word| word.len() >= 2 && !is_stop_word(word))
            .collect();
        for word in words {
            *expected_word_df.entry(word.to_string()).or_insert(0) += 1;
            if expected_word_df.len() > MAX_WORD_DF_ENTRIES {
                return Err(PrecomputedIndexError::InvalidCount("recomputed word frequencies"));
            }
        }
    }
    if expected_word_df != engine.word_df {
        return Err(PrecomputedIndexError::InconsistentWordFrequencies);
    }

    let document_count = engine.claims.len() as f32;
    for (claim, stored_vector) in engine.claims.iter().zip(&engine.vectors) {
        let recomputed = encode_text_idf(&claim.content, &expected_word_df, document_count);
        if &recomputed != stored_vector {
            return Err(PrecomputedIndexError::InconsistentVectors);
        }
    }
    Ok(())
}

#[derive(Default)]
struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    fn reserve_for(&self, additional: usize) -> Result<(), PrecomputedIndexError> {
        let new_len = self
            .bytes
            .len()
            .checked_add(additional)
            .ok_or(PrecomputedIndexError::TooLarge)?;
        if new_len > MAX_PAYLOAD_BYTES {
            return Err(PrecomputedIndexError::TooLarge);
        }
        Ok(())
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), PrecomputedIndexError> {
        self.reserve_for(bytes.len())?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn write_u8(&mut self, value: u8) -> Result<(), PrecomputedIndexError> {
        self.write_bytes(&[value])
    }

    fn write_u32(&mut self, value: usize) -> Result<(), PrecomputedIndexError> {
        self.write_bytes(
            &u32::try_from(value)
                .map_err(|_| PrecomputedIndexError::TooLarge)?
                .to_le_bytes(),
        )
    }

    fn write_u64(&mut self, value: u64) -> Result<(), PrecomputedIndexError> {
        self.write_bytes(&value.to_le_bytes())
    }

    fn write_count(
        &mut self,
        count: usize,
        maximum: usize,
        label: &'static str,
    ) -> Result<(), PrecomputedIndexError> {
        if count > maximum {
            return Err(PrecomputedIndexError::InvalidCount(label));
        }
        self.write_u32(count)
    }

    fn write_string(
        &mut self,
        value: &str,
        maximum: usize,
        label: &'static str,
        non_empty: bool,
    ) -> Result<(), PrecomputedIndexError> {
        if (non_empty && value.is_empty()) || value.len() > maximum {
            return Err(PrecomputedIndexError::InvalidValue(label));
        }
        self.write_u32(value.len())?;
        self.write_bytes(value.as_bytes())
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], PrecomputedIndexError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(PrecomputedIndexError::TooLarge)?;
        let taken = self
            .bytes
            .get(self.offset..end)
            .ok_or(PrecomputedIndexError::Truncated)?;
        self.offset = end;
        Ok(taken)
    }

    fn read_u8(&mut self) -> Result<u8, PrecomputedIndexError> {
        Ok(self.take(1)?[0])
    }

    fn read_u32(&mut self) -> Result<u32, PrecomputedIndexError> {
        Ok(u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| PrecomputedIndexError::Truncated)?,
        ))
    }

    fn read_u64(&mut self) -> Result<u64, PrecomputedIndexError> {
        Ok(u64::from_le_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| PrecomputedIndexError::Truncated)?,
        ))
    }

    fn read_count(
        &mut self,
        maximum: usize,
        label: &'static str,
        minimum_encoded_size: usize,
    ) -> Result<usize, PrecomputedIndexError> {
        let raw = self.read_u32()? as usize;
        if raw > maximum
            || (minimum_encoded_size != 0 && raw > self.remaining() / minimum_encoded_size)
        {
            return Err(PrecomputedIndexError::InvalidCount(label));
        }
        Ok(raw)
    }

    fn read_string(
        &mut self,
        maximum: usize,
        label: &'static str,
        non_empty: bool,
    ) -> Result<String, PrecomputedIndexError> {
        let len = self.read_u32()? as usize;
        if len > maximum || (non_empty && len == 0) {
            return Err(PrecomputedIndexError::InvalidValue(label));
        }
        let bytes = self.take(len)?;
        let text = std::str::from_utf8(bytes).map_err(|_| PrecomputedIndexError::InvalidUtf8)?;
        Ok(text.to_owned())
    }
}

fn empirical_to_wire(value: EmpiricalLevel) -> u8 {
    match value {
        EmpiricalLevel::E0 => 0,
        EmpiricalLevel::E1 => 1,
        EmpiricalLevel::E2 => 2,
        EmpiricalLevel::E3 => 3,
        EmpiricalLevel::E4 => 4,
    }
}

fn empirical_from_wire(value: u8) -> Result<EmpiricalLevel, PrecomputedIndexError> {
    match value {
        0 => Ok(EmpiricalLevel::E0),
        1 => Ok(EmpiricalLevel::E1),
        2 => Ok(EmpiricalLevel::E2),
        3 => Ok(EmpiricalLevel::E3),
        4 => Ok(EmpiricalLevel::E4),
        _ => Err(PrecomputedIndexError::InvalidValue("empirical level")),
    }
}

fn normative_to_wire(value: NormativeLevel) -> u8 {
    match value {
        NormativeLevel::N0 => 0,
        NormativeLevel::N1 => 1,
        NormativeLevel::N2 => 2,
        NormativeLevel::N3 => 3,
    }
}

fn normative_from_wire(value: u8) -> Result<NormativeLevel, PrecomputedIndexError> {
    match value {
        0 => Ok(NormativeLevel::N0),
        1 => Ok(NormativeLevel::N1),
        2 => Ok(NormativeLevel::N2),
        3 => Ok(NormativeLevel::N3),
        _ => Err(PrecomputedIndexError::InvalidValue("normative level")),
    }
}

fn materiality_to_wire(value: MaterialityLevel) -> u8 {
    match value {
        MaterialityLevel::M0 => 0,
        MaterialityLevel::M1 => 1,
        MaterialityLevel::M2 => 2,
        MaterialityLevel::M3 => 3,
    }
}

fn materiality_from_wire(value: u8) -> Result<MaterialityLevel, PrecomputedIndexError> {
    match value {
        0 => Ok(MaterialityLevel::M0),
        1 => Ok(MaterialityLevel::M1),
        2 => Ok(MaterialityLevel::M2),
        3 => Ok(MaterialityLevel::M3),
        _ => Err(PrecomputedIndexError::InvalidValue("materiality level")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prism_common::EmpiricalLevel;

    const TEST_HEADER_LEN: usize = 52;

    fn sample_index() -> SearchEngine {
        let mut engine = SearchEngine::new();
        engine.add_claim(
            "ocean acidification",
            EmpiricalLevel::E2,
            &["source://ocean"],
            &["climate"],
        );
        engine.add_claim(
            "quantum entanglement",
            EmpiricalLevel::E3,
            &["source://quantum"],
            &["physics"],
        );
        engine
    }

    fn reseal(bytes: &mut [u8]) {
        let digest = blake3::hash(&bytes[TEST_HEADER_LEN..]);
        bytes[20..52].copy_from_slice(digest.as_bytes());
    }

    fn vector_count_offset(bytes: &[u8]) -> usize {
        let mut cursor = Cursor::new(&bytes[TEST_HEADER_LEN..]);
        let claims = cursor.read_count(MAX_CLAIMS, "claims", 16).unwrap();
        for _ in 0..claims {
            cursor.read_string(MAX_CONTENT_BYTES, "content", true).unwrap();
            let sources = cursor.read_count(MAX_SOURCES_PER_CLAIM, "sources", 4).unwrap();
            for _ in 0..sources {
                cursor.read_string(MAX_SOURCE_BYTES, "source", false).unwrap();
            }
            cursor.read_u8().unwrap();
            cursor.read_u8().unwrap();
            cursor.read_u8().unwrap();
            let tags = cursor.read_count(MAX_TAGS_PER_CLAIM, "tags", 4).unwrap();
            for _ in 0..tags {
                cursor.read_string(MAX_TAG_BYTES, "tag", false).unwrap();
            }
        }
        TEST_HEADER_LEN + cursor.offset
    }

    fn first_word_frequency_offset(bytes: &[u8]) -> usize {
        let mut cursor = Cursor::new(&bytes[TEST_HEADER_LEN..]);
        let claims = cursor.read_count(MAX_CLAIMS, "claims", 16).unwrap();
        for _ in 0..claims {
            cursor.read_string(MAX_CONTENT_BYTES, "content", true).unwrap();
            let sources = cursor.read_count(MAX_SOURCES_PER_CLAIM, "sources", 4).unwrap();
            for _ in 0..sources {
                cursor.read_string(MAX_SOURCE_BYTES, "source", false).unwrap();
            }
            cursor.read_u8().unwrap();
            cursor.read_u8().unwrap();
            cursor.read_u8().unwrap();
            let tags = cursor.read_count(MAX_TAGS_PER_CLAIM, "tags", 4).unwrap();
            for _ in 0..tags {
                cursor.read_string(MAX_TAG_BYTES, "tag", false).unwrap();
            }
        }
        let vectors = cursor.read_count(MAX_CLAIMS, "vectors", BinaryHV::BYTES).unwrap();
        cursor.take(vectors * BinaryHV::BYTES).unwrap();
        let words = cursor.read_count(MAX_WORD_DF_ENTRIES, "words", 13).unwrap();
        assert!(words > 0);
        cursor.read_string(MAX_WORD_BYTES, "word", true).unwrap();
        TEST_HEADER_LEN + cursor.offset
    }

    #[test]
    fn versioned_round_trip_is_deterministic_and_checks_derived_state() {
        let engine = sample_index();
        let bytes = engine.to_precomputed().unwrap();
        let repeated = engine.to_precomputed().unwrap();
        assert_eq!(bytes, repeated);
        let loaded = SearchEngine::try_from_precomputed(&bytes).unwrap();
        assert_eq!(loaded.claim_count(), 2);
        assert_eq!(loaded.vectors.len(), loaded.claims.len());
        assert_eq!(loaded.word_df.get("ocean"), Some(&1));
    }

    #[test]
    fn rejects_legacy_unversioned_bincode_and_malformed_bytes() {
        assert!(matches!(
            SearchEngine::try_from_precomputed(b"not a valid bincode index"),
            Err(PrecomputedIndexError::Truncated)
        ));
        assert!(matches!(
            SearchEngine::try_from_precomputed(&[0_u8; TEST_HEADER_LEN]),
            Err(PrecomputedIndexError::InvalidMagic)
        ));
    }

    #[test]
    fn rejects_unknown_version_and_nonzero_flags() {
        let mut bytes = sample_index().to_precomputed().unwrap();
        bytes[8..10].copy_from_slice(&2_u16.to_le_bytes());
        assert!(matches!(
            SearchEngine::try_from_precomputed(&bytes),
            Err(PrecomputedIndexError::UnsupportedVersion(2))
        ));

        let mut bytes = sample_index().to_precomputed().unwrap();
        bytes[10..12].copy_from_slice(&1_u16.to_le_bytes());
        assert!(matches!(
            SearchEngine::try_from_precomputed(&bytes),
            Err(PrecomputedIndexError::InvalidFlags(1))
        ));
    }

    #[test]
    fn rejects_truncation_oversized_length_prefix_and_corrupt_digest() {
        let bytes = sample_index().to_precomputed().unwrap();
        assert!(matches!(
            SearchEngine::try_from_precomputed(&bytes[..10]),
            Err(PrecomputedIndexError::Truncated)
        ));

        let mut oversized = bytes.clone();
        oversized[12..20].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(
            SearchEngine::try_from_precomputed(&oversized),
            Err(PrecomputedIndexError::TooLarge)
        ));

        let mut corrupt = bytes;
        corrupt[TEST_HEADER_LEN] ^= 0x01;
        assert!(matches!(
            SearchEngine::try_from_precomputed(&corrupt),
            Err(PrecomputedIndexError::DigestMismatch)
        ));
    }

    #[test]
    fn rejects_malicious_content_length_before_copying() {
        let mut bytes = sample_index().to_precomputed().unwrap();
        let offset = TEST_HEADER_LEN + 4;
        bytes[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        reseal(&mut bytes);
        assert!(matches!(
            SearchEngine::try_from_precomputed(&bytes),
            Err(PrecomputedIndexError::InvalidValue("claim content"))
        ));
    }

    #[test]
    fn rejects_excessive_index_terms_before_vector_recomputation() {
        let content = std::iter::repeat("ocean")
            .take(MAX_INDEXED_WORDS_PER_CLAIM + 1)
            .collect::<Vec<_>>()
            .join(" ");
        let engine = SearchEngine {
            claims: vec![ClaimEntry {
                content,
                sources: Vec::new(),
                empirical_level: EmpiricalLevel::E2,
                normative_level: NormativeLevel::N2,
                materiality_level: MaterialityLevel::M2,
                tags: Vec::new(),
            }],
            vectors: vec![BinaryHV([0_u8; BinaryHV::BYTES])],
            word_df: HashMap::new(),
        };

        assert_eq!(
            validate_derived_state(&engine),
            Err(PrecomputedIndexError::InvalidValue("claim indexed word count"))
        );
        assert_eq!(
            engine.to_precomputed(),
            Err(PrecomputedIndexError::InvalidValue("claim indexed word count"))
        );
    }

    #[test]
    fn rejects_excessive_aggregate_index_terms_before_vector_recomputation() {
        // Every claim is individually under the 2,048-word limit, but the
        // aggregate exceeds the work budget. No stored vector is trusted and
        // expensive vector recomputation must not begin.
        let content = std::iter::repeat("ocean")
            .take(2_000)
            .collect::<Vec<_>>()
            .join(" ");
        let claim_count = MAX_TOTAL_INDEXED_WORDS / 2_000 + 1;
        let engine = SearchEngine {
            claims: (0..claim_count)
                .map(|_| ClaimEntry {
                    content: content.clone(),
                    sources: Vec::new(),
                    empirical_level: EmpiricalLevel::E2,
                    normative_level: NormativeLevel::N2,
                    materiality_level: MaterialityLevel::M2,
                    tags: Vec::new(),
                })
                .collect(),
            vectors: vec![BinaryHV([0_u8; BinaryHV::BYTES]); claim_count],
            word_df: HashMap::from([("ocean".to_string(), claim_count)]),
        };

        assert_eq!(
            engine.to_precomputed(),
            Err(PrecomputedIndexError::InvalidCount("total indexed words"))
        );
    }

    #[test]
    fn rejects_malicious_declared_claim_count_before_allocating() {
        let mut bytes = sample_index().to_precomputed().unwrap();
        bytes[TEST_HEADER_LEN..TEST_HEADER_LEN + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        reseal(&mut bytes);
        assert!(matches!(
            SearchEngine::try_from_precomputed(&bytes),
            Err(PrecomputedIndexError::InvalidCount("claims"))
        ));
    }

    #[test]
    fn rejects_mismatched_vector_count() {
        let mut bytes = sample_index().to_precomputed().unwrap();
        let offset = vector_count_offset(&bytes);
        bytes[offset..offset + 4].copy_from_slice(&1_u32.to_le_bytes());
        reseal(&mut bytes);
        assert!(matches!(
            SearchEngine::try_from_precomputed(&bytes),
            Err(PrecomputedIndexError::InconsistentClaimVectorCount)
        ));
    }

    #[test]
    fn rejects_inconsistent_vectors_even_with_valid_digest() {
        let mut bytes = sample_index().to_precomputed().unwrap();
        let offset = vector_count_offset(&bytes);
        let vectors_len =
            u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        let first_vector = offset + 4;
        assert!(vectors_len > 0);
        bytes[first_vector] ^= 1;
        reseal(&mut bytes);
        assert!(matches!(
            SearchEngine::try_from_precomputed(&bytes),
            Err(PrecomputedIndexError::InconsistentVectors)
        ));
    }

    #[test]
    fn rejects_stale_word_frequencies_even_with_valid_digest() {
        let mut bytes = sample_index().to_precomputed().unwrap();
        let offset = first_word_frequency_offset(&bytes);
        let existing = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        let replacement = if existing == 1 { 2_u64 } else { 1_u64 };
        bytes[offset..offset + 8].copy_from_slice(&replacement.to_le_bytes());
        reseal(&mut bytes);
        assert!(matches!(
            SearchEngine::try_from_precomputed(&bytes),
            Err(PrecomputedIndexError::InconsistentWordFrequencies)
        ));
    }
    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(128))]

        #[test]
        fn payload_byte_mutations_never_panic(
            offset_seed in proptest::prelude::any::<usize>(),
            replacement in proptest::prelude::any::<u8>(),
        ) {
            let mut bytes = sample_index().to_precomputed().unwrap();
            let payload_len = bytes.len() - TEST_HEADER_LEN;
            let offset = TEST_HEADER_LEN + (offset_seed % payload_len);
            bytes[offset] = replacement;
            reseal(&mut bytes);

            let result = std::panic::catch_unwind(|| SearchEngine::try_from_precomputed(&bytes));
            proptest::prop_assert!(result.is_ok());
        }
    }
}
