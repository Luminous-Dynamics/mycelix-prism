// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Epistemic knowledge search engine for Prism.
//!
//! Uses Symthaea's 16,384-bit BinaryHV for semantic encoding and
//! batch similarity search over a pre-seeded claim index.
//!
//! Encoding: word-level random indexing (each word → deterministic BinaryHV,
//! bound with position vector, bundled into document vector).

// HDC byte-level operations use explicit indexing for clarity and performance.
#![allow(clippy::needless_range_loop)]

use prism_common::{EmpiricalLevel, MaterialityLevel, NormativeLevel, SearchResult};
use serde::{Deserialize, Serialize};

pub mod binary_hv;
use binary_hv::BinaryHV;

/// Epistemic knowledge search engine.
#[derive(Serialize, Deserialize)]
pub struct SearchEngine {
    claims: Vec<ClaimEntry>,
    vectors: Vec<BinaryHV>,
    /// Word → document frequency (how many claims contain this word).
    word_df: std::collections::HashMap<String, usize>,
}

#[derive(Serialize, Deserialize)]
struct ClaimEntry {
    content: String,
    sources: Vec<String>,
    empirical_level: EmpiricalLevel,
    normative_level: NormativeLevel,
    materiality_level: MaterialityLevel,
    tags: Vec<String>,
}

impl SearchEngine {
    /// Create an empty search engine.
    pub fn new() -> Self {
        Self {
            claims: Vec::new(),
            vectors: Vec::new(),
            word_df: std::collections::HashMap::new(),
        }
    }

    /// Load a pre-computed index from bytes (bincode format).
    /// Falls back to an empty engine if deserialization fails.
    pub fn from_precomputed(bytes: &[u8]) -> Self {
        match bincode::deserialize(bytes) {
            Ok(engine) => engine,
            Err(e) => {
                log::error!("Failed to deserialize precomputed index: {}", e);
                Self::new()
            }
        }
    }

    /// Create a search engine pre-loaded with claims from prism-ingest.
    ///
    /// If the `precomputed-index` feature is enabled and `prism-index.bin` exists,
    /// deserializes the pre-built index instead of computing from scratch.
    pub fn with_seed_claims() -> Self {
        #[cfg(feature = "precomputed-index")]
        {
            let bytes = include_bytes!("../prism-index.bin");
            log::info!("Loading precomputed index ({} bytes)", bytes.len());
            return Self::from_precomputed(bytes);
        }

        #[cfg(not(feature = "precomputed-index"))]
        Self::with_seed_claims_compute()
    }

    /// Compute the search index from scratch (used when no precomputed index is available).
    fn with_seed_claims_compute() -> Self {
        let mut engine = Self::new();
        let all_claims = prism_ingest::load_all_claims();

        // Build document frequency map
        for claim in &all_claims {
            let lowered = claim.content.to_lowercase();
            let words: std::collections::HashSet<&str> = lowered
                .split(|c: char| !c.is_alphanumeric())
                .filter(|w| w.len() >= 2 && !is_stop_word(w))
                .collect();
            for word in words {
                *engine.word_df.entry(word.to_string()).or_insert(0) += 1;
            }
        }

        // Encode with IDF weighting
        let n_docs = all_claims.len() as f32;
        for claim in &all_claims {
            let hv = encode_text_idf(&claim.content, &engine.word_df, n_docs);
            engine.claims.push(ClaimEntry {
                content: claim.content.clone(),
                sources: claim.sources.clone(),
                empirical_level: claim.empirical_level,
                normative_level: claim.normative_level,
                materiality_level: claim.materiality_level,
                tags: claim.tags.clone(),
            });
            engine.vectors.push(hv);
        }

        log::info!("Search engine loaded {} claims", engine.claims.len());
        engine
    }

    /// Build index from curated + pipeline + mycelix claims (no Wikidata).
    /// Produces the core index suitable for mobile loading.
    pub fn with_core_claims() -> Self {
        let mut engine = Self::new();
        let mut all_claims = Vec::new();
        all_claims.extend(prism_ingest::curated_claims());
        all_claims.extend(prism_ingest::pipeline_claims());
        all_claims.extend(prism_ingest::mycelix_claims());

        for claim in &all_claims {
            let lowered = claim.content.to_lowercase();
            let words: std::collections::HashSet<&str> = lowered
                .split(|c: char| !c.is_alphanumeric())
                .filter(|w| w.len() >= 2 && !is_stop_word(w))
                .collect();
            for word in words {
                *engine.word_df.entry(word.to_string()).or_insert(0) += 1;
            }
        }

        let n_docs = all_claims.len() as f32;
        for claim in all_claims {
            let hv = encode_text_idf(&claim.content, &engine.word_df, n_docs);
            engine.claims.push(ClaimEntry {
                content: claim.content,
                sources: claim.sources,
                empirical_level: claim.empirical_level,
                normative_level: claim.normative_level,
                materiality_level: claim.materiality_level,
                tags: claim.tags,
            });
            engine.vectors.push(hv);
        }

        log::info!("Core index loaded {} claims", engine.claims.len());
        engine
    }

    /// Merge another engine's claims into this one (for lazy-loading).
    pub fn merge(&mut self, other: Self) {
        // Claim identity must not be inferred from a truncated prefix: two
        // distinct claims can share the same first 80 characters. Normalize
        // case and whitespace, then compare the full content.
        let mut content_keys: std::collections::HashSet<String> = self
            .claims
            .iter()
            .map(|claim| normalize_claim_content(&claim.content))
            .collect();

        for claim in other.claims {
            let key = normalize_claim_content(&claim.content);
            if content_keys.insert(key) {
                self.claims.push(claim);
            }
        }

        // Recompute corpus statistics and every vector together. Merging vectors
        // encoded against different IDF statistics would make similarity scores
        // incomparable and leave query encoding inconsistent with document vectors.
        self.rebuild_index();
    }

    /// Rebuild corpus statistics and document vectors as one consistent snapshot.
    ///
    /// IDF depends on the entire indexed corpus. Any mutation that changes the
    /// corpus must therefore update both the word frequencies and all document vectors.
    fn rebuild_index(&mut self) {
        let mut word_df = std::collections::HashMap::new();

        for claim in &self.claims {
            let lowered = claim.content.to_lowercase();
            let words: std::collections::HashSet<&str> = lowered
                .split(|c: char| !c.is_alphanumeric())
                .filter(|w| w.len() >= 2 && !is_stop_word(w))
                .collect();

            for word in words {
                *word_df.entry(word.to_string()).or_insert(0) += 1;
            }
        }

        let n_docs = self.claims.len() as f32;
        let vectors = self
            .claims
            .iter()
            .map(|claim| encode_text_idf(&claim.content, &word_df, n_docs))
            .collect();

        self.word_df = word_df;
        self.vectors = vectors;
    }

    /// Add a claim to the index.
    pub fn add_claim(
        &mut self,
        content: &str,
        empirical_level: EmpiricalLevel,
        sources: &[&str],
        tags: &[&str],
    ) {
        self.add_claims(std::iter::once((
            content.to_string(),
            empirical_level,
            sources.iter().map(|s| s.to_string()).collect(),
            tags.iter().map(|s| s.to_string()).collect(),
        )));
    }

    /// Add a batch of claims and rebuild shared IDF statistics only once.
    ///
    /// Prefer this method when importing many claims: a corpus-dependent IDF
    /// snapshot requires rebuilding all document vectors after a mutation, so
    /// batching avoids an O(n) rebuild for every item in a large import.
    pub fn add_claims<I>(&mut self, claims: I)
    where
        I: IntoIterator<Item = (String, EmpiricalLevel, Vec<String>, Vec<String>)>,
    {
        for (content, empirical_level, sources, tags) in claims {
            self.claims.push(ClaimEntry {
                content,
                sources,
                empirical_level,
                normative_level: NormativeLevel::N2, // Default for dynamic adds
                materiality_level: MaterialityLevel::M2,
                tags,
            });
        }
        self.rebuild_index();
    }

    /// Search for claims matching a query. Returns top-k results ranked by composite score.
    ///
    /// Uses a two-pass LSH approach for speed:
    /// 1. Locality-sensitive hashing: partition the 2048-byte vector into 32 bands
    ///    of 64 bytes each. Hash each band. Candidates share at least one band hash.
    /// 2. Exact Hamming similarity only on LSH candidates.
    pub fn search(&self, query: &str, top_k: usize) -> Vec<SearchResult> {
        let top_k = top_k.min(100);
        if self.vectors.is_empty() || query.trim().is_empty() {
            return Vec::new();
        }

        let query_hv = if self.word_df.is_empty() {
            encode_text(query)
        } else {
            encode_text_idf(query, &self.word_df, self.claims.len() as f32)
        };

        // Correctness-first exhaustive retrieval: score every indexed claim.
        //
        // The previous prefilter XORed three sampled bytes and counted bit matches.
        // For near-random binary hypervectors, XOR parity largely destroys the
        // modest similarity signal the index is meant to preserve. Its 128/512
        // threshold was also below the 256/512 random expectation, so it was not
        // a defensible locality-sensitive hash and could not justify a recall claim.
        // Keep the exhaustive scan until a real LSH/ANN implementation is backed
        // by a pinned relevance set, measured recall@k, and latency benchmarks.
        let candidates: Vec<usize> = (0..self.vectors.len()).collect();

        // Exact similarity on candidates only
        let baseline = 0.50_f32; // True baseline for 16,384-bit BinaryHV
        let mut scored: Vec<(usize, f32)> = candidates
            .iter()
            .map(|&i| {
                let sim = query_hv.similarity(&self.vectors[i]);
                let claim = &self.claims[i];
                let epistemic = claim.empirical_level.as_f32();
                let norm_sim = ((sim - baseline) / (1.0 - baseline)).clamp(0.0, 1.0);
                // Keep ordering identical to SearchResult::rank_score(), which is
                // also the score exposed to callers and rendered in the UI.
                let freshness = 1.0 / (1.0 + 1.0 / 365.0);
                let composite =
                    0.4 * norm_sim + 0.3 * epistemic + 0.2 * 0.9 + 0.1 * freshness;
                (i, composite)
            })
            .collect();

        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(top_k);

        scored
            .into_iter()
            .map(|(i, _)| {
                let claim = &self.claims[i];
                let sim = query_hv.similarity(&self.vectors[i]);
                let norm_sim = ((sim - baseline) / (1.0 - baseline)).clamp(0.0, 1.0);
                SearchResult {
                    content: claim.content.clone(),
                    sources: claim.sources.clone(),
                    empirical_level: claim.empirical_level,
                    normative_level: claim.normative_level,
                    materiality_level: claim.materiality_level,
                    query_similarity: norm_sim,
                    author_reputation: 0.9,
                    age_days: 1,
                    tags: claim.tags.clone(),
                }
            })
            .collect()
    }

    /// Number of indexed claims.
    pub fn claim_count(&self) -> usize {
        self.claims.len()
    }
}

impl Default for SearchEngine {
    fn default() -> Self {
        Self::with_seed_claims()
    }
}

/// Encode text with IDF weighting (used for indexing claims when corpus stats available).
fn encode_text_idf(
    text: &str,
    word_df: &std::collections::HashMap<String, usize>,
    n_docs: f32,
) -> BinaryHV {
    let lowered = text.to_lowercase();
    let words: Vec<&str> = lowered
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() >= 2 && !is_stop_word(w))
        .collect();

    if words.is_empty() {
        return BinaryHV::random(0);
    }

    // Weight each word by its IDF (rare words matter more)
    let mut hvs: Vec<BinaryHV> = Vec::new();
    let mut weights: Vec<f32> = Vec::new();

    for word in &words {
        let df = *word_df.get(*word).unwrap_or(&1) as f32;
        let idf = (n_docs / df).ln().max(0.1); // log(N/df), floor at 0.1
        hvs.push(BinaryHV::random(hash_word(word)));
        weights.push(idf);
    }

    // Bigrams (high IDF — very specific)
    for pair in words.windows(2) {
        let bigram_seed = hash_word(pair[0])
            .wrapping_mul(31)
            .wrapping_add(hash_word(pair[1]));
        hvs.push(BinaryHV::random(bigram_seed));
        weights.push(3.0); // Bigrams get high weight
    }

    if hvs.is_empty() {
        BinaryHV::random(0)
    } else {
        BinaryHV::weighted_bundle(&hvs, &weights)
    }
}

/// Encode text to a 16,384-bit BinaryHV using improved word-level random indexing.
///
/// Improvements over naive encoding:
/// 1. Stop word filtering (removes noise from common words)
/// 2. Bigram encoding (adjacent word pairs for phrase matching)
/// 3. No position binding for short queries (reduces noise)
/// 4. Content words weighted higher than function words
pub fn encode_text(text: &str) -> BinaryHV {
    let lowered = text.to_lowercase();
    let words: Vec<&str> = lowered
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() >= 2 && !is_stop_word(w))
        .collect();

    if words.is_empty() {
        return BinaryHV::random(0);
    }

    let mut hvs: Vec<BinaryHV> = Vec::with_capacity(words.len() * 2);

    // Unigrams (individual content words)
    for word in &words {
        hvs.push(BinaryHV::random(hash_word(word)));
    }

    // Bigrams (adjacent word pairs — captures "ocean acidification", "quantum physics")
    for pair in words.windows(2) {
        let bigram_seed = hash_word(pair[0])
            .wrapping_mul(31)
            .wrapping_add(hash_word(pair[1]));
        hvs.push(BinaryHV::random(bigram_seed));
    }

    BinaryHV::bundle(&hvs)
}

/// Common English stop words that add noise to semantic encoding.
fn is_stop_word(word: &str) -> bool {
    matches!(
        word,
        "the"
            | "is"
            | "are"
            | "was"
            | "were"
            | "be"
            | "been"
            | "being"
            | "have"
            | "has"
            | "had"
            | "do"
            | "does"
            | "did"
            | "will"
            | "would"
            | "could"
            | "should"
            | "may"
            | "might"
            | "shall"
            | "can"
            | "need"
            | "must"
            | "am"
            | "it"
            | "its"
            | "in"
            | "on"
            | "at"
            | "to"
            | "for"
            | "of"
            | "with"
            | "by"
            | "from"
            | "as"
            | "into"
            | "about"
            | "an"
            | "and"
            | "or"
            | "but"
            | "not"
            | "no"
            | "nor"
            | "so"
            | "if"
            | "than"
            | "too"
            | "very"
            | "just"
            | "that"
            | "this"
            | "these"
            | "those"
            | "what"
            | "which"
            | "who"
            | "whom"
            | "how"
            | "when"
            | "where"
            | "why"
            | "all"
            | "each"
            | "every"
            | "both"
            | "few"
            | "more"
            | "most"
            | "other"
            | "some"
            | "such"
            | "only"
            | "then"
    )
}

/// Normalize content for conservative duplicate detection.
fn normalize_claim_content(content: &str) -> String {
    content
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// Deterministic hash of a word to a u64 seed for BinaryHV::random().
fn hash_word(word: &str) -> u64 {
    // FNV-1a hash
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in word.bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Escape dynamic text before embedding it in a generated HTML document.
///
/// Search claims can come from imported corpora, DHT peers, or user submissions.
/// They are data, not markup, even though the native shell renders its local
/// results by parsing an HTML document. Keeping this helper in the search crate
/// makes the invariant apply to every caller rather than relying on a later UI
/// sanitizer.
pub fn escape_html_text(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for character in input.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

/// Generate a data-only HTML view of search results.
pub fn render_search_results_html(query: &str, results: &[SearchResult]) -> String {
    let mut results_html = String::new();

    if results.is_empty() {
        results_html.push_str("<p>No results found. Try different keywords.</p>");
    } else {
        for (i, result) in results.iter().enumerate() {
            let e_badge = match result.empirical_level {
                EmpiricalLevel::E0 => "E0 Unverified",
                EmpiricalLevel::E1 => "E1 Preliminary",
                EmpiricalLevel::E2 => "E2 Tested",
                EmpiricalLevel::E3 => "E3 Replicated",
                EmpiricalLevel::E4 => "E4 Established",
            };
            let score_pct = (result.rank_score() * 100.0) as u32;
            let source = result.sources.first().map(String::as_str).unwrap_or("—");
            let tags = result.tags.join(", ");

            results_html.push_str(&format!(
                "<p><strong>{}. [{}] ({}%)</strong> {}</p>\n<p>Source: {} | Tags: {}</p>\n",
                i + 1,
                e_badge,
                score_pct,
                escape_html_text(&result.content),
                escape_html_text(source),
                escape_html_text(&tags),
            ));
        }
    }

    let query = escape_html_text(query);
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Search: {query}</title></head>
<body>
    <h1>Prism Search</h1>
    <h2>Results for &quot;{query}&quot;</h2>
    <p>{count} results returned</p>
    <hr>
    {results_html}
</body>
</html>"#,
        query = query,
        count = results.len(),
        results_html = results_html,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_text_escaping_covers_markup_and_attributes() {
        assert_eq!(
            escape_html_text(r#"<img src=x onerror="boom"> & 'quoted'"#),
            "&lt;img src=x onerror=&quot;boom&quot;&gt; &amp; &#39;quoted&#39;"
        );
    }

    #[test]
    fn generated_results_treat_claims_and_queries_as_data() {
        let mut engine = SearchEngine::new();
        engine.add_claim(
            r#"<script>claim()</script>"#,
            EmpiricalLevel::E1,
            &[r#"<img src=x onerror=source()>"#],
            &[r#"</p><script>tag()</script>"#],
        );
        let result = engine.search("claim", 1);
        let html = render_search_results_html(r#"</h2><script>query()</script>"#, &result);

        assert!(!html.contains("<script>"));
        assert!(!html.contains("<img"));
        assert!(html.contains("&lt;script&gt;claim()&lt;/script&gt;"));
        assert!(html.contains("&lt;/h2&gt;&lt;script&gt;query()&lt;/script&gt;"));
    }

    #[test]
    fn encode_deterministic() {
        let hv1 = encode_text("hello world");
        let hv2 = encode_text("hello world");
        assert!(
            hv1.similarity(&hv2) > 0.99,
            "Same text should produce identical vectors"
        );
    }

    #[test]
    fn encode_similar_texts_correlate() {
        let hv1 = encode_text("ocean acidification causes");
        let hv2 = encode_text("what causes ocean acidification");
        let sim = hv1.similarity(&hv2);
        assert!(
            sim > 0.3,
            "Similar texts should have similarity > 0.3, got {}",
            sim
        );
    }

    #[test]
    fn encode_different_texts_diverge() {
        let hv1 = encode_text("quantum physics experiments");
        let hv2 = encode_text("chocolate cake recipe");
        let sim = hv1.similarity(&hv2);
        assert!(
            sim < 0.6,
            "Unrelated texts should have low similarity, got {}",
            sim
        );
    }

    #[test]
    fn search_returns_relevant_results() {
        let engine = SearchEngine::with_seed_claims();
        let results = engine.search("ocean acidification", 5);
        assert!(
            !results.is_empty(),
            "Should find results for ocean acidification"
        );
        // Top result should mention ocean or CO2
        let top = &results[0];
        let content_lower = top.content.to_lowercase();
        assert!(
            content_lower.contains("ocean")
                || content_lower.contains("co2")
                || content_lower.contains("acid"),
            "Top result should be relevant: {}",
            top.content
        );
    }

    #[test]
    fn exact_scan_ranks_matching_claim_after_more_than_200_documents() {
        let mut engine = SearchEngine::new();
        for i in 0..250 {
            engine.add_claim(
                &format!("unrelated gardening topic number {i}"),
                EmpiricalLevel::E1,
                &[],
                &[],
            );
        }

        let target = "quantum entanglement preserves phase coherence in a controlled experiment";
        engine.add_claim(target, EmpiricalLevel::E3, &["https://example.test/quantum"], &[]);

        let results = engine.search(target, 5);
        assert!(!results.is_empty());
        assert_eq!(results[0].content, target);
    }

    #[test]
    fn search_empty_query_returns_empty() {
        let engine = SearchEngine::with_seed_claims();
        assert!(engine.search("", 5).is_empty());
        assert!(engine.search("   ", 5).is_empty());
    }

    #[test]
    fn search_results_are_ranked() {
        let engine = SearchEngine::with_seed_claims();
        let results = engine.search("programming language memory safety", 10);
        if results.len() >= 2 {
            assert!(
                results[0].rank_score() >= results[1].rank_score(),
                "Results should be ranked by score"
            );
        }
    }

    #[test]
    fn seed_claims_loaded() {
        let engine = SearchEngine::with_seed_claims();
        assert!(
            engine.claim_count() >= 50,
            "Should have at least 50 seed claims, got {}",
            engine.claim_count()
        );
    }

    #[test]
    fn add_claim_rebuilds_document_frequencies_and_vectors() {
        let mut engine = SearchEngine::new();
        engine.add_claim(
            "sharedterm ocean",
            EmpiricalLevel::E1,
            &["https://example.test/ocean"],
            &[],
        );
        engine.add_claim(
            "sharedterm climate",
            EmpiricalLevel::E2,
            &["https://example.test/climate"],
            &[],
        );

        assert_eq!(engine.claim_count(), 2);
        assert_eq!(engine.word_df.get("sharedterm"), Some(&2));
        assert_eq!(engine.vectors.len(), engine.claims.len());
        assert!(!engine.search("climate", 2).is_empty());
    }

    #[test]
    fn merge_does_not_drop_distinct_claims_with_shared_prefixes() {
        let shared_prefix = "this claim deliberately shares a long common prefix ".repeat(3);
        let first = format!("{shared_prefix}alpha");
        let second = format!("{shared_prefix}beta");

        let mut left = SearchEngine::new();
        left.add_claim(&first, EmpiricalLevel::E1, &[], &[]);
        let mut right = SearchEngine::new();
        right.add_claim(&second, EmpiricalLevel::E2, &[], &[]);

        left.merge(right);

        assert_eq!(left.claim_count(), 2);
        assert!(left.claims.iter().any(|claim| claim.content == first));
        assert!(left.claims.iter().any(|claim| claim.content == second));
    }

    #[test]
    fn batch_add_rebuilds_one_consistent_index_snapshot() {
        let mut engine = SearchEngine::new();
        engine.add_claims(vec![
            (
                "sharedterm ocean".to_string(),
                EmpiricalLevel::E1,
                Vec::new(),
                Vec::new(),
            ),
            (
                "sharedterm climate".to_string(),
                EmpiricalLevel::E2,
                Vec::new(),
                Vec::new(),
            ),
        ]);

        assert_eq!(engine.claim_count(), 2);
        assert_eq!(engine.word_df.get("sharedterm"), Some(&2));
        assert_eq!(engine.vectors.len(), engine.claims.len());
        assert!(!engine.search("climate", 2).is_empty());
    }

    #[test]
    fn merge_rebuilds_document_frequencies_and_vectors() {
        let mut left = SearchEngine::new();
        left.add_claim("sharedterm ocean", EmpiricalLevel::E1, &[], &[]);

        let mut right = SearchEngine::new();
        right.add_claim("sharedterm climate", EmpiricalLevel::E2, &[], &[]);

        left.merge(right);

        assert_eq!(left.claim_count(), 2);
        assert_eq!(left.word_df.get("sharedterm"), Some(&2));
        assert_eq!(left.vectors.len(), left.claims.len());
        assert!(!left.search("climate", 2).is_empty());
    }

    #[test]
    fn render_results_html_valid() {
        let engine = SearchEngine::with_seed_claims();
        let results = engine.search("rust programming", 3);
        let html = render_search_results_html("rust programming", &results);
        assert!(html.contains("Prism Search"));
        assert!(html.contains("rust programming"));
        assert!(html.contains("results returned"));
        assert!(!html.contains("seed indexed claims"));
    }
}
