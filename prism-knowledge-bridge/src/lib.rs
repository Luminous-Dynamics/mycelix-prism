// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bidirectional bridge between Prism HDC search and Knowledge DHT.
//!
//! Search chain: Local HDC → Knowledge DHT → (future: Wikidata)
//! Publish chain: Prism claim → Knowledge DHT (via holochain.rs)
//!
//! This crate provides the DHT query functions that the Prism search
//! engine can use as a fallback when local results are insufficient.

use prism_common::SearchResult;
#[cfg(feature = "dht")]
use prism_common::{EmpiricalLevel, MaterialityLevel, NormativeLevel};

#[cfg(feature = "dht")]
const CONDUCTOR_URL: &str = "ws://localhost:8888";
#[cfg(feature = "dht")]
const APP_ID: &str = "mycelix-knowledge";
const MIN_LOCAL_RESULTS: usize = 3;

/// Query the Knowledge DHT for claims matching a tag or keyword.
///
/// Returns DHT-sourced claims with similarity, reputation, and age left unknown
/// until those properties are actually measured or verified.
#[cfg(feature = "dht")]
pub async fn query_dht_claims(tag: &str) -> Vec<SearchResult> {
    let transport = mycelix_leptos_client::BrowserWsTransport::new();
    let client = mycelix_leptos_client::HolochainClient::new(transport, APP_ID, "knowledge");

    if client.connect(CONDUCTOR_URL, None).await.is_err() {
        log::info!("[KnowledgeBridge] Conductor not available for DHT search");
        return vec![];
    }

    // Query claims by tag
    let records: Vec<serde_json::Value> = match client
        .call_zome("claims", "get_claims_by_tag", &tag.to_string())
        .await
    {
        Ok(r) => r,
        Err(e) => {
            log::info!("[KnowledgeBridge] DHT query failed: {e}");
            return vec![];
        }
    };

    // Convert Records to SearchResults
    records
        .iter()
        .filter_map(|record| {
            let entry = record.get("entry")?.get("Present")?;
            let content = entry.get("content")?.as_str()?;
            let sources: Vec<String> = entry
                .get("sources")
                .and_then(|s| serde_json::from_value(s.clone()).ok())
                .unwrap_or_default();
            let tags: Vec<String> = entry
                .get("tags")
                .and_then(|t| serde_json::from_value(t.clone()).ok())
                .unwrap_or_default();

            // Parse epistemic classification
            let classification = entry.get("classification")?;
            let e_val = classification.get("empirical")?.as_f64().unwrap_or(0.0) as f32;
            let n_val = classification.get("normative")?.as_f64().unwrap_or(0.5) as f32;
            let m_val = classification
                .get("mythic")
                .or_else(|| classification.get("materiality"))?
                .as_f64()
                .unwrap_or(0.5) as f32;

            Some(SearchResult {
                content: content.to_string(),
                sources,
                empirical_level: EmpiricalLevel::from_f32(e_val),
                normative_level: if n_val >= 0.75 {
                    NormativeLevel::N3
                } else if n_val >= 0.5 {
                    NormativeLevel::N2
                } else if n_val >= 0.25 {
                    NormativeLevel::N1
                } else {
                    NormativeLevel::N0
                },
                materiality_level: if m_val >= 0.75 {
                    MaterialityLevel::M3
                } else if m_val >= 0.5 {
                    MaterialityLevel::M2
                } else if m_val >= 0.25 {
                    MaterialityLevel::M1
                } else {
                    MaterialityLevel::M0
                },
                query_similarity: None, // Similarity has not been computed locally.
                author_reputation: None, // DHT availability alone is not reputation evidence.
                age_days: None, // Source creation/retrieval timestamp is not verified here.
                tags,
            })
        })
        .collect()
}

/// Portable fallback when browser Holochain transport is not enabled.
#[cfg(not(feature = "dht"))]
pub async fn query_dht_claims(_tag: &str) -> Vec<SearchResult> {
    Vec::new()
}

/// Unified search: local HDC results + DHT fallback.
///
/// If local results are fewer than MIN_LOCAL_RESULTS, queries the DHT
/// for additional claims and merges them by normalized full content.
pub async fn unified_search(local_results: Vec<SearchResult>, query: &str) -> Vec<SearchResult> {
    if local_results.len() >= MIN_LOCAL_RESULTS {
        return local_results;
    }

    log::info!(
        "[KnowledgeBridge] Local results ({}) below threshold ({}), querying DHT...",
        local_results.len(),
        MIN_LOCAL_RESULTS
    );

    // Use the first tag from the query as DHT search key
    let dht_results = query_dht_claims(query).await;

    if dht_results.is_empty() {
        return local_results;
    }

    log::info!(
        "[KnowledgeBridge] DHT returned {} additional claims",
        dht_results.len()
    );

    merge_unique_results(local_results, dht_results)
}

/// Merge DHT claims without pretending that unmeasured relevance is a comparable score.
///
/// Local results are already ordered by measured query similarity using the local
/// corpus's IDF statistics. DHT results currently have no computed query similarity,
/// so their normalized composite scores are not comparable to the local scores.
/// Preserve the local ranking, deduplicate by full normalized content, then rank the
/// DHT-only tier by evidence level and deterministic content order until both sources
/// share a calibrated scoring contract.
fn merge_unique_results(
    mut local_results: Vec<SearchResult>,
    dht_results: Vec<SearchResult>,
) -> Vec<SearchResult> {
    let mut seen: std::collections::HashSet<String> = local_results
        .iter()
        .map(|result| normalize_claim_content(&result.content))
        .collect();
    let mut unique_dht = Vec::with_capacity(dht_results.len());

    for result in dht_results {
        if seen.insert(normalize_claim_content(&result.content)) {
            unique_dht.push(result);
        }
    }

    // DHT's similarity/reputation/age are unknown today. Rank this tier only by
    // the explicit evidence classification, never by mixing partial scores.
    unique_dht.sort_by(|a, b| {
        b.empirical_level
            .as_f32()
            .partial_cmp(&a.empirical_level.as_f32())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.content.cmp(&b.content))
    });

    local_results.extend(unique_dht);
    local_results
}

/// Normalize whitespace and case while preserving the full claim.
fn normalize_claim_content(content: &str) -> String {
    content
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use prism_common::{EmpiricalLevel, MaterialityLevel, NormativeLevel};

    fn result(content: &str) -> SearchResult {
        SearchResult {
            content: content.to_string(),
            sources: Vec::new(),
            empirical_level: EmpiricalLevel::E2,
            normative_level: NormativeLevel::N2,
            materiality_level: MaterialityLevel::M2,
            query_similarity: Some(0.5),
            author_reputation: None,
            age_days: None,
            tags: Vec::new(),
        }
    }

    fn dht_result(content: &str) -> SearchResult {
        let mut result = result(content);
        result.query_similarity = None;
        result
    }

    #[test]
    fn fallback_does_not_compare_unknown_dht_relevance_to_local_similarity() {
        let local = result("local result with measured similarity");
        let mut dht = dht_result("remote result with unknown similarity");
        dht.empirical_level = EmpiricalLevel::E4;

        // The rank_score values are not semantically comparable because the
        // local result has a measured similarity component but the DHT result does not.
        assert!(dht.rank_score() > local.rank_score());

        let merged = merge_unique_results(vec![local], vec![dht]);
        assert_eq!(merged[0].content, "local result with measured similarity");
        assert_eq!(merged[0].query_similarity, Some(0.5));
        assert_eq!(merged[1].content, "remote result with unknown similarity");
        assert_eq!(merged[1].query_similarity, None);
    }

    #[test]
    fn dht_tier_order_is_deterministic_for_tied_evidence_levels() {
        let forward = merge_unique_results(
            Vec::new(),
            vec![dht_result("zeta claim"), dht_result("alpha claim"), dht_result("beta claim")],
        );
        let reverse = merge_unique_results(
            Vec::new(),
            vec![dht_result("beta claim"), dht_result("alpha claim"), dht_result("zeta claim")],
        );

        let forward_contents = forward
            .iter()
            .map(|item| item.content.as_str())
            .collect::<Vec<_>>();
        let reverse_contents = reverse
            .iter()
            .map(|item| item.content.as_str())
            .collect::<Vec<_>>();
        assert_eq!(forward_contents, reverse_contents);
        assert_eq!(forward_contents, vec!["alpha claim", "beta claim", "zeta claim"]);
    }

    #[test]
    fn merge_uses_full_normalized_content_and_deduplicates_incoming_batch() {
        let shared_prefix = "this claim has a shared introduction that is intentionally longer than fifty characters ".repeat(2);
        let first = format!("{shared_prefix}alpha");
        let second = format!("{shared_prefix}beta");
        let first_with_different_case_and_spacing = first.to_uppercase().replace(' ', "   ");

        let merged = merge_unique_results(
            vec![result(&first)],
            vec![
                dht_result(&second),
                dht_result(&first_with_different_case_and_spacing),
                dht_result(&second),
            ],
        );

        assert_eq!(merged.len(), 2);
        assert!(merged.iter().any(|claim| claim.content == first));
        assert!(merged.iter().any(|claim| claim.content == second));
    }
}
