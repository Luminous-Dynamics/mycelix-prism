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

/// Merge claims using their full normalized text as identity.
///
/// A prefix is not a sound identity: distinct claims can share arbitrarily long
/// introductions. Updating the seen-set after insertion also prevents duplicate
/// items within the incoming DHT batch from being appended more than once.
fn merge_unique_results(
    mut merged: Vec<SearchResult>,
    dht_results: Vec<SearchResult>,
) -> Vec<SearchResult> {
    let mut seen: std::collections::HashSet<String> = merged
        .iter()
        .map(|result| normalize_claim_content(&result.content))
        .collect();

    for result in dht_results {
        if seen.insert(normalize_claim_content(&result.content)) {
            merged.push(result);
        }
    }

    // Re-rank by composite score, with a content tie-break so equal-score
    // results do not inherit arbitrary DHT arrival order.
    merged.sort_by(|a, b| {
        b.rank_score()
            .partial_cmp(&a.rank_score())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.content.cmp(&b.content))
    });
    merged
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

    #[test]
    fn equal_score_results_have_deterministic_content_order() {
        let forward = merge_unique_results(
            Vec::new(),
            vec![result("zeta claim"), result("alpha claim"), result("beta claim")],
        );
        let reverse = merge_unique_results(
            Vec::new(),
            vec![result("beta claim"), result("alpha claim"), result("zeta claim")],
        );

        let forward_contents = forward.iter().map(|item| item.content.as_str()).collect::<Vec<_>>();
        let reverse_contents = reverse.iter().map(|item| item.content.as_str()).collect::<Vec<_>>();
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
                result(&second),
                result(&first_with_different_case_and_spacing),
                result(&second),
            ],
        );

        assert_eq!(merged.len(), 2);
        assert!(merged.iter().any(|claim| claim.content == first));
        assert!(merged.iter().any(|claim| claim.content == second));
    }
}
