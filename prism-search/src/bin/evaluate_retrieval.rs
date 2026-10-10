// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Deterministic retrieval-evaluation bootstrap for Prism.
//!
//! Run with: cargo run -p prism-search --bin evaluate_retrieval
//!
//! The bundled corpus has synthetic documents and hand-authored labels. Its
//! scores validate the evaluator and provide a smoke baseline only; they are
//! not evidence of public-web search quality or production relevance.

use prism_common::EmpiricalLevel;
use prism_search::SearchEngine;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::error::Error;

const CUTOFF: usize = 5;
const FIXTURE: &str = include_str!("../../fixtures/retrieval_v1.json");

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: String,
    fixture_kind: String,
    documents: Vec<Document>,
    queries: Vec<EvaluationQuery>,
}

#[derive(Debug, Deserialize)]
struct Document {
    id: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct EvaluationQuery {
    id: String,
    text: String,
    relevance: HashMap<String, u8>,
}

#[derive(Debug, Default, Clone, Copy)]
struct Metrics {
    reciprocal_rank: f64,
    recall_at_k: f64,
    ndcg_at_k: f64,
}

#[derive(Debug, Serialize)]
struct MetricSummary {
    queries_evaluated: usize,
    mrr_at_5: f64,
    recall_at_5: f64,
    ndcg_at_5: f64,
}

#[derive(Debug, Serialize)]
struct QueryMetrics {
    mrr_at_5: f64,
    recall_at_5: f64,
    ndcg_at_5: f64,
}

#[derive(Debug, Serialize)]
struct QueryEvaluation {
    query_id: String,
    hdc_ranked_ids: Vec<String>,
    bm25_ranked_ids: Vec<String>,
    hdc: QueryMetrics,
    bm25: QueryMetrics,
}

#[derive(Debug, Serialize)]
struct EvaluationReport {
    schema_version: String,
    fixture_kind: String,
    documents: usize,
    queries: usize,
    cutoff: usize,
    per_query: Vec<QueryEvaluation>,
    hdc: MetricSummary,
    bm25: MetricSummary,
    interpretation: &'static str,
}

/// Validate the committed fixture before using it to compute metrics.
/// Fail closed on schema drift, ambiguous document identity, unknown relevance
/// labels, or unsupported grades; otherwise the resulting metrics can look valid
/// while silently measuring a different corpus than the author intended.
fn validate_fixture(fixture: &Fixture) -> Result<(), String> {
    const EXPECTED_SCHEMA: &str = "prism-search-eval-v1";
    const EXPECTED_KIND: &str = "synthetic-bootstrap-not-public-web-evidence";

    if fixture.schema_version != EXPECTED_SCHEMA {
        return Err(format!(
            "unsupported fixture schema version {:?}; expected {:?}",
            fixture.schema_version, EXPECTED_SCHEMA
        ));
    }
    if fixture.fixture_kind != EXPECTED_KIND {
        return Err(format!(
            "unsupported fixture kind {:?}; this evaluator only accepts the synthetic smoke fixture",
            fixture.fixture_kind
        ));
    }
    if fixture.documents.is_empty() || fixture.queries.is_empty() {
        return Err("evaluation fixture must contain documents and queries".into());
    }

    let mut document_ids = HashSet::new();
    let mut normalized_contents = HashSet::new();
    for document in &fixture.documents {
        if document.id.trim().is_empty() || document.content.trim().is_empty() {
            return Err("document IDs and contents must be non-empty".into());
        }
        if !document_ids.insert(document.id.as_str()) {
            return Err(format!("duplicate document ID {:?}", document.id));
        }
        let normalized = document
            .content
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase();
        if !normalized_contents.insert(normalized) {
            return Err(format!(
                "duplicate normalized document content for ID {:?}",
                document.id
            ));
        }
    }

    let mut query_ids = HashSet::new();
    for query in &fixture.queries {
        if query.id.trim().is_empty() || query.text.trim().is_empty() {
            return Err("query IDs and text must be non-empty".into());
        }
        if !query_ids.insert(query.id.as_str()) {
            return Err(format!("duplicate query ID {:?}", query.id));
        }
        if query.relevance.is_empty() {
            return Err(format!("query {:?} has no relevance labels", query.id));
        }

        let mut has_relevant_document = false;
        for (document_id, grade) in &query.relevance {
            if !document_ids.contains(document_id.as_str()) {
                return Err(format!(
                    "query {:?} references unknown document ID {:?}",
                    query.id, document_id
                ));
            }
            if !(1..=3).contains(grade) {
                return Err(format!(
                    "query {:?} has unsupported relevance grade {}; expected 1, 2, or 3",
                    query.id, grade
                ));
            }
            has_relevant_document = true;
        }
        if !has_relevant_document {
            return Err(format!("query {:?} has no relevant documents", query.id));
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let fixture: Fixture = serde_json::from_str(FIXTURE)?;
    validate_fixture(&fixture).map_err(|error| format!("invalid retrieval fixture: {error}"))?;

    let mut engine = SearchEngine::new();
    let claims = fixture
        .documents
        .iter()
        .map(|document| {
            (
                document.content.clone(),
                EmpiricalLevel::E2,
                vec![format!("fixture://{}", document.id)],
                vec!["synthetic-evaluation".to_string()],
            )
        })
        .collect::<Vec<_>>();
    engine.add_claims(claims);

    let content_to_id = fixture
        .documents
        .iter()
        .map(|document| (document.content.clone(), document.id.clone()))
        .collect::<HashMap<_, _>>();

    let mut hdc_metrics = Vec::with_capacity(fixture.queries.len());
    let mut bm25_metrics = Vec::with_capacity(fixture.queries.len());
    let mut per_query = Vec::with_capacity(fixture.queries.len());

    for query in &fixture.queries {
        let hdc_ids = engine
            .search(&query.text, CUTOFF)
            .iter()
            .filter_map(|result| content_to_id.get(&result.content).cloned())
            .collect::<Vec<_>>();
        let bm25_ids = bm25_rank(&query.text, &fixture.documents, CUTOFF);
        let hdc_result = evaluate_ranking(&hdc_ids, &query.relevance, CUTOFF);
        let bm25_result = evaluate_ranking(&bm25_ids, &query.relevance, CUTOFF);

        hdc_metrics.push(hdc_result);
        bm25_metrics.push(bm25_result);
        per_query.push(QueryEvaluation {
            query_id: query.id.clone(),
            hdc_ranked_ids: hdc_ids,
            bm25_ranked_ids: bm25_ids,
            hdc: as_query_metrics(hdc_result),
            bm25: as_query_metrics(bm25_result),
        });
    }

    let report = EvaluationReport {
        schema_version: fixture.schema_version,
        fixture_kind: fixture.fixture_kind,
        documents: fixture.documents.len(),
        queries: fixture.queries.len(),
        cutoff: CUTOFF,
        per_query,
        hdc: summarize(&hdc_metrics),
        bm25: summarize(&bm25_metrics),
        interpretation: "synthetic smoke baseline only; not public-web relevance evidence",
    };

    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn tokenize(text: &str) -> Vec<String> {
    text.to_lowercase()
        .split(|character: char| !character.is_alphanumeric())
        .filter(|term| term.len() >= 2)
        .map(str::to_string)
        .collect()
}

/// A small deterministic BM25 baseline, intentionally kept local to the
/// evaluator so its implementation and parameters remain inspectable.
fn bm25_rank(query: &str, documents: &[Document], top_k: usize) -> Vec<String> {
    const K1: f64 = 1.2;
    const B: f64 = 0.75;

    let query_terms = tokenize(query).into_iter().collect::<BTreeSet<_>>();
    let tokenized = documents
        .iter()
        .map(|document| tokenize(&document.content))
        .collect::<Vec<_>>();
    let average_length = tokenized
        .iter()
        .map(|tokens| tokens.len() as f64)
        .sum::<f64>()
        / tokenized.len().max(1) as f64;

    let mut document_frequency = HashMap::<String, usize>::new();
    for tokens in &tokenized {
        for term in tokens.iter().collect::<HashSet<_>>() {
            *document_frequency.entry((*term).clone()).or_insert(0) += 1;
        }
    }

    let mut scored = documents
        .iter()
        .zip(tokenized.iter())
        .map(|(document, tokens)| {
            let mut score = 0.0;
            for term in &query_terms {
                let term_frequency = tokens.iter().filter(|token| *token == term).count() as f64;
                if term_frequency == 0.0 {
                    continue;
                }
                let df = *document_frequency.get(term).unwrap_or(&0) as f64;
                let n = documents.len() as f64;
                let inverse_document_frequency = (1.0 + (n - df + 0.5) / (df + 0.5)).ln();
                let length = tokens.len() as f64;
                let denominator = term_frequency
                    + K1 * (1.0 - B + B * length / average_length.max(1.0));
                score += inverse_document_frequency * term_frequency * (K1 + 1.0) / denominator;
            }
            (document.id.clone(), score)
        })
        .collect::<Vec<_>>();

    scored.sort_by(|left, right| {
        right
            .1
            .partial_cmp(&left.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.0.cmp(&right.0))
    });
    scored
        .into_iter()
        .take(top_k)
        .map(|(id, _)| id)
        .collect()
}

fn evaluate_ranking(
    ranked_ids: &[String],
    relevance: &HashMap<String, u8>,
    cutoff: usize,
) -> Metrics {
    let relevant_count = relevance.values().filter(|&&grade| grade > 0).count();
    if relevant_count == 0 {
        return Metrics::default();
    }

    let mut reciprocal_rank = 0.0;
    let mut hits = 0usize;
    let mut dcg = 0.0;

    let mut seen_ids = HashSet::new();
    for (index, id) in ranked_ids.iter().take(cutoff).enumerate() {
        // A duplicate document occupies its rank position but must not count
        // twice toward hits/DCG or inflate Recall@k above the unique-item limit.
        if !seen_ids.insert(id.as_str()) {
            continue;
        }
        let grade = *relevance.get(id).unwrap_or(&0);
        if grade > 0 {
            hits += 1;
            if reciprocal_rank == 0.0 {
                reciprocal_rank = 1.0 / (index as f64 + 1.0);
            }
        }
        if grade > 0 {
            dcg += (2_f64.powi(grade as i32) - 1.0) / ((index as f64 + 2.0).log2());
        }
    }

    let mut ideal_grades = relevance.values().copied().filter(|grade| *grade > 0).collect::<Vec<_>>();
    ideal_grades.sort_unstable_by(|left, right| right.cmp(left));
    let idcg = ideal_grades
        .iter()
        .take(cutoff)
        .enumerate()
        .map(|(index, grade)| {
            (2_f64.powi(*grade as i32) - 1.0) / ((index as f64 + 2.0).log2())
        })
        .sum::<f64>();

    Metrics {
        reciprocal_rank,
        recall_at_k: hits as f64 / relevant_count as f64,
        ndcg_at_k: if idcg > 0.0 { dcg / idcg } else { 0.0 },
    }
}

fn as_query_metrics(metrics: Metrics) -> QueryMetrics {
    QueryMetrics {
        mrr_at_5: metrics.reciprocal_rank,
        recall_at_5: metrics.recall_at_k,
        ndcg_at_5: metrics.ndcg_at_k,
    }
}

fn summarize(metrics: &[Metrics]) -> MetricSummary {
    let count = metrics.len().max(1) as f64;
    MetricSummary {
        queries_evaluated: metrics.len(),
        mrr_at_5: metrics.iter().map(|metric| metric.reciprocal_rank).sum::<f64>() / count,
        recall_at_5: metrics.iter().map(|metric| metric.recall_at_k).sum::<f64>() / count,
        ndcg_at_5: metrics.iter().map(|metric| metric.ndcg_at_k).sum::<f64>() / count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_fixture() -> Fixture {
        Fixture {
            schema_version: "prism-search-eval-v1".into(),
            fixture_kind: "synthetic-bootstrap-not-public-web-evidence".into(),
            documents: vec![
                Document {
                    id: "doc-1".into(),
                    content: "A unique document about ocean chemistry".into(),
                },
                Document {
                    id: "doc-2".into(),
                    content: "A separate document about quantum states".into(),
                },
            ],
            queries: vec![EvaluationQuery {
                id: "query-1".into(),
                text: "ocean chemistry".into(),
                relevance: HashMap::from([("doc-1".into(), 3)]),
            }],
        }
    }

    #[test]
    fn fixture_validation_accepts_the_expected_schema() {
        assert!(validate_fixture(&valid_fixture()).is_ok());
    }

    #[test]
    fn fixture_validation_rejects_unknown_relevance_document_ids() {
        let mut fixture = valid_fixture();
        fixture.queries[0].relevance.insert("missing-doc".into(), 2);
        assert!(validate_fixture(&fixture)
            .unwrap_err()
            .contains("unknown document ID"));
    }

    #[test]
    fn fixture_validation_rejects_duplicate_document_ids() {
        let mut fixture = valid_fixture();
        fixture.documents[1].id = fixture.documents[0].id.clone();
        assert!(validate_fixture(&fixture)
            .unwrap_err()
            .contains("duplicate document ID"));
    }

    #[test]
    fn fixture_validation_rejects_duplicate_normalized_content() {
        let mut fixture = valid_fixture();
        fixture.documents[1].content = "  A UNIQUE DOCUMENT about OCEAN chemistry  ".into();
        assert!(validate_fixture(&fixture)
            .unwrap_err()
            .contains("duplicate normalized document content"));
    }

    #[test]
    fn fixture_validation_rejects_out_of_range_grades() {
        let mut fixture = valid_fixture();
        fixture.queries[0].relevance.insert("doc-1".into(), 4);
        assert!(validate_fixture(&fixture)
            .unwrap_err()
            .contains("expected 1, 2, or 3"));
    }

    #[test]
    fn fixture_validation_rejects_schema_drift() {
        let mut fixture = valid_fixture();
        fixture.schema_version = "prism-search-eval-v2".into();
        assert!(validate_fixture(&fixture)
            .unwrap_err()
            .contains("unsupported fixture schema version"));
    }

    #[test]
    fn duplicate_ranked_ids_do_not_inflate_recall() {
        let relevance = HashMap::from([
            ("relevant".to_string(), 3_u8),
            ("another-relevant".to_string(), 2_u8),
        ]);
        let ranking = vec![
            "relevant".to_string(),
            "relevant".to_string(),
            "irrelevant".to_string(),
        ];
        let metrics = evaluate_ranking(&ranking, &relevance, 5);

        assert_eq!(metrics.recall_at_k, 0.5);
        assert_eq!(metrics.reciprocal_rank, 1.0);
    }

    #[test]
    fn metrics_reward_relevant_documents_at_the_top() {
        let relevance = HashMap::from([
            ("best".to_string(), 3_u8),
            ("second".to_string(), 2_u8),
        ]);
        let best_first = vec!["best".to_string(), "second".to_string()];
        let second_first = vec!["second".to_string(), "best".to_string()];

        let best = evaluate_ranking(&best_first, &relevance, 5);
        let second = evaluate_ranking(&second_first, &relevance, 5);

        assert_eq!(best.reciprocal_rank, 1.0);
        assert!(best.ndcg_at_k > second.ndcg_at_k);
        assert_eq!(best.recall_at_k, 1.0);
    }

    #[test]
    fn missing_relevant_results_have_zero_recall_and_reciprocal_rank() {
        let relevance = HashMap::from([("relevant".to_string(), 3_u8)]);
        let ranking = vec!["irrelevant".to_string()];
        let metrics = evaluate_ranking(&ranking, &relevance, 5);

        assert_eq!(metrics.recall_at_k, 0.0);
        assert_eq!(metrics.reciprocal_rank, 0.0);
        assert_eq!(metrics.ndcg_at_k, 0.0);
    }
}
