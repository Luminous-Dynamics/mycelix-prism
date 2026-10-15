// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Local-data-only BEIR SciFact test-split retrieval evaluation.
//!
//! Run:
//! cargo run --release -p prism-search --bin evaluate_beir_scifact -- /path/to/scifact
//!
//! Expected inputs: corpus.jsonl, queries.jsonl, and qrels/test.tsv.
//! The tool never downloads or bundles the corpus. It fingerprints the exact
//! input bytes and compares Prism HDC retrieval against a deterministic BM25
//! baseline. This is an experiment harness, not a claim of BEIR leaderboard
//! equivalence: score semantics, top-k limits, and corpus preprocessing differ.

use blake3::Hash;
use prism_common::EmpiricalLevel;
use prism_search::SearchEngine;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::error::Error;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::Instant;

const RETRIEVAL_LIMIT: usize = 100;
const MRR_CUTOFF: usize = 10;
const NDCG_CUTOFF: usize = 10;
const EXPECTED_CANONICAL_CORPUS_DOCUMENTS: usize = 5_183;
const EXPECTED_CANONICAL_QUERY_RECORDS: usize = 1_109;
const EXPECTED_CANONICAL_TEST_QUERIES: usize = 300;
const MAX_CORPUS_FILE_BYTES: usize = 64 * 1024 * 1024;
const MAX_QUERIES_FILE_BYTES: usize = 8 * 1024 * 1024;
const MAX_QRELS_FILE_BYTES: usize = 8 * 1024 * 1024;
const CORPUS_SOURCE_PREFIX: &str = "beir-scifact-id:";

#[derive(Debug, Deserialize)]
struct TextRecord {
    #[serde(rename = "_id")]
    id: String,
    #[serde(default)]
    title: String,
    text: String,
}

impl TextRecord {
    fn content(&self) -> String {
        match (self.title.trim().is_empty(), self.text.trim().is_empty()) {
            (true, _) => self.text.trim().to_string(),
            (false, true) => self.title.trim().to_string(),
            (false, false) => format!("{}\n{}", self.title.trim(), self.text.trim()),
        }
    }
}

#[derive(Debug)]
struct Document {
    id: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct QueryRecord {
    #[serde(rename = "_id")]
    id: String,
    #[serde(default)]
    title: String,
    text: String,
}

impl QueryRecord {
    fn query_text(&self) -> String {
        match (self.title.trim().is_empty(), self.text.trim().is_empty()) {
            (true, _) => self.text.trim().to_string(),
            (false, true) => self.title.trim().to_string(),
            (false, false) => format!("{}\n{}", self.title.trim(), self.text.trim()),
        }
    }
}

#[derive(Debug)]
struct Fingerprint {
    path: String,
    byte_len: usize,
    blake3: String,
}

type Relevance = HashMap<String, u8>;
type Qrels = BTreeMap<String, Relevance>;

#[derive(Debug, Clone, Copy, Default)]
struct Metrics {
    mrr_at_10: f64,
    recall_at_100: f64,
    ndcg_at_10: f64,
}

#[derive(Debug)]
struct LatencySummary {
    count: usize,
    mean_ms: f64,
    p50_ms: f64,
    p95_ms: f64,
    max_ms: f64,
}

#[derive(Debug)]
struct MetricSummary {
    query_count: usize,
    mrr_at_10: f64,
    recall_at_100: f64,
    ndcg_at_10: f64,
}

#[derive(Debug)]
struct QueryReport {
    query_id: String,
    relevant_documents: usize,
    hdc_top_10_ids: Vec<String>,
    bm25_top_10_ids: Vec<String>,
    hdc: Metrics,
    bm25: Metrics,
    hdc_latency_ms: f64,
    bm25_latency_ms: f64,
}

#[derive(Debug)]
struct EvaluationReport {
    schema_version: &'static str,
    dataset: &'static str,
    split: &'static str,
    corpus_documents: usize,
    query_records: usize,
    qrels_queries: usize,
    positive_relevance_judgments: usize,
    hdc_max_returned_results: usize,
    canonical_reference_counts: CanonicalCounts,
    inputs: Vec<Fingerprint>,
    data_load_ms: f64,
    index_build_ms: f64,
    bm25_build_ms: f64,
    hdc_metrics: MetricSummary,
    bm25_metrics: MetricSummary,
    hdc_latency: LatencySummary,
    bm25_latency: LatencySummary,
    per_query: Vec<QueryReport>,
    limitations: Vec<&'static str>,
}

#[derive(Debug)]
struct CanonicalCounts {
    corpus_documents: usize,
    query_records: usize,
    test_queries: usize,
    counts_match: bool,
}

struct Bm25Index {
    document_ids: Vec<String>,
    term_frequencies: Vec<HashMap<String, usize>>,
    document_lengths: Vec<usize>,
    document_frequency: HashMap<String, usize>,
    average_document_length: f64,
}

impl Bm25Index {
    fn build(documents: &[Document]) -> Self {
        let mut term_frequencies = Vec::with_capacity(documents.len());
        let mut document_lengths = Vec::with_capacity(documents.len());
        let mut document_frequency = HashMap::<String, usize>::new();
        let mut total_length = 0usize;

        for document in documents {
            let mut frequencies = HashMap::<String, usize>::new();
            for term in tokenize(&document.content) {
                *frequencies.entry(term).or_insert(0) += 1;
            }
            let length = frequencies.values().sum();
            total_length += length;
            for term in frequencies.keys() {
                *document_frequency.entry(term.clone()).or_insert(0) += 1;
            }
            term_frequencies.push(frequencies);
            document_lengths.push(length);
        }

        let average_document_length =
            total_length as f64 / documents.len().max(1) as f64;
        Self {
            document_ids: documents.iter().map(|document| document.id.clone()).collect(),
            term_frequencies,
            document_lengths,
            document_frequency,
            average_document_length,
        }
    }

    fn rank(&self, query: &str, top_k: usize) -> Vec<String> {
        const K1: f64 = 1.2;
        const B: f64 = 0.75;
        let terms = tokenize(query).into_iter().collect::<BTreeSet<_>>();
        let document_count = self.document_ids.len() as f64;
        let average_length = self.average_document_length.max(1.0);

        let mut scores = Vec::with_capacity(self.document_ids.len());
        for index in 0..self.document_ids.len() {
            let frequencies = &self.term_frequencies[index];
            let mut score = 0.0_f64;
            for term in &terms {
                let term_frequency = *frequencies.get(term).unwrap_or(&0) as f64;
                if term_frequency == 0.0 {
                    continue;
                }
                let document_frequency =
                    *self.document_frequency.get(term).unwrap_or(&0) as f64;
                let idf = (1.0
                    + (document_count - document_frequency + 0.5)
                        / (document_frequency + 0.5))
                    .ln();
                let document_length = self.document_lengths[index] as f64;
                let denominator =
                    term_frequency + K1 * (1.0 - B + B * document_length / average_length);
                score += idf * term_frequency * (K1 + 1.0) / denominator;
            }
            scores.push((index, score));
        }

        scores.sort_by(|left, right| {
            right
                .1
                .partial_cmp(&left.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| self.document_ids[left.0].cmp(&self.document_ids[right.0]))
        });
        scores
            .into_iter()
            .take(top_k)
            .map(|(index, _)| self.document_ids[index].clone())
            .collect()
    }
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn read_jsonl<T: DeserializeOwned>(
    raw: &[u8],
    label: &str,
) -> Result<Vec<T>, Box<dyn Error>> {
    let text = std::str::from_utf8(raw)
        .map_err(|error| invalid_data(format!("{label} is not UTF-8: {error}")))?;
    let mut values = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let value = serde_json::from_str::<T>(line).map_err(|error| {
            invalid_data(format!("{label}: invalid JSON on line {}: {error}", index + 1))
        })?;
        values.push(value);
    }
    Ok(values)
}

fn fingerprint(path: &str, raw: &[u8]) -> Fingerprint {
    let digest: Hash = blake3::hash(raw);
    Fingerprint {
        path: path.to_string(),
        byte_len: raw.len(),
        blake3: digest.to_hex().to_string(),
    }
}

/// Read one input with a hard byte budget, stopping after at most limit + 1
/// bytes. Metadata prechecks alone would be racy and would not bound the read.
fn read_bounded<R: Read>(
    reader: R,
    label: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let read_limit = u64::try_from(max_bytes)?
        .checked_add(1)
        .ok_or_else(|| invalid_data("input byte limit overflow"))?;
    let mut bytes = Vec::new();
    reader.take(read_limit).read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(invalid_data(format!(
            "{label} exceeds the {max_bytes}-byte input limit"
        ))
        .into());
    }
    Ok(bytes)
}

fn parse_qrels(text: &str) -> Result<Qrels, Box<dyn Error>> {
    let mut lines = text.lines().enumerate().filter(|(_, line)| !line.trim().is_empty());
    let (_, header) = lines.next().ok_or_else(|| invalid_data("qrels file is empty"))?;
    let normalized_header = header.trim_start_matches('\u{feff}');
    if normalized_header != "query-id\tcorpus-id\tscore" {
        return Err(invalid_data(format!(
            "unsupported qrels header {header:?}; expected query-id<TAB>corpus-id<TAB>score"
        ))
        .into());
    }

    let mut qrels = Qrels::new();
    for (line_index, line) in lines {
        let columns = line.split('\t').collect::<Vec<_>>();
        if columns.len() != 3 {
            return Err(invalid_data(format!(
                "qrels line {} has {} columns; expected 3",
                line_index + 1,
                columns.len()
            ))
            .into());
        }
        let query_id = columns[0].trim();
        let document_id = columns[1].trim();
        if query_id.is_empty() || document_id.is_empty() {
            return Err(invalid_data(format!(
                "qrels line {} has an empty query/document ID",
                line_index + 1
            ))
            .into());
        }
        let score = columns[2].trim().parse::<u8>().map_err(|error| {
            invalid_data(format!("qrels line {} has invalid score: {error}", line_index + 1))
        })?;
        if score > 3 {
            return Err(invalid_data(format!(
                "qrels line {} score {score} exceeds the supported graded range 0..=3",
                line_index + 1
            ))
            .into());
        }
        let judgments = qrels.entry(query_id.to_string()).or_default();
        if judgments.insert(document_id.to_string(), score).is_some() {
            return Err(invalid_data(format!(
                "duplicate qrels pair at line {}: query {query_id:?}, document {document_id:?}",
                line_index + 1
            ))
            .into());
        }
    }
    if qrels.is_empty() {
        return Err(invalid_data("qrels contains no judgments").into());
    }
    Ok(qrels)
}

fn validate_dataset(
    documents: &[Document],
    queries: &[QueryRecord],
    qrels: &Qrels,
) -> Result<(), Box<dyn Error>> {
    if documents.is_empty() || queries.is_empty() {
        return Err(invalid_data("corpus and query files must be non-empty").into());
    }

    let mut document_ids = HashSet::<&str>::with_capacity(documents.len());
    for document in documents {
        if document.id.trim().is_empty() || document.content.trim().is_empty() {
            return Err(invalid_data("document IDs/content must be non-empty").into());
        }
        if !document_ids.insert(&document.id) {
            return Err(invalid_data(format!("duplicate corpus document ID {:?}", document.id))
                .into());
        }
    }

    let mut query_ids = HashSet::<&str>::with_capacity(queries.len());
    for query in queries {
        if query.id.trim().is_empty() || query.query_text().is_empty() {
            return Err(invalid_data("query IDs/text must be non-empty").into());
        }
        if !query_ids.insert(&query.id) {
            return Err(invalid_data(format!("duplicate query ID {:?}", query.id)).into());
        }
    }

    for (query_id, judgments) in qrels {
        if !query_ids.contains(query_id.as_str()) {
            return Err(invalid_data(format!(
                "qrels references unknown query ID {query_id:?}"
            ))
            .into());
        }
        if !judgments.keys().any(|id| document_ids.contains(id.as_str())) {
            return Err(invalid_data(format!(
                "qrels query {query_id:?} has no corpus documents"
            ))
            .into());
        }
        if !judgments.values().any(|grade| *grade > 0) {
            return Err(invalid_data(format!(
                "qrels query {query_id:?} has no positive relevance judgment"
            ))
            .into());
        }
        for document_id in judgments.keys() {
            if !document_ids.contains(document_id.as_str()) {
                return Err(invalid_data(format!(
                    "qrels query {query_id:?} references unknown corpus document {document_id:?}"
                ))
                .into());
            }
        }
    }
    Ok(())
}

fn tokenize(text: &str) -> Vec<String> {
    text.to_lowercase()
        .split(|character: char| !character.is_alphanumeric())
        .filter(|term| term.len() >= 2)
        .map(str::to_string)
        .collect()
}

fn id_from_source(sources: &[String]) -> Option<String> {
    sources
        .iter()
        .find_map(|source| source.strip_prefix(CORPUS_SOURCE_PREFIX))
        .map(str::to_string)
}

fn evaluate_ranking(ranked_ids: &[String], relevance: &Relevance) -> Metrics {
    let relevant_count = relevance.values().filter(|&&grade| grade > 0).count();
    if relevant_count == 0 {
        return Metrics::default();
    }

    let mut reciprocal_rank = 0.0;
    let mut hits = 0usize;
    let mut dcg = 0.0;
    let mut seen_ids = HashSet::<&str>::new();

    for (index, id) in ranked_ids.iter().take(RETRIEVAL_LIMIT).enumerate() {
        if !seen_ids.insert(id.as_str()) {
            continue;
        }
        let grade = *relevance.get(id).unwrap_or(&0);
        if index < MRR_CUTOFF && grade > 0 && reciprocal_rank == 0.0 {
            reciprocal_rank = 1.0 / (index as f64 + 1.0);
        }
        if grade > 0 {
            hits += 1;
            if index < NDCG_CUTOFF {
                dcg += (2_f64.powi(grade as i32) - 1.0) / ((index as f64 + 2.0).log2());
            }
        }
    }

    let mut ideal_grades = relevance
        .values()
        .copied()
        .filter(|grade| *grade > 0)
        .collect::<Vec<_>>();
    ideal_grades.sort_unstable_by(|left, right| right.cmp(left));
    let idcg = ideal_grades
        .iter()
        .take(NDCG_CUTOFF)
        .enumerate()
        .map(|(index, grade)| {
            (2_f64.powi(*grade as i32) - 1.0) / ((index as f64 + 2.0).log2())
        })
        .sum::<f64>();

    Metrics {
        mrr_at_10: reciprocal_rank,
        recall_at_100: hits as f64 / relevant_count as f64,
        ndcg_at_10: if idcg > 0.0 { dcg / idcg } else { 0.0 },
    }
}

fn summarize(metrics: &[Metrics]) -> MetricSummary {
    let query_count = metrics.len();
    let denominator = query_count.max(1) as f64;
    MetricSummary {
        query_count,
        mrr_at_10: metrics.iter().map(|metric| metric.mrr_at_10).sum::<f64>() / denominator,
        recall_at_100: metrics.iter().map(|metric| metric.recall_at_100).sum::<f64>() / denominator,
        ndcg_at_10: metrics.iter().map(|metric| metric.ndcg_at_10).sum::<f64>() / denominator,
    }
}

fn summarize_latencies(latencies_ms: &[f64]) -> LatencySummary {
    let mut sorted = latencies_ms.to_vec();
    sorted.sort_by(f64::total_cmp);
    let percentile = |p: f64| {
        if sorted.is_empty() {
            return 0.0;
        }
        let index = ((sorted.len() - 1) as f64 * p).ceil() as usize;
        sorted[index.min(sorted.len() - 1)]
    };
    let mean_ms = if sorted.is_empty() {
        0.0
    } else {
        sorted.iter().sum::<f64>() / sorted.len() as f64
    };
    LatencySummary {
        count: sorted.len(),
        mean_ms,
        p50_ms: percentile(0.50),
        p95_ms: percentile(0.95),
        max_ms: sorted.last().copied().unwrap_or(0.0),
    }
}

fn run(dataset_dir: &Path) -> Result<EvaluationReport, Box<dyn Error>> {
    let corpus_path = dataset_dir.join("corpus.jsonl");
    let queries_path = dataset_dir.join("queries.jsonl");
    let qrels_path = dataset_dir.join("qrels").join("test.tsv");

    let load_started = Instant::now();
    let corpus_raw = read_bounded(
        fs::File::open(&corpus_path)?,
        "corpus.jsonl",
        MAX_CORPUS_FILE_BYTES,
    )?;
    let queries_raw = read_bounded(
        fs::File::open(&queries_path)?,
        "queries.jsonl",
        MAX_QUERIES_FILE_BYTES,
    )?;
    let qrels_raw = read_bounded(
        fs::File::open(&qrels_path)?,
        "qrels/test.tsv",
        MAX_QRELS_FILE_BYTES,
    )?;
    let corpus_records = read_jsonl::<TextRecord>(&corpus_raw, "corpus.jsonl")?;
    let query_records = read_jsonl::<QueryRecord>(&queries_raw, "queries.jsonl")?;
    let qrels_text = std::str::from_utf8(&qrels_raw)
        .map_err(|error| invalid_data(format!("qrels/test.tsv is not UTF-8: {error}")))?;
    let qrels = parse_qrels(qrels_text)?;
    let data_load_ms = load_started.elapsed().as_secs_f64() * 1000.0;

    let documents = corpus_records
        .iter()
        .map(|record| Document {
            id: record.id.clone(),
            content: record.content(),
        })
        .collect::<Vec<_>>();
    validate_dataset(&documents, &query_records, &qrels)?;

    let query_by_id = query_records
        .iter()
        .map(|query| (query.id.as_str(), query))
        .collect::<HashMap<_, _>>();

    let index_started = Instant::now();
    let mut engine = SearchEngine::new();
    let claims = documents
        .iter()
        .map(|document| {
            (
                document.content.clone(),
                EmpiricalLevel::E2,
                vec![format!("{CORPUS_SOURCE_PREFIX}{}", document.id)],
                vec!["beir-scifact-evaluation".to_string()],
            )
        })
        .collect::<Vec<_>>();
    engine.add_claims(claims);
    let index_build_ms = index_started.elapsed().as_secs_f64() * 1000.0;

    let bm25_started = Instant::now();
    let bm25 = Bm25Index::build(&documents);
    let bm25_build_ms = bm25_started.elapsed().as_secs_f64() * 1000.0;

    let mut hdc_metric_rows = Vec::with_capacity(qrels.len());
    let mut bm25_metric_rows = Vec::with_capacity(qrels.len());
    let mut hdc_latencies_ms = Vec::with_capacity(qrels.len());
    let mut bm25_latencies_ms = Vec::with_capacity(qrels.len());
    let mut per_query = Vec::with_capacity(qrels.len());

    for (query_id, relevance) in &qrels {
        let query = query_by_id
            .get(query_id.as_str())
            .copied()
            .ok_or_else(|| invalid_data(format!("qrels references missing query {query_id:?}")))?;
        let query_text = query.query_text();

        let start = Instant::now();
        let hdc_results = engine.search(&query_text, RETRIEVAL_LIMIT);
        let hdc_latency_ms = start.elapsed().as_secs_f64() * 1000.0;
        let hdc_ids = hdc_results
            .iter()
            .filter_map(|result| id_from_source(&result.sources))
            .collect::<Vec<_>>();

        let start = Instant::now();
        let bm25_ids = bm25.rank(&query_text, RETRIEVAL_LIMIT);
        let bm25_latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        let hdc_metrics = evaluate_ranking(&hdc_ids, relevance);
        let bm25_metrics = evaluate_ranking(&bm25_ids, relevance);
        let relevant_documents = relevance.values().filter(|&&grade| grade > 0).count();

        hdc_metric_rows.push(hdc_metrics);
        bm25_metric_rows.push(bm25_metrics);
        hdc_latencies_ms.push(hdc_latency_ms);
        bm25_latencies_ms.push(bm25_latency_ms);
        per_query.push(QueryReport {
            query_id: query_id.clone(),
            relevant_documents,
            hdc_top_10_ids: hdc_ids.iter().take(10).cloned().collect(),
            bm25_top_10_ids: bm25_ids.iter().take(10).cloned().collect(),
            hdc: hdc_metrics,
            bm25: bm25_metrics,
            hdc_latency_ms,
            bm25_latency_ms,
        });
    }

    let canonical_counts_match = documents.len() == EXPECTED_CANONICAL_CORPUS_DOCUMENTS
        && query_records.len() == EXPECTED_CANONICAL_QUERY_RECORDS
        && qrels.len() == EXPECTED_CANONICAL_TEST_QUERIES;

    Ok(EvaluationReport {
        schema_version: "prism-beir-eval-v1",
        dataset: "BEIR SciFact",
        split: "test",
        corpus_documents: documents.len(),
        query_records: query_records.len(),
        qrels_queries: qrels.len(),
        positive_relevance_judgments: qrels
            .values()
            .flat_map(|judgments| judgments.values())
            .filter(|&&grade| grade > 0)
            .count(),
        hdc_max_returned_results: RETRIEVAL_LIMIT,
        canonical_reference_counts: CanonicalCounts {
            corpus_documents: EXPECTED_CANONICAL_CORPUS_DOCUMENTS,
            query_records: EXPECTED_CANONICAL_QUERY_RECORDS,
            test_queries: EXPECTED_CANONICAL_TEST_QUERIES,
            counts_match: canonical_counts_match,
        },
        inputs: vec![
            fingerprint("corpus.jsonl", &corpus_raw),
            fingerprint("queries.jsonl", &queries_raw),
            fingerprint("qrels/test.tsv", &qrels_raw),
        ],
        data_load_ms,
        index_build_ms,
        bm25_build_ms,
        hdc_metrics: summarize(&hdc_metric_rows),
        bm25_metrics: summarize(&bm25_metric_rows),
        hdc_latency: summarize_latencies(&hdc_latencies_ms),
        bm25_latency: summarize_latencies(&bm25_latencies_ms),
        per_query,
        limitations: vec![
            "Input files are user-supplied; no data is downloaded or bundled.",
            concat!(
                "BLAKE3 hashes identify exact bytes; ",
                "they do not prove dataset authenticity or licensing."
            ),
            concat!(
                "HDC search currently caps returned candidates at 100, ",
                "so Recall@1000 is not available."
            ),
            concat!(
                "Metrics compare this Prism implementation with this local BM25 baseline, ",
                "not BEIR leaderboard scores."
            ),
            concat!(
                "All corpus entries receive the same E2 metadata, ",
                "so epistemic levels do not intentionally bias within-corpus ranking."
            ),
            concat!(
                "Runtime timings depend on the host, build mode, and system load; ",
                "report hardware and compiler separately."
            ),
        ],
    })
}

fn print_report(report: &EvaluationReport) -> Result<(), Box<dyn Error>> {
    // Emit plain JSON without adding serde derives to internal evaluation types.
    let value = serde_json::json!({
        "schema_version": report.schema_version,
        "dataset": report.dataset,
        "split": report.split,
        "corpus_documents": report.corpus_documents,
        "query_records": report.query_records,
        "qrels_queries": report.qrels_queries,
        "positive_relevance_judgments": report.positive_relevance_judgments,
        "hdc_max_returned_results": report.hdc_max_returned_results,
        "canonical_reference_counts": {
            "corpus_documents": report.canonical_reference_counts.corpus_documents,
            "query_records": report.canonical_reference_counts.query_records,
            "test_queries": report.canonical_reference_counts.test_queries,
            "counts_match": report.canonical_reference_counts.counts_match
        },
        "inputs": report.inputs.iter().map(|fingerprint| serde_json::json!({
            "path": fingerprint.path,
            "byte_len": fingerprint.byte_len,
            "blake3": fingerprint.blake3
        })).collect::<Vec<_>>(),
        "timing": {
            "data_load_ms": report.data_load_ms
            "hdc_index_build_ms": report.index_build_ms,
            "bm25_index_build_ms": report.bm25_build_ms,
            "hdc_query_latency_ms": {
                "count": report.hdc_latency.count,
                "mean": report.hdc_latency.mean_ms,
                "p50": report.hdc_latency.p50_ms,
                "p95": report.hdc_latency.p95_ms,
                "max": report.hdc_latency.max_ms
            },
            "bm25_query_latency_ms": {
                "count": report.bm25_latency.count,
                "mean": report.bm25_latency.mean_ms,
                "p50": report.bm25_latency.p50_ms,
                "p95": report.bm25_latency.p95_ms,
                "max": report.bm25_latency.max_ms
            }
        },
        "metrics": {
            "hdc": {
                "query_count": report.hdc_metrics.query_count,
                "mrr_at_10": report.hdc_metrics.mrr_at_10,
                "recall_at_100": report.hdc_metrics.recall_at_100,
                "ndcg_at_10": report.hdc_metrics.ndcg_at_10
            },
            "bm25": {
                "query_count": report.bm25_metrics.query_count,
                "mrr_at_10": report.bm25_metrics.mrr_at_10,
                "recall_at_100": report.bm25_metrics.recall_at_100,
                "ndcg_at_10": report.bm25_metrics.ndcg_at_10
            }
        },
        "per_query": report.per_query.iter().map(|query| serde_json::json!({
            "query_id": query.query_id,
            "relevant_documents": query.relevant_documents,
            "hdc_top_10_ids": query.hdc_top_10_ids,
            "bm25_top_10_ids": query.bm25_top_10_ids,
            "hdc": {
                "mrr_at_10": query.hdc.mrr_at_10,
                "recall_at_100": query.hdc.recall_at_100,
                "ndcg_at_10": query.hdc.ndcg_at_10,
                "latency_ms": query.hdc_latency_ms
            },
            "bm25": {
                "mrr_at_10": query.bm25.mrr_at_10,
                "recall_at_100": query.bm25.recall_at_100,
                "ndcg_at_10": query.bm25.ndcg_at_10,
                "latency_ms": query.bm25_latency_ms
            }
        })).collect::<Vec<_>>(),
        "limitations": report.limitations
    });
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() != 1 || arguments[0] == "--help" || arguments[0] == "-h" {
        eprintln!("Usage: evaluate_beir_scifact <path-to-BEIR-SciFact-directory>");
        eprintln!("Expected files: corpus.jsonl, queries.jsonl, qrels/test.tsv");
        if arguments.len() == 1 && (arguments[0] == "--help" || arguments[0] == "-h") {
            return Ok(());
        }
        return Err(invalid_data("exactly one dataset directory argument is required").into());
    }

    let dataset_dir = PathBuf::from(&arguments[0]);
    let report = run(&dataset_dir)?;
    print_report(&report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relevance(entries: &[(&str, u8)]) -> Relevance {
        entries
            .iter()
            .map(|(id, grade)| ((*id).to_string(), *grade))
            .collect()
    }

    #[test]
    fn bounded_reader_accepts_exact_limit_and_rejects_over_limit() {
        use std::io::Cursor;

        assert_eq!(
            read_bounded(Cursor::new(b"1234"), "fixture", 4).unwrap(),
            b"1234"
        );
        assert!(read_bounded(Cursor::new(b"12345"), "fixture", 4).is_err());
    }

    #[test]
    fn qrels_parser_requires_header_and_preserves_relevance_grades() {
        let parsed = parse_qrels(
            "query-id\tcorpus-id\tscore\nq1\tdoc1\t3\nq1\tdoc2\t1\nq2\tdoc2\t0\n",
        )
        .unwrap();
        assert_eq!(parsed["q1"]["doc1"], 3);
        assert_eq!(parsed["q1"]["doc2"], 1);
        assert_eq!(parsed["q2"]["doc2"], 0);
        assert!(parse_qrels("q1\tdoc1\t1\n").is_err());
    }

    #[test]
    fn qrels_parser_rejects_duplicate_pairs_and_invalid_grades() {
        assert!(
            parse_qrels("query-id\tcorpus-id\tscore\nq1\tdoc1\t1\nq1\tdoc1\t1\n").is_err()
        );
        assert!(parse_qrels("query-id\tcorpus-id\tscore\nq1\tdoc1\t4\n").is_err());
    }

    #[test]
    fn validation_rejects_unknown_documents_and_queries() {
        let documents = vec![Document {
            id: "d1".into(),
            content: "unique science claim".into(),
        }];
        let queries = vec![QueryRecord {
            id: "q1".into(),
            title: String::new(),
            text: "science".into(),
        }];
        let missing_doc = BTreeMap::from([("q1".into(), relevance(&[("unknown", 1)]))]);
        assert!(validate_dataset(&documents, &queries, &missing_doc).is_err());
        let missing_query = BTreeMap::from([("unknown-query".into(), relevance(&[("d1", 1)]))]);
        assert!(validate_dataset(&documents, &queries, &missing_query).is_err());
    }

    #[test]
    fn ndcg_rewards_the_higher_relevance_grade_at_the_top() {
        let relevance = relevance(&[("best", 3), ("second", 1)]);
        let best_first = vec!["best".into(), "second".into()];
        let second_first = vec!["second".into(), "best".into()];
        assert!(
            evaluate_ranking(&best_first, &relevance).ndcg_at_10
                > evaluate_ranking(&second_first, &relevance).ndcg_at_10
        );
    }

    #[test]
    fn recall_at_100_does_not_count_duplicate_ranked_ids_twice() {
        let relevance = relevance(&[("match", 1), ("other", 1)]);
        let ranking = vec!["match".into(), "match".into()];
        assert_eq!(evaluate_ranking(&ranking, &relevance).recall_at_100, 0.5);
    }

    #[test]
    fn run_fixture_records_fingerprints_and_metrics() -> Result<(), Box<dyn Error>> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "prism-beir-evaluator-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(directory.join("qrels"))?;

        fs::write(
            directory.join("corpus.jsonl"),
            concat!(
                "{\"_id\":\"d1\",\"title\":\"Ocean\",\"text\":\"Ocean chemistry changes pH.\"}\n",
                "{\"_id\":\"d2\",\"title\":\"Quantum\",",
                "\"text\":\"Quantum entanglement physics.\"}\n"
            ),
        )?;
        fs::write(
            directory.join("queries.jsonl"),
            concat!(
                "{\"_id\":\"q1\",\"text\":\"ocean chemistry\"}\n",
                "{\"_id\":\"q2\",\"text\":\"quantum entanglement\"}\n"
            ),
        )?;
        fs::write(
            directory.join("qrels").join("test.tsv"),
            "query-id\tcorpus-id\tscore\nq1\td1\t1\nq2\td2\t1\n",
        )?;

        let report = run(&directory)?;
        assert_eq!(report.corpus_documents, 2);
        assert_eq!(report.query_records, 2);
        assert_eq!(report.qrels_queries, 2);
        assert_eq!(report.hdc_metrics.query_count, 2);
        assert_eq!(report.bm25_metrics.query_count, 2);
        assert_eq!(report.inputs.len(), 3);
        assert!(report.inputs.iter().all(|input| input.blake3.len() == 64));
        assert!(!report.canonical_reference_counts.counts_match);

        fs::remove_dir_all(&directory)?;
        Ok(())
    }

    #[test]
    fn bm25_ties_are_deterministic() {
        let documents = vec![
            Document { id: "z".into(), content: "ocean acidity".into() },
            Document { id: "a".into(), content: "ocean acidity".into() },
        ];
        let index = Bm25Index::build(&documents);
        assert_eq!(index.rank("ocean acidity", 2), vec!["a".to_string(), "z".to_string()]);
    }
}
