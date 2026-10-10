// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Benchmarks for the Prism epistemic search engine.
//!
//! Search-size fixtures are synthetic performance probes, not relevance or
//! web-scale claims. Use a pinned labeled corpus for retrieval-quality claims.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use prism_common::EmpiricalLevel;
use prism_search::binary_hv::BinaryHV;
use prism_search::SearchEngine;

fn bench_binary_hv_similarity(c: &mut Criterion) {
    let a = BinaryHV::random(42);
    let b = BinaryHV::random(43);
    c.bench_function("binary_hv_similarity", |bencher| {
        bencher.iter(|| black_box(a.similarity(&b)))
    });
}

fn bench_binary_hv_bind(c: &mut Criterion) {
    let a = BinaryHV::random(42);
    let b = BinaryHV::random(43);
    c.bench_function("binary_hv_bind", |bencher| {
        bencher.iter(|| black_box(a.bind(&b)))
    });
}

fn bench_binary_hv_bundle_10(c: &mut Criterion) {
    let vecs: Vec<BinaryHV> = (0..10).map(|i| BinaryHV::random(i)).collect();
    c.bench_function("binary_hv_bundle_10", |bencher| {
        bencher.iter(|| black_box(BinaryHV::bundle(&vecs)))
    });
}

fn bench_encode_text(c: &mut Criterion) {
    c.bench_function("encode_text_short", |bencher| {
        bencher.iter(|| black_box(prism_search::encode_text("ocean acidification causes")))
    });
}

fn bench_search(c: &mut Criterion) {
    let engine = SearchEngine::with_seed_claims();
    c.bench_function("search_top_10_seed_corpus", |bencher| {
        bencher.iter(|| black_box(engine.search("consciousness neural correlates", 10)))
    });
}

fn bench_search_by_corpus_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("search_top_10_by_synthetic_corpus_size");

    for size in [50usize, 200, 1_000] {
        let mut engine = SearchEngine::new();
        let claims = (0..size)
            .map(|i| {
                (
                    format!(
                        "synthetic benchmark document {i} about astronomy climate ocean ecology"
                    ),
                    EmpiricalLevel::E1,
                    vec![format!("https://example.test/bench/{i}")],
                    vec!["synthetic-benchmark".to_string()],
                )
            })
            .collect::<Vec<_>>();
        engine.add_claims(claims);

        group.bench_with_input(
            BenchmarkId::new("query", size),
            &engine,
            |bencher, index| {
                bencher.iter(|| black_box(index.search("astronomy climate", 10)))
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_binary_hv_similarity,
    bench_binary_hv_bind,
    bench_binary_hv_bundle_10,
    bench_encode_text,
    bench_search,
    bench_search_by_corpus_size,
);
criterion_main!(benches);
