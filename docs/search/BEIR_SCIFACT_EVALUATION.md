# Real-corpus evaluation: BEIR SciFact

## Purpose

Use the actual BEIR SciFact test split to compare Prism's BinaryHV/HDC search with a small, deterministic BM25 lexical baseline. This is intentionally separate from the committed synthetic smoke fixture: a passing synthetic test validates the evaluator plumbing, not retrieval quality on an external corpus.

This benchmark is exploratory and local-data-only. It does not claim that Prism matches BEIR's official leaderboard implementations or preprocessing.

## Obtain the data explicitly

Download the official BEIR SciFact archive from the BEIR project's published distribution:

- Archive: https://public.ukp.informatik.tu-darmstadt.de/thakur/BEIR/datasets/scifact.zip
- Published archive MD5 in the BEIR dataset list: 5f7d1de60b170fc8027bb7898e2efca1
- BEIR dataset reference: https://github.com/beir-cellar/beir/wiki/Datasets-available
- Expected extracted files: corpus.jsonl, queries.jsonl, and qrels/test.tsv.

Example, after separately downloading the archive into your chosen directory:

~~~sh
printf '%s  %s\n' '5f7d1de60b170fc8027bb7898e2efca1' './scifact.zip' | md5sum --check
unzip ./scifact.zip -d ./datasets
find ./datasets -type f \( -name corpus.jsonl -o -name queries.jsonl -o -path '*/qrels/test.tsv' \) -print
~~~

Pass the directory that directly contains corpus.jsonl and queries.jsonl and whose qrels subdirectory contains test.tsv. Nothing is downloaded automatically by the Rust program. No benchmark corpus or labels are committed to Prism, and normal CI does not fetch this research dataset. The reader enforces hard input limits of 64 MiB for `corpus.jsonl`, 8 MiB for `queries.jsonl`, and 8 MiB for `qrels/test.tsv`; oversize inputs fail before parsing proceeds.

## Run

From the Prism repository root:

~~~sh
nix develop --command cargo run --release -p prism-search --bin evaluate_beir_scifact -- /path/to/scifact > scifact-prism-report.json
~~~

The directory should be supplied locally. The program reads the corpus, query records, and test qrels; validates their IDs and relationships; and exits nonzero on malformed JSONL, a bad qrels header, duplicate IDs or judgment pairs, unknown IDs, unsupported relevance grades, or a query with no positive relevance labels.

The JSON report contains:

- counts for documents, query records, judged queries and positive judgments;
- the raw-byte BLAKE3 fingerprint and byte length of each input file (paths are reported as logical filenames, not absolute paths);
- Prism HDC and local BM25 macro-averaged MRR@10, nDCG@10, and Recall@100;
- index build times and per-query mean, p50, p95, and maximum retrieval latencies;
- each judged query's top 10 IDs from each ranker, plus per-query metrics;
- a boolean saying whether input counts match the common BEIR SciFact reference counts: 5,183 documents, 1,109 query records, and 300 test queries.

The count flag is a diagnostic rather than proof of dataset identity. Preserve the report's three BLAKE3 hashes to distinguish exact input bytes. The report intentionally avoids recording absolute input paths. Archive MD5 verifies against the published historical digest only; it is not a signature.

## Ranking and metric contract

- Each corpus item is indexed as title plus text (omitting empty fields). Its original corpus ID is carried in a private source marker in the in-memory index so retrieval results map back to qrels IDs without ambiguous text matching.
- All records receive the same E2 evidence level. The evidence term is therefore constant across this benchmark; the experiment measures the HDC similarity/retrieval implementation, not evidence-level policy.
- Prism's current search API returns at most 100 items. Consequently this harness uses MRR@10, nDCG@10, and Recall@100; it does not claim Recall@1000.
- The BM25 baseline uses the same title/text strings, a documented local implementation with k1=1.2 and b=0.75, and deterministic document-ID tie breaks. It is a useful lexical comparator, not a substitute for BEIR's official evaluator.
- Metrics are macro averages across query IDs present in qrels/test.tsv, not across all query records. Only positive grades count as relevant. The parser supports qrels grades 0–3 and rejects duplicate pairs.
- Run in release mode for a primary performance measurement. Record host/CPU, OS, Rust version, Nix flake revision, build mode, and any concurrent workload alongside the report before making latency claims.

## License and attribution boundaries

The original SciFact repository states that the claims and evidence annotations are CC BY 4.0, while article abstracts in its corpus are part of S2ORC and licensed under ODC-By 1.0: https://github.com/allenai/scifact/blob/master/LICENSE.md. The BEIR-hosted SciFact dataset card labels its repackaged dataset CC BY-SA 4.0: https://huggingface.co/datasets/BeIR/scifact. Review the terms and attribution obligations for the exact distribution you use. This repository intentionally stores only the evaluator code and generated aggregate/report data; users are responsible for obtaining and using source data lawfully.

## Limits and next steps

1. Run the evaluator against the exact, verified test inputs and archive its JSON report with the commit SHA and machine/toolchain details.
2. Review HDC and BM25 quality separately from build/query latency. A difference on this one scientific claim-retrieval dataset is not evidence of universal search quality.
3. Investigate errors by query and document IDs against the source annotations. Do not tune the held-out test split repeatedly and then present it as an untouched evaluation.
4. Only after measured relevance and recall justify it, evaluate changes to approximate retrieval or the API's top-k cap. Do not introduce an approximate prefilter without an exhaustive-retrieval recall comparison.
5. For broader claims, add separately licensed and pinned domains (for example, other BEIR tasks) with explicit dataset-specific score semantics. Do not merge corpora with incompatible qrels or reuse one dataset's license label for another.
