#!/usr/bin/env python3
"""Positive and negative tests for Prism's benchmark scorecard contract."""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from validate_engine_benchmark_scorecard import validate_scorecard  # noqa: E402

SCHEMA = json.loads((ROOT / "docs/engine-strategy/benchmark-scorecard.schema.json").read_text(encoding="utf-8"))
SCORECARD = json.loads((ROOT / "docs/engine-strategy/benchmark-scorecard.json").read_text(encoding="utf-8"))


class BenchmarkScorecardTests(unittest.TestCase):
    def test_current_scorecard_valid(self) -> None:
        self.assertEqual(validate_scorecard(SCHEMA, SCORECARD), [])

    def test_rejects_duplicate_suite_id(self) -> None:
        scorecard = copy.deepcopy(SCORECARD)
        scorecard["suites"].append(copy.deepcopy(scorecard["suites"][0]))
        self.assertTrue(any("duplicate suite id" in e for e in validate_scorecard(SCHEMA, scorecard)))

    def test_rejects_duplicate_metric_id(self) -> None:
        scorecard = copy.deepcopy(SCORECARD)
        suite = scorecard["suites"][0]
        suite["metrics"].append(copy.deepcopy(suite["metrics"][0]))
        self.assertTrue(any("duplicate metric id" in e for e in validate_scorecard(SCHEMA, scorecard)))

    def test_rejects_perf_gate_before_baseline(self) -> None:
        scorecard = copy.deepcopy(SCORECARD)
        metric = next(m for s in scorecard["suites"] for m in s["metrics"] if m["target_stage"] == "provisional")
        metric["release_gate"] = True
        self.assertTrue(any("provisional target cannot be an active release gate" in e for e in validate_scorecard(SCHEMA, scorecard)))

    def test_rejects_invented_industry_score_target(self) -> None:
        scorecard = copy.deepcopy(SCORECARD)
        suite = next(s for s in scorecard["suites"] if s["class"] == "industry-comparator")
        suite["metrics"][0]["target_value"] = 12345
        self.assertTrue(any("baseline-only metrics must not invent a score target" in e for e in validate_scorecard(SCHEMA, scorecard)))

    def test_requires_enough_baseline_samples(self) -> None:
        scorecard = copy.deepcopy(SCORECARD)
        scorecard["measurement_protocol"]["minimum_baseline_samples_for_regression_gates"] = 5
        self.assertTrue(any("at least 30" in e for e in validate_scorecard(SCHEMA, scorecard)))

    def test_requires_tail_and_variability_statistics(self) -> None:
        scorecard = copy.deepcopy(SCORECARD)
        scorecard["measurement_protocol"]["report_statistics"] = ["mean"]
        self.assertTrue(any("median, p95, IQR, MAD and raw samples" in e for e in validate_scorecard(SCHEMA, scorecard)))

    def test_requires_security_and_privacy_suites(self) -> None:
        scorecard = copy.deepcopy(SCORECARD)
        scorecard["suites"] = [s for s in scorecard["suites"] if s["id"] != "local-only-egress"]
        self.assertTrue(any("required P0 suite missing" in e for e in validate_scorecard(SCHEMA, scorecard)))

    def test_rejects_non_string_suite_class_without_crashing(self) -> None:
        scorecard = copy.deepcopy(SCORECARD)
        scorecard["suites"][0]["class"] = {"bad": "type"}
        errors = validate_scorecard(SCHEMA, scorecard)
        self.assertTrue(any("class is not allowed" in e for e in errors))

    def test_rejects_malformed_statistics_without_crashing(self) -> None:
        scorecard = copy.deepcopy(SCORECARD)
        scorecard["measurement_protocol"]["report_statistics"] = [{"not": "a string"}]
        errors = validate_scorecard(SCHEMA, scorecard)
        self.assertTrue(any("report_statistics must retain" in e for e in errors))

    def test_every_suite_has_authoritative_reference(self) -> None:
        scorecard = copy.deepcopy(SCORECARD)
        scorecard["suites"][0]["references"] = []
        errors = validate_scorecard(SCHEMA, scorecard)
        self.assertTrue(any("fewer than 1 items" in e for e in errors))

    def test_rejects_missing_numeric_target(self) -> None:
        scorecard = copy.deepcopy(SCORECARD)
        scorecard["suites"][0]["metrics"][0]["target_value"] = None
        self.assertTrue(any("needs a numeric target" in e for e in validate_scorecard(SCHEMA, scorecard)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
