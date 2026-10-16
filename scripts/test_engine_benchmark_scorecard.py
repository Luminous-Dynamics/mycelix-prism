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
        metric["gate_when_activated"] = True
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

    def test_requires_100_paired_blocks_for_release_gate(self) -> None:
        scorecard = copy.deepcopy(SCORECARD)
        scorecard["measurement_protocol"]["minimum_paired_blocks_for_release_gates"] = 30
        self.assertTrue(any("at least 100" in e for e in validate_scorecard(SCHEMA, scorecard)))

    def test_requires_bootstrap_replicates_and_valid_alpha(self) -> None:
        scorecard = copy.deepcopy(SCORECARD)
        scorecard["measurement_protocol"]["bootstrap_replicates"] = 999
        scorecard["measurement_protocol"]["familywise_alpha"] = float("nan")
        errors = validate_scorecard(SCHEMA, scorecard)
        self.assertTrue(any("at least 10000" in e for e in errors))
        self.assertTrue(any("finite and strictly between 0 and 1" in e for e in errors))

    def test_requires_multiple_comparison_policy(self) -> None:
        scorecard = copy.deepcopy(SCORECARD)
        scorecard["measurement_protocol"]["multiple_comparison_policy"] = ""
        self.assertTrue(any("multiple_comparison_policy must be a non-empty reproducibility policy" in e for e in validate_scorecard(SCHEMA, scorecard)))

    def test_requires_paired_blocks_before_regression_gating(self) -> None:
        scorecard = copy.deepcopy(SCORECARD)
        scorecard["measurement_protocol"]["minimum_paired_blocks_for_regression_gates"] = 5
        self.assertTrue(any("at least 30 paired blocks" in e for e in validate_scorecard(SCHEMA, scorecard)))

    def test_requires_first_half_second_half_statistics(self) -> None:
        scorecard = copy.deepcopy(SCORECARD)
        scorecard["measurement_protocol"]["report_statistics"].remove("first-half/second-half medians")
        self.assertTrue(any("first-half/second-half medians" in e for e in validate_scorecard(SCHEMA, scorecard)))

    def test_requires_explicit_drift_policy(self) -> None:
        scorecard = copy.deepcopy(SCORECARD)
        scorecard["measurement_protocol"]["drift_policy"] = "   "
        self.assertTrue(any("drift_policy must be a non-empty reproducibility policy" in e for e in validate_scorecard(SCHEMA, scorecard)))

    def test_requires_tail_and_variability_statistics(self) -> None:
        scorecard = copy.deepcopy(SCORECARD)
        scorecard["measurement_protocol"]["report_statistics"] = ["mean"]
        self.assertTrue(any("median, p95, IQR, MAD and raw samples" in e for e in validate_scorecard(SCHEMA, scorecard)))

    def test_requires_security_and_privacy_suites(self) -> None:
        scorecard = copy.deepcopy(SCORECARD)
        scorecard["suites"] = [s for s in scorecard["suites"] if s["id"] != "local-only-egress"]
        self.assertTrue(any("required P0 suite missing" in e for e in validate_scorecard(SCHEMA, scorecard)))

    def test_requires_policy_noninterference_suite(self) -> None:
        scorecard = copy.deepcopy(SCORECARD)
        scorecard["suites"] = [s for s in scorecard["suites"] if s["id"] != "policy-noninterference"]
        self.assertTrue(any("required P0 suite missing: policy-noninterference" in e for e in validate_scorecard(SCHEMA, scorecard)))

    def test_requires_all_policy_noninterference_metrics(self) -> None:
        scorecard = copy.deepcopy(SCORECARD)
        suite = next(s for s in scorecard["suites"] if s["id"] == "policy-noninterference")
        suite["metrics"] = [m for m in suite["metrics"] if m["metric_id"] != "unconsented_cross_zone_flows"]
        self.assertTrue(any("required policy-noninterference metric missing: unconsented_cross_zone_flows" in e for e in validate_scorecard(SCHEMA, scorecard)))

    def test_rejects_weakened_policy_noninterference_gate(self) -> None:
        scorecard = copy.deepcopy(SCORECARD)
        suite = next(s for s in scorecard["suites"] if s["id"] == "policy-noninterference")
        metric = next(m for m in suite["metrics"] if m["metric_id"] == "post_revocation_completions")
        metric["target_value"] = 1
        self.assertTrue(any("must remain a zero-tolerance activation gate" in e for e in validate_scorecard(SCHEMA, scorecard)))

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

    def test_rejects_non_finite_target(self) -> None:
        scorecard = copy.deepcopy(SCORECARD)
        scorecard["suites"][0]["metrics"][0]["target_value"] = float("nan")
        self.assertTrue(any("finite, non-negative number" in e for e in validate_scorecard(SCHEMA, scorecard)))

    def test_provisional_metrics_are_not_active_release_gates(self) -> None:
        scorecard = copy.deepcopy(SCORECARD)
        metric = next(m for s in scorecard["suites"] for m in s["metrics"] if m["target_stage"] == "provisional")
        self.assertFalse(metric["gate_when_activated"])
        metric["gate_when_activated"] = True
        self.assertTrue(any("provisional target cannot be a release gate when activated" in e for e in validate_scorecard(SCHEMA, scorecard)))

    def test_rejects_missing_numeric_target(self) -> None:
        scorecard = copy.deepcopy(SCORECARD)
        scorecard["suites"][0]["metrics"][0]["target_value"] = None
        self.assertTrue(any("needs a numeric target" in e for e in validate_scorecard(SCHEMA, scorecard)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
