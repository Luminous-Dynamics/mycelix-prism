#!/usr/bin/env python3
"""Fail-closed structural and semantic checks for Prism's benchmark scorecard."""
from __future__ import annotations

import json
import math
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "docs/engine-strategy/benchmark-scorecard.schema.json"
SCORECARD_PATH = ROOT / "docs/engine-strategy/benchmark-scorecard.json"
ALLOWED_CLASS = {"correctness", "conformance", "security", "privacy", "performance", "resource", "reliability", "industry-comparator"}
REQUIRED_POLICY_NONINTERFERENCE_METRICS = (
    "unauthorized_side_effects",
    "unconsented_cross_zone_flows",
    "post_revocation_completions",
    "policy_evaluation_fail_open_count",
)


def _allowed(value: Any, allowed: set[str]) -> bool:
    return isinstance(value, str) and value in allowed


def validate_scorecard(schema: Any, scorecard: Any) -> list[str]:
    from engine_ledger_schema import validate_instance, validate_schema_definition

    errors = validate_schema_definition(schema)
    if errors:
        return [f"schema contract error: {e}" for e in errors]
    errors = validate_instance(scorecard, schema)
    if not isinstance(scorecard, dict):
        return errors or ["scorecard root must be an object"]

    protocol = scorecard.get("measurement_protocol")
    if isinstance(protocol, dict):
        warmups = protocol.get("warmup_runs")
        measured = protocol.get("measured_runs")
        minimum = protocol.get("minimum_baseline_samples_for_regression_gates")
        paired_blocks = protocol.get("minimum_paired_blocks_for_regression_gates")
        release_blocks = protocol.get("minimum_paired_blocks_for_release_gates")
        bootstrap_replicates = protocol.get("bootstrap_replicates")
        alpha = protocol.get("familywise_alpha")
        if isinstance(paired_blocks, bool) or not isinstance(paired_blocks, int) or paired_blocks < 30:
            errors.append("at least 30 paired blocks are required before regression screening")
        if isinstance(release_blocks, bool) or not isinstance(release_blocks, int) or release_blocks < 100:
            errors.append("minimum paired blocks must be at least 100 before release-blocking performance decisions")
        if isinstance(bootstrap_replicates, bool) or not isinstance(bootstrap_replicates, int) or bootstrap_replicates < 10000:
            errors.append("bootstrap_replicates must be at least 10000 for release-blocking performance decisions")
        if isinstance(alpha, bool) or not isinstance(alpha, (int, float)) or not math.isfinite(alpha) or not 0 < alpha < 1:
            errors.append("familywise_alpha must be finite and strictly between 0 and 1")
        for policy_name in ("comparison_design", "drift_policy", "campaign_policy", "multiple_comparison_policy"):
            policy_text = protocol.get(policy_name)
            if not isinstance(policy_text, str) or not policy_text.strip():
                errors.append(f"{policy_name} must be a non-empty reproducibility policy")
        if isinstance(warmups, bool) or not isinstance(warmups, int) or warmups < 0:
            errors.append("warmup_runs must be a non-negative integer")
        if isinstance(measured, bool) or not isinstance(measured, int) or measured < 10:
            errors.append("measured_runs must be at least 10")
        if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 30:
            errors.append("minimum baseline samples must be at least 30 before regression gating")
        report_stats = protocol.get("report_statistics")
        if (
            not isinstance(report_stats, list)
            or any(not isinstance(item, str) for item in report_stats)
            or not {
                "median", "p95", "IQR", "MAD", "raw samples",
                "first-half/second-half medians", "paired relative-effect distribution",
                "95% paired-effect confidence interval", "raw and Holm-adjusted p-values",
            }.issubset(set(report_stats))
        ):
            errors.append("report_statistics must retain median, p95, IQR, MAD and raw samples, plus first-half/second-half medians, paired relative-effect distribution, a 95% paired-effect confidence interval, and raw and Holm-adjusted p-values")

    suites = scorecard.get("suites")
    if not isinstance(suites, list):
        return errors + ["suites must be a list"]
    suite_ids: set[str] = set()
    metric_keys: set[tuple[str, str]] = set()
    for index, suite in enumerate(suites):
        prefix = f"suites[{index}]"
        if not isinstance(suite, dict):
            errors.append(f"{prefix} must be an object")
            continue
        suite_id = suite.get("id")
        if isinstance(suite_id, str):
            if suite_id in suite_ids:
                errors.append(f"duplicate suite id: {suite_id}")
            suite_ids.add(suite_id)
        if not _allowed(suite.get("class"), ALLOWED_CLASS):
            errors.append(f"{prefix}.class is not allowed")
        metrics = suite.get("metrics")
        if not isinstance(metrics, list):
            errors.append(f"{prefix}.metrics must be a list")
            continue
        seen_metrics: set[str] = set()
        for mindex, metric in enumerate(metrics):
            mpath = f"{prefix}.metrics[{mindex}]"
            if not isinstance(metric, dict):
                errors.append(f"{mpath} must be an object")
                continue
            metric_id = metric.get("metric_id")
            if isinstance(metric_id, str):
                if metric_id in seen_metrics:
                    errors.append(f"duplicate metric id {metric_id} within suite {suite_id}")
                seen_metrics.add(metric_id)
                metric_keys.add((suite_id, metric_id))
            direction = metric.get("direction")
            target = metric.get("target_value")
            stage = metric.get("target_stage")
            gate = metric.get("gate_when_activated")
            if direction == "baseline_only":
                if target is not None or stage != "baseline_only" or gate is True:
                    errors.append(f"{mpath} baseline-only metrics must not invent a score target or release gate when activated")
            elif target is None:
                errors.append(f"{mpath} needs a numeric target unless it is explicitly baseline_only")
            elif isinstance(target, bool) or not isinstance(target, (int, float)) or not math.isfinite(target) or target < 0:
                errors.append(f"{mpath} target must be a finite, non-negative number")
            if stage == "provisional" and gate is True:
                errors.append(f"{mpath} provisional target cannot be an active release gate; a provisional target cannot be a release gate when activated")
            if direction == "must_equal" and target is None:
                errors.append(f"{mpath} must_equal metric needs an explicit target")
    ids = {s.get("id") for s in suites if isinstance(s, dict) and isinstance(s.get("id"), str)}
    for required in ("local-fixture-correctness", "wpt-supported-subset", "broker-negative-controls", "local-only-egress", "policy-noninterference"):
        if required not in ids:
            errors.append(f"required P0 suite missing: {required}")
    privacy_suite = next(
        (suite for suite in suites if isinstance(suite, dict) and suite.get("id") == "policy-noninterference"),
        None,
    )
    if privacy_suite is not None:
        raw_metrics = privacy_suite.get("metrics")
        metrics_by_id: dict[str, dict[str, Any]] = {}
        if isinstance(raw_metrics, list):
            for metric in raw_metrics:
                if isinstance(metric, dict) and isinstance(metric.get("metric_id"), str):
                    metrics_by_id[metric["metric_id"]] = metric
        for required_metric_id in REQUIRED_POLICY_NONINTERFERENCE_METRICS:
            metric = metrics_by_id.get(required_metric_id)
            if not isinstance(metric, dict):
                errors.append(f"required policy-noninterference metric missing: {required_metric_id}")
                continue
            target = metric.get("target_value")
            if (
                metric.get("direction") != "must_equal"
                or isinstance(target, bool)
                or not isinstance(target, (int, float))
                or target != 0
                or metric.get("target_stage") != "activation_gate"
                or metric.get("gate_when_activated") is not True
            ):
                errors.append(
                    f"policy-noninterference metric {required_metric_id} must remain a zero-tolerance "
                    "activation gate (must_equal 0 with gate_when_activated=true)"
                )

    return errors


def main() -> int:
    try:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        scorecard = json.loads(SCORECARD_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot read benchmark contract: {exc}", file=sys.stderr)
        return 2
    errors = validate_scorecard(schema, scorecard)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        print(f"FAIL: {len(errors)} benchmark scorecard invariant(s) violated", file=sys.stderr)
        return 1
    metric_count = sum(len(s["metrics"]) for s in scorecard["suites"])
    print(f"PASS: benchmark scorecard structurally valid ({len(scorecard['suites'])} suites, {metric_count} metrics)")
    print("NOTE: targets are protocol entries, not measured scores; blocked suites have not run.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
