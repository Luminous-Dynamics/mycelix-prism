#!/usr/bin/env python3
"""Validate Prism browser-test result capsules without running browser tests."""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "docs/engine-strategy/test-capsule.schema.json"
OUTCOMES = ("passed", "failed", "timeout", "unsupported", "skipped", "not_run")
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def validate_capsule(schema: Any, capsule: Any) -> list[str]:
    """Check schema and cross-field invariants; no network access is used."""
    from engine_ledger_schema import validate_instance, validate_schema_definition

    schema_errors = validate_schema_definition(schema)
    if schema_errors:
        return [f"schema contract error: {error}" for error in schema_errors]
    errors = validate_instance(capsule, schema)
    if not isinstance(capsule, dict):
        return errors or ["capsule root must be an object"]

    for field in ("prism_revision", "engine_revision", "suite_revision"):
        value = capsule.get(field)
        if not isinstance(value, str) or not SHA1_RE.fullmatch(value):
            errors.append(f"{field} must be a full lowercase 40-character commit SHA")
    if not isinstance(capsule.get("manifest_sha256"), str) or not SHA256_RE.fullmatch(capsule["manifest_sha256"]):
        errors.append("manifest_sha256 must be a full lowercase SHA-256 digest")

    manifest_count = capsule.get("manifest_case_count")
    if isinstance(manifest_count, bool) or not isinstance(manifest_count, int) or manifest_count < 1:
        errors.append("manifest_case_count must be a positive integer")

    timestamp = capsule.get("generated_at_utc")
    if isinstance(timestamp, str):
        try:
            parsed = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != timestamp:
                errors.append("generated_at_utc is not canonical UTC time")
        except ValueError:
            errors.append("generated_at_utc is not a real UTC timestamp")

    cases = capsule.get("cases")
    summary = capsule.get("summary")
    if not isinstance(cases, list):
        return errors + ["cases must be a list"]
    if not isinstance(summary, dict):
        return errors + ["summary must be an object"]
    if isinstance(manifest_count, int) and not isinstance(manifest_count, bool) and len(cases) != manifest_count:
        errors.append("cases length does not match manifest_case_count; missing or extra cases must be explicit")

    ids: set[str] = set()
    observed = {outcome: 0 for outcome in OUTCOMES}
    for index, case in enumerate(cases):
        prefix = f"cases[{index}]"
        if not isinstance(case, dict):
            errors.append(f"{prefix} must be an object")
            continue
        case_id = case.get("case_id")
        if isinstance(case_id, str):
            if case_id in ids:
                errors.append(f"duplicate case_id: {case_id}")
            ids.add(case_id)
        outcome = case.get("outcome")
        if outcome not in OUTCOMES:
            continue
        observed[outcome] += 1
        elapsed = case.get("duration_ms")
        if isinstance(elapsed, bool) or not isinstance(elapsed, int) or elapsed < 0:
            errors.append(f"{prefix}.duration_ms must be a non-negative integer")
        actual_digest = case.get("actual_sha256")
        if outcome in {"passed", "failed"} and (
            not isinstance(actual_digest, str) or not SHA256_RE.fullmatch(actual_digest)
        ):
            errors.append(f"{prefix} needs an actual_sha256 digest for a passed/failed observation")

    for outcome in OUTCOMES:
        count = summary.get(outcome)
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            errors.append(f"summary.{outcome} must be a non-negative integer")
        elif count != observed[outcome]:
            errors.append(f"summary.{outcome} does not match per-case outcomes")
    total = summary.get("total")
    if isinstance(total, bool) or not isinstance(total, int) or total < 0:
        errors.append("summary.total must be a non-negative integer")
    elif total != len(cases):
        errors.append("summary.total does not match the number of case records")

    return errors


def derive_outcome(capsule: dict[str, Any]) -> str:
    """Derive overall status from per-case records instead of trusting a label."""
    summary = capsule["summary"]
    if summary["failed"] > 0 or summary["timeout"] > 0:
        return "failed"
    if summary["unsupported"] > 0 or summary["skipped"] > 0 or summary["not_run"] > 0:
        return "incomplete"
    return "passed"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-schema", action="store_true", help="validate schema support without claiming any run happened")
    parser.add_argument("--capsule", type=Path, help="path to one result-capsule JSON file")
    args = parser.parse_args()
    try:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot load capsule schema: {exc}", file=sys.stderr)
        return 2

    from engine_ledger_schema import validate_schema_definition
    schema_errors = validate_schema_definition(schema)
    if schema_errors:
        for error in schema_errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    if args.check_schema:
        print("PASS: test-capsule schema uses only supported, checked keywords")
        return 0
    if args.capsule is None:
        parser.error("provide --check-schema or --capsule")
    try:
        capsule = json.loads(args.capsule.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot load capsule: {exc}", file=sys.stderr)
        return 2
    errors = validate_capsule(schema, capsule)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        print(f"FAIL: {len(errors)} test-capsule invariant(s) violated", file=sys.stderr)
        return 1
    print(f"PASS: result capsule structurally consistent ({len(capsule['cases'])} cases; derived outcome={derive_outcome(capsule)})")
    print("NOTE: this validates a record, not the browser behavior it describes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
