#!/usr/bin/env python3
"""Positive and negative regression tests for Prism's browser result capsule."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from engine_ledger_schema import validate_schema_definition  # noqa: E402
from validate_engine_test_capsule import derive_outcome, validate_capsule  # noqa: E402

SCHEMA_PATH = ROOT / "docs/engine-strategy/test-capsule.schema.json"
ZERO_SHA1 = "0" * 40
ZERO_SHA256 = "0" * 64
ONE_SHA256 = "1" * 64


def valid_capsule() -> dict:
    return {
        "schema_version": "1.0.0",
        "prism_revision": ZERO_SHA1,
        "engine_id": "ladybird",
        "engine_revision": "1" * 40,
        "capability_ids": ["html_css_dom"],
        "suite": "prism_fixture",
        "suite_revision": ZERO_SHA1,
        "manifest_sha256": ZERO_SHA256,
        "manifest_case_count": 2,
        "environment": {
            "os": "linux",
            "architecture": "x86_64",
            "runner_image": "ubuntu-24.04",
            "toolchain": "clang-19 / rust-1.99.0",
            "toolchain_lock_sha256": ONE_SHA256,
            "gpu_backend": "not-applicable",
        },
        "command": "fixture-runner --manifest fixtures.json",
        "generated_at_utc": "2026-10-15T20:00:00Z",
        "cases": [
            {
                "case_id": "fixture/basic-html",
                "input_sha256": ZERO_SHA256,
                "expectation_ref": "prism-fixture/basic-html",
                "outcome": "passed",
                "actual_sha256": ONE_SHA256,
                "duration_ms": 2,
            },
            {
                "case_id": "fixture/malformed-html",
                "input_sha256": ONE_SHA256,
                "expectation_ref": "prism-fixture/malformed-html",
                "outcome": "passed",
                "actual_sha256": ZERO_SHA256,
                "duration_ms": 5,
            },
        ],
        "summary": {
            "passed": 2, "failed": 0, "timeout": 0,
            "unsupported": 0, "skipped": 0, "not_run": 0, "total": 2,
        },
    }


class EngineTestCapsuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    def test_schema_uses_only_supported_keywords(self) -> None:
        self.assertEqual(validate_schema_definition(self.schema), [])

    def test_accepts_consistent_all_pass_capsule(self) -> None:
        self.assertEqual(validate_capsule(self.schema, valid_capsule()), [])

    def test_detects_summary_tampering(self) -> None:
        capsule = valid_capsule()
        capsule["summary"]["passed"] = 1
        errors = validate_capsule(self.schema, capsule)
        self.assertTrue(any("summary.passed does not match" in error for error in errors))

    def test_requires_each_manifest_case_to_be_represented(self) -> None:
        capsule = valid_capsule()
        capsule["manifest_case_count"] = 3
        errors = validate_capsule(self.schema, capsule)
        self.assertTrue(any("cases length does not match manifest_case_count" in error for error in errors))

    def test_rejects_duplicate_case_ids(self) -> None:
        capsule = valid_capsule()
        capsule["cases"][1]["case_id"] = capsule["cases"][0]["case_id"]
        errors = validate_capsule(self.schema, capsule)
        self.assertTrue(any("duplicate case_id" in error for error in errors))

    def test_passed_case_requires_actual_output_digest(self) -> None:
        capsule = valid_capsule()
        capsule["cases"][0]["actual_sha256"] = None
        errors = validate_capsule(self.schema, capsule)
        self.assertTrue(any("needs an actual_sha256" in error for error in errors))

    def test_unsupported_case_makes_run_incomplete(self) -> None:
        capsule = valid_capsule()
        capsule["cases"][1]["outcome"] = "unsupported"
        capsule["cases"][1]["actual_sha256"] = None
        capsule["summary"] = {
            "passed": 1, "failed": 0, "timeout": 0,
            "unsupported": 1, "skipped": 0, "not_run": 0, "total": 2,
        }
        self.assertEqual(validate_capsule(self.schema, capsule), [])
        self.assertEqual(derive_outcome(capsule), "incomplete")

    def test_failure_and_timeout_take_precedence(self) -> None:
        capsule = valid_capsule()
        capsule["cases"][0]["outcome"] = "failed"
        capsule["summary"]["passed"] = 1
        capsule["summary"]["failed"] = 1
        self.assertEqual(derive_outcome(capsule), "failed")

    def test_rejects_unknown_output_field(self) -> None:
        capsule = valid_capsule()
        capsule["cases"][0]["confidence"] = 0.99
        errors = validate_capsule(self.schema, capsule)
        self.assertTrue(any("forbidden additional property: confidence" in error for error in errors))


if __name__ == "__main__":
    unittest.main(verbosity=2)
