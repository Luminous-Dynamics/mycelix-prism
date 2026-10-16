#!/usr/bin/env python3
"""Positive and negative tests for policy noninterference evidence capsules."""
from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from validate_policy_noninterference_capsule import validate_capsule, validate_manifest, derive_outcome  # noqa: E402

SCHEMA_PATH = ROOT / "docs/engine-strategy/policy-noninterference-capsule.schema.json"
MANIFEST_PATH = ROOT / "docs/engine-strategy/policy-noninterference-manifest.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
MANIFEST_BYTES = MANIFEST_PATH.read_bytes()
MANIFEST = json.loads(MANIFEST_BYTES)
ZERO = "0" * 64
KINDS = [scenario["kind"] for scenario in MANIFEST["scenarios"]]


def make_case(scenario: dict, index: int) -> dict:
    pre = f"{index + 1:064x}"
    post = pre
    expected = scenario["expected_decision"]
    observed = expected
    effects = {
        "state_writes": 0,
        "share_queue_writes": 0,
        "privileged_actions": 0,
        "outbound_flows": 0,
        "post_revocation_completions": 0,
    }
    if scenario["kind"] == "authorized_control":
        post = f"{index + 99:064x}"
        effects["state_writes"] = 1
    consent = {
        "present": False,
        "data_scope_matches": False,
        "recipient_matches": False,
        "purpose_matches": False,
        "not_expired": False,
    }
    return {
        "case_id": scenario["case_id"],
        "kind": scenario["kind"],
        "source_zone": scenario["source_zone"],
        "destination_zone": scenario["destination_zone"],
        "expected_decision": expected,
        "observed_decision": observed,
        "policy_failure_mode": scenario["policy_failure_mode"],
        "consent": consent,
        "revocation_acknowledged": scenario["kind"] == "post_revocation",
        "completed_after_revocation": False,
        "pre_state_sha256": pre,
        "post_state_sha256": post,
        "output_sha256": f"{index + 101:064x}",
        "event_trace_sha256": f"{index + 201:064x}",
        "observability": {"state_digest": True, "share_queue": True, "privileged_actions": True, "egress": True},
        "side_effects": effects,
    }


def make_capsule() -> dict:
    cases = [make_case(scenario, index) for index, scenario in enumerate(MANIFEST["scenarios"])]
    return {
        "schema_version": "1.0.0",
        "suite_id": "policy-noninterference",
        "prism_revision": "a" * 40,
        "policy_revision": "b" * 40,
        "manifest_sha256": hashlib.sha256(MANIFEST_BYTES).hexdigest(),
        "manifest_case_ids": [scenario["case_id"] for scenario in MANIFEST["scenarios"]],
        "manifest_case_count": len(cases),
        "environment": {
            "os": "linux",
            "architecture": "x86_64",
            "runner_image": "pinned-image@sha256:example",
            "toolchain": "rustc 1.99.0; policy harness 0.1",
            "toolchain_lock_sha256": "d" * 64,
        },
        "command": "nix develop --command cargo test -p prism-privacy --locked",
        "generated_at_utc": "2026-10-16T00:00:00Z",
        "cases": cases,
    }


class PolicyNoninterferenceCapsuleTests(unittest.TestCase):
    def test_positive_complete_capsule_derives_pass(self) -> None:
        capsule = make_capsule()
        self.assertEqual(validate_capsule(SCHEMA, capsule), [])
        self.assertEqual(derive_outcome(capsule), "passed")

    def test_rejects_manifest_digest_mismatch(self) -> None:
        capsule = make_capsule()
        capsule["manifest_sha256"] = "e" * 64
        self.assertTrue(any("does not match the exact scenario manifest bytes" in e for e in validate_capsule(SCHEMA, capsule)))

    def test_rejects_manifest_case_order_or_set_mismatch(self) -> None:
        capsule = make_capsule()
        capsule["manifest_case_ids"].reverse()
        self.assertTrue(any("ordered canonical manifest IDs" in e for e in validate_capsule(SCHEMA, capsule)))

    def test_rejects_case_decision_that_differs_from_manifest(self) -> None:
        capsule = make_capsule()
        capsule["cases"][0]["expected_decision"] = "allow"
        self.assertTrue(any("expected_decision differs from canonical manifest" in e for e in validate_capsule(SCHEMA, capsule)))

    def test_rejects_case_manifest_count_mismatch(self) -> None:
        capsule = make_capsule()
        capsule["manifest_case_count"] -= 1
        self.assertTrue(any("does not match manifest_case_count" in e for e in validate_capsule(SCHEMA, capsule)))

    def test_rejects_case_id_set_mismatch(self) -> None:
        capsule = make_capsule()
        capsule["cases"][0]["case_id"] = "case/not-in-manifest"
        self.assertTrue(any("case IDs and order" in e for e in validate_capsule(SCHEMA, capsule)))

    def test_rejects_duplicate_case_id(self) -> None:
        capsule = make_capsule()
        capsule["cases"][1]["case_id"] = capsule["cases"][0]["case_id"]
        self.assertTrue(any("duplicate case_id" in e for e in validate_capsule(SCHEMA, capsule)))

    def test_rejects_manifest_missing_required_scenario_kind(self) -> None:
        manifest = dict(MANIFEST)
        manifest["scenarios"] = [scenario for scenario in MANIFEST["scenarios"] if scenario["kind"] != "expired_authority"]
        self.assertTrue(any("each required scenario kind exactly once" in e for e in validate_manifest(manifest)))

    def test_denial_with_side_effect_fails_not_passes(self) -> None:
        capsule = make_capsule()
        capsule["cases"][0]["side_effects"]["privileged_actions"] = 1
        self.assertEqual(derive_outcome(capsule), "failed")

    def test_unconsented_cross_zone_egress_fails(self) -> None:
        capsule = make_capsule()
        case = next(c for c in capsule["cases"] if c["kind"] == "unconsented_cross_zone")
        case["side_effects"]["outbound_flows"] = 1
        self.assertEqual(derive_outcome(capsule), "failed")

    def test_post_revocation_completion_fails(self) -> None:
        capsule = make_capsule()
        case = next(c for c in capsule["cases"] if c["kind"] == "post_revocation")
        case["completed_after_revocation"] = True
        case["side_effects"]["post_revocation_completions"] = 1
        self.assertEqual(derive_outcome(capsule), "failed")

    def test_policy_failure_that_allows_fails(self) -> None:
        capsule = make_capsule()
        case = next(c for c in capsule["cases"] if c["kind"] == "policy_evaluation_failure")
        case["observed_decision"] = "allow"
        self.assertEqual(derive_outcome(capsule), "failed")

    def test_noninterference_requires_unchanged_state_digest(self) -> None:
        capsule = make_capsule()
        capsule["cases"][1]["post_state_sha256"] = "e" * 64
        self.assertEqual(derive_outcome(capsule), "failed")

    def test_missing_telemetry_blocks_pass(self) -> None:
        capsule = make_capsule()
        capsule["cases"][2]["observability"]["egress"] = False
        self.assertEqual(derive_outcome(capsule), "blocked")

    def test_missing_required_scenario_is_incomplete(self) -> None:
        capsule = make_capsule()
        capsule["cases"] = [case for case in capsule["cases"] if case["kind"] != "expired_authority"]
        capsule["manifest_case_ids"] = [scenario["case_id"] for scenario in MANIFEST["scenarios"] if scenario["kind"] != "expired_authority"]
        capsule["manifest_case_count"] = len(capsule["cases"])
        self.assertEqual(derive_outcome(capsule), "incomplete")

    def test_authorized_control_must_exercise_observable_write(self) -> None:
        capsule = make_capsule()
        case = next(c for c in capsule["cases"] if c["kind"] == "authorized_control")
        case["side_effects"]["state_writes"] = 0
        self.assertEqual(derive_outcome(capsule), "failed")

    def test_rejects_bool_used_as_side_effect_count(self) -> None:
        capsule = make_capsule()
        capsule["cases"][0]["side_effects"]["state_writes"] = True
        self.assertTrue(any("non-negative integer" in e for e in validate_capsule(SCHEMA, capsule)))

    def test_requires_revocation_acknowledgement_for_revocation_case(self) -> None:
        capsule = make_capsule()
        case = next(c for c in capsule["cases"] if c["kind"] == "post_revocation")
        case["revocation_acknowledged"] = False
        self.assertTrue(any("requires observed revocation acknowledgement" in e for e in validate_capsule(SCHEMA, capsule)))

    def test_derive_outcome_fails_closed_for_malformed_case(self) -> None:
        capsule = make_capsule()
        capsule["cases"][0] = "not-an-object"
        self.assertEqual(derive_outcome(capsule), "incomplete")

    def test_derive_outcome_fails_closed_for_malformed_effects(self) -> None:
        capsule = make_capsule()
        capsule["cases"][0]["side_effects"] = None
        self.assertEqual(derive_outcome(capsule), "blocked")

    def test_manifest_malformed_unhashable_fields_do_not_crash(self) -> None:
        manifest = dict(MANIFEST)
        manifest["required_observability"] = [{}]
        self.assertTrue(any("required_observability" in e for e in validate_manifest(manifest)))

    def test_manifest_scenario_malformed_enum_does_not_crash(self) -> None:
        manifest = dict(MANIFEST)
        manifest["scenarios"] = [dict(item) for item in MANIFEST["scenarios"]]
        manifest["scenarios"][0]["expected_side_effects"] = {}
        self.assertTrue(any("expected_side_effects" in e for e in validate_manifest(manifest)))

    def test_derive_outcome_fails_closed_for_unhashable_kind(self) -> None:
        capsule = make_capsule()
        capsule["cases"][0]["kind"] = {"unexpected": "object"}
        self.assertEqual(derive_outcome(capsule), "incomplete")

    def test_derive_outcome_fails_closed_for_unhashable_expected_decision(self) -> None:
        capsule = make_capsule()
        capsule["cases"][0]["expected_decision"] = ["deny"]
        self.assertEqual(derive_outcome(capsule), "incomplete")

    def test_manifest_unhashable_post_revocation_decision_does_not_crash(self) -> None:
        manifest = dict(MANIFEST)
        manifest["scenarios"] = [dict(item) for item in MANIFEST["scenarios"]]
        scenario = next(item for item in manifest["scenarios"] if item["kind"] == "post_revocation")
        scenario["expected_decision"] = []
        self.assertTrue(any("post_revocation must expect" in e for e in validate_manifest(manifest)))

    def test_policy_capsule_schema_is_in_supported_subset(self) -> None:
        from engine_ledger_schema import validate_schema_definition
        self.assertEqual(validate_schema_definition(SCHEMA), [])
