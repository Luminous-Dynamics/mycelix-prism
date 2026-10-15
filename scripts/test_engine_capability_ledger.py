#!/usr/bin/env python3
"""Positive and negative tests for the engine capability evidence validator."""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from validate_engine_capability_ledger import SCHEMA_PATH, LEDGER_PATH, validate_documents  # noqa: E402


class EngineLedgerValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        cls.ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))

    def test_current_ledger_is_valid(self) -> None:
        self.assertEqual(validate_documents(self.schema, self.ledger), [])

    def test_rejects_unknown_evidence_reference(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        ledger["engines"][0]["capabilities"][0]["evidence_ids"].append("not-a-real-source")
        errors = validate_documents(self.schema, ledger)
        self.assertTrue(any("references unknown evidence id" in error for error in errors))

    def test_rejects_non_string_evidence_reference(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        ledger["engines"][0]["capabilities"][0]["evidence_ids"].append({"unexpected": "object"})
        errors = validate_documents(self.schema, ledger)
        self.assertTrue(any("list of unique strings" in error for error in errors))

    def test_rejects_duplicate_evidence_id(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        ledger["evidence_sources"].append(copy.deepcopy(ledger["evidence_sources"][0]))
        errors = validate_documents(self.schema, ledger)
        self.assertTrue(any("duplicate evidence source id" in error for error in errors))

    def test_rejects_duplicate_capability(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        ledger["engines"][0]["capabilities"].append(copy.deepcopy(ledger["engines"][0]["capabilities"][0]))
        errors = validate_documents(self.schema, ledger)
        self.assertTrue(any("duplicate capability_id" in error for error in errors))

    def test_rejects_malformed_git_revision(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        ledger["engines"][0]["identity"]["revision"] = "main"
        errors = validate_documents(self.schema, ledger)
        self.assertTrue(any("full lowercase 40-character SHA" in error for error in errors))

    def test_rejects_verified_claim_without_integration(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        ledger["engines"][0]["capabilities"][0]["prism_status"] = "verified"
        errors = validate_documents(self.schema, ledger)
        self.assertTrue(any("cannot be verified while engine integration is not implemented" in error for error in errors))
        self.assertTrue(any("without a passed, exact-revision Prism test artifact" in error for error in errors))

    def test_rejects_test_evidence_for_wrong_engine_revision(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        engine = ledger["engines"][0]
        engine["integration_status"] = "integrated"
        cap = engine["capabilities"][0]
        cap["prism_status"] = "verified"
        cap["evidence_ids"].append("synthetic-passing-test")
        ledger["evidence_sources"].append({
            "id": "synthetic-passing-test",
            "kind": "prism_test_result",
            "url": "https://example.invalid/test-report",
            "reviewed_at": "2026-10-15",
            "revision": None,
            "claim_scope": "negative-test fixture only; not real project evidence",
            "prism_revision": "a" * 40,
            "engine_revision": "b" * 40,
            "command": "fixture test",
            "artifact_url": "https://example.invalid/artifact",
            "result": "passed"
        })
        errors = validate_documents(self.schema, ledger)
        self.assertTrue(any("engine_revision does not match" in error for error in errors))


    def test_rejects_unknown_top_level_field(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        ledger["unreviewed_assumption"] = True
        errors = validate_documents(self.schema, ledger)
        self.assertTrue(any("forbidden additional property: unreviewed_assumption" in error for error in errors))

    def test_rejects_unknown_nested_field(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        ledger["engines"][0]["capabilities"][0]["confidence_score"] = 0.99
        errors = validate_documents(self.schema, ledger)
        self.assertTrue(any("forbidden additional property: confidence_score" in error for error in errors))

    def test_rejects_missing_schema_required_field(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        del ledger["decision"]
        errors = validate_documents(self.schema, ledger)
        self.assertTrue(any("missing required property: decision" in error for error in errors))

    def test_rejects_non_canonical_schema_date(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        ledger["reviewed_at"] = "2026-10-15T00:00:00"
        errors = validate_documents(self.schema, ledger)
        self.assertTrue(any("$.reviewed_at does not match format date" in error for error in errors))

    def test_rejects_invalid_uri_even_if_string(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        ledger["evidence_sources"][0]["url"] = "not a uri"
        errors = validate_documents(self.schema, ledger)
        self.assertTrue(any(".url does not match format uri" in error for error in errors))

    def test_rejects_unsupported_schema_keyword(self) -> None:
        schema = copy.deepcopy(self.schema)
        schema["properties"]["decision"]["x-unimplemented-rule"] = True
        errors = validate_documents(schema, self.ledger)
        self.assertTrue(any("unsupported schema keyword: x-unimplemented-rule" in error for error in errors))

    def test_rejects_schema_status_vocabulary_drift(self) -> None:
        schema = copy.deepcopy(self.schema)
        status_enum = schema["properties"]["engines"]["items"]["properties"]["capabilities"]["items"]["properties"]["prism_status"]["enum"]
        status_enum.append("works-on-my-machine")
        errors = validate_documents(schema, self.ledger)
        self.assertTrue(any("schema enum for prism_status does not match validator vocabulary" in error for error in errors))

    def test_rejects_passed_test_evidence_without_artifact_digest(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        engine = ledger["engines"][0]
        engine["integration_status"] = "integrated"
        cap = engine["capabilities"][0]
        cap["prism_status"] = "verified"
        cap["evidence_ids"].append("synthetic-capsule-evidence")
        ledger["evidence_sources"].append({
            "id": "synthetic-capsule-evidence",
            "kind": "prism_test_result",
            "url": "https://example.invalid/capsule.json",
            "reviewed_at": "2026-10-15",
            "revision": None,
            "claim_scope": "synthetic validator fixture only; not real browser evidence",
            "prism_revision": "a" * 40,
            "engine_revision": engine["identity"]["revision"],
            "command": "synthetic test fixture",
            "artifact_url": "https://example.invalid/capsule.json",
            "result": "passed",
        })
        errors = validate_documents(self.schema, ledger)
        self.assertTrue(any("artifact_sha256 is required" in error for error in errors))
        self.assertTrue(any("capsule_schema_version" in error for error in errors))

    def test_rejects_non_string_evidence_kind_without_crashing(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        ledger["evidence_sources"][0]["kind"] = {"unexpected": "object"}
        errors = validate_documents(self.schema, ledger)
        self.assertTrue(any("kind is not an allowed evidence kind" in error for error in errors))

    def test_rejects_non_string_engine_role_without_crashing(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        ledger["engines"][0]["role"] = ["selected_target"]
        errors = validate_documents(self.schema, ledger)
        self.assertTrue(any("role is not allowed" in error for error in errors))

    def test_rejects_unknown_status(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        ledger["engines"][0]["capabilities"][0]["prism_status"] = "probably-works"
        errors = validate_documents(self.schema, ledger)
        self.assertTrue(any("prism_status is not allowed" in error for error in errors))


if __name__ == "__main__":
    unittest.main(verbosity=2)
