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

    def test_rejects_unknown_status(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        ledger["engines"][0]["capabilities"][0]["prism_status"] = "probably-works"
        errors = validate_documents(self.schema, ledger)
        self.assertTrue(any("prism_status is not allowed" in error for error in errors))


if __name__ == "__main__":
    unittest.main(verbosity=2)
