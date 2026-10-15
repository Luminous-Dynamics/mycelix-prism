#!/usr/bin/env python3
"""Fail-closed semantic validator for Prism's engine capability evidence ledger.

Developer/CI tooling only. Runtime application code remains Rust-first; this tool
uses only Python's standard library so the evidence gate has no package supply
chain of its own. The adjacent JSON Schema is the interchange contract; this
validator enforces repository-specific cross-record invariants.
"""
from __future__ import annotations

import json
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any

from engine_ledger_schema import validate_json_schema

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "docs/engine-strategy/capability-ledger.schema.json"
LEDGER_PATH = ROOT / "docs/engine-strategy/capability-ledger.json"

ENGINE_ROLES = {"selected_target", "research_comparator", "future_option", "current_baseline"}
REVISION_KINDS = {"git_commit", "release", "branch_snapshot", "not_pinned"}
INTEGRATION_STATUSES = {"not_implemented", "research_only", "partially_existing", "integrated", "not_applicable"}
UPSTREAM_STATUSES = {
    "pinned_source_reviewed",
    "official_docs_reviewed",
    "implemented_in_source_only",
    "not_established",
    "not_reviewed",
    "not_applicable",
}
PRISM_STATUSES = {"not_implemented", "not_tested", "partial_unqualified", "verified", "failed", "not_applicable"}
SOURCE_KINDS = {
    "pinned_source",
    "official_project_documentation",
    "standard_or_specification",
    "prism_source",
    "prism_test_result",
    "benchmark_result",
    "security_review",
}
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
SOURCE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")


def _is_object(value: Any) -> bool:
    return isinstance(value, dict)


def _is_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _valid_date(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        date.fromisoformat(value)
        return True
    except ValueError:
        return False



def _schema_node(schema: Any, *path: str) -> Any:
    node = schema
    for component in path:
        if not isinstance(node, dict):
            return None
        node = node.get(component)
    return node


def _validate_schema_vocabularies(schema: Any) -> list[str]:
    """Prevent schema enums and semantic-validator vocabularies from drifting."""
    declarations = {
        ("properties", "evidence_sources", "items", "properties", "kind"): SOURCE_KINDS,
        ("properties", "engines", "items", "properties", "role"): ENGINE_ROLES,
        ("properties", "engines", "items", "properties", "identity", "properties", "revision_kind"): REVISION_KINDS,
        ("properties", "engines", "items", "properties", "integration_status"): INTEGRATION_STATUSES,
        ("properties", "engines", "items", "properties", "capabilities", "items", "properties", "upstream_evidence"): UPSTREAM_STATUSES,
        ("properties", "engines", "items", "properties", "capabilities", "items", "properties", "prism_status"): PRISM_STATUSES,
    }
    errors: list[str] = []
    for path, expected in declarations.items():
        node = _schema_node(schema, *path)
        actual = node.get("enum") if isinstance(node, dict) else None
        if not isinstance(actual, list) or set(actual) != expected or len(actual) != len(expected):
            field = path[-1]
            errors.append(f"schema enum for {field} does not match validator vocabulary")
    return errors


def validate_documents(schema: Any, ledger: Any) -> list[str]:
    """Return all detected contract/integrity violations; no network is used."""
    errors: list[str] = []
    if not _is_object(schema):
        return ["schema root must be an object"]
    if not _is_object(ledger):
        return ["ledger root must be an object"]

    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        errors.append("schema must declare JSON Schema draft 2020-12")
    schema_properties = schema.get("properties")
    schema_version_schema = schema_properties.get("schema_version") if isinstance(schema_properties, dict) else None
    if not isinstance(schema_version_schema, dict) or schema_version_schema.get("const") != "1.0.0":
        errors.append("schema must declare schema_version 1.0.0")
    errors.extend(_validate_schema_vocabularies(schema))
    errors.extend(validate_json_schema(schema, ledger))
    if ledger.get("schema_version") != "1.0.0":
        errors.append("ledger schema_version must be 1.0.0")
    if not _valid_date(ledger.get("reviewed_at")):
        errors.append("reviewed_at must be an ISO date")
    if not _is_string(ledger.get("decision")):
        errors.append("decision must be a non-empty string")
    if not isinstance(ledger.get("proof_policy"), list) or not ledger["proof_policy"]:
        errors.append("proof_policy must be a non-empty list")

    sources = ledger.get("evidence_sources")
    if not isinstance(sources, list) or not sources:
        errors.append("evidence_sources must be a non-empty list")
        sources = []
    source_by_id: dict[str, dict[str, Any]] = {}
    for index, source in enumerate(sources):
        prefix = f"evidence_sources[{index}]"
        if not _is_object(source):
            errors.append(f"{prefix} must be an object")
            continue
        source_id = source.get("id")
        if not isinstance(source_id, str) or not SOURCE_ID_RE.fullmatch(source_id):
            errors.append(f"{prefix}.id must be a lowercase slug")
        elif source_id in source_by_id:
            errors.append(f"duplicate evidence source id: {source_id}")
        else:
            source_by_id[source_id] = source
        if source.get("kind") not in SOURCE_KINDS:
            errors.append(f"{prefix}.kind is not an allowed evidence kind")
        if not _is_string(source.get("url")) or not source["url"].startswith("https://"):
            errors.append(f"{prefix}.url must be an HTTPS URL")
        if not _valid_date(source.get("reviewed_at")):
            errors.append(f"{prefix}.reviewed_at must be an ISO date")
        if not _is_string(source.get("claim_scope")):
            errors.append(f"{prefix}.claim_scope must explain what the source supports")
        if source.get("revision") is not None and not _is_string(source.get("revision")):
            errors.append(f"{prefix}.revision must be a string or null")
        if source.get("kind") in {"prism_test_result", "benchmark_result", "security_review"}:
            for key in ("prism_revision", "engine_revision", "command", "artifact_url", "result"):
                if not _is_string(source.get(key)):
                    errors.append(f"{prefix}.{key} is required for executable evidence")
            if isinstance(source.get("prism_revision"), str) and not SHA1_RE.fullmatch(source["prism_revision"]):
                errors.append(f"{prefix}.prism_revision must be a full lowercase 40-character commit SHA")
            if not _is_string(source.get("artifact_url")) or not source["artifact_url"].startswith("https://"):
                errors.append(f"{prefix}.artifact_url must be an HTTPS artifact/log URL")

    engines = ledger.get("engines")
    if not isinstance(engines, list) or not engines:
        errors.append("engines must be a non-empty list")
        engines = []
    engine_ids: set[str] = set()
    for engine_index, engine in enumerate(engines):
        prefix = f"engines[{engine_index}]"
        if not _is_object(engine):
            errors.append(f"{prefix} must be an object")
            continue

        engine_id = engine.get("engine_id")
        if not isinstance(engine_id, str) or not SLUG_RE.fullmatch(engine_id):
            errors.append(f"{prefix}.engine_id must be a lowercase slug")
        elif engine_id in engine_ids:
            errors.append(f"duplicate engine_id: {engine_id}")
        else:
            engine_ids.add(engine_id)

        if engine.get("role") not in ENGINE_ROLES:
            errors.append(f"{prefix}.role is not allowed")
        identity = engine.get("identity")
        if not _is_object(identity):
            errors.append(f"{prefix}.identity must be an object")
            identity = {}
        if not _is_string(identity.get("repository")) or not identity["repository"].startswith("https://"):
            errors.append(f"{prefix}.identity.repository must be an HTTPS URL")
        revision_kind = identity.get("revision_kind")
        revision = identity.get("revision")
        if revision_kind not in REVISION_KINDS:
            errors.append(f"{prefix}.identity.revision_kind is not allowed")
        if not _is_string(revision):
            errors.append(f"{prefix}.identity.revision must be a non-empty string")
        if revision_kind == "git_commit" and isinstance(revision, str) and not SHA1_RE.fullmatch(revision):
            errors.append(f"{prefix}.identity.revision must be a full lowercase 40-character SHA")
        if engine.get("integration_status") not in INTEGRATION_STATUSES:
            errors.append(f"{prefix}.integration_status is not allowed")

        capabilities = engine.get("capabilities")
        if not isinstance(capabilities, list) or not capabilities:
            errors.append(f"{prefix}.capabilities must be a non-empty list")
            continue
        capability_ids: set[str] = set()
        for cap_index, cap in enumerate(capabilities):
            cap_prefix = f"{prefix}.capabilities[{cap_index}]"
            if not _is_object(cap):
                errors.append(f"{cap_prefix} must be an object")
                continue
            cap_id = cap.get("capability_id")
            if not isinstance(cap_id, str) or not SLUG_RE.fullmatch(cap_id):
                errors.append(f"{cap_prefix}.capability_id must be a lowercase slug")
            elif cap_id in capability_ids:
                errors.append(f"duplicate capability_id {cap_id} within {engine_id}")
            else:
                capability_ids.add(cap_id)
            if cap.get("upstream_evidence") not in UPSTREAM_STATUSES:
                errors.append(f"{cap_prefix}.upstream_evidence is not allowed")
            prism_status = cap.get("prism_status")
            if prism_status not in PRISM_STATUSES:
                errors.append(f"{cap_prefix}.prism_status is not allowed")
            if not _is_string(cap.get("notes")):
                errors.append(f"{cap_prefix}.notes must explain current evidence limits")
            refs = cap.get("evidence_ids")
            refs_valid = (
                isinstance(refs, list)
                and all(isinstance(item, str) for item in refs)
                and len(refs) == len(set(refs))
            )
            if not refs_valid:
                errors.append(f"{cap_prefix}.evidence_ids must be a list of unique strings")
                refs = [item for item in refs if isinstance(item, str)] if isinstance(refs, list) else []
            for evidence_id in refs:
                if evidence_id not in source_by_id:
                    errors.append(f"{cap_prefix} references unknown evidence id: {evidence_id}")

            if prism_status == "verified":
                if engine.get("integration_status") not in {"partially_existing", "integrated"}:
                    errors.append(f"{cap_prefix} cannot be verified while engine integration is not implemented")
                test_sources = [
                    source_by_id[evidence_id]
                    for evidence_id in refs
                    if evidence_id in source_by_id
                    and source_by_id[evidence_id].get("kind") == "prism_test_result"
                    and source_by_id[evidence_id].get("result") == "passed"
                ]
                if not test_sources:
                    errors.append(f"{cap_prefix} cannot be verified without a passed, exact-revision Prism test artifact")
                for source in test_sources:
                    if source.get("engine_revision") != revision:
                        errors.append(f"{cap_prefix} test evidence engine_revision does not match this engine identity")

    return errors


def main() -> int:
    try:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot load schema/ledger: {exc}", file=sys.stderr)
        return 2
    errors = validate_documents(schema, ledger)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        print(f"FAIL: {len(errors)} engine-ledger invariant(s) violated", file=sys.stderr)
        return 1
    engine_count = len(ledger["engines"])
    source_count = len(ledger["evidence_sources"])
    capability_count = sum(len(engine["capabilities"]) for engine in ledger["engines"])
    print(
        f"PASS: schema-subset validation and evidence invariants are valid "
        f"({engine_count} engines, {capability_count} capability records, {source_count} evidence sources)"
    )
    print("NOTE: the validator enforces only the JSON Schema keywords used by this contract; it is not a general JSON Schema implementation.")
    print("NOTE: ledger integrity is not proof of browser builds, capabilities, or security.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
