#!/usr/bin/env python3
"""Validate policy noninterference evidence capsules without executing a browser."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "docs/engine-strategy/policy-noninterference-capsule.schema.json"
MANIFEST_PATH = ROOT / "docs/engine-strategy/policy-noninterference-manifest.json"
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
KINDS = {
    "unauthorized_request", "malformed_request", "expired_authority",
    "unconsented_cross_zone", "post_revocation", "policy_evaluation_failure",
    "authorized_control",
}
DENIED_KINDS = KINDS - {"authorized_control"}
REQUIRED_OBSERVABILITY = ("state_digest", "share_queue", "privileged_actions", "egress")
EFFECT_COUNTERS = (
    "state_writes", "share_queue_writes", "privileged_actions",
    "outbound_flows", "post_revocation_completions",
)
POLICY_FAILURE_MODES = {"timeout", "unavailable", "malformed_policy", "schema_mismatch"}


def _load_manifest(manifest: Any = None, manifest_bytes: bytes | None = None) -> tuple[Any, bytes]:
    """Load exact checked-in bytes by default; explicit bytes support negative tests."""
    if manifest_bytes is None and manifest is None:
        raw = MANIFEST_PATH.read_bytes()
        return json.loads(raw), raw
    if manifest_bytes is None:
        raw = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        return manifest, raw
    if manifest is None:
        return json.loads(manifest_bytes), manifest_bytes
    return manifest, manifest_bytes


def validate_manifest(manifest: Any) -> list[str]:
    """Enforce the small, versioned scenario-manifest contract."""
    errors: list[str] = []
    if not isinstance(manifest, dict):
        return ["manifest root must be an object"]
    expected_root_keys = {
        "schema_version", "suite_id", "reviewed_at", "principle",
        "required_observability", "effect_counters", "scenarios",
    }
    if set(manifest) != expected_root_keys:
        errors.append("manifest root keys do not match the versioned contract")
    for key in ("reviewed_at", "principle"):
        if not isinstance(manifest.get(key), str) or not manifest[key].strip():
            errors.append(f"manifest {key} must be a non-empty string")
    if manifest.get("schema_version") != "1.0.0":
        errors.append("manifest schema_version must be 1.0.0")
    if manifest.get("suite_id") != "policy-noninterference":
        errors.append("manifest suite_id must be policy-noninterference")
    scenarios = manifest.get("scenarios")
    if not isinstance(scenarios, list):
        return errors + ["manifest scenarios must be a list"]
    ids: set[str] = set()
    kinds: set[str] = set()
    for index, scenario in enumerate(scenarios):
        prefix = f"manifest.scenarios[{index}]"
        if not isinstance(scenario, dict):
            errors.append(f"{prefix} must be an object")
            continue
        expected_scenario_keys = {
            "case_id", "kind", "source_zone", "destination_zone",
            "expected_decision", "policy_failure_mode", "expected_side_effects",
        }
        if set(scenario) != expected_scenario_keys:
            errors.append(f"{prefix} keys do not match the versioned scenario contract")
        case_id, kind = scenario.get("case_id"), scenario.get("kind")
        if not isinstance(case_id, str) or not case_id:
            errors.append(f"{prefix}.case_id must be a non-empty string")
        elif case_id in ids:
            errors.append(f"duplicate manifest case_id: {case_id}")
        else:
            ids.add(case_id)
        if not isinstance(kind, str) or kind not in KINDS:
            errors.append(f"{prefix}.kind is not allowed")
        elif kind in kinds:
            errors.append(f"duplicate manifest scenario kind: {kind}")
        else:
            kinds.add(kind)
        side_effect_mode = scenario.get("expected_side_effects")
        if not isinstance(side_effect_mode, str) or side_effect_mode not in {"zero", "authorized_write"}:
            errors.append(f"{prefix}.expected_side_effects is not allowed")
        expected_decision = scenario.get("expected_decision")
        if kind == "authorized_control":
            if expected_decision != "allow" or side_effect_mode != "authorized_write":
                errors.append(f"{prefix} authorized_control must expect allow and authorized_write")
        elif not isinstance(expected_decision, str) or expected_decision not in {"deny", "no_op"} or side_effect_mode != "zero":
            errors.append(f"{prefix} denied scenario must expect deny/no_op and zero side effects")
        failure_mode = scenario.get("policy_failure_mode")
        if kind == "policy_evaluation_failure" and (not isinstance(failure_mode, str) or failure_mode not in POLICY_FAILURE_MODES):
            errors.append(f"{prefix} policy failure must declare a failure mode")
        elif kind != "policy_evaluation_failure" and failure_mode != "not_applicable":
            errors.append(f"{prefix} non-failure scenario must use policy_failure_mode=not_applicable")
        source_zone, destination_zone = scenario.get("source_zone"), scenario.get("destination_zone")
        if kind == "unconsented_cross_zone" and (
            not isinstance(source_zone, str) or source_zone not in {"PRIVATE", "LOCAL"} or destination_zone != "PUBLIC"
        ):
            errors.append(f"{prefix} must describe PRIVATE/LOCAL to PUBLIC")
        if kind == "post_revocation" and (
            not isinstance(expected_decision, str) or expected_decision not in {"deny", "no_op"}
        ):
            errors.append(f"{prefix} post_revocation must expect deny/no_op")
    if kinds != KINDS:
        errors.append("manifest must contain each required scenario kind exactly once")
    required_obs = manifest.get("required_observability")
    if (
        not isinstance(required_obs, list)
        or any(not isinstance(item, str) for item in required_obs)
        or set(required_obs) != set(REQUIRED_OBSERVABILITY)
        or len(required_obs) != len(REQUIRED_OBSERVABILITY)
    ):
        errors.append("manifest required_observability must contain the complete required channel set")
    counters = manifest.get("effect_counters")
    if (
        not isinstance(counters, list)
        or any(not isinstance(item, str) for item in counters)
        or set(counters) != set(EFFECT_COUNTERS)
        or len(counters) != len(EFFECT_COUNTERS)
    ):
        errors.append("manifest effect_counters must contain the complete required counter set")
    return errors


def validate_capsule(
    schema: Any,
    capsule: Any,
    manifest: Any = None,
    manifest_bytes: bytes | None = None,
) -> list[str]:
    """Check schema and manifest binding; behavior verdicts are derived separately."""
    from engine_ledger_schema import validate_instance, validate_schema_definition

    schema_errors = validate_schema_definition(schema)
    if schema_errors:
        return [f"schema contract error: {error}" for error in schema_errors]
    errors = validate_instance(capsule, schema)
    if not isinstance(capsule, dict):
        return errors or ["capsule root must be an object"]
    try:
        selected_manifest, raw_manifest = _load_manifest(manifest, manifest_bytes)
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        return errors + [f"cannot load scenario manifest: {exc}"]
    errors.extend(validate_manifest(selected_manifest))
    expected_digest = hashlib.sha256(raw_manifest).hexdigest()
    if capsule.get("manifest_sha256") != expected_digest:
        errors.append("manifest_sha256 does not match the exact scenario manifest bytes")

    for field in ("prism_revision", "policy_revision"):
        value = capsule.get(field)
        if not isinstance(value, str) or not SHA1_RE.fullmatch(value):
            errors.append(f"{field} must be a full lowercase 40-character commit SHA")
    value = capsule.get("manifest_sha256")
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        errors.append("manifest_sha256 must be a full lowercase SHA-256 digest")
    timestamp = capsule.get("generated_at_utc")
    if isinstance(timestamp, str):
        try:
            parsed = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != timestamp:
                errors.append("generated_at_utc is not canonical UTC time")
        except ValueError:
            errors.append("generated_at_utc is not a real UTC timestamp")

    manifest_count = capsule.get("manifest_case_count")
    if isinstance(manifest_count, bool) or not isinstance(manifest_count, int) or manifest_count < 1:
        errors.append("manifest_case_count must be a positive integer")
    manifest_ids = capsule.get("manifest_case_ids")
    cases = capsule.get("cases")
    if not isinstance(manifest_ids, list) or any(not isinstance(item, str) for item in manifest_ids):
        errors.append("manifest_case_ids must be a list of strings")
        manifest_ids = []
    if not isinstance(cases, list):
        return errors + ["cases must be a list"]
    scenarios = selected_manifest.get("scenarios", []) if isinstance(selected_manifest, dict) else []
    canonical_ids = [item["case_id"] for item in scenarios if isinstance(item, dict) and isinstance(item.get("case_id"), str)]
    if manifest_ids != canonical_ids:
        errors.append("manifest_case_ids must exactly match the ordered canonical manifest IDs")
    actual_ids = [
        case.get("case_id") for case in cases
        if isinstance(case, dict) and isinstance(case.get("case_id"), str)
    ]
    if isinstance(manifest_count, int) and not isinstance(manifest_count, bool) and len(cases) != manifest_count:
        errors.append("cases length does not match manifest_case_count")
    if manifest_count != len(canonical_ids):
        errors.append("manifest_case_count does not match canonical manifest scenario count")
    if actual_ids != canonical_ids:
        errors.append("case IDs and order must exactly match the canonical manifest")

    scenario_by_id = {
        scenario["case_id"]: scenario for scenario in scenarios
        if isinstance(scenario, dict) and isinstance(scenario.get("case_id"), str)
    }
    ids: set[str] = set()
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
        scenario = scenario_by_id.get(case_id) if isinstance(case_id, str) else None
        if scenario is not None:
            for field in ("kind", "source_zone", "destination_zone", "expected_decision", "policy_failure_mode"):
                if case.get(field) != scenario.get(field):
                    errors.append(f"{prefix}.{field} differs from canonical manifest scenario")
        kind = case.get("kind")
        if not isinstance(kind, str) or kind not in KINDS:
            continue
        expected = case.get("expected_decision")
        failure_mode = case.get("policy_failure_mode")
        consent = case.get("consent")
        if kind == "authorized_control":
            if expected != "allow":
                errors.append(f"{prefix} authorized_control must expect allow")
        elif not isinstance(expected, str) or expected not in {"deny", "no_op"}:
            errors.append(f"{prefix} {kind} must expect deny or no_op")
        if kind == "policy_evaluation_failure":
            if not isinstance(failure_mode, str) or failure_mode not in POLICY_FAILURE_MODES:
                errors.append(f"{prefix} policy failure needs an explicit failure mode")
        elif failure_mode != "not_applicable":
            errors.append(f"{prefix} non-failure case must use policy_failure_mode=not_applicable")
        if kind == "unconsented_cross_zone":
            source_zone, destination_zone = case.get("source_zone"), case.get("destination_zone")
            if not isinstance(source_zone, str) or source_zone not in {"PRIVATE", "LOCAL"} or destination_zone != "PUBLIC":
                errors.append(f"{prefix} unconsented_cross_zone must describe PRIVATE/LOCAL to PUBLIC")
            if not isinstance(consent, dict):
                errors.append(f"{prefix} consent must be an object")
            elif all(consent.get(key) is True for key in ("present", "data_scope_matches", "recipient_matches", "purpose_matches", "not_expired")):
                errors.append(f"{prefix} unconsented_cross_zone cannot claim valid complete consent")
        if kind == "post_revocation" and case.get("revocation_acknowledged") is not True:
            errors.append(f"{prefix} post_revocation requires observed revocation acknowledgement")
        effects = case.get("side_effects")
        if not isinstance(effects, dict):
            errors.append(f"{prefix} side_effects must be an object")
            continue
        for name in EFFECT_COUNTERS:
            count = effects.get(name)
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                errors.append(f"{prefix}.side_effects.{name} must be a non-negative integer")
    return errors


def derive_outcome(capsule: Any) -> str:
    """Fail closed: violations fail, missing telemetry blocks, missing cases are incomplete."""
    if not isinstance(capsule, dict) or not isinstance(capsule.get("cases"), list):
        return "incomplete"
    cases = capsule["cases"]
    if len(cases) != 7 or any(not isinstance(case, dict) for case in cases):
        return "incomplete"
    case_ids = [case.get("case_id") for case in cases]
    if case_ids != ["deny-unauthorized-request", "deny-malformed-request", "deny-expired-authority", "deny-unconsented-cross-zone", "deny-post-revocation", "deny-policy-evaluation-failure", "allow-authorized-control"]:
        return "incomplete"
    blocked = False
    for case in cases:
        kind = case.get("kind")
        if not isinstance(kind, str) or kind not in KINDS:
            return "incomplete"
        obs, effects = case.get("observability"), case.get("side_effects")
        if not isinstance(obs, dict) or any(obs.get(channel) is not True for channel in REQUIRED_OBSERVABILITY):
            blocked = True
        if not isinstance(effects, dict):
            return "blocked"
        if any(isinstance(effects.get(name), bool) or not isinstance(effects.get(name), int) or effects.get(name) < 0 for name in EFFECT_COUNTERS):
            return "blocked"
        effect_present = any(effects[name] > 0 for name in EFFECT_COUNTERS)
        observed, expected = case.get("observed_decision"), case.get("expected_decision")
        if kind in DENIED_KINDS:
            if not isinstance(observed, str) or observed not in {"deny", "no_op"} or effect_present:
                return "failed"
            if case.get("pre_state_sha256") != case.get("post_state_sha256"):
                return "failed"
            if kind == "post_revocation" and (
                case.get("revocation_acknowledged") is not True
                or case.get("completed_after_revocation") is True
                or effects["post_revocation_completions"] != 0
            ):
                return "failed"
            if case.get("completed_after_revocation") is True:
                return "failed"
        else:
            if observed != "allow":
                return "failed"
            if effects["state_writes"] < 1 or case.get("pre_state_sha256") == case.get("post_state_sha256"):
                return "failed"
        if not isinstance(expected, str):
            return "incomplete"
        if expected == "allow" and observed != "allow":
            return "failed"
        if expected in {"deny", "no_op"} and observed not in {"deny", "no_op"}:
            return "failed"
    return "blocked" if blocked else "passed"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-schema", action="store_true", help="validate supported schema/manifest contracts only")
    parser.add_argument("--capsule", type=Path, help="path to an evidence capsule JSON file")
    args = parser.parse_args()
    try:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        manifest = json.loads(MANIFEST_PATH.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot load policy capsule schema/manifest: {exc}", file=sys.stderr)
        return 2
    from engine_ledger_schema import validate_schema_definition
    schema_errors = validate_schema_definition(schema)
    if schema_errors:
        for error in schema_errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    manifest_errors = validate_manifest(manifest)
    if manifest_errors:
        for error in manifest_errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    if args.check_schema:
        print("PASS: policy noninterference schema and canonical scenario manifest are valid")
        return 0
    if args.capsule is None:
        parser.error("provide --check-schema or --capsule")
    try:
        capsule = json.loads(args.capsule.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot load policy capsule: {exc}", file=sys.stderr)
        return 2
    errors = validate_capsule(schema, capsule)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        print(f"FAIL: {len(errors)} policy capsule contract violation(s)", file=sys.stderr)
        return 1
    outcome = derive_outcome(capsule)
    print(f"RESULT: policy capsule is structurally valid; derived outcome={outcome}")
    print("NOTE: a valid record is not proof that the runtime or event-trace provenance is authentic.")
    return 0 if outcome == "passed" else (3 if outcome in {"blocked", "incomplete"} else 1)


if __name__ == "__main__":
    raise SystemExit(main())
