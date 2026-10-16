#!/usr/bin/env python3
"""Validate policy noninterference evidence capsules without executing a browser."""
from __future__ import annotations
import argparse, json, re, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "docs/engine-strategy/policy-noninterference-capsule.schema.json"
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
KINDS = {"unauthorized_request","malformed_request","expired_authority","unconsented_cross_zone","post_revocation","policy_evaluation_failure","authorized_control"}
DENIED_KINDS = KINDS - {"authorized_control"}
REQUIRED_OBSERVABILITY = ("state_digest","share_queue","privileged_actions","egress")
EFFECT_COUNTERS = ("state_writes","share_queue_writes","privileged_actions","outbound_flows","post_revocation_completions")
POLICY_FAILURE_MODES = {"timeout","unavailable","malformed_policy","schema_mismatch"}

def validate_capsule(schema: Any, capsule: Any) -> list[str]:
    """Check schema and semantic integrity; behavior verdicts are derived separately."""
    from engine_ledger_schema import validate_instance, validate_schema_definition
    schema_errors = validate_schema_definition(schema)
    if schema_errors:
        return [f"schema contract error: {error}" for error in schema_errors]
    errors = validate_instance(capsule, schema)
    if not isinstance(capsule, dict):
        return errors or ["capsule root must be an object"]
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
    if isinstance(manifest_count, int) and not isinstance(manifest_count, bool) and len(cases) != manifest_count:
        errors.append("cases length does not match manifest_case_count")
    if len(manifest_ids) != len(set(manifest_ids)):
        errors.append("manifest_case_ids contains duplicates")
    actual_ids = {case.get("case_id") for case in cases if isinstance(case, dict) and isinstance(case.get("case_id"), str)}
    if len(cases) != len(manifest_ids) or set(manifest_ids) != actual_ids:
        errors.append("case IDs do not exactly match manifest_case_ids")
    ids: set[str] = set()
    for index, case in enumerate(cases):
        prefix = f"cases[{index}]"
        if not isinstance(case, dict):
            errors.append(f"{prefix} must be an object")
            continue
        case_id = case.get("case_id")
        if isinstance(case_id, str):
            if case_id in ids: errors.append(f"duplicate case_id: {case_id}")
            ids.add(case_id)
        kind = case.get("kind")
        if not isinstance(kind, str) or kind not in KINDS: continue
        source, destination = case.get("source_zone"), case.get("destination_zone")
        expected, failure_mode, consent = case.get("expected_decision"), case.get("policy_failure_mode"), case.get("consent")
        if kind == "authorized_control":
            if expected != "allow": errors.append(f"{prefix} authorized_control must expect allow")
        elif not isinstance(expected, str) or expected not in {"deny","no_op"}:
            errors.append(f"{prefix} {kind} must expect deny or no_op")
        if kind == "policy_evaluation_failure":
            if not isinstance(failure_mode, str) or failure_mode not in POLICY_FAILURE_MODES:
                errors.append(f"{prefix} policy failure needs an explicit failure mode")
        elif failure_mode != "not_applicable":
            errors.append(f"{prefix} non-failure case must use policy_failure_mode=not_applicable")
        if kind == "unconsented_cross_zone":
            if not isinstance(source, str) or source not in {"PRIVATE","LOCAL"} or destination != "PUBLIC":
                errors.append(f"{prefix} unconsented_cross_zone must describe PRIVATE/LOCAL to PUBLIC")
            if not isinstance(consent, dict):
                errors.append(f"{prefix} consent must be an object")
            elif all(consent.get(key) is True for key in ("present","data_scope_matches","recipient_matches","purpose_matches","not_expired")):
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

def derive_outcome(capsule: dict[str, Any]) -> str:
    """Fail closed: known violations fail, missing telemetry or scenario coverage block."""
    cases = capsule.get("cases")
    if not isinstance(cases, list): return "incomplete"
    seen = {case.get("kind") for case in cases if isinstance(case, dict) and isinstance(case.get("kind"), str)}
    if seen != KINDS: return "incomplete"
    blocked = False
    for case in cases:
        kind = case.get("kind")
        obs, effects = case.get("observability"), case.get("side_effects")
        if not isinstance(obs, dict) or any(obs.get(ch) is not True for ch in REQUIRED_OBSERVABILITY): blocked = True
        if not isinstance(effects, dict): return "blocked"
        if any(isinstance(effects.get(n), bool) or not isinstance(effects.get(n), int) or effects.get(n) < 0 for n in EFFECT_COUNTERS): return "blocked"
        effect_present = any(effects[n] > 0 for n in EFFECT_COUNTERS)
        observed, expected = case.get("observed_decision"), case.get("expected_decision")
        if kind in DENIED_KINDS:
            if not isinstance(observed, str) or observed not in {"deny","no_op"} or effect_present: return "failed"
            if case.get("pre_state_sha256") != case.get("post_state_sha256"): return "failed"
            if kind == "post_revocation" and (case.get("revocation_acknowledged") is not True or case.get("completed_after_revocation") is True or effects["post_revocation_completions"] != 0): return "failed"
            if case.get("completed_after_revocation") is True: return "failed"
        else:
            if observed != "allow": return "failed"
            if effects["state_writes"] < 1 or case.get("pre_state_sha256") == case.get("post_state_sha256"): return "failed"
        if expected == "allow" and observed != "allow": return "failed"
        if expected in {"deny","no_op"} and observed not in {"deny","no_op"}: return "failed"
    return "blocked" if blocked else "passed"

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-schema", action="store_true", help="validate supported schema keywords only")
    parser.add_argument("--capsule", type=Path, help="path to an evidence capsule JSON file")
    args = parser.parse_args()
    try: schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot load policy capsule schema: {exc}", file=sys.stderr); return 2
    from engine_ledger_schema import validate_schema_definition
    schema_errors = validate_schema_definition(schema)
    if schema_errors:
        for error in schema_errors: print(f"ERROR: {error}", file=sys.stderr)
        return 1
    if args.check_schema:
        print("PASS: policy noninterference capsule schema uses only supported, checked keywords"); return 0
    if args.capsule is None: parser.error("provide --check-schema or --capsule")
    try: capsule = json.loads(args.capsule.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot load policy capsule: {exc}", file=sys.stderr); return 2
    errors = validate_capsule(schema, capsule)
    if errors:
        for error in errors: print(f"ERROR: {error}", file=sys.stderr)
        print(f"FAIL: {len(errors)} policy capsule contract violation(s)", file=sys.stderr); return 1
    outcome = derive_outcome(capsule)
    print(f"RESULT: policy noninterference capsule structurally valid; derived outcome={outcome}")
    print("NOTE: a valid record is not proof of runtime behavior; preserve trace artifacts and verify provenance.")
    return 0 if outcome == "passed" else (3 if outcome in {"blocked","incomplete"} else 1)

if __name__ == "__main__":
    raise SystemExit(main())
