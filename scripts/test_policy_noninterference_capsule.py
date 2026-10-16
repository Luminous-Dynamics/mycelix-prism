#!/usr/bin/env python3
"""Positive and negative tests for policy noninterference evidence capsules."""
from __future__ import annotations
import json, sys, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from validate_policy_noninterference_capsule import validate_capsule, derive_outcome  # noqa: E402
SCHEMA = json.loads((ROOT / "docs/engine-strategy/policy-noninterference-capsule.schema.json").read_text(encoding="utf-8"))
KINDS = ["unauthorized_request","malformed_request","expired_authority","unconsented_cross_zone","post_revocation","policy_evaluation_failure","authorized_control"]

def make_case(kind: str, index: int) -> dict:
    pre, post = f"{index + 1:064x}", f"{index + 1:064x}"
    source, destination, expected, observed, mode = "LOCAL","NONE","deny","deny","not_applicable"
    revoked, consent = False, {"present":False,"data_scope_matches":False,"recipient_matches":False,"purpose_matches":False,"not_expired":False}
    effects = {"state_writes":0,"share_queue_writes":0,"privileged_actions":0,"outbound_flows":0,"post_revocation_completions":0}
    if kind == "unconsented_cross_zone": source, destination = "PRIVATE","PUBLIC"
    elif kind == "post_revocation": revoked = True
    elif kind == "policy_evaluation_failure": mode, observed = "unavailable","no_op"
    elif kind == "authorized_control":
        source, destination, expected, observed = "LOCAL","LOCAL","allow","allow"
        post, effects["state_writes"] = f"{index + 99:064x}",1
    return {"case_id":f"case/{kind}","kind":kind,"source_zone":source,"destination_zone":destination,"expected_decision":expected,"observed_decision":observed,"policy_failure_mode":mode,"consent":consent,"revocation_acknowledged":revoked,"completed_after_revocation":False,"pre_state_sha256":pre,"post_state_sha256":post,"output_sha256":f"{index + 101:064x}","event_trace_sha256":f"{index + 201:064x}","observability":{"state_digest":True,"share_queue":True,"privileged_actions":True,"egress":True},"side_effects":effects}

def make_capsule() -> dict:
    cases=[make_case(k,i) for i,k in enumerate(KINDS)]
    return {"schema_version":"1.0.0","suite_id":"policy-noninterference","prism_revision":"a"*40,"policy_revision":"b"*40,"manifest_sha256":"c"*64,"manifest_case_ids":[c["case_id"] for c in cases],"manifest_case_count":len(cases),"environment":{"os":"linux","architecture":"x86_64","runner_image":"pinned-image@sha256:example","toolchain":"rustc 1.99.0; policy harness 0.1","toolchain_lock_sha256":"d"*64},"command":"nix develop --command cargo test -p prism-policy-broker --locked","generated_at_utc":"2026-10-16T00:00:00Z","cases":cases}

class PolicyNoninterferenceCapsuleTests(unittest.TestCase):
    def test_positive_complete_capsule_derives_pass(self):
        c=make_capsule(); self.assertEqual(validate_capsule(SCHEMA,c),[]); self.assertEqual(derive_outcome(c),"passed")
    def test_rejects_case_manifest_mismatch(self):
        c=make_capsule(); c["manifest_case_count"]-=1; self.assertTrue(any("does not match manifest_case_count" in e for e in validate_capsule(SCHEMA,c)))
    def test_rejects_case_id_set_mismatch(self):
        c=make_capsule(); c["manifest_case_ids"][0]="case/not-in-cases"; self.assertTrue(any("exactly match manifest_case_ids" in e for e in validate_capsule(SCHEMA,c)))
    def test_rejects_duplicate_case_id(self):
        c=make_capsule(); c["cases"][1]["case_id"]=c["cases"][0]["case_id"]; c["manifest_case_ids"][1]=c["manifest_case_ids"][0]; self.assertTrue(any("duplicate case_id" in e for e in validate_capsule(SCHEMA,c)))
    def test_malformed_kind_type_does_not_crash_validator(self):
        c=make_capsule(); c["cases"][0]["kind"]={"unexpected":"object"}; self.assertTrue(validate_capsule(SCHEMA,c))
    def test_denial_with_side_effect_fails_not_passes(self):
        c=make_capsule(); c["cases"][0]["side_effects"]["privileged_actions"]=1; self.assertEqual(derive_outcome(c),"failed")
    def test_unconsented_cross_zone_egress_fails(self):
        c=make_capsule(); case=next(x for x in c["cases"] if x["kind"]=="unconsented_cross_zone"); case["side_effects"]["outbound_flows"]=1; self.assertEqual(derive_outcome(c),"failed")
    def test_post_revocation_completion_fails(self):
        c=make_capsule(); case=next(x for x in c["cases"] if x["kind"]=="post_revocation"); case["completed_after_revocation"]=True; case["side_effects"]["post_revocation_completions"]=1; self.assertEqual(derive_outcome(c),"failed")
    def test_policy_failure_that_allows_fails(self):
        c=make_capsule(); case=next(x for x in c["cases"] if x["kind"]=="policy_evaluation_failure"); case["observed_decision"]="allow"; self.assertEqual(derive_outcome(c),"failed")
    def test_noninterference_requires_unchanged_state_digest(self):
        c=make_capsule(); c["cases"][1]["post_state_sha256"]="e"*64; self.assertEqual(derive_outcome(c),"failed")
    def test_missing_telemetry_blocks_pass(self):
        c=make_capsule(); c["cases"][2]["observability"]["egress"]=False; self.assertEqual(derive_outcome(c),"blocked")
    def test_missing_required_scenario_is_incomplete(self):
        c=make_capsule(); c["cases"]=[x for x in c["cases"] if x["kind"]!="expired_authority"]; c["manifest_case_ids"]=[x["case_id"] for x in c["cases"]]; c["manifest_case_count"]=len(c["cases"]); self.assertEqual(derive_outcome(c),"incomplete")
    def test_authorized_control_must_exercise_observable_write(self):
        c=make_capsule(); case=next(x for x in c["cases"] if x["kind"]=="authorized_control"); case["side_effects"]["state_writes"]=0; self.assertEqual(derive_outcome(c),"failed")
    def test_rejects_bool_used_as_side_effect_count(self):
        c=make_capsule(); c["cases"][0]["side_effects"]["state_writes"]=True; self.assertTrue(any("non-negative integer" in e for e in validate_capsule(SCHEMA,c)))
    def test_requires_revocation_acknowledgement_for_revocation_case(self):
        c=make_capsule(); case=next(x for x in c["cases"] if x["kind"]=="post_revocation"); case["revocation_acknowledged"]=False; self.assertTrue(any("requires observed revocation acknowledgement" in e for e in validate_capsule(SCHEMA,c)))
    def test_requires_real_canonical_utc_timestamp(self):
        c=make_capsule(); c["generated_at_utc"]="2026-02-30T00:00:00Z"; self.assertTrue(any("not a real UTC timestamp" in e for e in validate_capsule(SCHEMA,c)))
    def test_policy_capsule_schema_is_in_supported_subset(self):
        from engine_ledger_schema import validate_schema_definition
        self.assertEqual(validate_schema_definition(SCHEMA),[])

if __name__ == "__main__": unittest.main(verbosity=2)
