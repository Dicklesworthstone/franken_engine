#!/usr/bin/env python3
"""Paired truth gate for external_trust_no_mock_auditor_drill.py outputs.

Rejects green (`pass`) or degraded drill claims when required stage receipts are
missing, corrupted, hash-mismatched, mutation-contaminated, or contradictory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


REQUIRED_STAGE_IDS = (
    "01_claim_observed",
    "02_claim_target_not_promotable",
    "03_claim_hypothesis_not_promotable",
    "04_bundle_doctor_healthy",
    "05_bundle_doctor_missing_member_fail_closed",
    "06_bundle_doctor_mock_contaminated_fail_closed",
    "07_bundle_doctor_e8_smuggle_not_promotable",
    "08_e8_report_degraded_before_certifier",
    "09_e8_report_healthy_with_capstone",
    "10_e8_report_smuggle_not_promotable",
    "11_replay_command_present_not_auto_executed",
    "12_replay_command_absent_fail_closed",
)


def sha256_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_drill_bundle(bundle_dir: Path) -> dict[str, Any]:
    violations: list[str] = []
    manifest_path = bundle_dir / "run_manifest.json"
    if not manifest_path.is_file():
        return {
            "schema_version": "franken-engine.external-trust-auditor-drill-truth-gate.v1",
            "verdict": "fail_closed",
            "violations": ["missing_run_manifest"],
        }

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return {
            "schema_version": "franken-engine.external-trust-auditor-drill-truth-gate.v1",
            "verdict": "fail_closed",
            "violations": [f"malformed_run_manifest:{exc}"],
        }

    if manifest.get("schema_version") != "franken-engine.external-trust-auditor-drill.v1":
        violations.append("unsupported_drill_schema")

    overall_decision = manifest.get("overall_decision")
    if overall_decision not in ("pass", "degraded", "fail_closed"):
        violations.append(f"invalid_overall_decision:{overall_decision}")

    for companion_field, sha_field in (
        ("commands_transcript_path", "commands_transcript_sha256"),
        ("reason_code_summary_path", "reason_code_summary_sha256"),
        ("artifact_hashes_path", "artifact_hashes_sha256"),
        ("remediation_path", "remediation_sha256"),
    ):
        rel = manifest.get(companion_field)
        expected_sha = manifest.get(sha_field)
        if not isinstance(rel, str) or not rel:
            violations.append(f"missing_field:{companion_field}")
            continue
        cpath = bundle_dir / rel
        actual_sha = sha256_file(cpath)
        if actual_sha is None:
            violations.append(f"missing_companion_file:{rel}")
        elif actual_sha != expected_sha:
            violations.append(f"companion_hash_mismatch:{rel}")

    replay_guard = manifest.get("replay_auto_execution_guard")
    if not isinstance(replay_guard, dict) or replay_guard.get("sentinel_triggered") is not False:
        violations.append("replay_auto_execution_violation")
    if isinstance(replay_guard, dict) and replay_guard.get("auto_executes_replay") is not False:
        violations.append("replay_policy_violation")

    immutability = manifest.get("immutability_guard")
    if not isinstance(immutability, dict) or immutability.get("mutated") is not False:
        violations.append("repo_immutability_violation")

    mut_policy = manifest.get("mutation_policy")
    if not isinstance(mut_policy, dict) or not mut_policy or not all(
        val is False for val in mut_policy.values()
    ):
        violations.append("drill_mutation_policy_violation")

    stages = manifest.get("stages")
    if not isinstance(stages, list):
        violations.append("invalid_stages_array")
        stages = []

    by_id: dict[str, dict[str, Any]] = {}
    for entry in stages:
        if isinstance(entry, dict) and isinstance(entry.get("stage_id"), str):
            sid = entry["stage_id"]
            if sid in by_id:
                violations.append(f"duplicate_stage:{sid}")
            by_id[sid] = entry

    for req_id in REQUIRED_STAGE_IDS:
        if req_id not in by_id:
            violations.append(f"missing_required_stage:{req_id}")

    any_degraded_stage = False
    any_failed_stage = False

    for sid, stage in by_id.items():
        rel_receipt = stage.get("receipt_path")
        if not isinstance(rel_receipt, str) or not rel_receipt:
            violations.append(f"missing_stage_receipt_path:{sid}")
            continue
        rpath = bundle_dir / rel_receipt
        actual_sha = sha256_file(rpath)
        if actual_sha is None:
            violations.append(f"missing_stage_receipt_file:{sid}")
            continue
        if actual_sha != stage.get("receipt_sha256"):
            violations.append(f"stage_receipt_hash_mismatch:{sid}")
            continue
        try:
            receipt_obj = json.loads(rpath.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            violations.append(f"malformed_stage_receipt_json:{sid}")
            continue

        receipt_decision = receipt_obj.get("decision")
        if receipt_decision != stage.get("actual_decision"):
            violations.append(
                f"contradictory_stage_decision:{sid}:manifest={stage.get('actual_decision')}!=receipt={receipt_decision}"
            )

        receipt_reasons = receipt_obj.get("reason_codes") or []
        for req_reason in stage.get("required_reasons") or []:
            if req_reason not in receipt_reasons:
                violations.append(f"missing_required_reason:{sid}:{req_reason}")

        if stage.get("require_non_empty_replay") and not (receipt_obj.get("replay_commands") or []):
            violations.append(f"missing_expected_replay_commands:{sid}")

        r_mut = receipt_obj.get("mutation_policy")
        if not isinstance(r_mut, dict) or not r_mut or not all(v is False for v in r_mut.values()):
            violations.append(f"stage_receipt_mutation_policy_violation:{sid}")

        expected_decisions = stage.get("expected_decisions") or []
        live_degraded = stage.get("live_degraded_decisions") or []
        if receipt_decision in expected_decisions:
            pass
        elif receipt_decision in live_degraded and manifest.get("mode") == "live":
            any_degraded_stage = True
        else:
            any_failed_stage = True

        # Explicitly reject negative guards falsely reporting supported
        if stage.get("polarity") == "negative_guard" and receipt_decision == "supported":
            violations.append(f"negative_guard_falsely_supported:{sid}")

    if overall_decision == "pass" and (any_failed_stage or any_degraded_stage):
        violations.append("contradictory_green_overall_decision")
    if overall_decision == "degraded" and any_failed_stage:
        violations.append("contradictory_degraded_overall_decision")

    verdict = "pass" if not violations and overall_decision in ("pass", "degraded") else "fail_closed"
    return {
        "schema_version": "franken-engine.external-trust-auditor-drill-truth-gate.v1",
        "bundle_dir": str(bundle_dir),
        "drill_overall_decision": overall_decision,
        "verdict": verdict,
        "violations": violations,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify an external-trust auditor drill output directory."
    )
    parser.add_argument("--drill-dir", required=True, help="Auditor drill output directory.")
    args = parser.parse_args()

    result = verify_drill_bundle(Path(args.drill_dir).resolve())
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["verdict"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
