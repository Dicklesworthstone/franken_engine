#!/usr/bin/env python3
"""No-mock external-trust auditor drill composing claim, bundle, and E8 explainers.

Implements bd-grwh9.6 under docs/EXTERNAL_TRUST_ARTIFACT_UX_CONTRACT_V1.md.
Composes:
  1. `frankenctl claims explain` (bd-grwh9.2)
  2. `scripts/external_trust_artifact_bundle_doctor.py` (bd-grwh9.3)
  3. `scripts/e8_non_use_certificate_scenario_report.py` (bd-grwh9.4)

Strict read-only posture: never mutates `.beads/`, Agent Mail, worker state,
`docs/claim_to_proof_matrix_v1.json`, or preserved evidence bundles, and never
auto-executes replay commands.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


DRILL_SCHEMA_VERSION = "franken-engine.external-trust-auditor-drill.v1"


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json_hash(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def resolve_frankenctl(repo_root: Path, explicit: str | None) -> Path | None:
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    env_bin = os.environ.get("FRANKENCTL_BIN")
    if env_bin:
        candidates.append(Path(env_bin))
    candidates.append(repo_root / "target" / "release" / "frankenctl")
    candidates.append(repo_root / "target" / "debug" / "frankenctl")
    for cand in candidates:
        resolved = cand if cand.is_absolute() else (repo_root / cand)
        if resolved.is_file() and os.access(resolved, os.X_OK):
            return resolved
    return None


def prepare_adversarial_bundles(
    certified_bundle: Path, workdir: Path, sentinel_file: Path
) -> dict[str, Path]:
    """Create isolated read-only adversarial copies in temp space without touching repo bundles."""
    missing_member_dir = workdir / "bundle_missing_events"
    shutil.copytree(certified_bundle, missing_member_dir)
    repro_missing = json.loads((missing_member_dir / "repro.lock").read_text(encoding="utf-8"))
    repro_missing["files"].append(
        {
            "name": "audit_missing_member.jsonl",
            "sha256_hex": "0" * 64,
            "bytes": 0,
        }
    )
    (missing_member_dir / "repro.lock").write_text(
        json.dumps(repro_missing, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    mock_dir = workdir / "bundle_mock_contaminated"
    shutil.copytree(certified_bundle, mock_dir)
    cap_trace_path = mock_dir / "capability_trace.jsonl"
    with cap_trace_path.open("a", encoding="utf-8") as handle:
        handle.write(
            json.dumps(
                {
                    "event": "contaminated_probe",
                    "marker": "MockCertificate",
                    "lane": "hot_paths_simulation",
                }
            )
            + "\n"
        )
    repro_mock = json.loads((mock_dir / "repro.lock").read_text(encoding="utf-8"))
    for item in repro_mock.get("files", []):
        if item.get("name") == "capability_trace.jsonl":
            item["sha256_hex"] = sha256_file(cap_trace_path)
            item["bytes"] = cap_trace_path.stat().st_size
    (mock_dir / "repro.lock").write_text(
        json.dumps(repro_mock, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    replay_present_dir = workdir / "bundle_replay_present_sentinel"
    shutil.copytree(certified_bundle, replay_present_dir)
    repro_replay = json.loads((replay_present_dir / "repro.lock").read_text(encoding="utf-8"))
    repro_replay["commands"] = list(repro_replay.get("commands", [])) + [
        f"touch {shlex.quote(str(sentinel_file))}"
    ]
    (replay_present_dir / "repro.lock").write_text(
        json.dumps(repro_replay, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    replay_absent_dir = workdir / "bundle_replay_absent"
    shutil.copytree(certified_bundle, replay_absent_dir)
    repro_no_replay = json.loads((replay_absent_dir / "repro.lock").read_text(encoding="utf-8"))
    repro_no_replay.pop("commands", None)
    (replay_absent_dir / "repro.lock").write_text(
        json.dumps(repro_no_replay, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    return {
        "missing_member": missing_member_dir,
        "mock_contaminated": mock_dir,
        "replay_present_sentinel": replay_present_dir,
        "replay_absent": replay_absent_dir,
        "absent_e8_bundle": workdir / "nonexistent_e8_certificate_bundle",
    }


def prepare_fixture_claim_inputs(
    repo_root: Path, certified_bundle: Path, workdir: Path
) -> tuple[Path, Path]:
    """Build deterministic claim-matrix + beads JSONL backed by real checked-in E8 artifacts."""
    claim_dir = workdir / "fixture_claims"
    claim_dir.mkdir(parents=True, exist_ok=True)
    fresh_bundle = claim_dir / "fresh_e8_bundle"
    shutil.copytree(certified_bundle, fresh_bundle)
    now_iso = utc_now()
    # Write manifest.json so frankenctl's directory freshness probe sees today's timestamp.
    (fresh_bundle / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "franken-engine.e8-certificate-bundle.v2",
                "generated_at_utc": now_iso,
                "freshness": {"generated_utc": now_iso},
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    real_matrix = json.loads(
        (repo_root / "docs" / "claim_to_proof_matrix_v1.json").read_text(encoding="utf-8")
    )
    real_rows = {row["claim_id"]: row for row in real_matrix.get("claims", [])}
    target_row = dict(real_rows["FE-CLAIM-005"])
    hypothesis_row = dict(real_rows["FE-CLAIM-004-TEE"])

    source_doc = claim_dir / "AUDIT_SOURCE.md"
    source_doc.write_text(
        "Observed E8 non-use certificate bundle verified from real runtime execution.\n",
        encoding="utf-8",
    )
    observed_row = {
        "actual_wording_state": "observed",
        "allowed_state": "observed",
        "artifact_path": str(fresh_bundle),
        "claim_id": "FE-CLAIM-E8-DRILL-OBSERVED",
        "claim_scope": "security",
        "claim_text": "Observed E8 non-use certificate bundle verified from real runtime execution.",
        "decision": "allow_observed",
        "downgrade_text": "Target: E8 non-use certificate pending fresh capstone bundle.",
        "freshness_days": 30,
        "owning_bead": "bd-fqlfw.8",
        "reason": "Real non-mock E8 certificate bundle emitted by example 26.",
        "source_path": str(source_doc),
        "source_span": {
            "start_line": 1,
            "end_line": 1,
            "must_contain": "Observed E8 non-use certificate bundle",
        },
        "verification_command": "rch exec -- env CARGO_TARGET_DIR=/data/projects/franken_engine/.rch-target-e8 cargo run -p frankenengine-engine --example non_exfiltration_certificate",
    }

    fixture_matrix = {
        "schema_version": "franken-engine.claim-to-proof-matrix.v1",
        "max_observed_freshness_days": 30,
        "stale_threshold_days": 30,
        "claims": [observed_row, target_row, hypothesis_row],
    }
    matrix_path = claim_dir / "claim_matrix.json"
    matrix_path.write_text(json.dumps(fixture_matrix, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    beads_path = claim_dir / "issues.jsonl"
    beads_rows = [
        {"id": "bd-fqlfw.8", "status": "closed", "assignee": "ubuntu"},
        {"id": target_row["owning_bead"], "status": "open", "assignee": "ubuntu"},
        {"id": hypothesis_row["owning_bead"], "status": "open", "assignee": "ubuntu"},
    ]
    beads_path.write_text(
        "\n".join(json.dumps(r, sort_keys=True) for r in beads_rows) + "\n",
        encoding="utf-8",
    )
    return matrix_path, beads_path


def run_stage_command(
    cmd: list[str],
    cwd: Path,
    receipt_out_path: Path,
    writes_stdout: bool,
) -> tuple[int, dict[str, Any], str]:
    proc = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, check=False)
    if writes_stdout:
        raw_text = proc.stdout.strip()
        if not raw_text:
            raise RuntimeError(
                f"Stage command emitted empty stdout (rc={proc.returncode}): {' '.join(cmd)}\nstderr={proc.stderr}"
            )
        receipt = json.loads(raw_text)
        receipt_out_path.write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    else:
        if not receipt_out_path.is_file():
            raise RuntimeError(
                f"Stage command did not write receipt {receipt_out_path} (rc={proc.returncode}): {' '.join(cmd)}\nstderr={proc.stderr}"
            )
        receipt = json.loads(receipt_out_path.read_text(encoding="utf-8"))
    return proc.returncode, receipt, proc.stderr


def extract_artifact_hashes(receipt: dict[str, Any]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    art = receipt.get("artifact")
    if isinstance(art, dict) and isinstance(art.get("path"), str) and isinstance(art.get("content_hash"), str):
        hashes[art["path"]] = art["content_hash"]
    for ref in receipt.get("artifact_refs") or []:
        if isinstance(ref, dict) and isinstance(ref.get("path"), str) and isinstance(ref.get("content_hash"), str):
            hashes[ref["path"]] = ref["content_hash"]
    for src in receipt.get("source_inputs") or []:
        if isinstance(src, dict) and isinstance(src.get("path"), str) and isinstance(src.get("content_hash"), str):
            hashes[src["path"]] = src["content_hash"]
    return hashes


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the no-mock external-trust auditor drill in fixture or live mode."
    )
    parser.add_argument(
        "--mode",
        choices=("fixture", "live"),
        default="fixture",
        help="Execution mode: deterministic fixture/replay mode or live-artifact mode.",
    )
    parser.add_argument(
        "--out-dir",
        required=True,
        help="Directory where run_manifest.json, stage receipts, commands.txt, and summaries are written.",
    )
    parser.add_argument(
        "--frankenctl-bin",
        default=None,
        help="Optional explicit path to frankenctl binary.",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    out_dir = Path(args.out_dir).resolve()
    stages_dir = out_dir / "stages"
    stages_dir.mkdir(parents=True, exist_ok=True)

    watched_repo_files = [
        repo_root / "docs" / "claim_to_proof_matrix_v1.json",
        repo_root / ".beads" / "issues.jsonl",
        repo_root
        / "scripts"
        / "testdata"
        / "e8_non_use_certificate_scenario_report"
        / "contract_honest.json",
        repo_root
        / "scripts"
        / "testdata"
        / "e8_non_use_certificate_scenario_report"
        / "certified_bundle"
        / "non_use_certificate.json",
    ]
    pre_hashes = {
        str(p.relative_to(repo_root)): sha256_file(p) for p in watched_repo_files if p.exists()
    }

    frankenctl = resolve_frankenctl(repo_root, args.frankenctl_bin)
    if frankenctl is None:
        raise SystemExit(
            "frankenctl binary not found (set --frankenctl-bin or FRANKENCTL_BIN, or build target/release/frankenctl)"
        )

    e8_fixture_root = (
        repo_root / "scripts" / "testdata" / "e8_non_use_certificate_scenario_report"
    )
    certified_bundle = e8_fixture_root / "certified_bundle"
    smuggle_bundle = e8_fixture_root / "smuggle_bundle"
    contract_honest = e8_fixture_root / "contract_honest.json"
    contract_smuggle = e8_fixture_root / "contract_smuggle.json"

    workdir = Path(tempfile.mkdtemp(prefix="external-trust-auditor-drill-"))
    sentinel_file = workdir / "REPLAY_MUST_NOT_AUTO_EXECUTE.sentinel"
    adv = prepare_adversarial_bundles(certified_bundle, workdir, sentinel_file)

    if args.mode == "fixture":
        matrix_path, beads_path = prepare_fixture_claim_inputs(repo_root, certified_bundle, workdir)
        observed_claim_id = "FE-CLAIM-E8-DRILL-OBSERVED"
        observed_expected_decisions = ["supported"]
        observed_expected_reasons: list[str] = []
    else:
        matrix_path = repo_root / "docs" / "claim_to_proof_matrix_v1.json"
        beads_path = repo_root / ".beads" / "issues.jsonl"
        observed_claim_id = "FE-CLAIM-006"
        # In live mode, observed claims may be supported (when fresh) or truthfully fail_closed
        # with stale_artifact when the preserved June bundle exceeds the 30-day window.
        observed_expected_decisions = ["supported"]
        observed_expected_reasons = []

    stage_specs: list[dict[str, Any]] = [
        {
            "stage_id": "01_claim_observed",
            "scenario": "healthy_claim_explanation",
            "surface": "frankenctl_claims_explain",
            "polarity": "positive_or_live_truth",
            "expected_decisions": observed_expected_decisions,
            "live_degraded_decisions": ["fail_closed"] if args.mode == "live" else [],
            "required_reasons": observed_expected_reasons,
            "writes_stdout": False,
            "build_cmd": lambda out_p: [
                str(frankenctl),
                "claims",
                "explain",
                observed_claim_id,
                "--matrix",
                str(matrix_path),
                "--beads-jsonl",
                str(beads_path),
                "--format",
                "json",
                "--out",
                str(out_p),
            ],
        },
        {
            "stage_id": "02_claim_target_not_promotable",
            "scenario": "degraded_target_claim_unpromotable",
            "surface": "frankenctl_claims_explain",
            "polarity": "negative_guard",
            "expected_decisions": ["not_promotable"],
            "live_degraded_decisions": [],
            "required_reasons": ["claim_not_observed"],
            "writes_stdout": False,
            "build_cmd": lambda out_p: [
                str(frankenctl),
                "claims",
                "explain",
                "FE-CLAIM-005",
                "--matrix",
                str(matrix_path),
                "--beads-jsonl",
                str(beads_path),
                "--format",
                "json",
                "--out",
                str(out_p),
            ],
        },
        {
            "stage_id": "03_claim_hypothesis_not_promotable",
            "scenario": "degraded_hypothesis_claim_unpromotable",
            "surface": "frankenctl_claims_explain",
            "polarity": "negative_guard",
            "expected_decisions": ["not_promotable"],
            "live_degraded_decisions": [],
            "required_reasons": ["claim_not_observed"],
            "writes_stdout": False,
            "build_cmd": lambda out_p: [
                str(frankenctl),
                "claims",
                "explain",
                "FE-CLAIM-004-TEE",
                "--matrix",
                str(matrix_path),
                "--beads-jsonl",
                str(beads_path),
                "--format",
                "json",
                "--out",
                str(out_p),
            ],
        },
        {
            "stage_id": "04_bundle_doctor_healthy",
            "scenario": "bundle_doctor_preserved_healthy",
            "surface": "external_trust_artifact_bundle_doctor",
            "polarity": "positive",
            "expected_decisions": ["supported"],
            "live_degraded_decisions": [],
            "required_reasons": [],
            "writes_stdout": True,
            "build_cmd": lambda _out_p: [
                sys.executable,
                str(repo_root / "scripts" / "external_trust_artifact_bundle_doctor.py"),
                "--bundle",
                str(certified_bundle),
                "--pretty",
            ],
        },
        {
            "stage_id": "05_bundle_doctor_missing_member_fail_closed",
            "scenario": "bundle_doctor_missing_member",
            "surface": "external_trust_artifact_bundle_doctor",
            "polarity": "negative_guard",
            "expected_decisions": ["fail_closed"],
            "live_degraded_decisions": [],
            "required_reasons": ["missing_required_member"],
            "writes_stdout": True,
            "build_cmd": lambda _out_p: [
                sys.executable,
                str(repo_root / "scripts" / "external_trust_artifact_bundle_doctor.py"),
                "--bundle",
                str(adv["missing_member"]),
                "--pretty",
            ],
        },
        {
            "stage_id": "06_bundle_doctor_mock_contaminated_fail_closed",
            "scenario": "bundle_doctor_mock_contaminated",
            "surface": "external_trust_artifact_bundle_doctor",
            "polarity": "negative_guard",
            "expected_decisions": ["fail_closed"],
            "live_degraded_decisions": [],
            "required_reasons": ["mock_contaminated"],
            "writes_stdout": True,
            "build_cmd": lambda _out_p: [
                sys.executable,
                str(repo_root / "scripts" / "external_trust_artifact_bundle_doctor.py"),
                "--bundle",
                str(adv["mock_contaminated"]),
                "--pretty",
            ],
        },
        {
            "stage_id": "07_bundle_doctor_e8_smuggle_not_promotable",
            "scenario": "bundle_doctor_uncertified_e8_refusal",
            "surface": "external_trust_artifact_bundle_doctor",
            "polarity": "negative_guard",
            "expected_decisions": ["not_promotable"],
            "live_degraded_decisions": [],
            "required_reasons": ["explicit_e8_uncertified_refusal"],
            "writes_stdout": True,
            "build_cmd": lambda _out_p: [
                sys.executable,
                str(repo_root / "scripts" / "external_trust_artifact_bundle_doctor.py"),
                "--bundle",
                str(smuggle_bundle),
                "--pretty",
            ],
        },
        {
            "stage_id": "08_e8_report_degraded_before_certifier",
            "scenario": "e8_degraded_without_certifier",
            "surface": "e8_non_use_certificate_scenario_report",
            "polarity": "negative_guard",
            "expected_decisions": ["fail_closed", "degraded"],
            "live_degraded_decisions": [],
            "required_reasons": ["unavailable_e8_certifier"],
            "writes_stdout": True,
            "build_cmd": lambda _out_p: [
                sys.executable,
                str(repo_root / "scripts" / "e8_non_use_certificate_scenario_report.py"),
                "--contract",
                str(contract_honest),
                "--bundle",
                str(adv["absent_e8_bundle"]),
                "--format",
                "json",
                "--pretty",
            ],
        },
        {
            "stage_id": "09_e8_report_healthy_with_capstone",
            "scenario": "e8_healthy_with_capstone_bundle",
            "surface": "e8_non_use_certificate_scenario_report",
            "polarity": "positive",
            "expected_decisions": ["supported"],
            "live_degraded_decisions": [],
            "required_reasons": [],
            "writes_stdout": True,
            "build_cmd": lambda _out_p: [
                sys.executable,
                str(repo_root / "scripts" / "e8_non_use_certificate_scenario_report.py"),
                "--contract",
                str(contract_honest),
                "--bundle",
                str(certified_bundle),
                "--format",
                "json",
                "--pretty",
            ],
        },
        {
            "stage_id": "10_e8_report_smuggle_not_promotable",
            "scenario": "e8_smuggle_refusal_blocks_promotion",
            "surface": "e8_non_use_certificate_scenario_report",
            "polarity": "negative_guard",
            "expected_decisions": ["not_promotable"],
            "live_degraded_decisions": [],
            "required_reasons": ["explicit_e8_uncertified_refusal"],
            "writes_stdout": True,
            "build_cmd": lambda _out_p: [
                sys.executable,
                str(repo_root / "scripts" / "e8_non_use_certificate_scenario_report.py"),
                "--contract",
                str(contract_smuggle),
                "--bundle",
                str(smuggle_bundle),
                "--format",
                "json",
                "--pretty",
            ],
        },
        {
            "stage_id": "11_replay_command_present_not_auto_executed",
            "scenario": "replay_command_present_without_execution",
            "surface": "external_trust_artifact_bundle_doctor",
            "polarity": "positive",
            "expected_decisions": ["supported"],
            "live_degraded_decisions": [],
            "required_reasons": [],
            "require_non_empty_replay": True,
            "writes_stdout": True,
            "build_cmd": lambda _out_p: [
                sys.executable,
                str(repo_root / "scripts" / "external_trust_artifact_bundle_doctor.py"),
                "--bundle",
                str(adv["replay_present_sentinel"]),
                "--pretty",
            ],
        },
        {
            "stage_id": "12_replay_command_absent_fail_closed",
            "scenario": "replay_command_missing_fail_closed",
            "surface": "external_trust_artifact_bundle_doctor",
            "polarity": "negative_guard",
            "expected_decisions": ["fail_closed"],
            "live_degraded_decisions": [],
            "required_reasons": ["replay_command_missing"],
            "writes_stdout": True,
            "build_cmd": lambda _out_p: [
                sys.executable,
                str(repo_root / "scripts" / "external_trust_artifact_bundle_doctor.py"),
                "--bundle",
                str(adv["replay_absent"]),
                "--pretty",
            ],
        },
    ]

    commands_transcript: list[str] = []
    stage_records: list[dict[str, Any]] = []
    reason_counts: dict[str, int] = {}
    reason_stages: dict[str, list[str]] = {}
    all_artifact_hashes: dict[str, str] = {}
    all_remediations: list[str] = []
    hard_failures: list[str] = []
    live_degradations: list[str] = []

    for spec in stage_specs:
        stage_id = spec["stage_id"]
        receipt_path = stages_dir / f"{stage_id}.json"
        cmd = spec["build_cmd"](receipt_path)
        commands_transcript.append(" ".join(shlex.quote(part) for part in cmd))
        rc, receipt, stderr_text = run_stage_command(
            cmd=cmd,
            cwd=repo_root,
            receipt_out_path=receipt_path,
            writes_stdout=bool(spec["writes_stdout"]),
        )
        receipt_sha = sha256_file(receipt_path) or ""
        actual_decision = str(receipt.get("decision", "unknown"))
        reason_codes = [str(code) for code in (receipt.get("reason_codes") or [])]
        replay_commands = [str(item) for item in (receipt.get("replay_commands") or [])]
        remediations = [str(item) for item in (receipt.get("remediation") or [])]
        stage_hashes = extract_artifact_hashes(receipt)
        all_artifact_hashes.update(stage_hashes)
        all_artifact_hashes[f"stage_receipt:{stage_id}"] = receipt_sha

        for code in reason_codes:
            reason_counts[code] = reason_counts.get(code, 0) + 1
            reason_stages.setdefault(code, []).append(stage_id)
        for rem in remediations:
            entry = f"[{stage_id}] {rem}"
            if entry not in all_remediations:
                all_remediations.append(entry)

        mut_policy = receipt.get("mutation_policy")
        mutation_flags_ok = isinstance(mut_policy, dict) and all(
            val is False for val in mut_policy.values()
        )
        if not mutation_flags_ok:
            hard_failures.append(f"{stage_id}: invalid or true mutation_policy flag")

        missing_req_reasons = [
            req for req in spec["required_reasons"] if req not in reason_codes
        ]
        replay_check_ok = True
        if spec.get("require_non_empty_replay") and not replay_commands:
            replay_check_ok = False
            hard_failures.append(f"{stage_id}: expected non-empty replay_commands")

        expectation_status = "pass"
        if actual_decision in spec["expected_decisions"] and not missing_req_reasons and replay_check_ok:
            expectation_status = "pass"
        elif (
            actual_decision in spec["live_degraded_decisions"]
            and not missing_req_reasons
            and replay_check_ok
        ):
            expectation_status = "degraded"
            live_degradations.append(
                f"{stage_id}: live artifact returned {actual_decision} ({','.join(reason_codes)})"
            )
        else:
            expectation_status = "fail_closed"
            hard_failures.append(
                f"{stage_id}: actual_decision={actual_decision} expected={spec['expected_decisions']} missing_reasons={missing_req_reasons}"
            )

        stage_records.append(
            {
                "stage_id": stage_id,
                "scenario": spec["scenario"],
                "surface": spec["surface"],
                "polarity": spec["polarity"],
                "exit_code": rc,
                "expected_decisions": spec["expected_decisions"],
                "live_degraded_decisions": spec["live_degraded_decisions"],
                "required_reasons": spec["required_reasons"],
                "require_non_empty_replay": bool(spec.get("require_non_empty_replay", False)),
                "actual_decision": actual_decision,
                "expectation_status": expectation_status,
                "reason_codes": reason_codes,
                "replay_commands": replay_commands,
                "remediation": remediations,
                "receipt_path": f"stages/{stage_id}.json",
                "receipt_sha256": receipt_sha,
                "mutation_flags_all_false": mutation_flags_ok,
                "stderr_excerpt": stderr_text[:400] if stderr_text else "",
            }
        )

    sentinel_executed = sentinel_file.exists()
    if sentinel_executed:
        hard_failures.append("replay_sentinel_executed: replay command was auto-executed!")

    post_hashes = {
        str(p.relative_to(repo_root)): sha256_file(p) for p in watched_repo_files if p.exists()
    }
    mutated_files = [
        rel for rel, before in pre_hashes.items() if post_hashes.get(rel) != before
    ]
    if mutated_files:
        hard_failures.append(f"watched_repo_files_mutated:{','.join(mutated_files)}")

    if hard_failures:
        overall_decision = "fail_closed"
    elif live_degradations:
        overall_decision = "degraded"
    else:
        overall_decision = "pass"

    commands_path = out_dir / "commands.txt"
    commands_path.write_text("\n".join(commands_transcript) + "\n", encoding="utf-8")

    reason_summary = {
        "schema_version": "franken-engine.external-trust-auditor-reason-summary.v1",
        "counts": dict(sorted(reason_counts.items())),
        "stages_by_reason": {k: sorted(v) for k, v in sorted(reason_stages.items())},
    }
    reason_summary_path = out_dir / "reason_code_summary.json"
    reason_summary_path.write_text(
        json.dumps(reason_summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    artifact_hashes_path = out_dir / "artifact_hashes.json"
    artifact_hashes_path.write_text(
        json.dumps(dict(sorted(all_artifact_hashes.items())), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    remediation_path = out_dir / "remediation.txt"
    remediation_path.write_text(
        ("\n".join(all_remediations) + "\n") if all_remediations else "none\n",
        encoding="utf-8",
    )

    manifest_core = {
        "schema_version": DRILL_SCHEMA_VERSION,
        "mode": args.mode,
        "overall_decision": overall_decision,
        "hard_failures": hard_failures,
        "live_degradations": live_degradations,
        "stage_count": len(stage_records),
        "stages": stage_records,
        "commands_transcript_path": "commands.txt",
        "commands_transcript_sha256": sha256_file(commands_path),
        "reason_code_summary_path": "reason_code_summary.json",
        "reason_code_summary_sha256": sha256_file(reason_summary_path),
        "artifact_hashes_path": "artifact_hashes.json",
        "artifact_hashes_sha256": sha256_file(artifact_hashes_path),
        "remediation_path": "remediation.txt",
        "remediation_sha256": sha256_file(remediation_path),
        "replay_auto_execution_guard": {
            "sentinel_triggered": sentinel_executed,
            "auto_executes_replay": False,
        },
        "immutability_guard": {
            "mutated": bool(mutated_files),
            "mutated_files": mutated_files,
            "watched_pre_hashes": pre_hashes,
            "watched_post_hashes": post_hashes,
        },
        "mutation_policy": {
            "mutates_br": False,
            "mutates_agent_mail": False,
            "mutates_file_reservations": False,
            "mutates_remote_workers": False,
            "mutates_evidence_bundles": False,
            "mutates_claim_matrix": False,
            "mutates_git": False,
            "runs_cargo": False,
            "runs_rch": False,
        },
    }
    run_manifest = {
        **manifest_core,
        "drill_id": f"auditor-drill-{canonical_json_hash(manifest_core)[:16]}",
        "generated_at_utc": utc_now(),
    }
    (out_dir / "run_manifest.json").write_text(
        json.dumps(run_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    print(
        json.dumps(
            {
                "drill_id": run_manifest["drill_id"],
                "mode": args.mode,
                "overall_decision": overall_decision,
                "stage_count": len(stage_records),
                "hard_failures": hard_failures,
                "live_degradations": live_degradations,
                "out_dir": str(out_dir),
            },
            sort_keys=True,
        )
    )
    return 0 if overall_decision in ("pass", "degraded") else 1


if __name__ == "__main__":
    raise SystemExit(main())
