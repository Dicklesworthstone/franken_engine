#!/usr/bin/env python3
"""Neutral producer-distinct challenge checker for BRIDGE-00.2 (tu32j.1.2).

Independently challenges the live repository and `franken_execution_truth_ledger
audit-output-claims` against:
  1. Live repository baseline (must exit 0, status=pass)
  2. Valid executable-tier + conformance fixture bundles (must exit 0)
  3. Seeded false claim in synthesis doc (IR4 execution-ready over-claim -> FE-OUTGATE-2015)
  4. Seeded stale executable bundle (age > max_age_days -> FE-OUTGATE-2016)
  5. Seeded unowned document exclusion/override (-> FE-OUTGATE-2015)
  6. Seeded backend-label-only executable bundle (-> FE-OUTGATE-2004)
  7. Seeded simulated compile-duration executable bundle (-> FE-OUTGATE-2005)
  8. Seeded input-only hash executable bundle (-> FE-OUTGATE-2006)
  9. Seeded tampered machine-code byte hash (-> FE-OUTGATE-2007)
 10. Seeded synthetic Test262 conformance percentage (-> FE-OUTGATE-2014)

Emits an immutable content-addressed `challenge_handoff.json` for BRIDGE-21.6 / G0.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def write_json(path: Path, payload: object) -> str:
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    path.write_bytes(encoded)
    return sha256_bytes(encoded)


def make_valid_exec_bundle() -> dict:
    code = bytes([0x55, 0x48, 0x89, 0xE5, 0xB8, 0x2A, 0x00, 0x00, 0x00, 0x5D, 0xC3])
    return {
        "schema_version": "franken-engine.executable-tier-claim-bundle.v1",
        "bundle_id": "challenge-exec-valid",
        "owning_bead": "bd-performance-conformance-bridge-tu32j.1.2",
        "claim_id": "FE-CLAIM-010",
        "backend_kind": "x86_64_sysv_linked_jit",
        "generated_at_utc": "2026-11-17T08:00:00Z",
        "max_age_days": 14,
        "simulated": False,
        "compile_duration_origin": "measured_wall_ns",
        "compile_duration_ns": 152000,
        "input_ir_sha256": sha256_bytes(b"challenge-ir3-input-v1"),
        "machine_code_hex": code.hex(),
        "machine_code_byte_len": len(code),
        "final_byte_sha256": sha256_bytes(code),
        "actual_dispatch_count": 8,
        "disassembly_lines": [
            "0000: push rbp",
            "0001: mov rbp, rsp",
            "0004: mov eax, 42",
            "0009: pop rbp",
            "000a: ret",
        ],
        "stack_map_entries": [{"code_offset": 4, "live_root_slots": [0]}],
        "deopt_map_entries": [
            {"code_offset": 4, "ir3_pc": 1, "reason": "int32_overflow"}
        ],
        "tier_r_equivalence": {
            "verified": True,
            "witness_cases_passed": 16,
            "witness_cases_total": 16,
            "tier_r_trace_sha256": sha256_bytes(b"challenge-tier-r-trace-v1"),
        },
    }


def make_valid_conf_bundle(repo_root: Path) -> dict:
    manifest_rel = "docs/test262_real_corpus_pass_rate_v1.json"
    manifest_sha = sha256_file(repo_root / manifest_rel)
    return {
        "schema_version": "franken-engine.conformance-claim-bundle.v1",
        "bundle_id": "challenge-conf-valid",
        "owning_bead": "bd-performance-conformance-bridge-tu32j.1.2",
        "claim_id": "FE-CLAIM-TEST262",
        "generated_at_utc": "2026-11-17T08:00:00Z",
        "max_age_days": 14,
        "selected_manifest_path": manifest_rel,
        "selected_manifest_sha256": manifest_sha,
        "selected_case_ids": [
            "built-ins/Array/isArray/15.4.3.2-0-1.js",
            "language/types/number/S8.5_A1.js",
        ],
        "selected_case_count": 2,
        "executed_count": 2,
        "passed_count": 1,
        "failed_count": 1,
        "skipped_count": 0,
        "pass_rate_millionths": 500000,
        "synthetic_percentage": False,
        "estimation_method": "exact_executed_corpus",
        "full_suite_claim_allowed": False,
        "harness_oracle": {
            "oracle_kind": "test262_harness_v1",
            "includes_preloaded": True,
            "async_done_tracked": True,
            "negative_phase_verified": True,
        },
    }


def run_case(
    validator_bin: Path,
    repo_root: Path,
    case_id: str,
    extra_args: list[str],
    expect_pass: bool,
    expected_code: str | None,
) -> dict:
    cmd = [
        str(validator_bin),
        "audit-output-claims",
        "--repo-root",
        str(repo_root),
        "--scenario-id",
        f"challenge-{case_id}",
        "--as-of",
        "2026-11-17T09:00:00Z",
        *extra_args,
    ]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return {
            "case_id": case_id,
            "expect_pass": expect_pass,
            "expected_error_code": expected_code,
            "exit_code": proc.returncode,
            "report_status": f"invalid_json:{exc}",
            "observed_error_codes": [],
            "verdict": "fail",
        }
    observed_codes = sorted({f["error_code"] for f in report.get("findings", [])})
    if expect_pass:
        verdict_ok = proc.returncode == 0 and report.get("status") == "pass"
    else:
        verdict_ok = (
            proc.returncode == 1
            and report.get("status") == "fail"
            and (expected_code in observed_codes if expected_code else len(observed_codes) > 0)
        )
    return {
        "case_id": case_id,
        "expect_pass": expect_pass,
        "expected_error_code": expected_code,
        "exit_code": proc.returncode,
        "report_status": report.get("status"),
        "observed_error_codes": observed_codes,
        "verdict": "pass" if verdict_ok else "fail",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--validator-bin", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    fixtures_dir = args.work_dir / "challenge_fixtures"
    fixtures_dir.mkdir(parents=True, exist_ok=True)

    valid_exec = make_valid_exec_bundle()
    valid_conf = make_valid_conf_bundle(args.repo_root)
    valid_exec_path = fixtures_dir / "valid_exec.json"
    valid_conf_path = fixtures_dir / "valid_conf.json"
    write_json(valid_exec_path, valid_exec)
    write_json(valid_conf_path, valid_conf)

    false_claim_doc = fixtures_dir / "seeded_false_claim_readme.md"
    false_claim_doc.write_text(
        "# FrankenEngine\n100% ES2020 Test262 conformance achieved and Cranelift native JIT is active in production.\n",
        encoding="utf-8",
    )

    stale_exec = dict(valid_exec, bundle_id="seeded-stale", generated_at_utc="2026-09-01T00:00:00Z")
    stale_exec_path = fixtures_dir / "stale_exec.json"
    write_json(stale_exec_path, stale_exec)

    backend_label = dict(valid_exec, bundle_id="seeded-label", backend_kind="cranelift_planning_label")
    backend_label_path = fixtures_dir / "backend_label_exec.json"
    write_json(backend_label_path, backend_label)

    sim_compile = dict(valid_exec, bundle_id="seeded-simulated", simulated=True)
    sim_compile_path = fixtures_dir / "sim_compile_exec.json"
    write_json(sim_compile_path, sim_compile)

    input_hash = dict(
        valid_exec,
        bundle_id="seeded-input-hash",
        input_ir_sha256=valid_exec["final_byte_sha256"],
    )
    input_hash_path = fixtures_dir / "input_hash_exec.json"
    write_json(input_hash_path, input_hash)

    tampered_exec = dict(valid_exec, bundle_id="seeded-tamper", machine_code_hex="90c3", machine_code_byte_len=2)
    tampered_exec_path = fixtures_dir / "tampered_exec.json"
    write_json(tampered_exec_path, tampered_exec)

    synth_conf = dict(valid_conf, bundle_id="seeded-synthetic-pct", synthetic_percentage=True)
    synth_conf_path = fixtures_dir / "synthetic_conf.json"
    write_json(synth_conf_path, synth_conf)

    challenges = [
        run_case(args.validator_bin, args.repo_root, "live_repo_baseline", [], True, None),
        run_case(
            args.validator_bin,
            args.repo_root,
            "valid_bundles",
            [
                "--executable-bundle",
                str(valid_exec_path),
                "--conformance-bundle",
                str(valid_conf_path),
            ],
            True,
            None,
        ),
        run_case(
            args.validator_bin,
            args.repo_root,
            "seeded_false_claim",
            ["--doc-override", f"README.md={false_claim_doc}"],
            False,
            "FE-OUTGATE-2015",
        ),
        run_case(
            args.validator_bin,
            args.repo_root,
            "seeded_stale_input",
            ["--skip-repo-language-scan", "--executable-bundle", str(stale_exec_path)],
            False,
            "FE-OUTGATE-2016",
        ),
        run_case(
            args.validator_bin,
            args.repo_root,
            "seeded_unowned_exclusion",
            ["--doc-override", f"docs/UNOWNED_EXCLUSION.md={false_claim_doc}"],
            False,
            "FE-OUTGATE-2015",
        ),
        run_case(
            args.validator_bin,
            args.repo_root,
            "seeded_backend_label_only",
            ["--skip-repo-language-scan", "--executable-bundle", str(backend_label_path)],
            False,
            "FE-OUTGATE-2004",
        ),
        run_case(
            args.validator_bin,
            args.repo_root,
            "seeded_simulated_compile_time",
            ["--skip-repo-language-scan", "--executable-bundle", str(sim_compile_path)],
            False,
            "FE-OUTGATE-2005",
        ),
        run_case(
            args.validator_bin,
            args.repo_root,
            "seeded_input_only_hash",
            ["--skip-repo-language-scan", "--executable-bundle", str(input_hash_path)],
            False,
            "FE-OUTGATE-2006",
        ),
        run_case(
            args.validator_bin,
            args.repo_root,
            "seeded_byte_tamper",
            ["--skip-repo-language-scan", "--executable-bundle", str(tampered_exec_path)],
            False,
            "FE-OUTGATE-2007",
        ),
        run_case(
            args.validator_bin,
            args.repo_root,
            "seeded_synthetic_conformance_percentage",
            ["--skip-repo-language-scan", "--conformance-bundle", str(synth_conf_path)],
            False,
            "FE-OUTGATE-2014",
        ),
    ]

    all_passed = all(item["verdict"] == "pass" for item in challenges)
    handoff = {
        "schema_version": "franken-engine.executable-output-truth-gate.challenge-handoff.v1",
        "checker_id": "neutral_python_output_truth_challenger_v1",
        "producer_distinct": True,
        "owning_bead": "bd-performance-conformance-bridge-tu32j.1.2",
        "downstream_verifier_beads": [
            "bd-performance-conformance-bridge-tu32j.1.4",
            "bd-performance-conformance-bridge-tu32j.22.6",
        ],
        "validator_sha256": sha256_file(args.validator_bin),
        "challenge_count": len(challenges),
        "verdict": "pass" if all_passed else "fail",
        "challenges": challenges,
    }
    handoff_sha = write_json(args.out, handoff)
    print(json.dumps({"verdict": handoff["verdict"], "handoff_sha256": handoff_sha}))
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
