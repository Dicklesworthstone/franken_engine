#!/usr/bin/env python3
"""
Execution-derived receipt refresh entry point (bd-q0cwt).

Historically this script generated docs/evidence bundles in-process with
placeholder hashes and asserted booleans; bd-q0cwt removed those generators.
The writer of record is now ``reemit_evidence_receipts.py``: it executes each
claim's verification_command at HEAD and writes a receipt ONLY on success.
This entry point stays for callers of the old name and simply delegates,
propagating per-claim failures as a non-zero exit.
"""

import json
import subprocess
import sys
from pathlib import Path
from typing import Dict

# OBSERVED claims that need backfill (from bd-cixqu.4.1 audit)
OBSERVED_CLAIMS = [
    {
        "claim_id": "FE-CLAIM-001",
        "claim_scope": "runtime",
        "original_artifact_path": "docs/audit/ga_success_criteria_gap_analysis.md",
        "verification_command": "CARGO_TARGET_DIR=/data/projects/franken_engine/target_<agent> CARGO_INCREMENTAL=0 RUSTFLAGS=\"-C linker=cc -Clinker-features=-lld\" cargo check -p frankenengine-engine --tests",
        "replay_commands": [
            "cargo check -p frankenengine-engine --tests"
        ]
    },
    {
        "claim_id": "FE-CLAIM-002",
        "claim_scope": "security",
        "original_artifact_path": "scripts/e2e/live_guardplane_decision_smoke.sh",
        "verification_command": "./scripts/e2e/live_guardplane_decision_smoke.sh",
        "replay_commands": [
            "./scripts/e2e/live_guardplane_decision_smoke.sh"
        ]
    },
    {
        "claim_id": "FE-CLAIM-003",
        "claim_scope": "replay",
        "original_artifact_path": "crates/franken-engine/src/counterfactual_replay_engine.rs",
        "verification_command": "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_<agent> CARGO_INCREMENTAL=0 RUSTFLAGS=\"-C linker=cc -Clinker-features=-lld\" cargo test -p frankenengine-engine --test deterministic_replay_integration --test counterfactual_replay_engine_integration",
        "replay_commands": [
            "cargo test -p frankenengine-engine --test deterministic_replay_integration --test counterfactual_replay_engine_integration"
        ]
    },
    {
        "claim_id": "FE-CLAIM-004",
        "claim_scope": "security",
        "original_artifact_path": "scripts/run_rgc_signed_decision_receipt.sh",
        "verification_command": "./scripts/run_rgc_signed_decision_receipt.sh ci",
        "replay_commands": [
            "./scripts/run_rgc_signed_decision_receipt.sh ci"
        ]
    },
    {
        "claim_id": "FE-CLAIM-007",
        "claim_scope": "operations",
        "original_artifact_path": "scripts/e2e/readme_cli_workflow_smoke.sh",
        "verification_command": "FRANKENCTL_BIN=target/debug/frankenctl ./scripts/e2e/readme_cli_workflow_smoke.sh",
        "replay_commands": [
            "./scripts/e2e/readme_cli_workflow_smoke.sh"
        ]
    },
    {
        "claim_id": "FE-CLAIM-008",
        "claim_scope": "operations",
        "original_artifact_path": "README.md",
        "verification_command": "./scripts/run_claim_to_proof_matrix_gate.sh ci",
        "replay_commands": [
            "./scripts/run_claim_to_proof_matrix_gate.sh ci"
        ]
    },
    {
        "claim_id": "FE-CLAIM-011",
        "claim_scope": "security",
        "original_artifact_path": "scripts/run_red_team_compromise_rate_metric_gate.sh",
        "verification_command": "./scripts/run_red_team_compromise_rate_metric_gate.sh ci",
        "replay_commands": [
            "./scripts/run_red_team_compromise_rate_metric_gate.sh ci"
        ]
    },
    {
        "claim_id": "FE-CLAIM-012",
        "claim_scope": "security",
        "original_artifact_path": "scripts/run_containment_latency_metric_gate.sh",
        "verification_command": "./scripts/run_containment_latency_metric_gate.sh ci",
        "replay_commands": [
            "./scripts/run_containment_latency_metric_gate.sh ci"
        ]
    },
    {
        "claim_id": "FE-CLAIM-013",
        "claim_scope": "replay",
        "original_artifact_path": "scripts/run_replay_coverage_metric_gate.sh",
        "verification_command": "./scripts/run_replay_coverage_metric_gate.sh ci && rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_<agent> CARGO_INCREMENTAL=0 RUSTFLAGS=\"-C linker=cc -Clinker-features=-lld\" cargo test -p frankenengine-engine --test deterministic_replay_integration frankenctl_compile_and_run_artifacts_are_deterministic_with_fixed_inputs",
        "replay_commands": [
            "./scripts/run_replay_coverage_metric_gate.sh ci",
            "cargo test -p frankenengine-engine --test deterministic_replay_integration frankenctl_compile_and_run_artifacts_are_deterministic_with_fixed_inputs"
        ]
    },
    {
        "claim_id": "FE-CLAIM-015",
        "claim_scope": "ifc",
        "original_artifact_path": "scripts/e2e/live_ifc_declassification_smoke.sh",
        "verification_command": "./scripts/e2e/live_ifc_declassification_smoke.sh",
        "replay_commands": [
            "./scripts/e2e/live_ifc_declassification_smoke.sh"
        ]
    },
    {
        # bd-c1nbg: FE-CLAIM-023 was observed in the matrix but absent here, so
        # the standard generator never produced its manifest.json/env.json and
        # the claim-to-proof gate derived freshness=999 (stale -> exit 1).
        "claim_id": "FE-CLAIM-023",
        "claim_scope": "reproducibility",
        "original_artifact_path": "scripts/run_rgc_cross_platform_matrix_gate.sh",
        "verification_command": "./scripts/run_rgc_cross_platform_matrix_gate.sh ci",
        "replay_commands": [
            "./scripts/run_rgc_cross_platform_matrix_gate.sh ci"
        ]
    }
]

def get_git_commit_hash() -> str:
    """Get current git commit hash."""
    import subprocess
    try:
        result = subprocess.run(['git', 'rev-parse', 'HEAD'],
                              capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return "unknown"

def reemit_receipt(claim_id: str) -> int:
    """Run the honest receipt writer for one claim (bd-q0cwt).

    The in-process generators that used to live here emitted placeholder
    ``schema_hash`` values, unconditional validation booleans, and
    ``verification_result = "pending"`` without ever executing a producer --
    exactly the fixture-as-evidence class AGENTS.md bans. Bundles now come
    ONLY from ``reemit_evidence_receipts.py``, which runs each claim's
    verification_command at HEAD and writes nothing on a non-zero exit.
    """
    result = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).resolve().parent / "reemit_evidence_receipts.py"),
            "--only",
            claim_id,
        ],
    )
    return result.returncode


def backfill_claim(claim: Dict) -> bool:
    """Backfill one claim's receipt through the execution-derived writer."""
    claim_id = claim["claim_id"]
    print(f"Backfilling {claim_id} via reemit_evidence_receipts.py...")
    code = reemit_receipt(claim_id)
    if code == 0:
        print(f"  ✓ {claim_id}: execution-derived receipt refreshed")
    else:
        print(f"  ✗ {claim_id}: reemit exited {code}; no bundle was written")
    return code == 0

def update_claim_matrix() -> None:
    """Update claim_to_proof_matrix_v1.json to point to bundle directories."""
    matrix_path = Path("docs/claim_to_proof_matrix_v1.json")

    if not matrix_path.exists():
        print(f"Warning: {matrix_path} not found, skipping update")
        return

    print("Updating claim matrix artifact paths...")

    with open(matrix_path, 'r') as f:
        matrix = json.load(f)

    # Update artifact_path for each OBSERVED claim
    updated_count = 0
    for claim_data in OBSERVED_CLAIMS:
        claim_id = claim_data["claim_id"]
        new_path = f"artifacts/reproducibility_bundles/{claim_id}"

        # Find and update this claim in the matrix
        for section in matrix.get("claims", []):
            if section.get("claim_id") == claim_id:
                old_path = section.get("artifact_path")
                section["artifact_path"] = new_path
                print(f"  ✓ {claim_id}: {old_path} → {new_path}")
                updated_count += 1
                break

    # Write updated matrix
    write_json_file(matrix_path, matrix)
    print(f"Updated {updated_count} claims in matrix file")

def verify_bundles() -> None:
    """Verify all generated bundles have required files."""
    print("Verifying generated bundles...")

    for claim_data in OBSERVED_CLAIMS:
        claim_id = claim_data["claim_id"]
        bundle_dir = Path(f"artifacts/reproducibility_bundles/{claim_id}")

        required_files = ["env.json", "manifest.json", "repro.lock"]
        missing_files = []

        for file in required_files:
            if not (bundle_dir / file).exists():
                missing_files.append(file)

        if missing_files:
            print(f"  ✗ {claim_id}: Missing {', '.join(missing_files)}")
        else:
            print(f"  ✓ {claim_id}: Complete bundle")

def main():
    """Refresh every listed claim's receipt through the execution-derived writer."""
    print("Refreshing reproducibility receipts for OBSERVED FE-CLAIM-* rows...")
    print(f"Target claims: {len(OBSERVED_CLAIMS)}")
    print()

    failed = []
    for claim in OBSERVED_CLAIMS:
        if not backfill_claim(claim):
            failed.append(claim["claim_id"])
        print()

    update_claim_matrix()
    print()

    verify_bundles()
    print()

    if failed:
        print(f"FAILED ({len(failed)}): no receipt written for {', '.join(failed)}")
        return 1
    print("Receipt refresh complete: every claim re-verified by live producer runs.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
