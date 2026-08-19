#!/usr/bin/env python3
"""
Audit existing OBSERVED rows for missing repro.lock partner

For each currently-OBSERVED FE-CLAIM-*, confirm the artifact_path bundle contains
env.json + manifest.json + repro.lock per docs/REPRODUCIBILITY_CONTRACT.md.
Output a coverage report listing rows that need a backfill bundle.

Implements bd-cixqu.4.1
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Set, Optional

def load_latest_claim_report() -> Dict:
    """Load the most recent claim-to-proof gate report."""
    gate_dir = Path("artifacts/claim_to_proof_matrix_gate")
    if not gate_dir.exists():
        print(f"Error: {gate_dir} does not exist")
        sys.exit(1)

    # Get the latest report directory
    latest_dir = sorted(gate_dir.iterdir(), key=lambda x: x.name)[-1]
    report_path = latest_dir / "claim_to_proof_gate_report.json"

    if not report_path.exists():
        print(f"Error: {report_path} does not exist")
        sys.exit(1)

    print(f"Loading claim report from: {report_path}")

    with open(report_path, 'r') as f:
        return json.load(f)

def extract_observed_claims(report: Dict) -> List[Dict]:
    """Extract all OBSERVED FE-CLAIM-* entries from the report."""
    observed_claims = []

    for event in report.get("events", []):
        if (event.get("event_name") == "claim_to_proof_matrix.claim_checked" and
            event.get("actual_wording_state") == "observed" and
            event.get("claim_id", "").startswith("FE-CLAIM-")):
            observed_claims.append(event)

    return observed_claims

def check_reproducibility_bundle(artifact_path: str) -> Dict[str, bool]:
    """
    Check if artifact_path contains required reproducibility bundle files.

    Returns dict with status for each required file:
    - env.json
    - manifest.json
    - repro.lock
    """
    result = {
        "env.json": False,
        "manifest.json": False,
        "repro.lock": False,
        "is_directory": False,
        "exists": False
    }

    if not artifact_path:
        return result

    path = Path(artifact_path)
    result["exists"] = path.exists()

    if not path.exists():
        return result

    result["is_directory"] = path.is_dir()

    if path.is_dir():
        # Check for required files in directory
        result["env.json"] = (path / "env.json").exists()
        result["manifest.json"] = (path / "manifest.json").exists()
        result["repro.lock"] = (path / "repro.lock").exists()
    else:
        # Single file - this means it needs backfill to bundle format
        # None of the required bundle files are present
        pass

    return result

def generate_coverage_report(observed_claims: List[Dict]) -> None:
    """Generate coverage report for OBSERVED claims reproducibility compliance."""

    print("\n" + "="*80)
    print("OBSERVED FE-CLAIM-* REPRODUCIBILITY COMPLIANCE AUDIT")
    print("="*80)
    print(f"Report generated: {__file__}")
    print(f"Total OBSERVED claims: {len(observed_claims)}")
    print()

    compliant_claims = []
    non_compliant_claims = []

    for claim in observed_claims:
        claim_id = claim.get("claim_id")
        artifact_path = claim.get("artifact_path")

        bundle_status = check_reproducibility_bundle(artifact_path)

        is_compliant = (
            bundle_status["is_directory"] and
            bundle_status["env.json"] and
            bundle_status["manifest.json"] and
            bundle_status["repro.lock"]
        )

        claim_info = {
            "claim_id": claim_id,
            "artifact_path": artifact_path,
            "bundle_status": bundle_status,
            "is_compliant": is_compliant
        }

        if is_compliant:
            compliant_claims.append(claim_info)
        else:
            non_compliant_claims.append(claim_info)

    # Report compliant claims
    print("COMPLIANT CLAIMS (proper reproducibility bundles):")
    print("-" * 50)
    if compliant_claims:
        for claim in compliant_claims:
            print(f"✓ {claim['claim_id']}: {claim['artifact_path']}")
    else:
        print("None")

    print()

    # Report non-compliant claims requiring backfill
    print("NON-COMPLIANT CLAIMS (need backfill bundles):")
    print("-" * 50)
    for claim in non_compliant_claims:
        claim_id = claim['claim_id']
        artifact_path = claim['artifact_path']
        status = claim['bundle_status']

        print(f"✗ {claim_id}: {artifact_path}")

        if not status['exists']:
            print(f"   ERROR: artifact_path does not exist")
        elif not status['is_directory']:
            print(f"   ISSUE: artifact_path is single file, needs bundle directory")
        else:
            missing_files = []
            for file in ['env.json', 'manifest.json', 'repro.lock']:
                if not status[file]:
                    missing_files.append(file)
            print(f"   ISSUE: directory missing required files: {', '.join(missing_files)}")

        print()

    # Summary
    print("SUMMARY:")
    print("-" * 50)
    print(f"Total OBSERVED claims: {len(observed_claims)}")
    print(f"Compliant (ready): {len(compliant_claims)}")
    print(f"Non-compliant (need backfill): {len(non_compliant_claims)}")
    print(f"Compliance rate: {len(compliant_claims) / len(observed_claims) * 100:.1f}%")
    print()

    if non_compliant_claims:
        print("RECOMMENDED ACTIONS:")
        print("-" * 50)
        print("1. For single-file artifact_path entries:")
        print("   - Create bundle directory for each claim")
        print("   - Generate env.json, manifest.json, repro.lock per docs/REPRODUCIBILITY_CONTRACT.md")
        print("   - Update artifact_path to point to bundle directory")
        print()
        print("2. For directory entries missing files:")
        print("   - Generate missing files per reproducibility contract")
        print()
        print("3. Reference bd-cixqu.4.2 for backfill implementation")

    print("\nEND OF REPORT")

def main():
    """Main audit function."""
    print("Starting OBSERVED FE-CLAIM-* reproducibility audit...")

    # Load latest claim report
    report = load_latest_claim_report()

    # Extract OBSERVED claims
    observed_claims = extract_observed_claims(report)

    # Generate coverage report
    generate_coverage_report(observed_claims)

if __name__ == "__main__":
    main()