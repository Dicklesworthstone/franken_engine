#!/usr/bin/env python3
"""Docs and claim-language truth gate for external-trust artifact UX (bd-grwh9.7).

Rejects documentation claiming that external-trust explainers/doctors/reports:
  1. prove or establish runtime soundness;
  2. prove or certify E8 / certificate soundness;
  3. prove or execute replay success;
  4. prove or refresh artifact freshness without citing receipt freshness fields
     (`actual_freshness_days` / `evidence_freshness`) and an upstream gate;
  5. promote claims from transport-only evidence.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


GATE_SCHEMA_VERSION = "franken-engine.external-trust-docs-truth-gate.v1"

EXPL_SUBJECT = (
    r"(?:claim\s+explainer|bundle\s+doctor|e8\s+scenario\s+report|"
    r"external[- ]trust\s+explainer|explainer\s+receipt|frankenctl\s+claims\s+explain)"
)

NEGATION_GUARD = re.compile(
    r"\b(?:no|not|never|cannot|can't|does\s+not|do\s+not|doesn't|don't|neither|nor|non-authority|advisory)\b",
    re.IGNORECASE,
)

FORBIDDEN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "explainer_proves_runtime_soundness",
        re.compile(
            rf"{EXPL_SUBJECT}[^\n.;]{{0,80}}\b(?:proves?|establishes?|certifies|guarantees?)\b[^\n.;]{{0,60}}\bruntime\s+soundness\b",
            re.IGNORECASE,
        ),
    ),
    (
        "explainer_proves_certificate_soundness",
        re.compile(
            rf"{EXPL_SUBJECT}[^\n.;]{{0,80}}\b(?:proves?|establishes?|certifies|guarantees?)\b[^\n.;]{{0,60}}\b(?:certificate|non-use|non-exfiltration)\s+soundness\b",
            re.IGNORECASE,
        ),
    ),
    (
        "explainer_proves_replay_success",
        re.compile(
            rf"{EXPL_SUBJECT}[^\n.;]{{0,80}}\b(?:proves?|executes?|verifies|guarantees?)\b[^\n.;]{{0,60}}\breplay\s+success\b",
            re.IGNORECASE,
        ),
    ),
    (
        "transport_only_promotion_overclaim",
        re.compile(
            r"\bpromot(?:e|es|able)\b[^\n.;]{0,60}\bfrom\s+transport[- ]only\s+evidence\b",
            re.IGNORECASE,
        ),
    ),
)

FRESHNESS_OVERCLAIM_RE = re.compile(
    rf"{EXPL_SUBJECT}[^\n.;]{{0,80}}\b(?:proves?|refreshes|establishes?|guarantees?)\b[^\n.;]{{0,60}}\bartifact\s+freshness\b",
    re.IGNORECASE,
)

FRESHNESS_AUTHORITY_CITATION_RE = re.compile(
    r"(?:actual_freshness_days|evidence_freshness)[\s\S]{0,200}(?:run_claim_to_proof_matrix_gate\.sh|upstream\s+gate)"
    r"|(?:run_claim_to_proof_matrix_gate\.sh|upstream\s+gate)[\s\S]{0,200}(?:actual_freshness_days|evidence_freshness)",
    re.IGNORECASE,
)

REQUIRED_RUNBOOK_MARKERS = (
    "frankenctl claims explain",
    "scripts/external_trust_artifact_bundle_doctor.py",
    "scripts/e8_non_use_certificate_scenario_report.py",
    "scripts/external_trust_no_mock_auditor_drill.py",
    "scripts/check_external_trust_auditor_drill_truth_gate.py",
    "source_or_test_failure",
    "rch_admission_denial",
    "remote_stale_or_no_verdict",
    "partial_artifact_bundle",
    "explicit_owner_signoff_or_target_posture",
)

REQUIRED_UPSTREAM_PATHS = (
    "docs/external_trust_artifact_ux_contract_v1.json",
    "docs/EXTERNAL_TRUST_ARTIFACT_UX_CONTRACT_V1.md",
    "scripts/run_claim_to_proof_matrix_gate.sh",
    "scripts/run_dw_non_use_certificate.sh",
    "scripts/external_trust_artifact_bundle_doctor.py",
    "scripts/e8_non_use_certificate_scenario_report.py",
    "scripts/external_trust_no_mock_auditor_drill.py",
    "scripts/check_external_trust_auditor_drill_truth_gate.py",
)


def scan_doc(path: Path, require_runbook_structure: bool) -> list[dict[str, Any]]:
    violations: list[dict[str, Any]] = []
    if not path.is_file():
        return [{"doc": str(path), "line": 0, "code": "missing_doc_file", "excerpt": ""}]

    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    for idx, line in enumerate(lines, start=1):
        # Evaluate clause-by-clause (split on ';' or '.') so negation in one clause
        # only guards that clause.
        clauses = re.split(r"[.;]", line)
        for clause in clauses:
            if NEGATION_GUARD.search(clause):
                continue
            for code, pattern in FORBIDDEN_PATTERNS:
                if pattern.search(clause):
                    violations.append(
                        {
                            "doc": str(path),
                            "line": idx,
                            "code": code,
                            "excerpt": clause.strip()[:160],
                        }
                    )
            if FRESHNESS_OVERCLAIM_RE.search(clause):
                if not FRESHNESS_AUTHORITY_CITATION_RE.search(text):
                    violations.append(
                        {
                            "doc": str(path),
                            "line": idx,
                            "code": "explainer_overclaims_freshness_authority",
                            "excerpt": clause.strip()[:160],
                        }
                    )

    if require_runbook_structure:
        for marker in REQUIRED_RUNBOOK_MARKERS:
            if marker not in text:
                violations.append(
                    {
                        "doc": str(path),
                        "line": 0,
                        "code": f"missing_runbook_marker:{marker}",
                        "excerpt": "",
                    }
                )
    return violations


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate external-trust UX docs against forbidden soundness/replay/freshness overclaims."
    )
    parser.add_argument(
        "--doc",
        action="append",
        default=[],
        help="Explicit markdown document(s) to scan (defaults to repo runbook, contract, and README).",
    )
    parser.add_argument(
        "--require-runbook-markers",
        action="store_true",
        help="Require full operator runbook markers on all --doc inputs.",
    )
    parser.add_argument(
        "--skip-repo-upstream-check",
        action="store_true",
        help="Skip repository upstream file existence checks (for isolated unit fixtures).",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    violations: list[dict[str, Any]] = []

    if not args.skip_repo_upstream_check:
        for rel in REQUIRED_UPSTREAM_PATHS:
            if not (repo_root / rel).is_file():
                violations.append(
                    {
                        "doc": rel,
                        "line": 0,
                        "code": "missing_upstream_surface",
                        "excerpt": "",
                    }
                )
        contract_json = json.loads(
            (repo_root / "docs" / "external_trust_artifact_ux_contract_v1.json").read_text(
                encoding="utf-8"
            )
        )
        receipt_fields = json.dumps(contract_json)
        for required_field in ("evidence_freshness", "replay_commands", "mutation_policy"):
            if required_field not in receipt_fields:
                violations.append(
                    {
                        "doc": "docs/external_trust_artifact_ux_contract_v1.json",
                        "line": 0,
                        "code": f"missing_contract_receipt_field:{required_field}",
                        "excerpt": "",
                    }
                )

    if args.doc:
        targets = [(Path(p), args.require_runbook_markers) for p in args.doc]
    else:
        targets = [
            (repo_root / "runbooks" / "external_trust_artifact_ux.md", True),
            (repo_root / "docs" / "EXTERNAL_TRUST_ARTIFACT_UX_CONTRACT_V1.md", False),
            (repo_root / "README.md", False),
        ]

    for doc_path, req_markers in targets:
        violations.extend(scan_doc(doc_path, req_markers))

    verdict = "pass" if not violations else "fail_closed"
    report = {
        "schema_version": GATE_SCHEMA_VERSION,
        "scanned_docs": [str(p) for p, _ in targets],
        "verdict": verdict,
        "violation_count": len(violations),
        "violations": violations,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if verdict == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
