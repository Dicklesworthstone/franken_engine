#!/usr/bin/env python3
"""Compute source and environment drift for every OBSERVED claim.

ADR-0012 §1 defines an OBSERVED artifact as stale when ANY of three things holds:

  1. source drift       the source revision of the covered code moved since the receipt
  2. environment drift  the toolchain fingerprint moved since the receipt
  3. time backstop      the per-claim freshness window elapsed

Only (3) was implemented. That is why the ADR's own migration-risk clause forbids
calling the model "risk-weighted" in operator prose: a clock is not a risk model. It
cannot tell a receipt for code nobody has touched in six months (still perfectly
good) from a receipt for a file that changed an hour ago (already worthless).

This module implements (1) and (2). Both read data the receipts already carry:

  - `inputs.source_files`   the covered-paths list, present on all 16 OBSERVED claims
  - `source_revision.commit` the revision the receipt was generated at
  - `outputs.environment_fingerprint` written by reemit_evidence_receipts.py

Deliberately conservative
-------------------------
Every case where drift cannot be *computed* is reported as `unknown`, never as
`fresh`. An evidence system that reports "no drift" when it means "I could not
check" is worse than one that reports nothing, because the first is trusted.

Usage
-----
    python3 scripts/check_evidence_drift.py [--json PATH] [--only IDS] [--fail-on-drift]

Exit codes
----------
    0  no drift (or drift found, without --fail-on-drift)
    1  drift found and --fail-on-drift was passed (ADR-0012 §4 release mode)
    2  usage / IO error
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
MATRIX = REPO / "docs" / "claim_to_proof_matrix_v1.json"
EVIDENCE_DIR = REPO / "docs" / "evidence"

ENVIRONMENT_FINGERPRINT_SCHEMA = "franken-engine.evidence-environment-fingerprint.v1"


def _run(argv: list[str], timeout: int = 30) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            argv, cwd=str(REPO), capture_output=True, text=True, timeout=timeout
        )
        return proc.returncode, proc.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return 1, ""


def environment_fingerprint() -> dict:
    """Fingerprint the parts of the environment that can change a build's result.

    Shared with reemit_evidence_receipts.py by import rather than duplicated: two
    implementations that disagree by one field would report drift on every claim
    forever, which is indistinguishable from the noise this replaces.

    Deliberately excluded: wall clock, hostname, cwd, environment variables. Those
    vary between two runs that should be considered identical, and including them
    would make every fingerprint unique and the signal useless.
    """
    _, rustc_version = _run(["rustc", "--version"])
    _, rustc_verbose = _run(["rustc", "-vV"])

    host_triple = ""
    for line in rustc_verbose.splitlines():
        if line.startswith("host:"):
            host_triple = line.split(":", 1)[1].strip()
            break

    _, cargo_version = _run(["cargo", "--version"])

    fields = {
        "rustc_version": rustc_version,
        "cargo_version": cargo_version,
        "rustc_host_triple": host_triple,
        "kernel_release": platform.release(),
        "architecture": platform.machine(),
        "platform": platform.system().lower(),
    }
    canonical = json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()
    return {
        "schema_version": ENVIRONMENT_FINGERPRINT_SCHEMA,
        "digest": "sha256:" + hashlib.sha256(canonical).hexdigest(),
        "fields": fields,
    }


def observed_claims(only: set[str]) -> list[dict]:
    matrix = json.loads(MATRIX.read_text())
    claims = [c for c in matrix["claims"] if c.get("allowed_state") == "observed"]
    if only:
        claims = [c for c in claims if c["claim_id"] in only]
    return claims


def source_drift(manifest: dict) -> dict:
    """Has any covered path changed since the receipt's recorded revision?"""
    source_revision = manifest.get("source_revision") or {}
    recorded = source_revision.get("commit") or ""
    covered = (manifest.get("inputs") or {}).get("source_files") or []

    # A receipt produced while its covered paths were modified-but-uncommitted is
    # not attributable to any commit: a third party checking out `recorded` gets
    # different code than the one that passed. That is a stronger failure than "the
    # code moved since" -- the receipt was never true of the commit it names -- so
    # it must not be reported as clean no matter how recent it is. `drifted` rather
    # than a fourth verdict keeps ADR-0012 §1's three-state contract intact and
    # produces the correct gate behaviour (downgrade to provisional).
    if source_revision.get("worktree_dirty"):
        dirty_paths = source_revision.get("dirty_covered_paths") or []
        return {
            "status": "drifted",
            "reason": (
                "receipt was produced from a modified worktree; the pass is not "
                f"attributable to {recorded[:8] or 'the recorded revision'}"
            ),
            "covered_path_count": len(covered),
            "recorded_revision": recorded,
            "dirty_covered_paths": dirty_paths[:10],
        }

    if not covered:
        return {
            "status": "unknown",
            "reason": "receipt carries no inputs.source_files, so covered code is undeclared",
            "covered_path_count": 0,
        }
    if not recorded or recorded == "unknown":
        return {
            "status": "unknown",
            "reason": "receipt carries no source_revision.commit",
            "covered_path_count": len(covered),
        }

    # A recorded revision that is not an ancestor of HEAD (rebase, or a receipt
    # carried over from another branch) makes the range meaningless. Say so.
    code, _ = _run(["git", "merge-base", "--is-ancestor", recorded, "HEAD"])
    if code != 0:
        return {
            "status": "unknown",
            "reason": f"recorded revision {recorded[:8]} is not an ancestor of HEAD",
            "covered_path_count": len(covered),
            "recorded_revision": recorded,
        }

    code, out = _run(
        ["git", "log", "--oneline", f"{recorded}..HEAD", "--"] + covered, timeout=60
    )
    if code != 0:
        return {
            "status": "unknown",
            "reason": "git log over the covered paths failed",
            "covered_path_count": len(covered),
            "recorded_revision": recorded,
        }

    commits = [line for line in out.splitlines() if line.strip()]
    if not commits:
        return {
            "status": "clean",
            "covered_path_count": len(covered),
            "recorded_revision": recorded,
        }
    return {
        "status": "drifted",
        "reason": f"{len(commits)} commit(s) touched covered code since the receipt",
        "covered_path_count": len(covered),
        "recorded_revision": recorded,
        "commits": commits[:10],
    }


def environment_drift(manifest: dict, current: dict) -> dict:
    """Does the receipt's recorded environment fingerprint match the current one?"""
    recorded = (manifest.get("outputs") or {}).get("environment_fingerprint")
    if not recorded:
        return {
            "status": "unknown",
            "reason": (
                "receipt predates environment fingerprinting; re-emit it to make "
                "environment drift computable"
            ),
        }
    if recorded.get("digest") == current["digest"]:
        return {"status": "clean", "digest": current["digest"]}

    recorded_fields = recorded.get("fields") or {}
    changed = {
        key: {"recorded": recorded_fields.get(key), "current": value}
        for key, value in current["fields"].items()
        if recorded_fields.get(key) != value
    }
    return {
        "status": "drifted",
        "reason": f"{len(changed)} environment field(s) changed since the receipt",
        "changed_fields": changed,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compute ADR-0012 §1 source and environment drift per OBSERVED claim."
    )
    parser.add_argument("--json", dest="json_path", default="", help="write the report here")
    parser.add_argument("--only", default="", help="comma-separated claim ids")
    parser.add_argument(
        "--fail-on-drift",
        action="store_true",
        help="exit 1 when any claim has drifted (ADR-0012 §4 release mode)",
    )
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    only = {s.strip() for s in args.only.split(",") if s.strip()}

    try:
        claims = observed_claims(only)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: could not read the matrix: {exc}", file=sys.stderr)
        return 2

    current = environment_fingerprint()
    results = []

    for claim in claims:
        claim_id = claim["claim_id"]
        manifest_path = EVIDENCE_DIR / claim_id / "manifest.json"
        if not manifest_path.is_file():
            results.append(
                {
                    "claim_id": claim_id,
                    "freshness_tier": claim.get("freshness_tier"),
                    "source_drift": {"status": "unknown", "reason": "no receipt manifest"},
                    "environment_drift": {"status": "unknown", "reason": "no receipt manifest"},
                    "verdict": "unknown",
                }
            )
            continue

        try:
            manifest = json.loads(manifest_path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: {claim_id}: unreadable receipt: {exc}", file=sys.stderr)
            return 2

        src = source_drift(manifest)
        env = environment_drift(manifest, current)
        statuses = {src["status"], env["status"]}
        if "drifted" in statuses:
            verdict = "drifted"
        elif "unknown" in statuses:
            verdict = "unknown"
        else:
            verdict = "clean"

        results.append(
            {
                "claim_id": claim_id,
                "freshness_tier": claim.get("freshness_tier"),
                "owning_bead": claim.get("owning_bead"),
                "source_drift": src,
                "environment_drift": env,
                "verdict": verdict,
            }
        )

    counts: dict[str, int] = {}
    for result in results:
        counts[result["verdict"]] = counts.get(result["verdict"], 0) + 1

    report = {
        "schema_version": "franken-engine.evidence-drift-report.v1",
        "owning_bead": "bd-performance-conformance-bridge-tu32j.20.18",
        "adr": "docs/adr/ADR-0012-evidence-freshness-model.md",
        "current_environment": current,
        "summary": {
            "observed_total": len(results),
            "clean": counts.get("clean", 0),
            "drifted": counts.get("drifted", 0),
            "unknown": counts.get("unknown", 0),
        },
        "results": results,
    }

    if args.json_path:
        out = Path(args.json_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    if not args.quiet:
        summary = report["summary"]
        print(
            f"evidence_drift=observed_total={summary['observed_total']} "
            f"clean={summary['clean']} drifted={summary['drifted']} "
            f"unknown={summary['unknown']} env_digest={current['digest'][:19]}"
        )
        for result in results:
            if result["verdict"] == "clean":
                continue
            parts = []
            if result["source_drift"]["status"] != "clean":
                parts.append(f"source={result['source_drift']['status']}")
            if result["environment_drift"]["status"] != "clean":
                parts.append(f"env={result['environment_drift']['status']}")
            print(f"  {result['claim_id']}: {' '.join(parts)}", file=sys.stderr)

    drifted = report["summary"]["drifted"]
    return 1 if (args.fail_on_drift and drifted) else 0


if __name__ == "__main__":
    sys.exit(main())
