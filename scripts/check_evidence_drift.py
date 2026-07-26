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
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
MATRIX = REPO / "docs" / "claim_to_proof_matrix_v1.json"
EVIDENCE_DIR = REPO / "docs" / "evidence"

ENVIRONMENT_FINGERPRINT_SCHEMA = "franken-engine.evidence-environment-fingerprint.v1"

# ---------------------------------------------------------------------------
# Material vs advisory environment fields (ADR-0012 §5.3, BRIDGE-19.18)
# ---------------------------------------------------------------------------
# The first version of this check compared the whole fingerprint as one digest,
# so ANY difference in ANY field meant `drifted`. Measured consequence, less
# than a day after the 16 receipts were refreshed: `rustc 1.99.0-nightly
# (da86f4d07 2026-07-24)` became `(008fa22ce 2026-07-25)` and every claim that
# carried a fingerprint went stale at once.
#
# That is not conservatism, it is saturation. This repository has no
# `rust-toolchain.toml`; it floats on `nightly`, which rolls daily, so a
# comparison that includes the nightly build id fires on every claim every day
# and can therefore never distinguish a claim whose environment meaningfully
# moved from one whose did not. A signal that is always on carries no
# information, and an always-provisional gate is the "rubber-stamp" failure
# ADR-0012 exists to prevent.
#
# So each field is compared at the granularity at which a change plausibly
# changes a build's RESULT, not at the granularity at which the string changes:
#
#   verbatim       any difference is material (host triple, arch, platform)
#   release_token  the release+channel, without the build id
#                  `rustc 1.99.0-nightly (008fa22ce 2026-07-25)` -> `rustc 1.99.0-nightly`
#   kernel_series  major.minor, without the distro ABI suffix
#                  `6.17.0-41-generic` -> `6.17`
#
# What this deliberately gives up, and why that is affordable: a nightly bump
# CAN change codegen, and this projection no longer detects one. Two things
# bound that. (a) The time backstop is retained precisely for "environmental
# drift below the recorded granularity" (ADR-0012 §2), and advisory drift
# accumulates with the clock, so the backstop is the mechanism that eventually
# forces a re-verification. (b) If a toolchain bump actually breaks a claim,
# its verification command FAILS at the next scheduled refresh, and ADR-0012 §5
# reports that as a REGRESSION -- loud, and categorically distinct from
# staleness. The residual exposure is therefore "carrying an unverified but not
# known-broken OBSERVED for at most one freshness window", never "silently
# passing a claim known to fail".
#
# Advisory changes are still recorded per claim, so the demotion is visible
# rather than a silent hole.
MATERIAL_FIELD_RULES = {
    "platform": "verbatim",
    "architecture": "verbatim",
    "rustc_host_triple": "verbatim",
    "rustc_version": "release_token",
    "cargo_version": "release_token",
    "kernel_release": "kernel_series",
}


def _release_token(value: str) -> str:
    """`rustc 1.99.0-nightly (008fa22ce 2026-07-25)` -> `rustc 1.99.0-nightly`."""
    head, _, _ = value.partition(" (")
    return head.strip()


def _kernel_series(value: str) -> str:
    """`6.17.0-41-generic` -> `6.17`; anything unparseable is kept verbatim."""
    match = re.match(r"^(\d+)\.(\d+)", value.strip())
    return f"{match.group(1)}.{match.group(2)}" if match else value.strip()


def material_projection(fields: dict) -> dict:
    """Project a recorded fingerprint onto the fields compared for staleness.

    A field absent from MATERIAL_FIELD_RULES is compared verbatim: an unknown
    field is treated as material, so extending the fingerprint cannot silently
    widen what this check ignores.
    """
    projected = {}
    for key, value in fields.items():
        rule = MATERIAL_FIELD_RULES.get(key, "verbatim")
        text = "" if value is None else str(value)
        if rule == "release_token":
            projected[key] = _release_token(text)
        elif rule == "kernel_series":
            projected[key] = _kernel_series(text)
        else:
            projected[key] = text
    return projected


def material_digest(fields: dict) -> str:
    canonical = json.dumps(
        material_projection(fields), sort_keys=True, separators=(",", ":")
    ).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


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
        # Identity of the exact environment, for forensics. NOT the staleness
        # comparand -- see MATERIAL_FIELD_RULES.
        "digest": "sha256:" + hashlib.sha256(canonical).hexdigest(),
        # The comparand. Recorded so a receipt states which environment identity
        # it was judged under, rather than leaving that to the reader's version
        # of this script.
        "material_digest": material_digest(fields),
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
    """Has the receipt's environment moved *materially* since it was written?

    Compares the material projection (see MATERIAL_FIELD_RULES), not the raw
    fingerprint. A change confined to advisory precision -- a nightly build id,
    a distro kernel ABI bump -- is reported under `advisory_drift` and does not
    force staleness, because on an unpinned nightly that fires daily on every
    claim and so distinguishes nothing.
    """
    recorded = (manifest.get("outputs") or {}).get("environment_fingerprint")
    if not recorded:
        return {
            "status": "unknown",
            "reason": (
                "receipt predates environment fingerprinting; re-emit it to make "
                "environment drift computable"
            ),
        }

    # Fast path: byte-identical environment. Nothing to project or explain.
    if recorded.get("digest") == current["digest"]:
        return {"status": "clean", "digest": current["digest"]}

    recorded_fields = recorded.get("fields") or {}
    if not recorded_fields:
        # A digest with no fields cannot be projected, so material and advisory
        # change are indistinguishable. Stay with the conservative verdict
        # rather than guessing which one this was.
        return {
            "status": "drifted",
            "reason": (
                "receipt records an environment digest but no fields, so material "
                "drift cannot be separated from advisory drift"
            ),
            "recorded_digest": recorded.get("digest"),
            "current_digest": current["digest"],
        }

    recorded_material = material_projection(recorded_fields)
    current_material = material_projection(current["fields"])

    # Union of keys: a field present on one side and absent on the other is a
    # change, and iterating only `current` would miss a dropped field.
    keys = sorted(set(recorded_material) | set(current_material))

    changed_material = {
        key: {
            "recorded": recorded_fields.get(key),
            "current": current["fields"].get(key),
            "compared_as": MATERIAL_FIELD_RULES.get(key, "verbatim"),
            "recorded_material": recorded_material.get(key),
            "current_material": current_material.get(key),
        }
        for key in keys
        if recorded_material.get(key) != current_material.get(key)
    }

    advisory = {
        key: {"recorded": recorded_fields.get(key), "current": current["fields"].get(key)}
        for key in keys
        if key not in changed_material and recorded_fields.get(key) != current["fields"].get(key)
    }

    if changed_material:
        return {
            "status": "drifted",
            "reason": (
                f"{len(changed_material)} material environment field(s) changed "
                "since the receipt"
            ),
            "changed_fields": changed_material,
            "advisory_drift": advisory,
        }

    # Material identity held. Say precisely that, not "the environment is
    # identical" -- it demonstrably is not, and the difference is recorded.
    return {
        "status": "clean",
        "digest": current["digest"],
        "material_digest": material_digest(current["fields"]),
        "reason": (
            f"{len(advisory)} environment field(s) changed below material "
            "precision (build id / kernel ABI); the time backstop covers this class"
        ),
        "advisory_drift": advisory,
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

    # Claims whose environment moved, but only below material precision. Counted
    # separately so the ADR-0012 §5.3 demotion is auditable: "we saw N
    # environments move and deliberately did not call them stale" is a
    # reviewable statement; silence is not.
    advisory_only = sum(
        1
        for result in results
        if (result.get("environment_drift") or {}).get("advisory_drift")
        and (result.get("environment_drift") or {}).get("status") == "clean"
    )

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
            "environment_advisory_only": advisory_only,
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
            f"unknown={summary['unknown']} "
            f"env_advisory_only={summary['environment_advisory_only']} "
            f"env_digest={current['digest'][:19]}"
        )
        for result in results:
            env = result.get("environment_drift") or {}
            parts = []
            if result["source_drift"]["status"] != "clean":
                parts.append(f"source={result['source_drift']['status']}")
            if env.get("status") != "clean":
                parts.append(f"env={env.get('status')}")
            elif env.get("advisory_drift"):
                # Not stale, but not silent either.
                parts.append(f"env=advisory({len(env['advisory_drift'])})")
            if not parts:
                continue
            print(f"  {result['claim_id']}: {' '.join(parts)}", file=sys.stderr)

    drifted = report["summary"]["drifted"]
    return 1 if (args.fail_on_drift and drifted) else 0


if __name__ == "__main__":
    sys.exit(main())
