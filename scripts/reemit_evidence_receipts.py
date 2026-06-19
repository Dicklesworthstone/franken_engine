#!/usr/bin/env python3
"""CEI B.2 (bd-sde5e.2.2): re-emit *real* reproducibility receipts from live gate runs.

Replaces the `backfill_reproducibility_bundles.py` output (which stamped every
OBSERVED claim's manifest with ``verification_result = "pending"`` /
``generated_by = "backfill..."``) with receipts produced by actually running each
claim's ``verification_command``. A receipt is written ONLY when the command exits
zero; on any non-zero exit the existing receipt is left untouched and the claim is
reported as failed.

For each OBSERVED claim in ``docs/claim_to_proof_matrix_v1.json`` this updates the
committed ``docs/evidence/<CLAIM>/manifest.json`` in place:

* ``outputs.verification_result``  -> ``"passed"``
* ``outputs.verification_command`` -> the (substituted) command that was run
* ``outputs.verified_at_utc``      -> real UTC timestamp of the run
* ``outputs.exit_code``            -> 0
* ``provenance.generated_by``      -> ``"reemit_evidence_receipts.py (live gate run)"``
* ``generated_at_utc``             -> real UTC timestamp
* ``source_revision.commit``       -> current HEAD

After this runs, re-run ``franken_evidence_manifest generate`` so the
content-addressed ``evidence_manifest.json`` picks up the new receipt, and the
advisory soundness lattice (``claim_evidence_lattice.rs``) will score the row as
``verification_passed`` (tier Reproduced -> ceiling Observed).

Substitutions applied to each command so the gates reuse this session's warm
build instead of a cold per-agent / rch target:

* ``<agent>``                    -> ``icydeer``
* ``rch exec -- env ``           -> stripped (run locally with RCH bypass)
* ``/tmp/rch_target_icydeer``    -> ``<repo>/target_icydeer``
* ``target/debug/frankenctl``    -> ``<repo>/target_icydeer/debug/frankenctl``
* ``CARGO_TARGET_DIR`` for bare-cargo commands -> ``<repo>/target_icydeer``

Usage:
    python3 scripts/reemit_evidence_receipts.py [--only FE-CLAIM-XXX,...] [--timeout N]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
AGENT = "icydeer"
WARM_TARGET = str(REPO / "target_icydeer")
MATRIX = REPO / "docs" / "claim_to_proof_matrix_v1.json"
EVIDENCE_DIR = REPO / "docs" / "evidence"


def head_commit() -> str:
    out = subprocess.run(
        ["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True, text=True
    )
    return out.stdout.strip() if out.returncode == 0 else "unknown"


def observed_claims() -> list[dict]:
    matrix = json.loads(MATRIX.read_text())
    return [c for c in matrix["claims"] if c.get("allowed_state") == "observed"]


def substitute(command: str) -> str:
    """Rewrite a matrix verification_command to reuse the warm local target."""
    cmd = command.replace("<agent>", AGENT)
    # Neutralize rch: run the cargo locally with the wrapper bypassed.
    cmd = cmd.replace("rch exec -- env ", "")
    cmd = cmd.replace("rch exec -- ", "")
    cmd = cmd.replace(f"/tmp/rch_target_{AGENT}", WARM_TARGET)
    cmd = cmd.replace("target/debug/frankenctl", f"{WARM_TARGET}/debug/frankenctl")
    return cmd


def run_command(command: str, timeout: int) -> tuple[int, str]:
    env = dict(os.environ)
    env["RCH_CARGO_WRAPPER_BYPASS"] = "1"
    env.setdefault("RUSTFLAGS", "-C linker=cc")
    env.setdefault("CARGO_INCREMENTAL", "0")
    # Bare `cargo ...` commands (no explicit CARGO_TARGET_DIR) reuse the warm target.
    if "cargo" in command and "CARGO_TARGET_DIR" not in command:
        env["CARGO_TARGET_DIR"] = WARM_TARGET
    try:
        proc = subprocess.run(
            command,
            shell=True,
            cwd=str(REPO),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        tail = (proc.stdout + proc.stderr).strip().splitlines()[-3:]
        return proc.returncode, "\n".join(tail)
    except subprocess.TimeoutExpired:
        return 124, f"TIMEOUT after {timeout}s"


def reemit(claim_id: str, command: str, commit: str) -> None:
    manifest_path = EVIDENCE_DIR / claim_id / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    now = datetime.now(timezone.utc).isoformat()

    outputs = manifest.setdefault("outputs", {})
    outputs["verification_result"] = "passed"
    outputs["verification_command"] = command
    outputs["verified_at_utc"] = now
    outputs["exit_code"] = 0

    provenance = manifest.setdefault("provenance", {})
    provenance["generated_by"] = "reemit_evidence_receipts.py (live gate run)"

    manifest["generated_at_utc"] = now
    manifest.setdefault("source_revision", {})["commit"] = commit

    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="", help="comma-separated claim ids to run")
    ap.add_argument("--timeout", type=int, default=900)
    args = ap.parse_args()
    only = {s.strip() for s in args.only.split(",") if s.strip()}

    commit = head_commit()
    claims = observed_claims()
    if only:
        claims = [c for c in claims if c["claim_id"] in only]

    passed, failed = [], []
    for c in claims:
        cid = c["claim_id"]
        raw = c.get("verification_command", "")
        if not raw:
            print(f"[{cid}] SKIP (no verification_command)")
            continue
        command = substitute(raw)
        print(f"[{cid}] running: {command[:110]}")
        code, tail = run_command(command, args.timeout)
        if code == 0:
            reemit(cid, command, commit)
            passed.append(cid)
            print(f"[{cid}] PASSED -> real receipt written")
        else:
            failed.append((cid, code))
            print(f"[{cid}] FAILED exit={code}\n    {tail}")

    print(f"\nreemit: {len(passed)} passed, {len(failed)} failed")
    if failed:
        print("failed:", ", ".join(f"{c}({code})" for c, code in failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
