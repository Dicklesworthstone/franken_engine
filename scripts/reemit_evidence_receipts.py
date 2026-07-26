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
import time
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Both scripts live in scripts/, which is sys.path[0] when this is run as
# `python3 scripts/reemit_evidence_receipts.py`. Add it explicitly so the import
# also works when the script is invoked through a symlink or from a wrapper.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_evidence_drift import environment_fingerprint  # noqa: E402

# bd-...tu32j.20.18 (BRIDGE-19.18) / ADR-0012: the agent id and warm-target path
# used to be hardcoded to "icydeer" -- the agent who first wrote this script.
# That is fine for a human running it by hand in that agent's tree and wrong for
# the scheduled, unattended job this is becoming: on any other machine the
# substituted path does not exist, and claims whose verification_command embeds a
# binary path fail with a *tooling* error that is easy to misread as the claim
# having regressed. FE-CLAIM-007 failed exactly that way ("frankenctl binary is
# not executable: .../target_icydeer/debug/frankenctl") while the claim itself was
# fine. Both are now overridable, and the default target is the ordinary cargo
# target directory rather than one agent's scratch dir.
AGENT = os.environ.get("REEMIT_AGENT") or os.environ.get("AGENT_NAME") or "icydeer"
WARM_TARGET = os.environ.get("REEMIT_TARGET_DIR") or str(REPO / "target")
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
    # Only redirect a binary path if the redirected binary actually exists.
    # Rewriting it unconditionally is how a present-and-working frankenctl gets
    # replaced by a path that was never built, turning a passing claim into a
    # spurious "regression" (BRIDGE-19.18).
    warm_ctl = Path(WARM_TARGET) / "debug" / "frankenctl"
    if warm_ctl.is_file() and os.access(warm_ctl, os.X_OK):
        cmd = cmd.replace("target/debug/frankenctl", str(warm_ctl))
    return cmd


def linker_policy_is_effective(rustflags: str) -> bool:
    """Return whether the final linker-features directive disables implicit LLD."""
    tokens = rustflags.split()
    effective_value: str | None = None
    for index, token in enumerate(tokens):
        if token.startswith("-Clinker-features="):
            effective_value = token.removeprefix("-Clinker-features=")
        elif (
            token == "-C"
            and index + 1 < len(tokens)
            and tokens[index + 1].startswith("linker-features=")
        ):
            effective_value = tokens[index + 1].removeprefix("linker-features=")
    return effective_value == "-lld"


def run_command(command: str, timeout: int) -> tuple[int, str, float]:
    started = time.monotonic()
    env = dict(os.environ)
    env.pop("CARGO_ENCODED_RUSTFLAGS", None)
    env["RCH_CARGO_WRAPPER_BYPASS"] = "1"
    rustflags = env.get("RUSTFLAGS") or "-C linker=cc -Clinker-features=-lld"
    if not linker_policy_is_effective(rustflags):
        rustflags = f"{rustflags} -Clinker-features=-lld"
    env["RUSTFLAGS"] = rustflags
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
        return proc.returncode, "\n".join(tail), time.monotonic() - started
    except subprocess.TimeoutExpired:
        return 124, f"TIMEOUT after {timeout}s", time.monotonic() - started


def reemit(claim_id: str, command: str, commit: str) -> None:
    manifest_path = EVIDENCE_DIR / claim_id / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    now = datetime.now(timezone.utc).isoformat()

    outputs = manifest.setdefault("outputs", {})
    outputs["verification_result"] = "passed"
    outputs["verification_command"] = command
    outputs["verified_at_utc"] = now
    outputs["exit_code"] = 0
    # ADR-0012 §1 signal 2 (BRIDGE-19.18): record the environment this receipt was
    # actually produced under, so `check_evidence_drift.py` can later tell whether
    # the toolchain moved. The sibling env.json is NOT rewritten -- it is part of
    # the reproducibility contract and its retention block declares it immutable.
    #
    # Imported rather than reimplemented: two fingerprint functions that disagreed
    # by a single field would report drift on every claim forever.
    outputs["environment_fingerprint"] = environment_fingerprint()

    provenance = manifest.setdefault("provenance", {})
    provenance["generated_by"] = "reemit_evidence_receipts.py (live gate run)"

    manifest["generated_at_utc"] = now
    manifest.setdefault("source_revision", {})["commit"] = commit

    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Re-emit real reproducibility receipts by running each OBSERVED "
        "claim's verification_command."
    )
    ap.add_argument("--only", default="", help="comma-separated claim ids to run")
    ap.add_argument("--timeout", type=int, default=900)
    # ADR-0012 impl-note 1. The scheduled job needs two things this script did not
    # have: a way to run one shard so an expensive claim cannot gate the cheap
    # ones, and per-claim results, since a single aggregate exit code cannot say
    # WHICH claim regressed -- the thing an operator actually needs to know.
    ap.add_argument(
        "--tier",
        default="",
        help="only run claims in this freshness_tier (volatile|standard|frozen)",
    )
    ap.add_argument(
        "--json",
        dest="json_path",
        default="",
        help="write per-claim results (id, tier, exit code, duration) here",
    )
    args = ap.parse_args()
    only = {s.strip() for s in args.only.split(",") if s.strip()}

    commit = head_commit()
    claims = observed_claims()
    if only:
        claims = [c for c in claims if c["claim_id"] in only]
    if args.tier:
        claims = [c for c in claims if c.get("freshness_tier") == args.tier]
        if not claims:
            print(f"error: no OBSERVED claim carries freshness_tier={args.tier!r}", file=sys.stderr)
            return 2

    results: list[dict] = []
    passed, failed = [], []
    for c in claims:
        cid = c["claim_id"]
        tier = c.get("freshness_tier")
        raw = c.get("verification_command", "")
        if not raw:
            print(f"[{cid}] SKIP (no verification_command)")
            results.append({"claim_id": cid, "freshness_tier": tier, "status": "skipped"})
            continue
        command = substitute(raw)
        print(f"[{cid}] running: {command[:110]}")
        code, tail, duration = run_command(command, args.timeout)
        result = {
            "claim_id": cid,
            "freshness_tier": tier,
            "owning_bead": c.get("owning_bead"),
            "exit_code": code,
            # Recorded so a future pass can shard by MEASURED cost. Sharding is by
            # freshness tier today because no per-claim cost data existed to shard
            # on; this is how that data starts existing.
            "duration_seconds": round(duration, 1),
            "command": command,
        }
        if code == 0:
            reemit(cid, command, commit)
            passed.append(cid)
            result["status"] = "passed"
            print(f"[{cid}] PASSED -> real receipt written")
        else:
            failed.append((cid, code))
            result["status"] = "failed"
            result["output_tail"] = tail
            print(f"[{cid}] FAILED exit={code}\n    {tail}")
        results.append(result)

    if args.json_path:
        out = Path(args.json_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(
                {
                    "schema_version": "franken-engine.evidence-refresh-run.v1",
                    "generated_at_utc": datetime.now(timezone.utc).isoformat(),
                    "source_revision": commit,
                    "tier": args.tier or None,
                    "agent": AGENT,
                    "summary": {
                        "attempted": len(results),
                        "passed": len(passed),
                        "failed": len(failed),
                    },
                    "results": results,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
        print(f"reemit_report={out}")

    print(f"\nreemit: {len(passed)} passed, {len(failed)} failed")
    if failed:
        print("failed:", ", ".join(f"{c}({code})" for c, code in failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
