#!/usr/bin/env python3
"""CEI B.2 (bd-sde5e.2.2): re-emit *real* reproducibility receipts from live gate runs.

Replaces the `backfill_reproducibility_bundles.py` output (which stamped every
OBSERVED claim's manifest with ``verification_result = "pending"`` /
``generated_by = "backfill..."``) with receipts produced by actually running each
claim's ``verification_command``. A receipt is written ONLY when the command exits
zero; on any non-zero exit the existing receipt is left untouched and the claim is
reported as failed.

A non-zero exit is reported as one of *two* distinct states, never one (bd-566x4).
ADR-0012 §5 separates regression from staleness but names only those two outcomes;
there is a third, and collapsing it into "regression" points an operator at the
claim when the fault is the machine:

* ``regression``     -- the command ran and the claim did not hold. A real alarm.
* ``infrastructure`` -- the command could not be run to a verdict (build tree
  deleted underneath it, disk exhausted, stale crate metadata, timeout). Says
  nothing about the claim.

Both write no receipt, so the fail-closed property below is unchanged; they differ
only in what they tell the reader. An ``infrastructure`` result is retried once in
an isolated target directory before it can be reported at all, because the dominant
cause in this repo is target-tree contention between concurrent agents, and that is
exactly what isolation fixes.

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
import re
import shutil
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

# bd-566x4. The retry target dir is deliberately NOT a fresh mkdtemp per run: the
# whole point is a tree no other agent knows the name of, and a stable name stays
# warm across runs. A per-run temp dir would make every retry a cold ~30 GB build.
SIGNATURES_PATH = REPO / "docs" / "infrastructure_failure_signatures_v1.json"
RETRY_TARGET = os.environ.get("REEMIT_RETRY_TARGET_DIR") or str(
    REPO / "target_evidence_refresh"
)
# A retry allocates a build tree. Doing that unconditionally on a nearly-full disk
# turns one infrastructure failure into a worse one, so the retry declines itself
# and says so rather than pushing the machine over.
RETRY_MIN_FREE_GB = int(os.environ.get("REEMIT_RETRY_MIN_FREE_GB") or "60")


def head_commit() -> str:
    out = subprocess.run(
        ["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True, text=True
    )
    return out.stdout.strip() if out.returncode == 0 else "unknown"


def dirty_covered_paths(covered: list[str]) -> list[str]:
    """Which of a claim's covered paths differ from HEAD right now.

    A receipt names a commit, and a reader is entitled to assume that checking out
    that commit and re-running the verification command reproduces the pass. That
    assumption is false whenever the covered paths were modified-but-uncommitted at
    run time: what ran was the working tree, not the commit.

    This is not hypothetical. FE-CLAIM-022's 2026-07-26 receipt recorded 49e4edd3b,
    but the lockstep pipeline's CARGO_TARGET_DIR fix was still uncommitted when the
    run started (it landed 34 seconds later as 818dbe700). At 49e4edd3b the very
    command in the receipt exits 127. The receipt attributed a pass to a commit that
    fails -- over-claiming, in the one direction the evidence system exists to
    prevent.
    """
    if not covered:
        return []
    out = subprocess.run(
        ["git", "-C", str(REPO), "status", "--porcelain", "--"] + covered,
        capture_output=True,
        text=True,
    )
    if out.returncode != 0:
        # Cannot prove clean, so do not claim clean. Naming the whole covered set
        # keeps the receipt honest without inventing a path list we did not observe.
        return sorted(covered)
    paths = []
    for line in out.stdout.splitlines():
        if len(line) > 3:
            paths.append(line[3:].strip())
    return sorted(set(paths))


def observed_claims() -> list[dict]:
    matrix = json.loads(MATRIX.read_text())
    return [c for c in matrix["claims"] if c.get("allowed_state") == "observed"]


def load_covered_paths(claim_id: str) -> list[str]:
    """The claim's declared covered paths, read from its existing receipt.

    Same source `check_evidence_drift.py` reads, so the paths this script checks for
    uncommitted edits are exactly the paths the drift checker later scans for
    commits. Two different notions of "covered" would let a receipt pass one and
    fail the other for reasons no operator could act on.
    """
    manifest_path = EVIDENCE_DIR / claim_id / "manifest.json"
    if not manifest_path.is_file():
        return []
    try:
        manifest = json.loads(manifest_path.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    return (manifest.get("inputs") or {}).get("source_files") or []


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


def load_signatures() -> dict:
    """Load the shared infrastructure-failure contract (bd-566x4).

    Imported from a JSON contract rather than inlined for the same reason
    ``environment_fingerprint`` is imported from ``check_evidence_drift`` above:
    a second, drifting copy of the rules is how two parts of this system start
    disagreeing about what happened.
    """
    try:
        return json.loads(SIGNATURES_PATH.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        # Fail toward `regression`, the conservative direction: if the contract
        # cannot be read, nothing gets excused as infrastructure.
        print(f"warning: cannot read {SIGNATURES_PATH.name}: {exc}", file=sys.stderr)
        return {"exit_code_rules": [], "signatures": []}


def classify_failure(code: int, output: str, signatures: dict) -> tuple[str, str]:
    """Classify a non-zero exit as ``regression`` or ``infrastructure``.

    Returns ``(kind, reason)``. Per the contract's ``conservative_default``, a
    failure matching nothing is a regression: excusing a real regression as a
    machine problem is the dangerous error, so infrastructure carries the burden
    of proof.
    """
    if code == 0:
        return "ok", ""
    for rule in signatures.get("exit_code_rules", []):
        if code == rule.get("exit_code"):
            return "infrastructure", f"{rule['id']}: {rule['reason']}"
    for sig in signatures.get("signatures", []):
        pattern = sig.get("regex")
        if pattern and re.search(pattern, output, re.IGNORECASE):
            return "infrastructure", f"{sig['id']}: {sig['reason']}"
    return "regression", f"verification command exited {code}"


def free_gb(path: str) -> float:
    try:
        return shutil.disk_usage(path).free / (1024**3)
    except OSError:
        return 0.0


def run_command(
    command: str, timeout: int, target_dir: str | None = None
) -> tuple[int, str, float, str]:
    """Run one verification command. Returns ``(code, tail, seconds, full_output)``.

    The full output is returned alongside the 3-line tail because
    ``classify_failure`` has to see the whole transcript: the line that proves a
    build died on a deleted target tree ("failed to write ...invoked.timestamp")
    sits well above cargo's final summary, so a tail-only classifier would call
    it a regression (bd-566x4).
    """
    started = time.monotonic()
    env = dict(os.environ)
    env.pop("CARGO_ENCODED_RUSTFLAGS", None)
    env["RCH_CARGO_WRAPPER_BYPASS"] = "1"
    rustflags = env.get("RUSTFLAGS") or "-C linker=cc -Clinker-features=-lld"
    if not linker_policy_is_effective(rustflags):
        rustflags = f"{rustflags} -Clinker-features=-lld"
    env["RUSTFLAGS"] = rustflags
    env.setdefault("CARGO_INCREMENTAL", "0")
    # Pin the build tree for anything that does not pin its own.
    #
    # This used to test `"cargo" in command`, which silently exempted every
    # verification command that is a GATE SCRIPT -- `./scripts/run_rgc_*.sh ci`
    # contains no literal "cargo", so the ambient CARGO_TARGET_DIR leaked through
    # to the cargo invocations inside the script. On 2026-07-26 that put
    # FE-CLAIM-006 and FE-CLAIM-022 (the only two OBSERVED claims verified by a
    # bare gate script) into the shared /data/tmp/cargo-target, where a concurrent
    # agent deleted the tree mid-build and both were reported as regressions. The
    # test is now on the command's own text only.
    if "CARGO_TARGET_DIR" not in command:
        env["CARGO_TARGET_DIR"] = target_dir or WARM_TARGET
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
        output = proc.stdout + proc.stderr
        tail = output.strip().splitlines()[-3:]
        return proc.returncode, "\n".join(tail), time.monotonic() - started, output
    except subprocess.TimeoutExpired as exc:
        partial = (exc.stdout or "") + (exc.stderr or "")
        msg = f"TIMEOUT after {timeout}s"
        return 124, msg, time.monotonic() - started, f"{partial}\n{msg}"


def reemit(claim_id: str, command: str, commit: str, dirty: list[str]) -> None:
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
    source_revision = manifest.setdefault("source_revision", {})
    source_revision["commit"] = commit
    # Recorded even when clean, so a reader can tell "verified against a clean
    # checkout of this commit" apart from "the field predates this check".
    source_revision["worktree_dirty"] = bool(dirty)
    if dirty:
        source_revision["dirty_covered_paths"] = dirty
    else:
        source_revision.pop("dirty_covered_paths", None)

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
    ap.add_argument(
        "--no-retry",
        action="store_true",
        help="do not retry an infrastructure-classified failure in an isolated "
        "target dir (bd-566x4); still classifies and reports it as infrastructure",
    )
    args = ap.parse_args()
    only = {s.strip() for s in args.only.split(",") if s.strip()}

    # Per-claim progress is the whole point of the --json/per-claim reporting this
    # script grew for the scheduled job (BRIDGE-19.18): one aggregate exit code
    # cannot say WHICH claim regressed. But Python block-buffers stdout when it is
    # redirected to a file, so a run whose claims each take 10-90 minutes wrote
    # nothing observable until it finished -- the reporting existed and was
    # invisible exactly when it mattered. Line-buffer it.
    sys.stdout.reconfigure(line_buffering=True)

    start_commit = head_commit()
    claims = observed_claims()
    if only:
        claims = [c for c in claims if c["claim_id"] in only]
    if args.tier:
        claims = [c for c in claims if c.get("freshness_tier") == args.tier]
        if not claims:
            print(f"error: no OBSERVED claim carries freshness_tier={args.tier!r}", file=sys.stderr)
            return 2

    signatures = load_signatures()
    results: list[dict] = []
    passed, failed, blocked = [], [], []
    for c in claims:
        cid = c["claim_id"]
        tier = c.get("freshness_tier")
        raw = c.get("verification_command", "")
        if not raw:
            print(f"[{cid}] SKIP (no verification_command)")
            results.append({"claim_id": cid, "freshness_tier": tier, "status": "skipped"})
            continue
        command = substitute(raw)
        # Captured HERE, not once for the whole run. A claim can take 90 minutes,
        # and this script exists to run several of them back to back; stamping every
        # receipt with HEAD-as-of-process-start attributes each pass to whatever the
        # tree looked like before the earlier claims -- and to any commit that landed
        # while they ran. FE-CLAIM-022 hit exactly that: its receipt named a commit
        # made 34 seconds before the fix that let the command succeed at all.
        claim_commit = head_commit()
        covered = load_covered_paths(cid)
        dirty = dirty_covered_paths(covered)
        if dirty:
            print(
                f"[{cid}] WARNING: {len(dirty)} covered path(s) modified but not "
                f"committed; a pass here is not attributable to {claim_commit[:8]}"
            )
        print(f"[{cid}] running: {command[:110]}")
        code, tail, duration, output = run_command(command, args.timeout)
        kind, reason = classify_failure(code, output, signatures)

        # bd-566x4: one retry, in a build tree no other agent shares. The dominant
        # infrastructure failure here is target-tree contention between concurrent
        # agents, and isolation is the actual remedy -- so retry before reporting
        # anything, rather than reporting a failure the retry would have cleared.
        retry: dict | None = None
        if kind == "infrastructure" and not args.no_retry:
            available = free_gb(str(REPO))
            if available < RETRY_MIN_FREE_GB:
                retry = {
                    "attempted": False,
                    "skipped_reason": (
                        f"only {available:.0f} GB free, below the "
                        f"{RETRY_MIN_FREE_GB} GB required to allocate an isolated "
                        "build tree"
                    ),
                }
                print(f"[{cid}] INFRA ({reason}); retry skipped: {retry['skipped_reason']}")
            else:
                print(f"[{cid}] INFRA ({reason}); retrying once in {RETRY_TARGET}")
                r_code, r_tail, r_duration, r_output = run_command(
                    command, args.timeout, target_dir=RETRY_TARGET
                )
                duration += r_duration
                retry = {
                    "attempted": True,
                    "target_dir": RETRY_TARGET,
                    "exit_code": r_code,
                    "duration_seconds": round(r_duration, 1),
                    "first_attempt_reason": reason,
                }
                code, tail, output = r_code, r_tail, r_output
                kind, reason = classify_failure(code, output, signatures)

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
            "source_revision": claim_commit,
            "worktree_dirty": bool(dirty),
        }
        if dirty:
            result["dirty_covered_paths"] = dirty
        if retry is not None:
            result["retry"] = retry
        if code == 0:
            reemit(cid, command, claim_commit, dirty)
            passed.append(cid)
            result["status"] = "passed"
            print(f"[{cid}] PASSED -> real receipt written")
        elif kind == "infrastructure":
            # NOT a regression, and NOT evidence either. The receipt is left
            # untouched exactly as it is for a regression -- the claim stays as
            # provisional as it was. All that differs is what the operator is told,
            # which is the whole point: "audit this claim" and "fix this machine"
            # are different work orders.
            blocked.append((cid, reason))
            result["status"] = "infrastructure"
            result["truth_state"] = "validation_environment_blocker"
            result["infrastructure_reason"] = reason
            result["output_tail"] = tail
            print(f"[{cid}] INFRASTRUCTURE ({reason}) -- claim NOT implicated\n    {tail}")
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
                    # HEAD when the run began. Each claim also carries its own
                    # `source_revision`, captured immediately before its command ran,
                    # which is the one its receipt is stamped with.
                    "source_revision": start_commit,
                    "tier": args.tier or None,
                    "agent": AGENT,
                    "summary": {
                        "attempted": len(results),
                        "passed": len(passed),
                        # `failed` counts REGRESSIONS only. Infrastructure blockers
                        # are a separate count so a consumer cannot accidentally
                        # read "the machine broke" as "the claim broke" (bd-566x4).
                        "failed": len(failed),
                        "infrastructure": len(blocked),
                    },
                    "results": results,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
        print(f"reemit_report={out}")

    print(
        f"\nreemit: {len(passed)} passed, {len(failed)} regressed, "
        f"{len(blocked)} infrastructure-blocked"
    )
    if failed:
        print("regressed:", ", ".join(f"{c}({code})" for c, code in failed))
    if blocked:
        print("infrastructure-blocked:", ", ".join(f"{c} [{r}]" for c, r in blocked))

    # Three exit codes for three outcomes (bd-566x4). Collapsing 3 into 1 is what
    # sends an operator to audit a claim membrane when the fix is a target dir.
    #   0 -- every attempted claim verified
    #   1 -- at least one REGRESSION. A real alarm; the claim did not hold.
    #   3 -- no regressions, but at least one claim could not be verified at all.
    if failed:
        return 1
    return 3 if blocked else 0


if __name__ == "__main__":
    sys.exit(main())
