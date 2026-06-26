#!/usr/bin/env python3
"""Build the content-addressed ES2020 weighted-coverage-summary bundle
(bd-fqlfw.7.4, E7.T4, FE-CLAIM-026).

Wraps a real `franken_coverage_frontier --coverage-summary` report into the
four-file reproducibility bundle the claim-to-proof machinery gates:

  - coverage_summary.json  (the measured report; schema franken-engine.coverage-summary.v1)
  - env.json               (execution environment / provenance; franken-engine.env.v1)
  - manifest.json          (content-addressed index; franken-engine.manifest.v1)
  - repro.lock             (deterministic recipe + expected output; franken-engine.repro-lock.v1)

The reproducible assertion is the coverage report's `report_digest` (a pure
function of the per-view (view, passed, total) counts), NOT any wall-clock value:
re-running the engine over the same corpus commit reproduces it byte-for-byte.

Usage:
  build_coverage_summary_bundle.py --summary <coverage_summary.json> \
      --out-dir docs/coverage/es2020_coverage_summary_bundle_v1 \
      [--source-commit <git-sha>] [--generated-at-utc <YYYYmmddTHHMMSSZ>]
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

CLAIM_ID = "FE-CLAIM-026"
OWNING_BEAD = "bd-fqlfw.7.4"
POLICY_ID = "policy-es2020-coverage-summary-bundle-v1"
COVERAGE_SCHEMA = "franken-engine.coverage-summary.v1"


def canonical_bytes(obj: Any) -> bytes:
    """Canonical JSON: lexicographic keys, 2-space indent, LF, trailing newline."""
    text = json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False)
    return (text + "\n").encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_canonical(path: Path, obj: Any) -> str:
    data = canonical_bytes(obj)
    path.write_bytes(data)
    return "sha256:" + sha256_hex(data)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def git_output(args: list[str], fallback: str) -> str:
    try:
        return subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return fallback


def tool_output(args: list[str], fallback: str) -> str:
    try:
        return subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return fallback


def main() -> int:
    ap = argparse.ArgumentParser(description="Build the ES2020 coverage-summary bundle")
    ap.add_argument("--summary", required=True, help="coverage_summary.json from franken_coverage_frontier --coverage-summary")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--source-commit", default=None, help="engine git commit (default: git HEAD)")
    ap.add_argument("--generated-at-utc", default=None, help="override timestamp (YYYYmmddTHHMMSSZ)")
    args = ap.parse_args()

    summary_in = Path(args.summary)
    if not summary_in.is_file():
        print(f"error: summary not found: {summary_in}", file=sys.stderr)
        return 2
    summary = load_json(summary_in)
    if summary.get("schema_version") != COVERAGE_SCHEMA:
        print(f"error: summary schema mismatch: {summary.get('schema_version')}", file=sys.stderr)
        return 2

    report_digest = summary.get("report_digest", "")
    corpus_commit = summary.get("corpus_commit", "unknown")
    if not report_digest:
        print("error: summary missing report_digest", file=sys.stderr)
        return 2

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    source_commit = args.source_commit or git_output(["git", "rev-parse", "HEAD"], "unknown")
    dirty = bool(git_output(["git", "status", "--porcelain"], ""))
    if args.generated_at_utc:
        stamp = args.generated_at_utc
    else:
        stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    # 1) coverage_summary.json — re-emit canonical (stable bytes for hashing).
    coverage_sha = write_canonical(out_dir / "coverage_summary.json", summary)

    # 2) env.json — provenance (host/toolchain-specific; not the repro assertion).
    env = {
        "schema_version": "franken-engine.env.v1",
        "captured_at_utc": stamp,
        "project": {
            "name": "franken_engine",
            "repo_url": "https://github.com/Dicklesworthstone/franken_engine",
            "commit": source_commit,
            "dirty": dirty,
        },
        "host": {
            "os": tool_output(["uname", "-s"], "unknown").lower(),
            "kernel": tool_output(["uname", "-r"], "unknown"),
            "arch": tool_output(["uname", "-m"], "unknown"),
        },
        "toolchain": {
            "rustc": tool_output(["rustc", "--version"], "unknown"),
            "cargo": tool_output(["cargo", "--version"], "unknown"),
            "target_triple": "x86_64-unknown-linux-gnu",
            "profile": "debug",
        },
        "runtime": {
            "mode": "test262-coverage-summary",
            "lane": "test262_conformance_runner",
            "engine_version": "0.1.0",
            "test262_commit": corpus_commit,
            "scope": "es2020-normative (language/* + built-ins/*)",
        },
        "policy": {
            "policy_id": POLICY_ID,
            "policy_digest_sha256": "sha256:" + sha256_hex(POLICY_ID.encode("utf-8")),
        },
    }
    env_sha = write_canonical(out_dir / "env.json", env)

    # 3) repro.lock — deterministic recipe + the reproducible assertion.
    repro_lock = {
        "schema_version": "franken-engine.repro-lock.v1",
        "generated_at_utc": stamp,
        "source_commit": source_commit,
        "determinism": {
            "allow_network": False,
            "allow_randomness": False,
            "allow_wall_clock": False,
            "max_clock_skew_seconds": 0,
            "reproducible_assertion": "report_digest",
            "note": "the locked expected output is the coverage report_digest (a pure function of the per-view (view, passed, total) counts); re-running the engine over the same test262 corpus commit reproduces it byte-for-byte",
        },
        "commands": [
            "target/release/franken_coverage_frontier --run-suite <tc39/test262 checkout> --coverage-summary --out coverage_summary.json",
            "scripts/build_coverage_summary_bundle.py --summary coverage_summary.json --out-dir docs/coverage/es2020_coverage_summary_bundle_v1",
        ],
        "inputs": [
            {
                "kind": "test262_corpus_commit",
                "path": "tc39/test262",
                "sha256": corpus_commit,
            }
        ],
        "expected_outputs": [
            {
                "kind": "coverage_report_digest",
                "path": "coverage_summary.json#report_digest",
                "sha256": report_digest,
            }
        ],
        "verification": {
            "command": "./scripts/run_coverage_summary_bundle_gate.sh ci",
            "expected_verdict": "pass",
        },
    }
    lock_sha = write_canonical(out_dir / "repro.lock", repro_lock)

    # 4) manifest.json — content-addressed index referencing the other three.
    manifest_core = {
        "schema_version": "franken-engine.manifest.v1",
        "generated_at_utc": stamp,
        "claim": {
            "claim_id": CLAIM_ID,
            "class": "CONFORMANCE",
            "statement": "A reproducible, content-addressed, gated coverage summary reports the measured fraction of the ES2020 observable surface the engine executes, in six weighted category views with a floor that exposes the weakest view.",
            "status": "target",
            "bundle_root": str(out_dir).replace("\\", "/"),
        },
        "owning_bead": OWNING_BEAD,
        "source_revision": {
            "repo": "franken_engine",
            "branch": "main",
            "commit": source_commit,
        },
        "headline": {
            "observable_surface_executed_millionths": summary.get("observable_surface_executed_millionths", 0),
            "in_scope_passed": summary.get("in_scope_passed", 0),
            "in_scope_total": summary.get("in_scope_total", 0),
            "floor_view": summary.get("floor_view", "none"),
            "floor_view_executed_millionths": summary.get("floor_view_executed_millionths", 0),
        },
        "artifacts": {
            "coverage": {"path": "coverage_summary.json", "sha256": coverage_sha},
            "env": {"path": "env.json", "sha256": env_sha},
            "lock": {"path": "repro.lock", "sha256": lock_sha},
        },
        "canonicalization": {
            "format": "json",
            "hash_algorithm": "sha256",
            "key_order": "lexicographic",
            "newline": "lf",
        },
        "validation": {
            "error_taxonomy": "FE-REPRO-0001..FE-REPRO-0008",
            "validator": "./scripts/run_coverage_summary_bundle_gate.sh ci",
        },
        "retention": {
            "min_days": 365,
            "rotation_policy": "archive-with-addressable-retrieval",
        },
    }
    manifest_id = "sha256:" + sha256_hex(canonical_bytes(manifest_core))
    manifest = dict(manifest_core)
    manifest["manifest_id"] = manifest_id
    manifest_sha = write_canonical(out_dir / "manifest.json", manifest)

    print(f"wrote bundle to {out_dir}")
    print(f"  coverage_summary.json {coverage_sha}")
    print(f"  env.json              {env_sha}")
    print(f"  repro.lock            {lock_sha}")
    print(f"  manifest.json         {manifest_sha}")
    print(f"  report_digest         {report_digest}")
    print(f"  headline_executed_millionths {summary.get('observable_surface_executed_millionths', 0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
