#!/usr/bin/env python3
"""Build the content-addressed E2 Node/Bun denominator reproducibility bundle.

Transforms a `differential-oracle perf` report (`report.json`, schema
`franken-engine.differential-oracle-perf.v1`) into the four-file reproducibility
bundle contract (`docs/REPRODUCIBILITY_CONTRACT.md`):

  - denominator.json  (the distilled, measured Node/Bun denominator + correctness verdicts)
  - env.json          (host / toolchain / runtime facts, with pinned node/bun versions)
  - repro.lock        (locked replay recipe; expected output is the *correctness verdict* hash)
  - manifest.json     (content-addressed index referencing the other three by sha256)

Reproducibility note (bd-fqlfw.2.6 ACCEPTANCE): wall-clock timing is inherently
non-deterministic, so the byte-identical assertion is scoped to the *correctness
verdicts* (per-case behavior-equivalence groups + corpus hash), captured as
`correctness_verdict_hash` and locked in `repro.lock.expected_outputs`. A
re-run on the same host must reproduce that hash exactly even though raw timings
differ.

When the perf report's denominators are degraded (e.g. Node/Bun unavailable, or
no case satisfied the admission preconditions), the builder writes a documented
`degraded_receipt.json` and marks the bundle `bundle_status="degraded"` instead
of silently emitting a passing number.

This is gate tooling, not engine source: it performs no source rewrites.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

BUNDLE_SCHEMA = "franken-engine.e2-denominator-bundle.v1"
ENV_SCHEMA = "franken-engine.env.v1"
MANIFEST_SCHEMA = "franken-engine.manifest.v1"
REPRO_LOCK_SCHEMA = "franken-engine.repro-lock.v1"
DEGRADED_SCHEMA = "franken-engine.e2-denominator-degraded-receipt.v1"
PERF_REPORT_SCHEMA = "franken-engine.differential-oracle-perf.v1"

CLAIM_ID = "FE-CLAIM-010"
OWNING_BEAD = "bd-fqlfw.2.6"
POLICY_ID = "policy-e2-denominator-bundle-v1"
FLOOR_MILLIONTHS = 3_000_000  # >= 3x throughput floor (DENOMINATOR_FLOOR_MILLIONTHS)

_EQUIV_GROUP_RE = re.compile(r"group\s+([0-9a-f]{16,64})")


def canonical_bytes(obj: Any) -> bytes:
    """Canonical JSON: lexicographic keys, 2-space indent, LF, trailing newline."""
    text = json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False)
    return (text + "\n").encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def schema_identity_hash(schema_version: str, required_fields: list[str]) -> str:
    """Deterministic identity hash binding schema version to its required keys."""
    payload = schema_version + "\x1f" + "\x1f".join(sorted(required_fields))
    return "sha256:" + sha256_hex(payload.encode("utf-8"))


def extract_equivalence_group(detail: str | None) -> str:
    if not detail:
        return ""
    m = _EQUIV_GROUP_RE.search(detail)
    return m.group(1) if m else ""


def build_correctness_verdicts(cases: list[dict]) -> list[dict]:
    verdicts = []
    for case in cases:
        verdicts.append(
            {
                "case_id": case.get("case_id", ""),
                "source_sha256": case.get("source_sha256", ""),
                "behavior_equivalent": bool(case.get("behavior_equivalent", False)),
                "equivalence_group": extract_equivalence_group(
                    case.get("equivalence_detail")
                ),
                "admitted": bool(case.get("admitted", False)),
            }
        )
    verdicts.sort(key=lambda v: v["case_id"])
    return verdicts


def correctness_verdict_hash(verdicts: list[dict]) -> str:
    return "sha256:" + sha256_hex(canonical_bytes(verdicts))


def denominator_view(dn: dict) -> dict:
    """Project a perf-report denominator into the bundle's stable shape."""
    return {
        "baseline": dn.get("baseline", ""),
        "admitted_cases": dn.get("admitted_cases", 0),
        "excluded_cases": dn.get("excluded_cases", 0),
        "geomean_speedup_millionths": dn.get("geomean_speedup_millionths"),
        "meets_3x_floor": dn.get("meets_3x_floor"),
        "status": dn.get("status", "degraded"),
        "degraded_reasons": dn.get("degraded_reasons", []),
    }


def interpretation_lines(node: dict, bun: dict) -> list[str]:
    lines: list[str] = []
    for label, dn in (("Node", node), ("Bun", bun)):
        g = dn.get("geomean_speedup_millionths")
        status = dn.get("status")
        if g is None or status != "published":
            lines.append(
                f"{label}: denominator degraded ({'; '.join(dn.get('degraded_reasons', [])) or 'unavailable'})."
            )
            continue
        # geomean is engine-speedup-vs-baseline in millionths (1_000_000 == parity).
        if g == 0:
            lines.append(f"{label}: engine speedup geomean is 0 (unmeasurable).")
            continue
        slower_factor = round(1_000_000 / g, 1) if g < 1_000_000 else None
        meets = dn.get("meets_3x_floor")
        if slower_factor is not None:
            lines.append(
                f"{label}: engine geomean throughput is {g} millionths of {label} "
                f"(~{slower_factor}x slower); meets_3x_floor={meets}."
            )
        else:
            lines.append(
                f"{label}: engine geomean speedup {g} millionths; meets_3x_floor={meets}."
            )
    lines.append(
        "FE-CLAIM-010 (>= 3x throughput vs Node and Bun) is NOT met by the "
        "measured denominator; the claim stays TARGET, now backed by real "
        "numbers rather than absence of data."
    )
    return lines


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def write_canonical(path: Path, obj: Any) -> str:
    data = canonical_bytes(obj)
    path.write_bytes(data)
    return "sha256:" + sha256_hex(data)


def main() -> int:
    ap = argparse.ArgumentParser(description="Build the E2 denominator reproducibility bundle.")
    ap.add_argument("--report", required=True, help="differential-oracle perf report.json")
    ap.add_argument(
        "--corpus",
        default="benchmarks/runtime_comparison/manifest.json",
        help="perf corpus manifest path (recorded as the locked input)",
    )
    ap.add_argument("--out-dir", required=True, help="bundle output directory")
    ap.add_argument("--commit", required=True, help="source git commit SHA")
    ap.add_argument("--rustc", default="unknown", help="rustc --version string")
    ap.add_argument("--cargo", default="unknown", help="cargo --version string")
    ap.add_argument(
        "--generated-at-utc",
        required=True,
        help="ISO-8601 UTC timestamp for provenance fields",
    )
    ap.add_argument("--dirty", default="false", help="dirty worktree flag (true/false)")
    args = ap.parse_args()

    report_path = Path(args.report)
    if not report_path.is_file():
        print(f"ERROR: report not found: {report_path}", file=sys.stderr)
        return 2
    report = load_json(report_path)

    if report.get("schema_version") != PERF_REPORT_SCHEMA:
        print(
            f"ERROR: report schema mismatch: expected {PERF_REPORT_SCHEMA}, "
            f"got {report.get('schema_version')}",
            file=sys.stderr,
        )
        return 2

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    env_in = report.get("environment", {})
    host = env_in.get("host", {})
    fairness = report.get("fairness", {})
    cases = report.get("cases", [])
    node_dn = denominator_view(report.get("node_denominator", {}))
    bun_dn = denominator_view(report.get("bun_denominator", {}))

    node_published = node_dn["status"] == "published"
    bun_published = bun_dn["status"] == "published"
    fairness_compliant = bool(fairness.get("compliant", False))
    node_genuine = bool(env_in.get("node_genuine", False))
    bun_genuine = bool(env_in.get("bun_genuine", True))

    bundle_status = (
        "published"
        if (node_published and bun_published and fairness_compliant)
        else "degraded"
    )

    verdicts = build_correctness_verdicts(cases)
    cv_hash = correctness_verdict_hash(verdicts)

    generated_at = args.generated_at_utc
    dirty = args.dirty.strip().lower() == "true"

    # The perf report's `corpus_sha256` is a length-prefixed digest over the
    # corpus *case contents* (see differential_oracle_perf::corpus_sha256), NOT
    # the manifest file's hash. Record both, correctly labelled, so a third party
    # hashing the manifest file gets a real match while the corpus-content digest
    # remains the semantic corpus identity.
    corpus_content_digest = env_in.get("corpus_sha256", "")
    corpus_path = Path(args.corpus)
    manifest_file_sha = (
        "sha256:" + sha256_hex(corpus_path.read_bytes()) if corpus_path.is_file() else ""
    )

    # --- denominator.json (results) ----------------------------------------
    denominator = {
        "schema_version": BUNDLE_SCHEMA,
        "claim_id": CLAIM_ID,
        "owning_bead": OWNING_BEAD,
        "bundle_status": bundle_status,
        "generated_at_utc": generated_at,
        "generated_unix_ns": report.get("generated_unix_ns"),
        "source_commit": args.commit,
        "floor_millionths": FLOOR_MILLIONTHS,
        "corpus": {
            "manifest_path": args.corpus,
            "manifest_file_sha256": manifest_file_sha,
            "corpus_content_digest": corpus_content_digest,
            "case_count": env_in.get("corpus_case_count", len(cases)),
        },
        "measurement": {
            "warmup_iterations": env_in.get("warmup_iterations"),
            "measured_iterations": env_in.get("measured_iterations"),
            "engine_instruction_budget": env_in.get("engine_instruction_budget"),
        },
        "baselines": {
            "node": {
                "program": env_in.get("node_resolved_program", ""),
                "version": env_in.get("node_version", ""),
                "genuine": node_genuine,
            },
            "bun": {
                "program": env_in.get("bun_resolved_program", ""),
                "version": env_in.get("bun_version", ""),
                "genuine": bun_genuine,
            },
        },
        "fairness": {
            "compliant": fairness_compliant,
            "notes": fairness.get("notes", []),
            "violations": fairness.get("violations", []),
        },
        "node_denominator": node_dn,
        "bun_denominator": bun_dn,
        "correctness_verdicts": verdicts,
        "correctness_verdict_hash": cv_hash,
        "interpretation": interpretation_lines(node_dn, bun_dn),
    }
    results_sha = write_canonical(out_dir / "denominator.json", denominator)

    # --- env.json ------------------------------------------------------------
    env_required = [
        "schema_version",
        "schema_hash",
        "captured_at_utc",
        "project",
        "host",
        "toolchain",
        "runtime",
        "policy",
    ]
    mem_kb = env_in.get("total_memory_kb")
    env = {
        "schema_version": ENV_SCHEMA,
        "schema_hash": schema_identity_hash(ENV_SCHEMA, env_required),
        "captured_at_utc": generated_at,
        "project": {
            "name": "franken_engine",
            "repo_url": "https://github.com/Dicklesworthstone/franken_engine",
            "commit": args.commit,
            "dirty": dirty,
        },
        "host": {
            "os": host.get("os", ""),
            "kernel": host.get("kernel", ""),
            "arch": host.get("arch", ""),
            "cpu_model": host.get("cpu_model", ""),
            "cpu_cores_logical": host.get("cpu_cores_logical", 0),
            "memory_bytes": (mem_kb * 1024) if isinstance(mem_kb, int) else 0,
        },
        "toolchain": {
            "rustc": args.rustc,
            "cargo": args.cargo,
            "llvm": "bundled-with-rustc",
            "target_triple": "x86_64-unknown-linux-gnu",
            "profile": "release",
        },
        "runtime": {
            "mode": "differential-oracle-perf",
            "lane": "baseline_interpreter",
            "engine_version": host.get("franken_engine_version", ""),
            "engine_instruction_budget": env_in.get("engine_instruction_budget"),
            "warmup_iterations": env_in.get("warmup_iterations"),
            "measured_iterations": env_in.get("measured_iterations"),
        },
        "baselines": {
            "node_version": env_in.get("node_version", ""),
            "node_genuine": node_genuine,
            "bun_version": env_in.get("bun_version", ""),
            "bun_genuine": bun_genuine,
        },
        "policy": {
            "policy_id": POLICY_ID,
            "policy_digest_sha256": "sha256:" + sha256_hex(POLICY_ID.encode("utf-8")),
        },
    }
    env_sha = write_canonical(out_dir / "env.json", env)

    # --- repro.lock ----------------------------------------------------------
    lock_id = "sha256:" + sha256_hex(
        (args.commit + "\x1f" + corpus_content_digest + "\x1f" + cv_hash).encode("utf-8")
    )
    perf_command = (
        "target/release/frankenctl differential-oracle perf "
        f"--manifest {args.corpus} "
        "--out report.json --events events.jsonl "
        f"--warmup {env_in.get('warmup_iterations', 3)} "
        f"--samples {env_in.get('measured_iterations', 10)} "
        "--case-timeout-ms 120000 "
        f"--engine-budget {env_in.get('engine_instruction_budget', 2000000000)} "
        "--node-bin <node> --bun-bin <bun>"
    )
    build_command = (
        "scripts/build_e2_denominator_bundle.py --report report.json "
        f"--corpus {args.corpus} --out-dir docs/perf/e2_denominator_bundle_v1"
    )
    repro_required = [
        "schema_version",
        "schema_hash",
        "generated_at_utc",
        "lock_id",
        "manifest_id",
        "source_commit",
        "determinism",
        "commands",
        "inputs",
        "expected_outputs",
        "replay",
        "verification",
    ]
    manifest_id = "sha256:" + sha256_hex(
        (lock_id + "\x1f" + env_sha + "\x1f" + results_sha).encode("utf-8")
    )
    repro_lock = {
        "schema_version": REPRO_LOCK_SCHEMA,
        "schema_hash": schema_identity_hash(REPRO_LOCK_SCHEMA, repro_required),
        "generated_at_utc": generated_at,
        "lock_id": lock_id,
        "manifest_id": manifest_id,
        "source_commit": args.commit,
        "determinism": {
            "allow_network": False,
            "allow_wall_clock": True,
            "allow_randomness": False,
            "max_clock_skew_seconds": 0,
            "reproducible_assertion": "correctness_verdict_hash",
            "note": (
                "wall-clock timing is measured and is inherently non-deterministic; "
                "the locked expected output is the byte-identical correctness verdict "
                "hash, not raw timings"
            ),
        },
        "commands": [perf_command, build_command],
        "inputs": [
            {
                "path": args.corpus,
                "sha256": manifest_file_sha,
                "kind": "corpus_manifest_file",
            },
            {
                "path": f"{args.corpus}#corpus_content",
                "sha256": "sha256:" + corpus_content_digest if corpus_content_digest else "",
                "kind": "corpus_content_digest",
            },
        ],
        "expected_outputs": [
            {
                "path": "denominator.json#correctness_verdicts",
                "sha256": cv_hash,
                "kind": "correctness_verdict",
            }
        ],
        "replay": {
            "trace_id": f"trace-e2-denominator-{args.commit[:12]}",
            "replay_pointer": f"replay://e2-denominator/{lock_id}",
        },
        "verification": {
            "command": "./scripts/run_e2_denominator_bundle_gate.sh ci",
            "expected_verdict": "pass",
        },
    }
    lock_sha = write_canonical(out_dir / "repro.lock", repro_lock)

    # --- manifest.json (content-addressed index) -----------------------------
    manifest_required = [
        "schema_version",
        "schema_hash",
        "manifest_id",
        "generated_at_utc",
        "claim",
        "source_revision",
        "provenance",
        "artifacts",
        "inputs",
        "outputs",
        "canonicalization",
        "validation",
        "retention",
    ]
    manifest = {
        "schema_version": MANIFEST_SCHEMA,
        "schema_hash": schema_identity_hash(MANIFEST_SCHEMA, manifest_required),
        "manifest_id": manifest_id,
        "generated_at_utc": generated_at,
        "claim": {
            "claim_id": CLAIM_ID,
            "class": "PERFORMANCE",
            "statement": (
                ">= 3x weighted-geometric-mean throughput versus Node and Bun "
                "under the benchmark denominator contract."
            ),
            "status": "target",
            "bundle_root": "docs/perf/e2_denominator_bundle_v1",
        },
        "source_revision": {
            "repo": "franken_engine",
            "branch": "main",
            "commit": args.commit,
        },
        "provenance": {
            "trace_id": f"trace-e2-denominator-{args.commit[:12]}",
            "decision_id": f"decision-e2-denominator-{args.commit[:12]}",
            "policy_id": POLICY_ID,
            "replay_pointer": f"replay://e2-denominator/{lock_id}",
            "evidence_pointer": f"evidence://e2-denominator/{manifest_id}",
            "receipt_ids": [],
        },
        "artifacts": {
            "env": {"path": "env.json", "sha256": env_sha},
            "lock": {"path": "repro.lock", "sha256": lock_sha},
            "results": {"path": "denominator.json", "sha256": results_sha},
        },
        "inputs": [{"path": args.corpus, "sha256": manifest_file_sha}],
        "outputs": [{"path": "denominator.json", "sha256": results_sha}],
        "canonicalization": {
            "format": "json",
            "key_order": "lexicographic",
            "newline": "lf",
            "hash_algorithm": "sha256",
        },
        "validation": {
            "validator": "./scripts/run_e2_denominator_bundle_gate.sh ci",
            "error_taxonomy": "FE-REPRO-0001..FE-REPRO-0008",
        },
        "retention": {
            "min_days": 365,
            "high_impact_min_days": 730,
            "rotation_policy": "archive-with-addressable-retrieval",
        },
    }
    write_canonical(out_dir / "manifest.json", manifest)

    # --- degraded_receipt.json (only when degraded; never silent-pass) -------
    degraded_path = out_dir / "degraded_receipt.json"
    if bundle_status == "degraded":
        reasons: list[str] = []
        if not node_genuine:
            reasons.append("node binary is not genuine (resolved to a shim)")
        if not node_published:
            reasons.extend(f"node: {r}" for r in node_dn["degraded_reasons"])
        if not bun_published:
            reasons.extend(f"bun: {r}" for r in bun_dn["degraded_reasons"])
        if not fairness_compliant:
            reasons.append("fairness rules unmet")
        if not reasons:
            reasons.append("denominator unavailable")
        receipt = {
            "schema_version": DEGRADED_SCHEMA,
            "claim_id": CLAIM_ID,
            "owning_bead": OWNING_BEAD,
            "generated_at_utc": generated_at,
            "source_commit": args.commit,
            "error_code": "FE-REPRO-0007",
            "verdict": "degraded",
            "reasons": reasons,
            "policy": (
                "Degraded mode must never promote claim status to observed "
                "(docs/REPRODUCIBILITY_CONTRACT.md). FE-CLAIM-010 stays TARGET."
            ),
        }
        write_canonical(degraded_path, receipt)
    elif degraded_path.is_file():
        # Stale degraded receipt from a prior degraded run must not linger.
        degraded_path.unlink()

    summary = {
        "bundle_status": bundle_status,
        "manifest_id": manifest_id,
        "env_sha256": env_sha,
        "lock_sha256": lock_sha,
        "results_sha256": results_sha,
        "correctness_verdict_hash": cv_hash,
        "node": node_dn,
        "bun": bun_dn,
        "out_dir": str(out_dir),
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
