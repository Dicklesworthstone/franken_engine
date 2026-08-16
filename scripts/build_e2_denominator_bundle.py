#!/usr/bin/env python3
"""Build the content-addressed E2 Node/Bun denominator reproducibility bundle.

Transforms a `differential-oracle perf` report (`report.json`, schema
`franken-engine.differential-oracle-perf.v3`) into the four-file reproducibility
bundle contract (`docs/REPRODUCIBILITY_CONTRACT.md`):

  - denominator.json  (the distilled, measured Node/Bun denominator + correctness verdicts)
  - env.json          (host / toolchain / runtime facts, with recorded node/bun versions)
  - repro.lock        (locked replay recipe; expected output is the *correctness verdict* hash)
  - manifest.json     (content-addressed index referencing the other three by sha256)

Reproducibility note (bd-fqlfw.2.6 ACCEPTANCE): wall-clock timing is inherently
non-deterministic, so the byte-identical assertion is scoped to the sorted
four-field *correctness verdict* projection (`case_id`, `source_sha256`,
`behavior_equivalent`, and `equivalence_group`), captured as
`correctness_verdict_hash` and locked in `repro.lock.expected_outputs`. The
corpus content digest is a separate locked input. A re-run against the same
corpus must reproduce the verdict hash exactly even though raw timings differ.

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
import math
import re
import shlex
import sys
from pathlib import Path
from typing import Any

BUNDLE_SCHEMA = "franken-engine.e2-denominator-bundle.v1"
ENV_SCHEMA = "franken-engine.env.v1"
MANIFEST_SCHEMA = "franken-engine.manifest.v1"
REPRO_LOCK_SCHEMA = "franken-engine.repro-lock.v1"
DEGRADED_SCHEMA = "franken-engine.e2-denominator-degraded-receipt.v1"
PERF_REPORT_SCHEMA = "franken-engine.differential-oracle-perf.v3"

CLAIM_ID = "FE-CLAIM-010"
OWNING_BEAD = "bd-fqlfw.2.6"
POLICY_ID = "policy-e2-denominator-bundle-v1"
FLOOR_MILLIONTHS = 3_000_000  # >= 3x throughput floor (DENOMINATOR_FLOOR_MILLIONTHS)

_EQUIV_GROUP_RE = re.compile(r"group\s+([0-9a-f]{16,64})")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_PROFILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_MILLIONTHS = 1_000_000
_U32_MAX = (1 << 32) - 1
_U64_MAX = (1 << 64) - 1
_V3_ENGINE_LIFECYCLE = "prepare_once_fresh_router_and_interpreter_core_per_iteration"
_V3_EXTERNAL_LIFECYCLE = "new_function_once_single_process_shared_realm_and_jit_state"


def _sample_stats(samples: list[int]) -> dict[str, int] | None:
    """Mirror differential_oracle_perf::compute_sample_stats exactly."""
    if not samples:
        return None
    count = len(samples)
    mean = sum(samples) // count
    if count < 2:
        variance = 0
    else:
        variance = sum(abs(sample - mean) ** 2 for sample in samples) // (count - 1)
    stddev = math.isqrt(variance)
    cv = 0 if mean == 0 else min((stddev * _MILLIONTHS) // mean, _U32_MAX)
    sqrt_n_millionths = math.isqrt(count * 1_000_000_000_000)
    ci_half = 0 if sqrt_n_millionths == 0 else (stddev * 1_960_000) // sqrt_n_millionths
    return {
        "sample_count": count,
        "mean_ns": mean,
        "stddev_ns": stddev,
        "cv_millionths": cv,
        "ci95_lower_ns": max(mean - ci_half, 0),
        "ci95_upper_ns": min(mean + ci_half, _U64_MAX),
        "min_ns": min(samples),
        "max_ns": max(samples),
    }


def _speedup_millionths(engine_mean: int, baseline_mean: int) -> int | None:
    if engine_mean == 0:
        return None
    return min((baseline_mean * _MILLIONTHS) // engine_mean, _U64_MAX)


def _geomean_millionths(ratios: list[int]) -> int | None:
    """Mirror positive-ratio Rust f64 log/exp aggregation and rounding."""
    if not ratios or 0 in ratios:
        return None
    value = math.exp(sum(math.log(ratio / _MILLIONTHS) for ratio in ratios) / len(ratios))
    scaled = value * _MILLIONTHS
    if not math.isfinite(scaled) or scaled < 0:
        return None
    return min(math.floor(scaled + 0.5), _U64_MAX)


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
    if node.get("status") == "published" and bun.get("status") == "published":
        if node.get("meets_3x_floor") is True and bun.get("meets_3x_floor") is True:
            lines.append(
                "This bundle's published denominators meet the FE-CLAIM-010 >= 3x "
                "floor for both Node and Bun; claim promotion remains a separate "
                "claim-matrix decision."
            )
        else:
            lines.append(
                "FE-CLAIM-010 (>= 3x throughput vs Node and Bun) is NOT met by "
                "this bundle's published denominators and remains TARGET."
            )
    else:
        lines.append(
            "FE-CLAIM-010 is NOT EVALUABLE from this bundle because at least one "
            "denominator is degraded. The claim remains TARGET; retained raw "
            "per-case measurements are diagnostic evidence only."
        )
    return lines


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def validate_v3_report(report: dict) -> list[str]:
    """Recompute raw statistics, lifecycle stability, and both denominators."""
    errors: list[str] = []

    def uint(value: object, maximum: int = _U64_MAX) -> bool:
        return (
            isinstance(value, int)
            and not isinstance(value, bool)
            and 0 <= value <= maximum
        )

    environment = report.get("environment")
    if not isinstance(environment, dict):
        return ["environment must be an object"]
    for field in ("engine_execution_lifecycle", "external_execution_lifecycle"):
        if not isinstance(environment.get(field), str) or not environment[field]:
            errors.append(f"environment.{field} must be a non-empty string")
    if environment.get("engine_execution_lifecycle") != _V3_ENGINE_LIFECYCLE:
        errors.append("environment.engine_execution_lifecycle is not the v3 contract")
    if environment.get("external_execution_lifecycle") != _V3_EXTERNAL_LIFECYCLE:
        errors.append("environment.external_execution_lifecycle is not the v3 contract")
    expected_warmup = environment.get("warmup_iterations")
    expected_measured = environment.get("measured_iterations")
    max_cv = environment.get("max_cv_millionths")
    if not uint(expected_warmup, _U32_MAX):
        errors.append("environment.warmup_iterations must be a nonnegative u32")
        expected_warmup = None
    if not uint(expected_measured, _U32_MAX) or expected_measured == 0:
        errors.append("environment.measured_iterations must be a positive u32")
        expected_measured = None
    if not uint(max_cv, _U32_MAX):
        errors.append("environment.max_cv_millionths must be a nonnegative u32")
        max_cv = None

    cases = report.get("cases")
    if not isinstance(cases, list):
        return errors + ["cases must be an array"]
    if not cases:
        errors.append("cases must contain at least one measured corpus case")
    if environment.get("corpus_case_count") != len(cases):
        errors.append("environment.corpus_case_count disagrees with cases")

    expected_backends = {
        "engine": "franken_engine",
        "node": "node_lts",
        "bun": "bun_stable",
    }
    seen_case_ids: set[str] = set()
    recomputed_cases: list[dict[str, Any]] = []
    for case_index, case in enumerate(cases):
        if not isinstance(case, dict):
            errors.append(f"cases[{case_index}] must be an object")
            continue
        case_id = case.get("case_id", f"index-{case_index}")
        if not isinstance(case_id, str) or not case_id:
            errors.append(f"cases[{case_index}].case_id must be a non-empty string")
            case_id = f"index-{case_index}"
        elif case_id in seen_case_ids:
            errors.append(f"duplicate case_id: {case_id}")
        seen_case_ids.add(case_id)
        if not isinstance(case.get("source_sha256"), str) or not _HEX64_RE.fullmatch(
            case.get("source_sha256", "")
        ):
            errors.append(f"case {case_id}: source_sha256 must be lowercase hex64")
        for field in ("behavior_equivalent", "measured_lifecycle_equivalent", "admitted"):
            if not isinstance(case.get(field), bool):
                errors.append(f"case {case_id}: {field} must be boolean")
        if not isinstance(case.get("measured_lifecycle_detail"), str):
            errors.append(f"case {case_id}: measured_lifecycle_detail must be string")

        lane_results: dict[str, dict] = {}
        lane_stats: dict[str, dict[str, int] | None] = {}
        for lane in ("engine", "node", "bun"):
            result = case.get(lane)
            if not isinstance(result, dict):
                errors.append(f"case {case_id}: {lane} must be an object")
                continue
            lane_results[lane] = result
            if result.get("backend") != expected_backends[lane]:
                errors.append(f"case {case_id}: {lane}.backend is incorrect")
            status = result.get("status")
            if status not in {"measured", "failed", "unavailable", "timeout"}:
                errors.append(f"case {case_id}: {lane}.status is invalid")
                continue
            if not isinstance(result.get("observations_complete"), bool):
                errors.append(f"case {case_id}: {lane}.observations_complete must be boolean")
            warmup = result.get("warmup_ns")
            measured = result.get("measured_ns")
            warmup_obs = result.get("warmup_observation_sha256", [])
            measured_obs = result.get("measured_observation_sha256", [])
            arrays = (
                ("warmup_ns", warmup),
                ("measured_ns", measured),
                ("warmup_observation_sha256", warmup_obs),
                ("measured_observation_sha256", measured_obs),
            )
            for field, value in arrays:
                if not isinstance(value, list):
                    errors.append(f"case {case_id}: {lane}.{field} must be an array")

            if status != "measured":
                if any(isinstance(value, list) and value for _, value in arrays):
                    errors.append(f"case {case_id}: unmeasured {lane} carries raw samples")
                if result.get("stats") is not None:
                    errors.append(f"case {case_id}: unmeasured {lane} carries statistics")
                lane_stats[lane] = None
                continue

            if not uint(result.get("preparation_ns")):
                errors.append(
                    f"case {case_id}: {lane}.preparation_ns must be a nonnegative u64"
                )
            if isinstance(warmup, list):
                if expected_warmup is not None and len(warmup) != expected_warmup:
                    errors.append(
                        f"case {case_id}: {lane}.warmup_ns count {len(warmup)} "
                        f"does not match environment {expected_warmup}"
                    )
                if not all(uint(value) for value in warmup):
                    errors.append(f"case {case_id}: {lane}.warmup_ns values must be u64")
            if isinstance(measured, list):
                if expected_measured is not None and len(measured) != expected_measured:
                    errors.append(
                        f"case {case_id}: {lane}.measured_ns count {len(measured)} "
                        f"does not match environment {expected_measured}"
                    )
                if not all(uint(value) for value in measured):
                    errors.append(f"case {case_id}: {lane}.measured_ns values must be u64")
            for phase, timings, observations in (
                ("warmup", warmup, warmup_obs),
                ("measured", measured, measured_obs),
            ):
                if isinstance(timings, list) and isinstance(observations, list):
                    if len(timings) != len(observations):
                        errors.append(
                            f"case {case_id}: {lane} {phase} timing/observation lengths differ"
                        )
                    if not all(
                        isinstance(value, str) and _HEX64_RE.fullmatch(value)
                        for value in observations
                    ):
                        errors.append(
                            f"case {case_id}: {lane} {phase} observation digests must be lowercase hex64"
                        )
            recomputed_stats = (
                _sample_stats(measured)
                if isinstance(measured, list) and all(uint(value) for value in measured)
                else None
            )
            lane_stats[lane] = recomputed_stats
            if result.get("stats") != recomputed_stats:
                errors.append(f"case {case_id}: {lane}.stats disagrees with raw samples")
            if lane == "engine":
                if not isinstance(result.get("engine_kind"), str):
                    errors.append(f"case {case_id}: engine.engine_kind must be string")
                if not isinstance(result.get("route_reason"), str):
                    errors.append(f"case {case_id}: engine.route_reason must be string")

        lifecycle_recomputed = False
        if len(lane_results) == 3:
            stable_digests: list[str] = []
            lifecycle_recomputed = True
            for lane in ("engine", "node", "bun"):
                result = lane_results[lane]
                warmup_obs = result.get("warmup_observation_sha256", [])
                measured_obs = result.get("measured_observation_sha256", [])
                digests = (
                    warmup_obs + measured_obs
                    if isinstance(warmup_obs, list) and isinstance(measured_obs, list)
                    else []
                )
                if (
                    result.get("status") != "measured"
                    or result.get("observations_complete") is not True
                    or not digests
                    or any(digest != digests[0] for digest in digests)
                ):
                    lifecycle_recomputed = False
                    break
                stable_digests.append(digests[0])
            lifecycle_recomputed = lifecycle_recomputed and len(set(stable_digests)) == 1
        if case.get("measured_lifecycle_equivalent") != lifecycle_recomputed:
            errors.append(
                f"case {case_id}: measured_lifecycle_equivalent disagrees with raw observations"
            )

        engine_stats = lane_stats.get("engine")
        node_stats = lane_stats.get("node")
        bun_stats = lane_stats.get("bun")
        node_ratio = (
            _speedup_millionths(engine_stats["mean_ns"], node_stats["mean_ns"])
            if engine_stats is not None and node_stats is not None
            else None
        )
        bun_ratio = (
            _speedup_millionths(engine_stats["mean_ns"], bun_stats["mean_ns"])
            if engine_stats is not None and bun_stats is not None
            else None
        )
        if case.get("node_over_engine_speedup_millionths") != node_ratio:
            errors.append(f"case {case_id}: Node speedup disagrees with raw samples")
        if case.get("bun_over_engine_speedup_millionths") != bun_ratio:
            errors.append(f"case {case_id}: Bun speedup disagrees with raw samples")
        global_admitted = (
            case.get("behavior_equivalent") is True
            and lifecycle_recomputed
            and len(lane_results) == 3
            and all(result.get("status") == "measured" for result in lane_results.values())
            and max_cv is not None
            and all(
                stats is not None and stats["cv_millionths"] <= max_cv
                for stats in (engine_stats, node_stats, bun_stats)
            )
        )
        if case.get("admitted") != global_admitted:
            errors.append(f"case {case_id}: admitted disagrees with raw admission gates")
        recomputed_cases.append(
            {
                "behavior_equivalent": case.get("behavior_equivalent") is True,
                "lifecycle_equivalent": lifecycle_recomputed,
                "lane_results": lane_results,
                "lane_stats": lane_stats,
                "node_ratio": node_ratio,
                "bun_ratio": bun_ratio,
            }
        )

    fairness = report.get("fairness")
    fairness_compliant = isinstance(fairness, dict) and fairness.get("compliant") is True
    if not isinstance(fairness, dict) or not isinstance(fairness.get("compliant"), bool):
        errors.append("fairness.compliant must be boolean")
    else:
        violations = fairness.get("violations", [])
        if not isinstance(violations, list) or not all(
            isinstance(value, str) and value for value in violations
        ):
            errors.append("fairness.violations must be an array of non-empty strings")
        elif fairness_compliant == bool(violations):
            errors.append("fairness.compliant disagrees with fairness.violations")
        if fairness_compliant:
            errors.append("v3 fresh-engine/shared-realm lifecycle must remain fairness-degraded")

    for lane, name in (("node", "node_denominator"), ("bun", "bun_denominator")):
        denominator = report.get(name)
        if not isinstance(denominator, dict):
            errors.append(f"{name} must be an object")
            continue
        admitted_ratios: list[int] = []
        for recomputed in recomputed_cases:
            engine_stats = recomputed["lane_stats"].get("engine")
            baseline_stats = recomputed["lane_stats"].get(lane)
            ratio = recomputed[f"{lane}_ratio"]
            if (
                recomputed["behavior_equivalent"]
                and recomputed["lifecycle_equivalent"]
                and recomputed["lane_results"].get("engine", {}).get("status") == "measured"
                and recomputed["lane_results"].get(lane, {}).get("status") == "measured"
                and max_cv is not None
                and engine_stats is not None
                and baseline_stats is not None
                and engine_stats["cv_millionths"] <= max_cv
                and baseline_stats["cv_millionths"] <= max_cv
                and ratio is not None
            ):
                admitted_ratios.append(ratio)
        geomean = _geomean_millionths(admitted_ratios)
        publishable = fairness_compliant and bool(admitted_ratios) and geomean is not None
        expected_status = "published" if publishable else "degraded"
        expected_geomean = geomean if publishable else None
        expected_floor = geomean >= FLOOR_MILLIONTHS if publishable else None
        if denominator.get("baseline") != lane:
            errors.append(f"{name}.baseline must be {lane}")
        if denominator.get("admitted_cases") != len(admitted_ratios):
            errors.append(f"{name}.admitted_cases disagrees with baseline-specific gates")
        if denominator.get("excluded_cases") != len(cases) - len(admitted_ratios):
            errors.append(f"{name}.excluded_cases disagrees with baseline-specific gates")
        if denominator.get("status") != expected_status:
            errors.append(f"{name}.status disagrees with recomputed publication gates")
        if denominator.get("geomean_speedup_millionths") != expected_geomean:
            errors.append(f"{name}.geomean_speedup_millionths disagrees with raw samples")
        if denominator.get("meets_3x_floor") != expected_floor:
            errors.append(f"{name}.meets_3x_floor disagrees with raw samples")
        degraded_reasons = denominator.get("degraded_reasons", [])
        if expected_status == "degraded" and (
            not isinstance(degraded_reasons, list) or not degraded_reasons
        ):
            errors.append(f"{name}.degraded_reasons must explain degraded status")
    return errors


def measurement_evidence_view(cases: list[dict]) -> list[dict]:
    evidence: list[dict] = []
    for case in cases:
        lanes: dict[str, dict] = {}
        for lane in ("engine", "node", "bun"):
            result = case.get(lane, {})
            lanes[lane] = {
                "status": result.get("status"),
                "preparation_ns": result.get("preparation_ns"),
                "engine_kind": result.get("engine_kind"),
                "route_reason": result.get("route_reason"),
                "warmup_ns": result.get("warmup_ns", []),
                "measured_ns": result.get("measured_ns", []),
                "warmup_observation_sha256": result.get("warmup_observation_sha256", []),
                "measured_observation_sha256": result.get("measured_observation_sha256", []),
                "observations_complete": result.get("observations_complete", False),
            }
        evidence.append(
            {
                "case_id": case.get("case_id", ""),
                "admitted": bool(case.get("admitted", False)),
                "measured_lifecycle_equivalent": case.get("measured_lifecycle_equivalent", False),
                "measured_lifecycle_detail": case.get("measured_lifecycle_detail", ""),
                "lanes": lanes,
            }
        )
    return evidence


def reproduction_perf_command(
    corpus_path: str,
    profile: str,
    environment: dict,
    cases: list[dict],
) -> str:
    """Reconstruct the exact corpus selection used by one v3 report."""
    argv = [
        f"target/{profile}/frankenctl",
        "differential-oracle",
        "perf",
        "--manifest",
        corpus_path,
        "--out",
        "report.json",
        "--events",
        "events.jsonl",
        "--warmup",
        str(environment.get("warmup_iterations", 3)),
        "--samples",
        str(environment.get("measured_iterations", 10)),
        "--case-timeout-ms",
        "120000",
        "--engine-budget",
        str(environment.get("engine_instruction_budget", 2_000_000_000)),
        "--node-bin",
        "<node>",
        "--bun-bin",
        "<bun>",
    ]
    for case in cases:
        case_id = case.get("case_id")
        if isinstance(case_id, str) and case_id:
            argv.extend(["--case", case_id])
    return shlex.join(argv)


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
        "--profile",
        default="release",
        help="Cargo profile used to build the measured frankenctl binary",
    )
    ap.add_argument(
        "--generated-at-utc",
        required=True,
        help="ISO-8601 UTC timestamp for provenance fields",
    )
    ap.add_argument("--dirty", default="false", help="dirty worktree flag (true/false)")
    args = ap.parse_args()

    if not _PROFILE_RE.fullmatch(args.profile) or ".." in args.profile:
        print(f"ERROR: invalid Cargo profile: {args.profile!r}", file=sys.stderr)
        return 2

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
    validation_errors = validate_v3_report(report)
    if validation_errors:
        for error in validation_errors:
            print(f"ERROR: invalid v3 report: {error}", file=sys.stderr)
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
            "build_profile": args.profile,
            "warmup_iterations": env_in.get("warmup_iterations"),
            "measured_iterations": env_in.get("measured_iterations"),
            "max_cv_millionths": env_in.get("max_cv_millionths"),
            "engine_instruction_budget": env_in.get("engine_instruction_budget"),
            "engine_execution_lifecycle": env_in.get("engine_execution_lifecycle"),
            "external_execution_lifecycle": env_in.get("external_execution_lifecycle"),
            "source_report_path": str(report_path),
            "source_report_sha256": "sha256:" + sha256_hex(report_path.read_bytes()),
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
        "measurement_evidence": measurement_evidence_view(cases),
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
            "profile": args.profile,
        },
        "runtime": {
            "mode": "differential-oracle-perf",
            "lane": "baseline_interpreter",
            "engine_version": host.get("franken_engine_version", ""),
            "engine_instruction_budget": env_in.get("engine_instruction_budget"),
            "warmup_iterations": env_in.get("warmup_iterations"),
            "measured_iterations": env_in.get("measured_iterations"),
            "max_cv_millionths": env_in.get("max_cv_millionths"),
            "engine_execution_lifecycle": env_in.get("engine_execution_lifecycle"),
            "external_execution_lifecycle": env_in.get("external_execution_lifecycle"),
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
    perf_command = reproduction_perf_command(args.corpus, args.profile, env_in, cases)
    build_command = shlex.join(
        [
            "scripts/build_e2_denominator_bundle.py",
            "--report",
            "report.json",
            "--corpus",
            args.corpus,
            "--out-dir",
            str(out_dir),
            "--commit",
            args.commit,
            "--rustc",
            args.rustc,
            "--cargo",
            args.cargo,
            "--profile",
            args.profile,
            "--generated-at-utc",
            args.generated_at_utc,
            "--dirty",
            str(dirty).lower(),
        ]
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
