#!/usr/bin/env python3
"""PERF-INFRA.8 (bd-o4cbn.8.8) — convert hyperfine JSON to PERF JSONL.

Reads a hyperfine ``--export-json`` file and emits one
``perf.profile.span_summary`` event per benchmarked command, conforming to
the canonical PERF JSONL schema (PERF-INFRA.3 / docs/operator-gates/
PERF_JSONL_SCHEMA.md). Numeric latency fields are integers in nanoseconds;
``_pct`` fields are floats.

It can additionally emit a ``startup_baseline.json`` (per-command cold-start
p50/p95 in milliseconds) for use as a checked-in regression baseline, and a
compact ``--p95-json`` summary the regression gate consumes.

Usage:
    hyperfine_to_perf_jsonl.py --input hyperfine.json --bead PERF-INFRA.8 \\
        --scenario startup_microbench --out events.jsonl \\
        [--baseline-out startup_baseline.json] [--p95-json p95.json]
"""

from __future__ import annotations

import argparse
import datetime
import json
import math
import sys


def percentile(sorted_vals: list[float], pct: float) -> float:
    """Linear-interpolation percentile (numpy 'linear' method).

    `sorted_vals` must be ascending and non-empty; `pct` in [0, 100].
    """
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    rank = (pct / 100.0) * (len(sorted_vals) - 1)
    lo = math.floor(rank)
    hi = math.ceil(rank)
    if lo == hi:
        return sorted_vals[int(rank)]
    frac = rank - lo
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * frac


def now_rfc3339() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def s_to_ns(seconds: float) -> int:
    return int(round(seconds * 1_000_000_000.0))


def s_to_ms(seconds: float) -> float:
    return seconds * 1000.0


def safe_name(command: str) -> str:
    """Normalize a hyperfine command/name into a sub_bench identifier."""
    return command.strip().replace(" ", "_").replace("/", "_")


def summarize(result: dict) -> dict:
    """Compute span-summary stats (in ns) for one hyperfine result."""
    times = sorted(float(t) for t in result.get("times", []))
    mean = float(result.get("mean", 0.0))
    stddev = float(result.get("stddev", 0.0) or 0.0)
    median = float(result.get("median", percentile(times, 50.0) if times else 0.0))
    n = len(times) if times else 1
    sem = stddev / math.sqrt(n) if n > 0 else 0.0
    return {
        "mean_ns": s_to_ns(mean),
        "median_ns": s_to_ns(median),
        "p50_ns": s_to_ns(percentile(times, 50.0)) if times else s_to_ns(median),
        "p95_ns": s_to_ns(percentile(times, 95.0)) if times else s_to_ns(mean),
        "p99_ns": s_to_ns(percentile(times, 99.0)) if times else s_to_ns(mean),
        "p999_ns": s_to_ns(percentile(times, 99.9)) if times else s_to_ns(mean),
        "std_dev_ns": s_to_ns(stddev),
        "cv_pct": round((stddev / mean * 100.0), 4) if mean > 0 else 0.0,
        "ci95_low_ns": s_to_ns(mean - 1.96 * sem),
        "ci95_high_ns": s_to_ns(mean + 1.96 * sem),
        # raw seconds kept for baseline/p95 emission convenience
        "_p50_ms": s_to_ms(percentile(times, 50.0)) if times else s_to_ms(median),
        "_p95_ms": s_to_ms(percentile(times, 95.0)) if times else s_to_ms(mean),
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="hyperfine JSON -> PERF JSONL")
    ap.add_argument("--input", required=True, help="hyperfine --export-json file")
    ap.add_argument("--bead", required=True, help="owning bead id, e.g. PERF-INFRA.8")
    ap.add_argument("--scenario", default="hyperfine", help="scenario_id label")
    ap.add_argument("--out", required=True, help="output JSONL path")
    ap.add_argument("--baseline-out", help="optional startup_baseline.json path")
    ap.add_argument("--p95-json", help="optional compact {name: p95_ms} JSON path")
    args = ap.parse_args(argv)

    try:
        with open(args.input, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read hyperfine JSON {args.input}: {exc}", file=sys.stderr)
        return 2

    results = data.get("results")
    if not isinstance(results, list) or not results:
        print(f"error: no results in {args.input}", file=sys.stderr)
        return 2

    baseline: dict[str, float] = {}
    p95_map: dict[str, float] = {}
    lines: list[str] = []

    for result in results:
        # hyperfine writes "command"; we also pass --command-name so it may be a label.
        raw_name = str(result.get("command", "unknown"))
        name = safe_name(raw_name)
        stats = summarize(result)
        ts = now_rfc3339()
        event = {
            "ts": ts,
            "event": "perf.profile.span_summary",
            "bead": args.bead,
            "scenario_id": args.scenario,
            "sub_bench": name,
            "span": name,
            "mean_ns": stats["mean_ns"],
            "median_ns": stats["median_ns"],
            "p50_ns": stats["p50_ns"],
            "p95_ns": stats["p95_ns"],
            "p99_ns": stats["p99_ns"],
            "p999_ns": stats["p999_ns"],
            "std_dev_ns": stats["std_dev_ns"],
            "cv_pct": stats["cv_pct"],
            "ci95_low_ns": stats["ci95_low_ns"],
            "ci95_high_ns": stats["ci95_high_ns"],
            "category": "STARTUP",
        }
        lines.append(json.dumps(event, separators=(",", ":")))
        baseline[f"{name}_cold_start_p50_ms"] = round(stats["_p50_ms"], 4)
        baseline[f"{name}_cold_start_p95_ms"] = round(stats["_p95_ms"], 4)
        p95_map[name] = round(stats["_p95_ms"], 4)

    with open(args.out, "w", encoding="utf-8") as fh:
        for line in lines:
            fh.write(line + "\n")
    print(f"wrote {len(lines)} span_summary event(s) to {args.out}")

    if args.baseline_out:
        with open(args.baseline_out, "w", encoding="utf-8") as fh:
            json.dump(baseline, fh, indent=2, sort_keys=True)
            fh.write("\n")
        print(f"wrote startup baseline to {args.baseline_out}")

    if args.p95_json:
        with open(args.p95_json, "w", encoding="utf-8") as fh:
            json.dump(p95_map, fh, indent=2, sort_keys=True)
            fh.write("\n")
        print(f"wrote p95 map to {args.p95_json}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
