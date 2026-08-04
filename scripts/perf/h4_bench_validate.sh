#!/bin/bash
set -euo pipefail

# PERF-H4.5 (bd-o4cbn.5.5): bench validation for the deterministic_serde
# buffer-reuse / canonical-sort-flattening H4 lane.
#
# H4 did not freeze a dedicated post-H4 Criterion artifact before the later H7
# allocator and ALIEN-2 measurements landed. This validator therefore consumes a
# preserved perf run (by default the H7.2 timing run) and applies only the H4.5
# end-state gate:
#
#   1. parser_arena_materialization mean <= 27 us.
#   2. lowering_pipeline_ir3 mean <= 72 us.
#   3. Combined target mean drop >= 15% vs frozen pass1.
#   4. No other sub-bench regresses > 5%, excluding separately-tracked known
#      regressions.
#   5. Each H4 target's 95% CI is strictly below the pass1 95% CI lower bound.
#
# The result is a cumulative end-state validation, not H4-isolated attribution.
# Use the H4.4 determinism tests and commit-scoped implementation review for the
# H4 semantic claim; this gate proves the recorded end state clears the original
# H4.5 numeric criteria.
#
# Emits, under tests/artifacts/perf/h4_bench/<ts>/ by default:
#   - source_events.jsonl  copied when --from-run is used
#   - events.jsonl         perf.profile.* + perf.regression.diff (H1.4 shape)
#   - fingerprint.json     host/toolchain/git/source-run fingerprint
#   - summary.md           before/after table + per-criterion verdict
#
# Usage:
#   scripts/perf/h4_bench_validate.sh
#   scripts/perf/h4_bench_validate.sh --from-run tests/artifacts/perf/h7_bench/20260526T071059Z
#   scripts/perf/h4_bench_validate.sh --verdict-only
#
# For local validation without creating repo-local artifacts:
#   H4_BENCH_ARTIFACT_ROOT=target/perf/h4_bench scripts/perf/h4_bench_validate.sh

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

GROUP="real_runtime_hot_paths"
PASS1_DIR="tests/artifacts/perf/20260520T214829Z-prof-pass1"
CRIT_DIR="target/criterion"
BEAD="bd-o4cbn.5.5"
SCENARIO="h4_bench"
DEFAULT_FROM_RUN="tests/artifacts/perf/h7_bench/20260526T071059Z"

BENCHES=(
    parser_arena_materialization
    lowering_pipeline_ir3
    baseline_interpreter_eval
    baseline_value_string_clone
    iterator_protocol_trace
    scheduler_queue_commit
    evidence_ledger_bundle
    transport_certificate_serialization
)

MODE="from-run"
FROM_RUN="$DEFAULT_FROM_RUN"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --from-run)
            MODE="from-run"
            FROM_RUN="${2:-}"
            if [[ -z "$FROM_RUN" ]]; then
                echo "[h4.5] --from-run requires a directory" >&2
                exit 2
            fi
            shift 2
            ;;
        --verdict-only)
            MODE="verdict-only"
            FROM_RUN=""
            shift
            ;;
        --help|-h)
            sed -n '1,42p' "$0"
            exit 0
            ;;
        *)
            echo "[h4.5] unknown arg: $1" >&2
            exit 2
            ;;
    esac
done

RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_ROOT="${H4_BENCH_ARTIFACT_ROOT:-tests/artifacts/perf/h4_bench}"
RUN_DIR="${RUN_ROOT}/${RUN_TS}"
mkdir -p "$RUN_DIR"
echo "[h4.5] run dir: $RUN_DIR"

if [[ "$MODE" == "from-run" ]]; then
    if [[ ! -f "$FROM_RUN/events.jsonl" ]]; then
        echo "[h4.5] --from-run must contain events.jsonl: $FROM_RUN" >&2
        exit 2
    fi
    echo "[h4.5] reading estimates from $FROM_RUN (no rebuild)"
    cp "$FROM_RUN/events.jsonl" "$RUN_DIR/source_events.jsonl"
else
    echo "[h4.5] verdict-only mode (using current target/criterion contents)"
fi

# --------------------------------------------------------------------------
# Fingerprint.
# --------------------------------------------------------------------------
python3 - "$RUN_DIR" "$BEAD" "$PASS1_DIR" "$MODE" "$FROM_RUN" <<'PYFP'
import json, platform, subprocess, sys, time

run_dir, bead, pass1_dir, mode, from_run = sys.argv[1:6]

def sh(*args):
    try:
        return subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return ""

fp = {
    "captured_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "git_sha": sh("git", "rev-parse", "HEAD"),
    "git_dirty": bool(sh("git", "status", "--porcelain")),
    "bead": bead,
    "baseline_ref": pass1_dir,
    "mode": mode,
    "source_run": from_run if from_run else None,
    "allocator_context": "mimalloc when using the default H7.2 source run",
    "claim_scope": "cumulative end-state H4.5 gate; not H4-isolated attribution",
    "hardware": {
        "cpu_model": next(
            (line.split(":", 1)[1].strip() for line in open("/proc/cpuinfo")
             if line.startswith("model name")),
            "",
        ),
        "kernel": platform.release(),
    },
    "toolchain": {"rustc": sh("rustc", "--version"), "python": platform.python_version()},
}
json.dump(fp, open(f"{run_dir}/fingerprint.json", "w"), indent=2)
PYFP

# --------------------------------------------------------------------------
# Verdict + JSONL emission.
# --------------------------------------------------------------------------
python3 - "$RUN_DIR" "$CRIT_DIR" "$GROUP" "$PASS1_DIR" "$BEAD" "$SCENARIO" \
    "$MODE" "$FROM_RUN" "${BENCHES[@]}" <<'PYVERDICT'
import hashlib
import json
import os
import subprocess
import sys
import time

run_dir, crit_dir, group, pass1_dir, bead, scenario, mode, from_run = sys.argv[1:9]
benches = sys.argv[9:]
now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
run_id = os.path.basename(run_dir)

H4_TARGETS = ("parser_arena_materialization", "lowering_pipeline_ir3")
ABS_CAP_NS = {
    "parser_arena_materialization": 27_000.0,
    "lowering_pipeline_ir3": 72_000.0,
}
MIN_COMBINED_DROP_PCT = 15.0
MAX_REGRESS_PCT = 5.0
KNOWN_REGRESSIONS = {"baseline_value_string_clone": "bd-o4cbn.15"}

def sh(*args):
    try:
        return subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return ""

def load_est_from_file(path):
    with open(path) as f:
        data = json.load(f)
    mean = data["mean"]["point_estimate"]
    ci = data["mean"]["confidence_interval"]
    std = data.get("std_dev", {}).get("point_estimate", 0.0)
    median = data.get("median", {}).get("point_estimate", mean)
    return {
        "mean": float(mean),
        "lo": float(ci["lower_bound"]),
        "hi": float(ci["upper_bound"]),
        "std": float(std),
        "median": float(median),
        "cv_pct": (float(std) / float(mean) * 100.0) if mean else float("nan"),
    }

def load_est_from_events(events_path, sub_bench):
    if not events_path or not os.path.exists(events_path):
        return None
    with open(events_path) as f:
        for line in f:
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if (
                event.get("event") == "perf.profile.span_summary"
                and event.get("sub_bench") == sub_bench
            ):
                mean = float(event.get("mean_ns") or 0.0)
                std = float(event.get("std_dev_ns") or 0.0)
                median = float(event.get("median_ns") or mean)
                lo = float(event.get("ci95_low_ns") or mean)
                hi = float(event.get("ci95_high_ns") or mean)
                return {
                    "mean": mean,
                    "lo": lo,
                    "hi": hi,
                    "std": std,
                    "median": median,
                    "cv_pct": (std / mean * 100.0) if mean else float("nan"),
                }
    return None

def load_pass1_estimate(sub_bench):
    path = os.path.join(pass1_dir, f"criterion_{sub_bench}_estimates.json")
    if os.path.exists(path):
        return load_est_from_file(path), path
    path = os.path.join(crit_dir, group, sub_bench, "pass1", "estimates.json")
    if os.path.exists(path):
        return load_est_from_file(path), path
    return None, None

def load_post_estimate(sub_bench):
    if from_run:
        events_path = os.path.join(from_run, "events.jsonl")
        event_est = load_est_from_events(events_path, sub_bench)
        if event_est is not None:
            return event_est, events_path
    for baseline in ("post_h4", "post_h7", "post_alien2", "new"):
        path = os.path.join(crit_dir, group, sub_bench, baseline, "estimates.json")
        if os.path.exists(path):
            return load_est_from_file(path), path
    return None, None

git_sha = sh("git", "rev-parse", "HEAD")
fp_path = os.path.join(run_dir, "fingerprint.json")
fp_hash = (
    hashlib.sha256(open(fp_path, "rb").read()).hexdigest()
    if os.path.exists(fp_path)
    else ""
)

events = [{
    "ts": now,
    "event": "perf.profile.run_start",
    "bead": bead,
    "scenario_id": scenario,
    "git_sha": git_sha,
    "fingerprint_hash": fp_hash,
    "build_profile": "bench",
    "rustc_version": sh("rustc", "--version"),
    "baseline_id": "pass1",
    "run_id": run_id,
    "mode": mode,
    "source_run": from_run if from_run else None,
}]

rows = []
fail_reasons = []
target_base_sum = 0.0
target_post_sum = 0.0
target_values = {}

for bench in benches:
    post, post_src = load_post_estimate(bench)
    base, base_src = load_pass1_estimate(bench)
    if post is None or base is None:
        rows.append((bench, None, None, None, None, "MISSING -> FAIL"))
        fail_reasons.append(
            f"{bench}: missing estimates ({'post' if post is None else 'pass1'})"
        )
        events.append({
            "ts": now,
            "event": "perf.regression.diff",
            "sub_bench": bench,
            "baseline_ns": None,
            "current_ns": None,
            "delta_pct": None,
            "threshold_pct": MAX_REGRESS_PCT,
            "verdict": "missing",
        })
        continue

    delta_pct = (post["mean"] - base["mean"]) / base["mean"] * 100.0
    notes = []
    bench_pass = True
    is_target = bench in H4_TARGETS
    is_known = bench in KNOWN_REGRESSIONS

    if delta_pct > MAX_REGRESS_PCT:
        if is_known:
            notes.append(f"KNOWN-REGRESSION ({KNOWN_REGRESSIONS[bench]})")
        else:
            notes.append("REGRESSED")
            bench_pass = False
            fail_reasons.append(
                f"{bench}: regressed {delta_pct:+.2f}% vs pass1 (> {MAX_REGRESS_PCT:.0f}%)"
            )

    if is_target:
        target_base_sum += base["mean"]
        target_post_sum += post["mean"]
        target_values[bench] = (base, post)
        cap = ABS_CAP_NS[bench]
        if post["mean"] > cap:
            bench_pass = False
            notes.append(f"CAP>{cap/1000:.0f}us")
            fail_reasons.append(
                f"{bench}: mean {post['mean']/1000:.2f} us exceeds cap {cap/1000:.0f} us"
            )
        else:
            notes.append(f"cap-ok ({post['mean']/1000:.2f}/{cap/1000:.0f}us)")
        if post["hi"] >= base["lo"]:
            bench_pass = False
            notes.append("CI95-overlap")
            fail_reasons.append(
                f"{bench}: post CI95.hi {post['hi']:.1f} ns is not below "
                f"pass1 CI95.lo {base['lo']:.1f} ns"
            )
        else:
            notes.append(
                f"CI95.hi {post['hi']/1000:.2f}us < pass1.lo {base['lo']/1000:.2f}us"
            )
    else:
        if delta_pct < 0:
            notes.append(f"drop {-delta_pct:.2f}%")
        elif delta_pct <= MAX_REGRESS_PCT:
            notes.append("within tolerance")

    rows.append((
        bench,
        base,
        post,
        delta_pct,
        is_target,
        ("PASS" if bench_pass else "FAIL") + " :: " + ", ".join(notes),
    ))

    events.append({
        "ts": now,
        "event": "perf.profile.span_summary",
        "bead": bead,
        "scenario_id": scenario,
        "sub_bench": bench,
        "span": bench,
        "mean_ns": round(post["mean"]),
        "median_ns": round(post["median"]),
        "p50_ns": round(post["median"]),
        "p95_ns": round(post["hi"]),
        "p99_ns": round(post["hi"]),
        "p999_ns": round(post["hi"]),
        "std_dev_ns": round(post["std"]),
        "cv_pct": round(post["cv_pct"], 3),
        "ci95_low_ns": round(post["lo"]),
        "ci95_high_ns": round(post["hi"]),
        "baseline_mean_ns": round(base["mean"]),
        "baseline_ci95_low_ns": round(base["lo"]),
        "baseline_ci95_high_ns": round(base["hi"]),
        "delta_pct": round(delta_pct, 3),
        "h4_target": is_target,
        "absolute_cap_ns": ABS_CAP_NS.get(bench),
        "post_source": post_src,
        "baseline_source": base_src,
    })
    events.append({
        "ts": now,
        "event": "perf.regression.diff",
        "sub_bench": bench,
        "baseline_ns": round(base["mean"]),
        "current_ns": round(post["mean"]),
        "delta_pct": round(delta_pct, 3),
        "threshold_pct": MAX_REGRESS_PCT,
        "verdict": (
            "known_regression"
            if is_known and delta_pct > MAX_REGRESS_PCT
            else ("regression" if delta_pct > MAX_REGRESS_PCT else "ok")
        ),
    })

if len(target_values) != len(H4_TARGETS):
    missing = sorted(set(H4_TARGETS) - set(target_values))
    fail_reasons.append(f"missing H4 target estimates: {', '.join(missing)}")

combined_drop_pct = (
    (target_base_sum - target_post_sum) / target_base_sum * 100.0
    if target_base_sum
    else float("nan")
)
if target_base_sum and combined_drop_pct < MIN_COMBINED_DROP_PCT:
    fail_reasons.append(
        f"combined H4 target drop {combined_drop_pct:.2f}% < required {MIN_COMBINED_DROP_PCT:.0f}%"
    )

all_pass = not fail_reasons
events.append({
    "ts": now,
    "event": "perf.profile.run_complete",
    "bead": bead,
    "h4_caps_ns": ABS_CAP_NS,
    "combined_baseline_ns": round(target_base_sum),
    "combined_current_ns": round(target_post_sum),
    "combined_drop_pct": round(combined_drop_pct, 3),
    "min_combined_drop_pct": MIN_COMBINED_DROP_PCT,
    "max_regress_pct": MAX_REGRESS_PCT,
    "known_regressions": KNOWN_REGRESSIONS,
    "artifacts_written": [
        f"{run_dir}/events.jsonl",
        f"{run_dir}/summary.md",
        f"{run_dir}/fingerprint.json",
    ],
    "verdict": "pass" if all_pass else "fail",
    "fail_reasons": fail_reasons,
})

with open(os.path.join(run_dir, "events.jsonl"), "w") as f:
    for event in events:
        f.write(json.dumps(event) + "\n")

with open(os.path.join(run_dir, "summary.md"), "w") as f:
    f.write(f"# PERF-H4.5 Bench Validation - {run_id}\n\n")
    f.write(
        f"Bead: {bead}. Generated {now}. Git `{git_sha[:12]}`. "
        f"Baseline `pass1`: `{pass1_dir}`.\n\n"
    )
    if from_run:
        f.write(f"Source timing run: `{from_run}`.\n\n")
    f.write(
        "This is a cumulative end-state validation for the original H4.5 numeric "
        "criteria. The default source is the preserved H7.2 timing run because "
        "H4 did not freeze a separate post-H4 benchmark artifact.\n\n"
    )
    f.write("| sub-bench | pass1 mean (ns) | current mean (ns) | current CI95 (ns) | delta | cap (ns) | verdict |\n")
    f.write("|---|---:|---:|---:|---:|---:|---|\n")
    for bench, base, post, delta_pct, _is_target, note in rows:
        if base is None or post is None:
            f.write(f"| {bench} | - | - | - | - | - | {note} |\n")
            continue
        cap = ABS_CAP_NS.get(bench)
        cap_s = f"{cap:.0f}" if cap is not None else "-"
        f.write(
            f"| {bench} | {base['mean']:.1f} | {post['mean']:.1f} | "
            f"[{post['lo']:.1f}, {post['hi']:.1f}] | "
            f"{delta_pct:+.2f}% | {cap_s} | {note} |\n"
        )
    f.write("\n")
    f.write("## Gate\n\n")
    f.write(f"- `parser_arena_materialization` mean <= {ABS_CAP_NS['parser_arena_materialization']/1000:.0f} us.\n")
    f.write(f"- `lowering_pipeline_ir3` mean <= {ABS_CAP_NS['lowering_pipeline_ir3']/1000:.0f} us.\n")
    f.write(
        f"- Combined H4 target drop >= {MIN_COMBINED_DROP_PCT:.0f}% vs pass1: "
        f"{target_base_sum:.1f} -> {target_post_sum:.1f} ns "
        f"({combined_drop_pct:.2f}%).\n"
    )
    f.write(
        f"- No other sub-bench regresses > {MAX_REGRESS_PCT:.0f}% vs pass1, "
        "except known separately-tracked regressions.\n"
    )
    f.write("- Each H4 target's post CI95 upper bound is below pass1 CI95 lower bound.\n\n")
    known = [
        (bench, KNOWN_REGRESSIONS[bench], delta_pct)
        for bench, base, post, delta_pct, _target, _note in rows
        if base is not None
        and bench in KNOWN_REGRESSIONS
        and delta_pct is not None
        and delta_pct > MAX_REGRESS_PCT
    ]
    if known:
        f.write("## Known Regressions Excluded From Gate\n\n")
        for bench, known_bead, delta_pct in known:
            f.write(
                f"- `{bench}` reads {delta_pct:+.2f}% vs pass1 and is tracked "
                f"separately by `{known_bead}`; it is reported, not hidden.\n"
            )
        f.write("\n")
    f.write(f"**Overall: {'PASS' if all_pass else 'FAIL'}**\n")
    if fail_reasons:
        f.write("\n## Failures\n\n")
        for reason in fail_reasons:
            f.write(f"- {reason}\n")

print(f"[h4.5] combined H4 target drop: {combined_drop_pct:.2f}%")
print(f"[h4.5] overall = {'PASS' if all_pass else 'FAIL'}")
for reason in fail_reasons:
    print(f"[h4.5]   - {reason}")
sys.exit(0 if all_pass else 1)
PYVERDICT
VERDICT_RC=$?

echo "[h4.5] artifacts written to $RUN_DIR"
find "$RUN_DIR" -maxdepth 1 -type f -printf '%f\n' | sort
exit "$VERDICT_RC"
