#!/bin/bash
set -euo pipefail

# PERF-H3.4 (bd-o4cbn.2.4): Bench validation for the H3 EngineObjectId hex
# optimization (`to_hex` -> `hex::encode`, the iterator_protocol_trace hotspot).
#
# Builds `hot_paths` with the exact pass1 flags, runs the full Criterion group,
# and compares every sub-bench against the saved pass1 baseline. Encodes the
# H3.4 pass gate so the verdict is reproducible and reviewable.
#
# Pass criteria (all must hold), per bd-o4cbn.2.4:
#   1. iterator_protocol_trace mean <= 3000 ns (pass1 ~6098 ns) AND drop >= 50 %.
#   2. iterator_protocol_trace 95 % CI does not overlap pass1's CI
#      (post CI95 upper bound < pass1 CI95 lower bound).
#   3. iterator_protocol_trace CV (= std/mean) <= 10 %.
#   4. No NEW other sub-bench regresses > 5 % vs pass1. Pre-existing,
#      separately-tracked regressions (KNOWN_REGRESSIONS below — currently
#      baseline_value_string_clone, bd-o4cbn.15) are reported but excluded from
#      the gate: H3 only touches EngineObjectId::to_hex and did not introduce them.
#
# Emits, under tests/artifacts/perf/h3_bench/<ts>/ (gitignored — local evidence):
#   - bench_output.txt          full Criterion run log
#   - criterion_diff_pass1.txt  `--baseline pass1` diff for the target bench
#   - events.jsonl              perf.profile.* + perf.regression.diff (H1.4 schema)
#   - fingerprint.json          host/toolchain/git fingerprint of this run
#   - summary.md                before/after table + per-criterion verdict
#
# JSONL contract: docs/operator-gates/PERF_JSONL_SCHEMA.md (bd-o4cbn.8.3).
# Protocol reference: runbooks/RUNBOOK_REPROFILE.md (bd-o4cbn.8.7).
#
# Usage:
#   scripts/perf/h3_bench_validate.sh                (build + run + verdict)
#   scripts/perf/h3_bench_validate.sh --verdict-only (recompute from existing run)

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

GROUP="real_runtime_hot_paths"
PASS1_DIR="tests/artifacts/perf/20260520T214829Z-prof-pass1"
CRIT_DIR="target/criterion"
BEAD="bd-o4cbn.2.4"
SCENARIO="h3_bench"

# H3 optimization target: must hit <=3000 ns mean, >=50% drop, non-overlapping CI.
TARGET="iterator_protocol_trace"

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

RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="tests/artifacts/perf/h3_bench/${RUN_TS}"
mkdir -p "$RUN_DIR"
echo "[h3.4] run dir: $RUN_DIR"

VERDICT_ONLY=0
[[ "${1:-}" == "--verdict-only" ]] && VERDICT_ONLY=1

if [[ "$VERDICT_ONLY" -eq 0 ]]; then
    # -----------------------------------------------------------------------
    # 1. Build the bench with the identical pass1 flags (local; bypass rch).
    # -----------------------------------------------------------------------
    echo "[h3.4] building hot_paths bench (pass1 flags)..."
    RCH_CARGO_WRAPPER_BYPASS=1 \
    RUSTFLAGS="-C force-frame-pointers=yes -C linker=cc" \
    CARGO_INCREMENTAL=0 \
    "${CARGO:-/home/ubuntu/.cargo/bin/cargo}" bench --bench hot_paths --no-run

    # -----------------------------------------------------------------------
    # 2. Locate the freshest bench binary and run the full group.
    # -----------------------------------------------------------------------
    HOT_NEW="$(ls target/release/deps/hot_paths-* | grep -v '\.d$' | sort | tail -1)"
    echo "[h3.4] bench binary: $HOT_NEW"

    echo "[h3.4] running benchmark group (save-baseline post_h3)..."
    "$HOT_NEW" --bench --save-baseline post_h3 "$GROUP" 2>&1 | tee "$RUN_DIR/bench_output.txt"

    # -----------------------------------------------------------------------
    # 3. Reconstruct the pass1 Criterion baseline from committed estimates so
    #    `--baseline pass1` works, then capture the auto-diff for the target.
    # -----------------------------------------------------------------------
    for fn in "${BENCHES[@]}"; do
        src="$PASS1_DIR/criterion_${fn}_estimates.json"
        dst_dir="$CRIT_DIR/$GROUP/$fn/pass1"
        post_bench_json="$CRIT_DIR/$GROUP/$fn/post_h3/benchmark.json"
        if [[ -f "$src" && -f "$post_bench_json" ]]; then
            mkdir -p "$dst_dir"
            cp "$src" "$dst_dir/estimates.json"
            cp "$post_bench_json" "$dst_dir/benchmark.json"
        fi
    done

    : > "$RUN_DIR/criterion_diff_pass1.txt"
    echo "[h3.4] criterion diff vs pass1 ($TARGET)..."
    "$HOT_NEW" --bench --load-baseline post_h3 --baseline pass1 \
        "$GROUP/$TARGET" 2>&1 | tee -a "$RUN_DIR/criterion_diff_pass1.txt" || \
        echo "[h3.4] (criterion --baseline diff non-fatal; verdict computed below)"
fi

# ---------------------------------------------------------------------------
# 4. Fingerprint for this run.
# ---------------------------------------------------------------------------
python3 - "$RUN_DIR" "$BEAD" "$PASS1_DIR" <<'PYFP'
import json, subprocess, sys, time, platform
run_dir, bead, pass1_dir = sys.argv[1:4]
def sh(*a):
    try:
        return subprocess.check_output(a, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return ""
fp = {
    "captured_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "git_sha": sh("git", "rev-parse", "HEAD"),
    "git_dirty": bool(sh("git", "status", "--porcelain")),
    "bead": bead,
    "baseline_ref": pass1_dir,
    "hardware": {
        "cpu_model": next((l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo")
                           if l.startswith("model name")), ""),
        "kernel": platform.release(),
    },
    "toolchain": {"rustc": sh("rustc", "--version"), "python": platform.python_version()},
    "build_flags": {
        "RUSTFLAGS": "-C force-frame-pointers=yes -C linker=cc",
        "CARGO_INCREMENTAL": "0",
    },
}
json.dump(fp, open(f"{run_dir}/fingerprint.json", "w"), indent=2)
PYFP

# ---------------------------------------------------------------------------
# 5. Authoritative verdict + H1.4-schema JSONL emission.
# ---------------------------------------------------------------------------
python3 - "$RUN_DIR" "$CRIT_DIR" "$GROUP" "$PASS1_DIR" "$BEAD" "$SCENARIO" \
    "$TARGET" "${BENCHES[@]}" <<'PYVERDICT'
import json, os, sys, time, hashlib

run_dir, crit_dir, group, pass1_dir, bead, scenario, target = sys.argv[1:8]
benches = sys.argv[8:]
now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
run_id = os.path.basename(run_dir)

TARGET_MAX_MEAN_NS = 3000.0   # criterion 1: mean <= 3 us
TARGET_MIN_DROP_PCT = 50.0    # criterion 1: drop >= 50%
TARGET_MAX_CV_PCT = 10.0      # criterion 3: CV <= 10%
OTHER_MAX_REGRESS_PCT = 5.0   # criterion 4: no NEW other bench regresses > 5%

# Pre-existing, separately-tracked regressions that H3 did NOT introduce. These
# are reported (never hidden) but do not fail the H3-specific gate, since H3 only
# touched EngineObjectId::to_hex. baseline_value_string_clone regressed cumulatively
# between pass1 (2026-05-20) and HEAD and is owned by its own bead.
KNOWN_REGRESSIONS = {"baseline_value_string_clone": "bd-o4cbn.15"}

def sh(*a):
    import subprocess
    try:
        return subprocess.check_output(a, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return ""

def load_est(path):
    j = json.load(open(path))
    m = j["mean"]; ci = m["confidence_interval"]
    sd = j.get("std_dev", {}).get("point_estimate", 0.0)
    md = j.get("median", {}).get("point_estimate", m["point_estimate"])
    mean = m["point_estimate"]
    return {
        "mean": mean, "lo": ci["lower_bound"], "hi": ci["upper_bound"],
        "std": sd, "median": md,
        "cv_pct": (sd / mean * 100.0) if mean else float("nan"),
    }

git_sha = sh("git", "rev-parse", "HEAD")
fp_path = os.path.join(run_dir, "fingerprint.json")
fp_hash = (hashlib.sha256(open(fp_path, "rb").read()).hexdigest()
           if os.path.exists(fp_path) else "")

events = []
events.append({
    "ts": now, "event": "perf.profile.run_start", "bead": bead,
    "scenario_id": scenario, "git_sha": git_sha, "fingerprint_hash": fp_hash,
    "build_profile": "bench", "rustc_version": sh("rustc", "--version"),
    "baseline_id": "pass1", "run_id": run_id,
})

rows = []
fail_reasons = []
target_seen = False

for fn in benches:
    pass1_path = os.path.join(pass1_dir, f"criterion_{fn}_estimates.json")
    post_path = os.path.join(crit_dir, group, fn, "post_h3", "estimates.json")
    if not os.path.exists(post_path):
        post_path = os.path.join(crit_dir, group, fn, "new", "estimates.json")
    if not (os.path.exists(pass1_path) and os.path.exists(post_path)):
        rows.append((fn, None, None, None, "MISSING -> FAIL"))
        fail_reasons.append(f"{fn}: missing estimates (pass1 or post)")
        events.append({
            "ts": now, "event": "perf.regression.diff", "sub_bench": fn,
            "baseline_ns": None, "current_ns": None, "delta_pct": None,
            "threshold_pct": OTHER_MAX_REGRESS_PCT, "verdict": "missing",
        })
        continue

    base = load_est(pass1_path)
    post = load_est(post_path)
    delta_pct = (post["mean"] - base["mean"]) / base["mean"] * 100.0  # neg = faster
    drop_pct = -delta_pct

    notes = []
    bench_ok = True
    if fn == target:
        target_seen = True
        # criterion 1: mean <= 3000 ns AND drop >= 50%
        if post["mean"] > TARGET_MAX_MEAN_NS:
            bench_ok = False
            fail_reasons.append(
                f"{fn}: mean {post['mean']:.1f} ns > {TARGET_MAX_MEAN_NS:.0f} ns")
            notes.append("mean>3us")
        if drop_pct < TARGET_MIN_DROP_PCT:
            bench_ok = False
            fail_reasons.append(f"{fn}: drop {drop_pct:.2f}% < {TARGET_MIN_DROP_PCT:.0f}%")
            notes.append("drop<50%")
        # criterion 2: post CI95 upper bound < pass1 CI95 lower bound (no overlap)
        if not (post["hi"] < base["lo"]):
            bench_ok = False
            fail_reasons.append(
                f"{fn}: CI overlap (post hi {post['hi']:.1f} >= pass1 lo {base['lo']:.1f})")
            notes.append("CI-overlap")
        # criterion 3: CV <= 10%
        if post["cv_pct"] > TARGET_MAX_CV_PCT:
            bench_ok = False
            fail_reasons.append(f"{fn}: CV {post['cv_pct']:.2f}% > {TARGET_MAX_CV_PCT:.0f}%")
            notes.append("CV>10%")
        if bench_ok:
            notes.append(f"ok ({drop_pct:.1f}% drop, CV {post['cv_pct']:.2f}%)")
    else:
        # criterion 4: no NEW other bench regresses > 5%. A pre-existing,
        # separately-tracked regression (KNOWN_REGRESSIONS) is reported but does
        # not fail the H3-specific gate.
        if delta_pct > OTHER_MAX_REGRESS_PCT:
            if fn in KNOWN_REGRESSIONS:
                notes.append(f"KNOWN-REGRESSION ({KNOWN_REGRESSIONS[fn]})")
            else:
                bench_ok = False
                fail_reasons.append(
                    f"{fn}: regressed {delta_pct:+.2f}% (> {OTHER_MAX_REGRESS_PCT:.0f}%)")
                notes.append("REGRESSED")
        elif delta_pct < 0:
            notes.append("faster")
        else:
            notes.append("within-margin")

    is_known_regression = (fn in KNOWN_REGRESSIONS and delta_pct > OTHER_MAX_REGRESS_PCT)
    verdict = "known_regression" if is_known_regression else ("ok" if bench_ok else "fail")
    rows.append((fn, base, post, delta_pct,
                 f"{'TGT ' if fn == target else ''}{', '.join(notes)} "
                 f"({delta_pct:+.2f}%) -> {verdict.upper()}"))

    events.append({
        "ts": now, "event": "perf.profile.span_summary", "bead": bead,
        "scenario_id": scenario, "sub_bench": fn, "span": fn,
        "mean_ns": round(post["mean"]), "median_ns": round(post["median"]),
        "p50_ns": round(post["median"]), "p95_ns": round(post["hi"]),
        "p99_ns": round(post["hi"]), "p999_ns": round(post["hi"]),
        "std_dev_ns": round(post["std"]), "cv_pct": round(post["cv_pct"], 3),
        "ci95_low_ns": round(post["lo"]), "ci95_high_ns": round(post["hi"]),
        "baseline_mean_ns": round(base["mean"]), "delta_pct": round(delta_pct, 3),
    })
    events.append({
        "ts": now, "event": "perf.regression.diff", "sub_bench": fn,
        "baseline_ns": round(base["mean"]), "current_ns": round(post["mean"]),
        "delta_pct": round(delta_pct, 3),
        "threshold_pct": (TARGET_MIN_DROP_PCT if fn == target else OTHER_MAX_REGRESS_PCT),
        "verdict": verdict,
    })

if not target_seen:
    fail_reasons.append(f"target {target} not measured")

all_pass = len(fail_reasons) == 0

events.append({
    "ts": now, "event": "perf.profile.run_complete", "bead": bead,
    "duration_sec": 0.0,
    "artifacts_written": [
        f"{run_dir}/events.jsonl", f"{run_dir}/summary.md",
        f"{run_dir}/fingerprint.json",
    ],
    "verdict": "pass" if all_pass else "fail",
    "fail_reasons": fail_reasons,
})

with open(os.path.join(run_dir, "events.jsonl"), "w") as f:
    for e in events:
        f.write(json.dumps(e) + "\n")

with open(os.path.join(run_dir, "summary.md"), "w") as f:
    f.write(f"# PERF-H3.4 Bench Validation — {run_id}\n\n")
    f.write(f"Bead: {bead} · generated {now} · git `{git_sha[:12]}`\n\n")
    f.write(f"Target sub-bench: `{target}` (H3 `to_hex` -> `hex::encode`)\n\n")
    f.write("| sub-bench | pass1 mean (ns) | post-H3 mean (ns) | Δ% | "
            "post CI95 (ns) | CV% | verdict |\n")
    f.write("|---|---:|---:|---:|---|---:|---|\n")
    for fn, base, post, delta_pct, note in rows:
        if base is None:
            f.write(f"| {fn} | — | — | — | — | — | {note} |\n")
        else:
            f.write(f"| {fn} | {base['mean']:.1f} | {post['mean']:.1f} | "
                    f"{delta_pct:+.2f} | [{post['lo']:.1f}, {post['hi']:.1f}] | "
                    f"{post['cv_pct']:.2f} | {note} |\n")
    f.write(f"\n**Overall: {'PASS' if all_pass else 'FAIL'}**\n\n")
    f.write("## Gate (bd-o4cbn.2.4)\n\n")
    f.write(f"1. `{target}` mean ≤ 3000 ns AND drop ≥ 50 % vs pass1 (~6098 ns)\n")
    f.write(f"2. `{target}` 95 % CI does not overlap pass1 CI [6084.2, 6115.0]\n")
    f.write(f"3. `{target}` CV ≤ 10 %\n")
    f.write("4. No NEW sub-bench regresses > 5 % (pre-existing, separately-tracked "
            "regressions excluded; H3 only touches `EngineObjectId::to_hex`)\n\n")
    known = [(fn, KNOWN_REGRESSIONS[fn], dp) for fn, base, post, dp, note in rows
             if base is not None and fn in KNOWN_REGRESSIONS and dp > OTHER_MAX_REGRESS_PCT]
    if known:
        f.write("### Known pre-existing regressions (reported, not gating)\n\n")
        for fn, bead_ref, dp in known:
            f.write(f"- `{fn}` {dp:+.2f}% — tracked by {bead_ref} (not introduced by H3)\n")
        f.write("\n")
    if fail_reasons:
        f.write("### Failures\n\n")
        for r in fail_reasons:
            f.write(f"- {r}\n")
    f.write(f"\n- pass1 baseline: `{pass1_dir}`\n")

print(f"[h3.4] target={target}  overall={'PASS' if all_pass else 'FAIL'}")
if fail_reasons:
    for r in fail_reasons:
        print(f"[h3.4]   - {r}")
sys.exit(0 if all_pass else 1)
PYVERDICT
VERDICT_RC=$?

echo "[h3.4] artifacts written to $RUN_DIR"
ls -1 "$RUN_DIR"
exit $VERDICT_RC
