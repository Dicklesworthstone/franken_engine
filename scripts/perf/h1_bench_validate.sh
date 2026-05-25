#!/bin/bash
set -euo pipefail

# PERF-H1.4 (bd-o4cbn.1.4): Bench validation — evidence_ledger_bundle >= 50% drop.
#
# Builds `hot_paths` with the exact pass1 flags, runs Criterion against the
# saved pass1 baseline, and asserts the H1 win is real and statistically
# significant while the other 7 sub-benches do not regress.
#
# Pass criteria (all must hold):
#   1. evidence_ledger_bundle Criterion mean drops >= 50% vs pass1.
#   2. post-H1 95% CI does NOT overlap pass1 95% CI (significant win).
#   3. post-H1 CV (std/mean) <= 10%.
#   4. The other 7 sub-benches' post means stay within their pass1 95% CI band.
#
# Emits, under tests/artifacts/perf/h1_bench/<ts>/ (gitignored — local evidence):
#   - bench_output.txt          full Criterion run log
#   - criterion_diff_pass1.txt  `--baseline pass1` diff for the target bench
#   - events.jsonl              one perf.profile.run_complete line per sub-bench
#   - criterion_evidence_ledger_bundle_post_h1.json  post estimates for target
#   - fingerprint.json          host/toolchain/git fingerprint of this run
#   - summary.md                1-page before/after table + verdict
#
# Usage: scripts/perf/h1_bench_validate.sh   (run from repo root)

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

GROUP="real_runtime_hot_paths"
TARGET_BENCH="evidence_ledger_bundle"
PASS1_DIR="tests/artifacts/perf/20260520T214829Z-prof-pass1"
CRIT_DIR="target/criterion"

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
RUN_DIR="tests/artifacts/perf/h1_bench/${RUN_TS}"
mkdir -p "$RUN_DIR"
echo "[h1.4] run dir: $RUN_DIR"

# ---------------------------------------------------------------------------
# 1. Build the bench with the identical pass1 flags.
# ---------------------------------------------------------------------------
echo "[h1.4] building hot_paths bench (pass1 flags)..."
RCH_CARGO_WRAPPER_BYPASS=1 \
RUSTFLAGS="-C force-frame-pointers=yes -C linker=cc" \
CARGO_INCREMENTAL=0 \
"${CARGO:-/home/ubuntu/.cargo/bin/cargo}" bench --bench hot_paths --no-run

# ---------------------------------------------------------------------------
# 2. Locate the freshest bench binary.
# ---------------------------------------------------------------------------
HOT_NEW="$(ls target/release/deps/hot_paths-* | grep -v '\.d$' | sort | tail -1)"
echo "[h1.4] bench binary: $HOT_NEW"

# ---------------------------------------------------------------------------
# 3. Run the full group, saving as Criterion baseline `post_h1`.
# ---------------------------------------------------------------------------
echo "[h1.4] running benchmark group (save-baseline post_h1)..."
"$HOT_NEW" --bench --save-baseline post_h1 "$GROUP" 2>&1 | tee "$RUN_DIR/bench_output.txt"

# ---------------------------------------------------------------------------
# 4. Reconstruct the pass1 Criterion baseline from saved estimates so that
#    `--baseline pass1` works, then produce the auto-diff for the target.
#    benchmark.json is metadata-only (group/function id), identical run-to-run,
#    so we borrow it from the just-saved post_h1 baseline.
# ---------------------------------------------------------------------------
for fn in "${BENCHES[@]}"; do
    src="$PASS1_DIR/criterion_${fn}_estimates.json"
    dst_dir="$CRIT_DIR/$GROUP/$fn/pass1"
    post_bench_json="$CRIT_DIR/$GROUP/$fn/post_h1/benchmark.json"
    if [[ -f "$src" && -f "$post_bench_json" ]]; then
        mkdir -p "$dst_dir"
        cp "$src" "$dst_dir/estimates.json"
        cp "$post_bench_json" "$dst_dir/benchmark.json"
    fi
done

echo "[h1.4] criterion diff vs pass1 (target bench)..."
"$HOT_NEW" --bench --load-baseline post_h1 --baseline pass1 \
    "$GROUP/$TARGET_BENCH" 2>&1 | tee "$RUN_DIR/criterion_diff_pass1.txt" || \
    echo "[h1.4] (criterion --baseline diff non-fatal; authoritative verdict is computed below)"

# ---------------------------------------------------------------------------
# 5. Fingerprint for this run.
# ---------------------------------------------------------------------------
python3 - "$RUN_DIR" <<'PYFP'
import json, subprocess, sys, time, platform
run_dir = sys.argv[1]
def sh(*a):
    try:
        return subprocess.check_output(a, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return ""
fp = {
    "run_id": f"{int(time.time())}_{int(time.time()*1e6)%1000000}",
    "captured_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "git_sha": sh("git", "rev-parse", "HEAD"),
    "git_dirty": bool(sh("git", "status", "--porcelain")),
    "bead": "PERF-H1.4 (bd-o4cbn.1.4)",
    "baseline_ref": "20260520T214829Z-prof-pass1",
    "hardware": {
        "cpu_model": next((l.split(":",1)[1].strip() for l in open("/proc/cpuinfo")
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
# 6. Authoritative verdict: compare post_h1 estimates vs pass1 estimates,
#    write events.jsonl + summary.md, copy target post estimates, set exit code.
# ---------------------------------------------------------------------------
python3 - "$RUN_DIR" "$CRIT_DIR" "$GROUP" "$TARGET_BENCH" "$PASS1_DIR" "${BENCHES[@]}" <<'PYVERDICT'
import json, os, sys, time

run_dir, crit_dir, group, target, pass1_dir = sys.argv[1:6]
benches = sys.argv[6:]
now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def load_est(path):
    j = json.load(open(path))
    m = j["mean"]; ci = m["confidence_interval"]
    sd = j.get("std_dev", {}).get("point_estimate", 0.0)
    mean = m["point_estimate"]
    return {
        "mean": mean, "lo": ci["lower_bound"], "hi": ci["upper_bound"],
        "std": sd, "cv_pct": (sd / mean * 100.0) if mean else float("nan"),
    }

def overlap(a, b):
    # closed-interval overlap test
    return not (a["hi"] < b["lo"] or b["hi"] < a["lo"])

events = []
rows = []
all_pass = True
target_drop_pct = None
target_run_id = os.path.basename(run_dir)

for fn in benches:
    pass1_path = os.path.join(pass1_dir, f"criterion_{fn}_estimates.json")
    post_path = os.path.join(crit_dir, group, fn, "post_h1", "estimates.json")
    if not os.path.exists(post_path):
        post_path = os.path.join(crit_dir, group, fn, "new", "estimates.json")
    base = load_est(pass1_path)
    post = load_est(post_path)
    delta_pct = (post["mean"] - base["mean"]) / base["mean"] * 100.0  # negative = faster

    if fn == target:
        drop_pct = -delta_pct  # positive = improvement
        target_drop_pct = drop_pct
        cond_drop = drop_pct >= 50.0
        cond_sig = not overlap(post, base)        # CIs must NOT overlap
        cond_cv = post["cv_pct"] <= 10.0
        verdict = "pass" if (cond_drop and cond_sig and cond_cv) else "fail"
        if verdict != "pass":
            all_pass = False
        rows.append((fn, base, post, delta_pct,
                     f"drop={drop_pct:.1f}% sig={'Y' if cond_sig else 'N'} "
                     f"cv={post['cv_pct']:.1f}% -> {verdict.upper()}"))
    else:
        # no-regression guard: post mean must stay within pass1 95% CI band
        within = base["lo"] <= post["mean"] <= base["hi"]
        # tolerate improvements (faster) regardless; only flag regressions beyond CI
        regressed = post["mean"] > base["hi"]
        verdict = "fail" if regressed else "pass"
        if regressed:
            all_pass = False
        note = ("within-CI" if within else
                ("FASTER(ok)" if post["mean"] < base["lo"] else "REGRESSED"))
        rows.append((fn, base, post, delta_pct,
                     f"{note} ({delta_pct:+.1f}%) -> {verdict.upper()}"))

    events.append({
        "event": "perf.profile.run_complete",
        "bead": "PERF-H1.4",
        "sub_bench": fn,
        "mean_ns": f"{post['mean']:.3f}",
        "baseline_ns": round(base["mean"]),
        "delta_pct": f"{delta_pct:.3f}",
        "verdict": verdict,
        "timestamp": now,
    })

# events.jsonl
with open(os.path.join(run_dir, "events.jsonl"), "w") as f:
    for e in events:
        f.write(json.dumps(e) + "\n")

# copy target post estimates
tgt_post = os.path.join(crit_dir, group, target, "post_h1", "estimates.json")
if not os.path.exists(tgt_post):
    tgt_post = os.path.join(crit_dir, group, target, "new", "estimates.json")
import shutil
shutil.copy(tgt_post, os.path.join(run_dir, "criterion_evidence_ledger_bundle_post_h1.json"))

# summary.md
with open(os.path.join(run_dir, "summary.md"), "w") as f:
    f.write(f"# PERF-H1.4 Bench Validation — {target_run_id}\n\n")
    f.write(f"Bead: bd-o4cbn.1.4 · generated {now}\n\n")
    f.write(f"**Target `{target}` drop: {target_drop_pct:.2f}%** "
            f"(threshold ≥ 50%)\n\n")
    f.write("| sub-bench | pass1 mean (ns) | post-H1 mean (ns) | Δ% | "
            "post CI95 (ns) | verdict |\n")
    f.write("|---|---:|---:|---:|---|---|\n")
    for fn, base, post, delta_pct, note in rows:
        f.write(f"| {fn} | {base['mean']:.1f} | {post['mean']:.1f} | "
                f"{delta_pct:+.1f} | [{post['lo']:.1f}, {post['hi']:.1f}] | "
                f"{note} |\n")
    f.write(f"\n**Overall: {'PASS' if all_pass else 'FAIL'}**\n\n")
    f.write(f"- pass1 baseline: `{pass1_dir}`\n")
    f.write(f"- target pass1 CI95: [223239.9, 227660.1] ns; "
            f"post-H1 CI must not overlap.\n")

print(f"[h1.4] target drop = {target_drop_pct:.2f}%  overall = "
      f"{'PASS' if all_pass else 'FAIL'}")
sys.exit(0 if all_pass else 1)
PYVERDICT
VERDICT_RC=$?

echo "[h1.4] artifacts written to $RUN_DIR"
ls -1 "$RUN_DIR"
exit $VERDICT_RC
