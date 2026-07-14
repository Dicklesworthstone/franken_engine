#!/bin/bash
set -euo pipefail

# PERF-H1.4 (bd-o4cbn.1.4): Bench validation — evidence_ledger_bundle >= 50% drop.
#
# Builds `hot_paths` with the current x86_64 Linux linker-policy successor
# flags, runs Criterion against the saved historical pass1 baseline, and
# asserts the H1 threshold while reporting that build-identity boundary.
#
# Pass criteria (all must hold):
#   1. evidence_ledger_bundle Criterion mean drops >= 50% vs pass1.
#   2. post-H1 95% CI does NOT overlap pass1 95% CI (significant win).
#   3. post-H1 CV (std/mean) <= 10%.
#   4. The other 7 sub-benches' post means stay within their pass1 95% CI band.
#      Pre-existing, separately-tracked regressions (KNOWN_REGRESSIONS below)
#      are reported but excluded from the H1-specific gate.
#
# This frozen-pass1 gate is not a same-day, same-allocator, or same-build-profile
# code-drift verdict. The frozen fingerprint does not bind Cargo flag channels;
# `honest_gate.sh` therefore fails its symmetry question for this comparison.
# See bd-bwztz for the 2026-06-12 endpoint audit.
#
# Emits, under tests/artifacts/perf/h1_bench/<ts>/ (gitignored — local evidence):
#   - bench_output.txt          full Criterion run log
#   - criterion_diff_pass1.txt  `--baseline pass1` diff for the target bench
#   - events.jsonl              one perf.profile.run_complete line per sub-bench
#   - criterion_evidence_ledger_bundle_post_h1.json  post estimates for target
#   - fingerprint.json          host/toolchain/git fingerprint of this run
#   - summary.md                1-page before/after table + verdict
#
# Usage:
#   scripts/perf/h1_bench_validate.sh
#
# This script does not run Cargo locally. It submits `cargo bench` itself
# through rch so the command classifies as cargo_bench.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

GROUP="real_runtime_hot_paths"
TARGET_BENCH="evidence_ledger_bundle"
PASS1_DIR="tests/artifacts/perf/20260520T214829Z-prof-pass1"
RUN_TS="${H1_BENCH_VALIDATE_RUN_TS:-$(date -u +%Y%m%dT%H%M%SZ)}"
RUN_DIR="tests/artifacts/perf/h1_bench/${RUN_TS}"
CRITERION_HOME_DIR="${REPO_ROOT}/${RUN_DIR}/criterion"
CARGO_TARGET_DIR_DEFAULT="/tmp/rch_target_franken_engine_h1_bench_validate_${USER:-agent}_${RUN_TS}"
EFFECTIVE_CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$CARGO_TARGET_DIR_DEFAULT}"
# RCH rewrites cargo target dirs to worker-local .rch-target-* paths and excludes
# them from sync-back. Keep build artifacts there, but force Criterion results
# into the run artifact directory so postprocessing has synced estimates.
CRIT_DIR="$CRITERION_HOME_DIR"
RCH_EXEC_TIMEOUT_SECONDS="${RCH_EXEC_TIMEOUT_SECONDS:-5400}"
RCH_LOG_DIR="${H1_BENCH_VALIDATE_RCH_LOG_DIR:-tests/artifacts/perf/h1_bench/rch_logs}"
CURRENT_RUSTFLAGS="-C force-frame-pointers=yes -C linker=cc -Clinker-features=-lld"
UNIT_SEPARATOR=$'\037'
CURRENT_ENCODED_RUSTFLAGS="-Cforce-frame-pointers=yes${UNIT_SEPARATOR}-Clinker=cc${UNIT_SEPARATOR}-Clinker-features=-lld"
export RCH_BUILD_TIMEOUT_SEC="$RCH_EXEC_TIMEOUT_SECONDS"

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

mkdir -p "$RUN_DIR" "$CRITERION_HOME_DIR"
echo "[h1.4] run dir: $RUN_DIR"

strip_ansi_file() {
    sed -E 's/\x1B\[[0-9;]*[[:alpha:]]//g' "$1"
}

reject_rch_local_fallback() {
    local log_path="$1"
    if strip_ansi_file "$log_path" | grep -Eiq 'Remote execution failed: .*running locally|Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Failed to query daemon:.*running locally|Dependency preflight blocked remote execution|RCH-E326'; then
        echo "[h1.4] refusing result: rch reported local fallback or dependency-preflight failure" >&2
        return 1
    fi
}

if ! command -v rch >/dev/null 2>&1; then
    echo "[h1.4] rch is required for H1.4 heavy bench validation" >&2
    exit 2
fi

mkdir -p "$RCH_LOG_DIR"
rch_log_path="${RCH_LOG_DIR}/${RUN_TS}.log"
remote_target_dir="$EFFECTIVE_CARGO_TARGET_DIR"
echo "[h1.4] heavy validation must run remotely through rch"
printf '[h1.4] probe command: env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RCH_REQUIRE_REMOTE=1 RCH_BUILD_TIMEOUT_SEC=%q rch diagnose --dry-run --json -- env -u RUSTFLAGS RCH_CARGO_WRAPPER_BYPASS=1 CRITERION_HOME=%q CARGO_ENCODED_RUSTFLAGS=%q CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=%q %q bench --bench hot_paths -- --save-baseline post_h1 %q\n' \
    "$RCH_BUILD_TIMEOUT_SEC" \
    "$CRITERION_HOME_DIR" \
    "$CURRENT_ENCODED_RUSTFLAGS" \
    "$remote_target_dir" \
    "${CARGO:-/home/ubuntu/.cargo/bin/cargo}" \
    "$GROUP"

# The probe proves the exact heavy command is classified as cargo_bench and
# selected for remote execution before any benchmark work starts.
if ! env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS \
    RCH_REQUIRE_REMOTE=1 \
    RCH_BUILD_TIMEOUT_SEC="$RCH_EXEC_TIMEOUT_SECONDS" \
    rch diagnose --dry-run --json -- \
    env -u RUSTFLAGS \
    RCH_CARGO_WRAPPER_BYPASS=1 \
    CRITERION_HOME="$CRITERION_HOME_DIR" \
    CARGO_ENCODED_RUSTFLAGS="$CURRENT_ENCODED_RUSTFLAGS" \
    CARGO_INCREMENTAL=0 \
    CARGO_TARGET_DIR="${remote_target_dir}" \
    "${CARGO:-/home/ubuntu/.cargo/bin/cargo}" bench --bench hot_paths -- \
    --save-baseline post_h1 "$GROUP" \
    >"$RUN_DIR/rch_dry_run.json"; then
    echo "[h1.4] rch dry-run rejected the hot_paths bench; see $RUN_DIR/rch_dry_run.json" >&2
    exit 1
fi
python3 - "$RUN_DIR/rch_dry_run.json" <<'PYRCHDRY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    report = json.load(f)

dry_run = report.get("data", {}).get("dry_run", {})
classification = report.get("data", {}).get("classification", {})
if dry_run.get("would_offload") is not True:
    reason = dry_run.get("reason") or classification.get("reason") or "unknown"
    raise SystemExit(f"rch dry-run would not offload hot_paths bench: {reason}")
PYRCHDRY

echo "[h1.4] remote cargo bench command:" | tee "$rch_log_path"
printf 'env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS RCH_REQUIRE_REMOTE=1 RCH_BUILD_TIMEOUT_SEC=%q timeout %q rch exec -- env -u RUSTFLAGS RCH_CARGO_WRAPPER_BYPASS=1 CRITERION_HOME=%q CARGO_ENCODED_RUSTFLAGS=%q CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=%q %q bench --bench hot_paths -- --save-baseline post_h1 %q\n' \
    "$RCH_EXEC_TIMEOUT_SECONDS" \
    "$RCH_EXEC_TIMEOUT_SECONDS" \
    "$CRITERION_HOME_DIR" \
    "$CURRENT_ENCODED_RUSTFLAGS" \
    "$remote_target_dir" \
    "${CARGO:-/home/ubuntu/.cargo/bin/cargo}" \
    "$GROUP" \
    | tee -a "$rch_log_path"

run_status=0
if ! env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS \
    RCH_REQUIRE_REMOTE=1 \
    RCH_BUILD_TIMEOUT_SEC="$RCH_EXEC_TIMEOUT_SECONDS" \
    timeout "$RCH_EXEC_TIMEOUT_SECONDS" \
    rch exec -- \
    env -u RUSTFLAGS \
    RCH_CARGO_WRAPPER_BYPASS=1 \
    CRITERION_HOME="$CRITERION_HOME_DIR" \
    CARGO_ENCODED_RUSTFLAGS="$CURRENT_ENCODED_RUSTFLAGS" \
    CARGO_INCREMENTAL=0 \
    CARGO_TARGET_DIR="${remote_target_dir}" \
    "${CARGO:-/home/ubuntu/.cargo/bin/cargo}" bench --bench hot_paths -- \
    --save-baseline post_h1 "$GROUP" \
    2>&1 | tee "$RUN_DIR/bench_output.txt" | tee -a "$rch_log_path"; then
    run_status=1
fi

if ! reject_rch_local_fallback "$rch_log_path"; then
    exit 1
fi
if [[ "$run_status" != "0" ]]; then
    exit "$run_status"
fi
if [[ ! -s "$CRIT_DIR/$GROUP/$TARGET_BENCH/post_h1/estimates.json" ]]; then
    echo "[h1.4] missing synced Criterion estimates under $CRIT_DIR" >&2
    echo "[h1.4] rch should sync CRITERION_HOME criterion/** artifacts for cargo bench; treat this as an artifact-sync failure" >&2
    exit 1
fi
echo "[h1.4] using Criterion output synced back from rch Criterion home: $CRIT_DIR"

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

{
    echo "# PERF-H1.4 computed pass1 comparison"
    echo
    echo "Remote-only mode submits cargo bench directly through rch, so this file"
    echo "records the authoritative computed comparison from synced Criterion"
    echo "estimates instead of running the benchmark binary locally for Criterion's"
    echo "interactive --baseline diff."
} >"$RUN_DIR/criterion_diff_pass1.txt"

# ---------------------------------------------------------------------------
# 5. Fingerprint for this run.
# ---------------------------------------------------------------------------
python3 - "$RUN_DIR" "${RUN_DIR}/rch_dry_run.json" "$rch_log_path" "$remote_target_dir" "$CRITERION_HOME_DIR" "$CURRENT_RUSTFLAGS" "$CURRENT_ENCODED_RUSTFLAGS" <<'PYFP'
import json, os, subprocess, sys, time, platform
(
    run_dir,
    rch_dry_run_path,
    rch_log_path,
    cargo_target_dir,
    criterion_home,
    current_rustflags,
    current_encoded_rustflags,
) = sys.argv[1:8]
def sh(*a):
    try:
        return subprocess.check_output(a, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return ""

def load_rch_dry_run(path):
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            report = json.load(f)
    except Exception:
        return {"path": path, "parse_error": True}
    data = report.get("data", {})
    classification = data.get("classification", {})
    dry_run = data.get("dry_run", {})
    worker_selection = data.get("worker_selection", {})
    return {
        "path": path,
        "command": data.get("command"),
        "normalized_command": data.get("normalized_command"),
        "classification_kind": classification.get("kind"),
        "classification_confidence": classification.get("confidence"),
        "would_offload": dry_run.get("would_offload"),
        "worker": worker_selection.get("worker"),
        "reason": dry_run.get("reason") or worker_selection.get("reason"),
        "daemon": data.get("daemon", {}),
        "local_capabilities": data.get("local_capabilities", {}),
    }

host_scope = "local_postprocess_host"
fp = {
    "run_id": f"{int(time.time())}_{int(time.time()*1e6)%1000000}",
    "captured_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "git_sha": sh("git", "rev-parse", "HEAD"),
    "git_dirty": bool(sh("git", "status", "--porcelain")),
    "bead": "PERF-H1.4 (bd-o4cbn.1.4)",
    "baseline_ref": "20260520T214829Z-prof-pass1",
    "execution": {
        "mode": "rch_remote",
        "cargo_target_dir": cargo_target_dir,
        "criterion_home": criterion_home,
        "build_timeout_sec": os.environ.get("RCH_BUILD_TIMEOUT_SEC", ""),
        "rch_log_path": rch_log_path,
        "rch_dry_run": load_rch_dry_run(rch_dry_run_path),
        "remote_fingerprint_note": (
            "hardware/toolchain below describe the local post-processing host; "
            "remote worker selection/classification evidence is in execution.rch_dry_run "
            "and the rch log"
        ),
    },
    "hardware": {
        "scope": host_scope,
        "cpu_model": next((l.split(":",1)[1].strip() for l in open("/proc/cpuinfo")
                           if l.startswith("model name")), ""),
        "kernel": platform.release(),
    },
    "toolchain": {"scope": host_scope, "rustc": sh("rustc", "--version"), "python": platform.python_version()},
    "build_flags": {
        "RUSTFLAGS": None,
        "RUSTFLAGS_SEMANTICS": current_rustflags,
        "CARGO_ENCODED_RUSTFLAGS": current_encoded_rustflags,
        "CARGO_INCREMENTAL": "0",
    },
    "build_provenance": {
        "status": "executed_build_command",
        "effective_channel": "CARGO_ENCODED_RUSTFLAGS",
        "note": "RUSTFLAGS was explicitly unset in both the rch client and remote command",
    },
}
json.dump(fp, open(f"{run_dir}/fingerprint.json", "w"), indent=2)
PYFP

# ---------------------------------------------------------------------------
# 6. Authoritative verdict: compare post_h1 estimates vs pass1 estimates,
#    write events.jsonl + summary.md, copy target post estimates, set exit code.
# ---------------------------------------------------------------------------
set +e
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

# The string-clone delta was attributed in bd-o4cbn.15 to the system->mimalloc
# allocator transition and measurement conditions, not to H1. Report it so the
# table stays honest, but do not fail this H1-specific gate on that known drift.
KNOWN_REGRESSIONS = {"baseline_value_string_clone": "bd-o4cbn.15"}

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
        known_regression = regressed and fn in KNOWN_REGRESSIONS
        verdict = "pass" if known_regression or not regressed else "fail"
        if regressed and not known_regression:
            all_pass = False
        note = ("within-CI" if within else
                ("FASTER(ok)" if post["mean"] < base["lo"] else
                 f"KNOWN-REGRESSION ({KNOWN_REGRESSIONS[fn]})" if known_regression
                 else "REGRESSED"))
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

# computed diff artifact
with open(os.path.join(run_dir, "criterion_diff_pass1.txt"), "a") as f:
    f.write("\n## Computed Target Comparison\n\n")
    for fn, base, post, delta_pct, note in rows:
        if fn == target:
            f.write(f"{group}/{fn}\n")
            f.write(f"  pass1 mean: {base['mean']:.1f} ns\n")
            f.write(f"  post_h1 mean: {post['mean']:.1f} ns\n")
            f.write(f"  delta: {delta_pct:+.2f}%\n")
            f.write(f"  post_h1 CI95: [{post['lo']:.1f}, {post['hi']:.1f}] ns\n")
            f.write(f"  verdict: {note}\n")

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
    if KNOWN_REGRESSIONS:
        known = ", ".join(f"{name} ({bead})" for name, bead in KNOWN_REGRESSIONS.items())
        f.write(f"- known regression exclusions: {known}; reported but excluded from "
                "the H1-specific no-regression gate.\n")
    f.write("- code-drift caveat: frozen-pass1 comparisons do not replace the "
            "same-day/same-allocator endpoint audit in bd-bwztz.\n")

print(f"[h1.4] target drop = {target_drop_pct:.2f}%  overall = "
      f"{'PASS' if all_pass else 'FAIL'}")
sys.exit(0 if all_pass else 1)
PYVERDICT
VERDICT_RC=$?
set -e

echo "[h1.4] artifacts written to $RUN_DIR"
ls -1 "$RUN_DIR"
exit $VERDICT_RC
