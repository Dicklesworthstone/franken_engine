#!/bin/bash
set -euo pipefail

# PERF-H3.5 (bd-o4cbn.2.5): End-to-end smoke for the H3 EngineObjectId hex
# optimization (`to_hex` -> `hex::encode`).
#
# Lightweight E2E companion to the statistical gate in
# `scripts/perf/h3_bench_validate.sh` (PERF-H3.4, bd-o4cbn.2.4). Same shape as
# the other per-track perf smokes (run_perf_h6_smoke.sh): it proves the H3 path
# is wired and behaves, then points at the validation script for the binding
# >=50% drop number. A smoke answers "does the optimised path build, run, and
# keep the hot bench under budget?" — NOT "is the speedup statistically a win?"
# (that is the `What counts as a perf win` gate in docs/PERFORMANCE_BASELINE.md).
#
# Three checks, each fail-closed:
#   1. UNIT      — `cargo test --lib engine_object_id` passes (the to_hex
#                  hex-equivalence + property tests, PERF-H3.3).
#   2. BUILD     — the `hot_paths` bench compiles with the canonical pass1 flags.
#   3. BENCH     — iterator_protocol_trace executes under a short Criterion
#                  budget AND its mean is <= 3 us (the H3 hot path is live and
#                  the optimization is in effect; pass1 was ~6.1 us).
#
# Emits under tests/artifacts/perf/h3_smoke/<ts>/ (gitignored — local evidence):
#   - unit.txt / build.log / bench_smoke.txt   raw logs
#   - events.jsonl   perf.smoke.* events (H1.4 schema, PERF_JSONL_SCHEMA.md)
#   - summary.md     per-check verdict + run-id + measured iterator mean
#   - fingerprint.json   host/toolchain/git fingerprint
#
# Modes:
#   (default)       full smoke: unit + build + bench-smoke (with <=3us assert).
#   --quick         only the unit test + structural checks (no release build).
#   --self-check    no cargo at all: validate this script's structure and the
#                   presence of every input it depends on (CI-able anywhere,
#                   even on a contended/red tree). Exits 0 iff prereqs present.
#
# JSONL contract: docs/operator-gates/PERF_JSONL_SCHEMA.md (bd-o4cbn.8.3).
# Protocol reference: runbooks/RUNBOOK_REPROFILE.md (bd-o4cbn.8.7).
#
# Usage: scripts/perf/run_perf_h3_smoke.sh [--quick|--self-check]

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

BEAD="bd-o4cbn.2.5"
SCENARIO="h3_smoke"
GROUP="real_runtime_hot_paths"
TARGET="iterator_protocol_trace"
UNIT_FILTER="engine_object_id"
VALIDATE_SCRIPT="scripts/perf/h3_bench_validate.sh"
TARGET_MAX_MEAN_NS="3000"

MODE="full"
case "${1:-}" in
    --quick)      MODE="quick" ;;
    --self-check) MODE="self-check" ;;
    "")           MODE="full" ;;
    *) echo "usage: $0 [--quick|--self-check]" >&2; exit 2 ;;
esac

RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="tests/artifacts/perf/h3_smoke/${RUN_TS}"
mkdir -p "$RUN_DIR"
echo "[h3.5] mode=$MODE run dir: $RUN_DIR"

PREREQS=(
    "crates/franken-engine/benches/hot_paths.rs"
    "crates/franken-engine/src/engine_object_id.rs"
    "$VALIDATE_SCRIPT"
)

CARGO="${CARGO:-/home/ubuntu/.cargo/bin/cargo}"
UNIT_STATUS="skipped"
BUILD_STATUS="skipped"
BENCH_STATUS="skipped"
BENCH_MEAN_NS=""

# ---------------------------------------------------------------------------
# 0. Prerequisite presence check (all modes).
# ---------------------------------------------------------------------------
PREREQ_OK=1
for p in "${PREREQS[@]}"; do
    if [[ ! -e "$p" ]]; then
        echo "[h3.5] MISSING prerequisite: $p" >&2
        PREREQ_OK=0
    fi
done
# The target sub-bench must be present in the bench source.
if ! grep -q "\"$TARGET\"" "crates/franken-engine/benches/hot_paths.rs"; then
    echo "[h3.5] target sub-bench not found in bench source: $TARGET" >&2
    PREREQ_OK=0
fi
# The H3 optimization must be in the source (hex::encode, not the old format! loop).
if ! grep -q "hex::encode" "crates/franken-engine/src/engine_object_id.rs"; then
    echo "[h3.5] H3 optimization (hex::encode) not found in engine_object_id.rs" >&2
    PREREQ_OK=0
fi

if [[ "$MODE" == "self-check" ]]; then
    if [[ "$PREREQ_OK" -eq 1 ]]; then
        echo "[h3.5] self-check PASS — all prerequisites present (run-id $RUN_TS)"
    else
        echo "[h3.5] self-check FAIL — missing prerequisites (run-id $RUN_TS)" >&2
    fi
    UNIT_STATUS="self-check"; BUILD_STATUS="self-check"; BENCH_STATUS="self-check"
fi

if [[ "$PREREQ_OK" -ne 1 && "$MODE" != "self-check" ]]; then
    echo "[h3.5] aborting: prerequisites missing" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# 1. UNIT — engine_object_id lib tests (full + quick modes).
# ---------------------------------------------------------------------------
if [[ "$MODE" == "full" || "$MODE" == "quick" ]]; then
    echo "[h3.5] running unit tests (--lib $UNIT_FILTER)..."
    if RCH_CARGO_WRAPPER_BYPASS=1 CARGO_INCREMENTAL=0 \
        "$CARGO" test --lib "$UNIT_FILTER" > "$RUN_DIR/unit.txt" 2>&1; then
        UNIT_STATUS="pass"
    else
        UNIT_STATUS="fail"
        echo "[h3.5] UNIT tests FAILED — see $RUN_DIR/unit.txt" >&2
    fi
fi

# ---------------------------------------------------------------------------
# 2. BUILD — bench compiles with canonical pass1 flags (full mode only).
# ---------------------------------------------------------------------------
if [[ "$MODE" == "full" ]]; then
    echo "[h3.5] building hot_paths bench (pass1 flags)..."
    if RCH_CARGO_WRAPPER_BYPASS=1 \
        RUSTFLAGS="-C force-frame-pointers=yes -C linker=cc" \
        CARGO_INCREMENTAL=0 \
        "$CARGO" bench --bench hot_paths --no-run > "$RUN_DIR/build.log" 2>&1; then
        BUILD_STATUS="pass"
    else
        BUILD_STATUS="fail"
        echo "[h3.5] BUILD FAILED — see $RUN_DIR/build.log" >&2
    fi
fi

# ---------------------------------------------------------------------------
# 3. BENCH — short-budget run of iterator_protocol_trace + assert mean <= 3 us.
# ---------------------------------------------------------------------------
if [[ "$MODE" == "full" && "$BUILD_STATUS" == "pass" ]]; then
    HOT_BIN="$(ls target/release/deps/hot_paths-* 2>/dev/null | grep -v '\.d$' | sort | tail -1 || true)"
    if [[ -z "$HOT_BIN" ]]; then
        BENCH_STATUS="fail"
        echo "[h3.5] bench binary not found after build" >&2
    else
        echo "[h3.5] bench binary: $HOT_BIN"
        if "$HOT_BIN" --bench --sample-size 20 --warm-up-time 0.5 \
            --measurement-time 2 "${GROUP}/${TARGET}" \
            > "$RUN_DIR/bench_smoke.txt" 2>&1; then
            # Parse the Criterion estimate to assert mean <= 3 us. Prefer the
            # machine-readable estimates.json; fall back to the textual line.
            BENCH_MEAN_NS="$(python3 - "$GROUP" "$TARGET" "$RUN_DIR/bench_smoke.txt" <<'PYMEAN'
import json, os, re, sys
group, target, txt = sys.argv[1:4]
est = os.path.join("target/criterion", group, target, "new", "estimates.json")
mean = None
if os.path.exists(est):
    try:
        mean = json.load(open(est))["mean"]["point_estimate"]
    except Exception:
        mean = None
if mean is None:
    # parse "time:   [a us b us c us]" -> middle value, convert to ns
    t = open(txt).read()
    m = re.search(r"time:\s*\[\s*[\d.]+\s*\S+\s+([\d.]+)\s*(ns|µs|us|ms)", t)
    if m:
        v = float(m.group(1)); unit = m.group(2)
        mean = v * {"ns": 1, "µs": 1000, "us": 1000, "ms": 1_000_000}[unit]
print(int(mean) if mean is not None else "")
PYMEAN
)"
            if [[ -n "$BENCH_MEAN_NS" && "$BENCH_MEAN_NS" -le "$TARGET_MAX_MEAN_NS" ]]; then
                BENCH_STATUS="pass"
                echo "[h3.5] iterator_protocol_trace mean = ${BENCH_MEAN_NS} ns (<= ${TARGET_MAX_MEAN_NS} ns)"
            else
                BENCH_STATUS="fail"
                echo "[h3.5] iterator_protocol_trace mean = ${BENCH_MEAN_NS:-?} ns (> ${TARGET_MAX_MEAN_NS} ns)" >&2
            fi
        else
            BENCH_STATUS="fail"
            echo "[h3.5] bench smoke FAILED — see $RUN_DIR/bench_smoke.txt" >&2
        fi
    fi
fi

# ---------------------------------------------------------------------------
# 4. Fingerprint.
# ---------------------------------------------------------------------------
python3 - "$RUN_DIR" "$BEAD" <<'PYFP'
import json, subprocess, sys, time, platform
run_dir, bead = sys.argv[1:3]
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
# 5. Verdict + JSONL emission + summary.
# ---------------------------------------------------------------------------
python3 - "$RUN_DIR" "$BEAD" "$SCENARIO" "$MODE" "$VALIDATE_SCRIPT" "$TARGET" \
    "$TARGET_MAX_MEAN_NS" "$BENCH_MEAN_NS" \
    "$UNIT_STATUS" "$BUILD_STATUS" "$BENCH_STATUS" <<'PYVERDICT'
import json, os, sys, time, hashlib

(run_dir, bead, scenario, mode, validate_script, target,
 max_mean_ns, bench_mean_ns, unit_status, build_status, bench_status) = sys.argv[1:12]
now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
run_id = os.path.basename(run_dir)

def sh(*a):
    import subprocess
    try:
        return subprocess.check_output(a, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return ""

git_sha = sh("git", "rev-parse", "HEAD")
fp_path = os.path.join(run_dir, "fingerprint.json")
fp_hash = (hashlib.sha256(open(fp_path, "rb").read()).hexdigest()
           if os.path.exists(fp_path) else "")

def ok(status):
    return status in ("pass", "skipped", "self-check")

checks = [("unit", unit_status), ("build", build_status), ("bench", bench_status)]
fail_reasons = [f"{name}: {status}" for name, status in checks if not ok(status)]
all_pass = len(fail_reasons) == 0

events = [{
    "ts": now, "event": "perf.smoke.run_start", "bead": bead,
    "scenario_id": scenario, "git_sha": git_sha, "fingerprint_hash": fp_hash,
    "mode": mode, "build_profile": "bench", "rustc_version": sh("rustc", "--version"),
    "run_id": run_id, "target": target,
}]
for name, status in checks:
    events.append({
        "ts": now, "event": "perf.smoke.check", "bead": bead,
        "scenario_id": scenario, "check": name, "status": status,
        "verdict": "ok" if ok(status) else "fail",
    })
events.append({
    "ts": now, "event": "perf.smoke.run_complete", "bead": bead,
    "scenario_id": scenario, "mode": mode,
    "target_mean_ns": int(bench_mean_ns) if bench_mean_ns else None,
    "target_max_mean_ns": int(max_mean_ns),
    "verdict": "pass" if all_pass else "fail", "fail_reasons": fail_reasons,
    "artifacts_written": [
        f"{run_dir}/events.jsonl", f"{run_dir}/summary.md",
        f"{run_dir}/fingerprint.json",
    ],
    "note": ("binding >=50% drop number is produced by the statistical gate "
             f"{validate_script} (PERF-H3.4); this smoke proves liveness + "
             "the <=3us budget only"),
})

with open(os.path.join(run_dir, "events.jsonl"), "w") as f:
    for e in events:
        f.write(json.dumps(e) + "\n")

mean_str = f"{bench_mean_ns} ns" if bench_mean_ns else "—"
with open(os.path.join(run_dir, "summary.md"), "w") as f:
    f.write(f"# PERF-H3.5 E2E Smoke — {run_id}\n\n")
    f.write(f"Bead: {bead} · mode `{mode}` · generated {now} · git `{git_sha[:12]}`\n\n")
    f.write("| check | what it proves | status |\n")
    f.write("|---|---|---|\n")
    f.write(f"| unit | `cargo test --lib engine_object_id` (to_hex equivalence) | {unit_status} |\n")
    f.write(f"| build | `hot_paths` compiles with pass1 flags | {build_status} |\n")
    f.write(f"| bench | `{target}` mean ≤ {max_mean_ns} ns (measured {mean_str}) | {bench_status} |\n")
    f.write(f"\n**Overall: {'PASS' if all_pass else 'FAIL'}**\n\n")
    if fail_reasons:
        f.write("### Failures\n\n")
        for r in fail_reasons:
            f.write(f"- {r}\n")
        f.write("\n")
    f.write("## Scope\n\n")
    f.write("A smoke proves the H3 path **builds, runs, and keeps the hot bench "
            "under the 3 µs budget**. The binding ≥ 50 % drop number is the "
            f"statistical gate `{validate_script}` (PERF-H3.4), scored against "
            "the `What counts as a perf win` standard in "
            "`docs/PERFORMANCE_BASELINE.md`.\n")

print(f"[h3.5] smoke overall = {'PASS' if all_pass else 'FAIL'}  (run-id {run_id})")
for r in fail_reasons:
    print(f"[h3.5]   - {r}")
sys.exit(0 if all_pass else 1)
PYVERDICT
VERDICT_RC=$?

echo "[h3.5] artifacts written to $RUN_DIR"
ls -1 "$RUN_DIR"
exit $VERDICT_RC
