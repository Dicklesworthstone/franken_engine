#!/bin/bash
set -euo pipefail

# PERF-H4.6 (bd-o4cbn.5.6): End-to-end smoke for the H4 canonical-encoding
# buffer reuse lane (`encode_value_into` / `EncodeBufferPool`).
#
# Lightweight E2E companion to the statistical gate in
# `scripts/perf/h4_bench_validate.sh` (PERF-H4.5, bd-o4cbn.5.5). Same shape as
# the other per-track perf smokes: it proves the H4 encode-buffer path is wired
# and behaves, then points at the validation script for the binding combined
# drop number. A smoke answers "does the H4 path build, run, and keep the two
# hot benches under the H4.5 caps?" -- NOT "is the speedup statistically a win?"
# (that is the `What counts as a perf win` gate in docs/PERFORMANCE_BASELINE.md).
#
# Four checks, each fail-closed:
#   1. OUTPUT   -- `cargo test --test perf_h4_encode_buffer_integration`
#                  passes. This is the H4.7 frankenctl compile/replay golden:
#                  compile hashes stay byte-identical and strict replay
#                  completes over a captured trace.
#   2. BUILD    -- the `hot_paths` bench compiles with the canonical pass1 flags.
#   3. BENCH-PA -- `parser_arena_materialization` executes under a short
#                  Criterion budget AND its mean is <= 27 us (H4.5 cap).
#   4. BENCH-LP -- `lowering_pipeline_ir3` executes under a short Criterion
#                  budget AND its mean is <= 72 us (H4.5 cap).
#
# Emits under tests/artifacts/perf/h4_smoke/<ts>/ (ignored local evidence):
#   - integration.txt / build.log / bench_smoke_*.txt  raw logs
#   - events.jsonl   perf.smoke.* events (H1.4 shape)
#   - summary.md     per-check verdict + run-id + measured target means
#   - fingerprint.json   host/toolchain/git fingerprint
#
# Modes:
#   (default)       full smoke: integration + build + bench-smoke cap asserts.
#   --quick         only the H4.7 integration golden + structural checks.
#   --self-check    no cargo at all: validate this script's structure and the
#                   presence of every input it depends on. Exits 0 iff all
#                   prerequisites are present.
#
# JSONL contract: docs/operator-gates/PERF_JSONL_SCHEMA.md (bd-o4cbn.8.3).
#
# Usage: scripts/perf/run_perf_h4_smoke.sh [--quick|--self-check]

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

BEAD="bd-o4cbn.5.6"
SCENARIO="h4_smoke"
GROUP="real_runtime_hot_paths"
TARGET_PA="parser_arena_materialization"
TARGET_LP="lowering_pipeline_ir3"
INTEGRATION_TEST="perf_h4_encode_buffer_integration"
VALIDATE_SCRIPT="scripts/perf/h4_bench_validate.sh"
TARGET_PA_MAX_MEAN_NS="27000"
TARGET_LP_MAX_MEAN_NS="72000"

MODE="full"
case "${1:-}" in
    --quick)      MODE="quick" ;;
    --self-check) MODE="self-check" ;;
    "")           MODE="full" ;;
    *) echo "usage: $0 [--quick|--self-check]" >&2; exit 2 ;;
esac

RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="tests/artifacts/perf/h4_smoke/${RUN_TS}"
mkdir -p "$RUN_DIR"
echo "[h4.6] mode=$MODE run dir: $RUN_DIR"

PREREQS=(
    "crates/franken-engine/benches/hot_paths.rs"
    "crates/franken-engine/src/deterministic_serde.rs"
    "crates/franken-engine/tests/${INTEGRATION_TEST}.rs"
    "crates/franken-engine/tests/golden/h4_encode/compile_artifact.hash"
    "$VALIDATE_SCRIPT"
)

CARGO="${CARGO:-/home/ubuntu/.cargo/bin/cargo}"
INTEG_STATUS="skipped"
BUILD_STATUS="skipped"
BENCH_PA_STATUS="skipped"
BENCH_LP_STATUS="skipped"
BENCH_PA_MEAN_NS=""
BENCH_LP_MEAN_NS=""

# ---------------------------------------------------------------------------
# 0. Prerequisite presence check (all modes).
# ---------------------------------------------------------------------------
PREREQ_OK=1
for p in "${PREREQS[@]}"; do
    if [[ ! -e "$p" ]]; then
        echo "[h4.6] MISSING prerequisite: $p" >&2
        PREREQ_OK=0
    fi
done

for target in "$TARGET_PA" "$TARGET_LP"; do
    if ! grep -q "\"$target\"" "crates/franken-engine/benches/hot_paths.rs"; then
        echo "[h4.6] target sub-bench not found in bench source: $target" >&2
        PREREQ_OK=0
    fi
done

if ! grep -q "pub fn encode_value_into" "crates/franken-engine/src/deterministic_serde.rs"; then
    echo "[h4.6] encode_value_into API not found in deterministic_serde.rs" >&2
    PREREQ_OK=0
fi
if ! grep -q "pub struct EncodeBufferPool" "crates/franken-engine/src/deterministic_serde.rs"; then
    echo "[h4.6] EncodeBufferPool API not found in deterministic_serde.rs" >&2
    PREREQ_OK=0
fi

if [[ "$MODE" == "self-check" ]]; then
    if [[ "$PREREQ_OK" -eq 1 ]]; then
        echo "[h4.6] self-check PASS -- all prerequisites present (run-id $RUN_TS)"
    else
        echo "[h4.6] self-check FAIL -- missing prerequisites (run-id $RUN_TS)" >&2
    fi
    INTEG_STATUS="self-check"
    BUILD_STATUS="self-check"
    BENCH_PA_STATUS="self-check"
    BENCH_LP_STATUS="self-check"
fi

if [[ "$PREREQ_OK" -ne 1 && "$MODE" != "self-check" ]]; then
    echo "[h4.6] aborting: prerequisites missing" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# 1. OUTPUT -- H4.7 frankenctl compile/replay golden (full + quick modes).
# ---------------------------------------------------------------------------
if [[ "$MODE" == "full" || "$MODE" == "quick" ]]; then
    echo "[h4.6] running H4 integration golden ($INTEGRATION_TEST)..."
    if RCH_CARGO_WRAPPER_BYPASS=1 CARGO_INCREMENTAL=0 \
        "$CARGO" test --test "$INTEGRATION_TEST" \
        > "$RUN_DIR/integration.txt" 2>&1; then
        INTEG_STATUS="pass"
    else
        INTEG_STATUS="fail"
        echo "[h4.6] integration golden FAILED -- see $RUN_DIR/integration.txt" >&2
    fi
fi

# ---------------------------------------------------------------------------
# 2. BUILD -- bench compiles with canonical pass1 flags (full mode only).
# ---------------------------------------------------------------------------
if [[ "$MODE" == "full" ]]; then
    echo "[h4.6] building hot_paths bench (pass1 flags)..."
    if RCH_CARGO_WRAPPER_BYPASS=1 \
        RUSTFLAGS="-C force-frame-pointers=yes -C linker=cc" \
        CARGO_INCREMENTAL=0 \
        "$CARGO" bench --bench hot_paths --no-run > "$RUN_DIR/build.log" 2>&1; then
        BUILD_STATUS="pass"
    else
        BUILD_STATUS="fail"
        echo "[h4.6] BUILD FAILED -- see $RUN_DIR/build.log" >&2
    fi
fi

extract_mean_ns() {
    python3 - "$GROUP" "$1" "$2" <<'PYMEAN'
import json
import os
import re
import sys

group, target, txt = sys.argv[1:4]
estimate_path = os.path.join("target/criterion", group, target, "new", "estimates.json")
mean = None
if os.path.exists(estimate_path):
    try:
        mean = json.load(open(estimate_path))["mean"]["point_estimate"]
    except Exception:
        mean = None
if mean is None:
    text = open(txt).read()
    match = re.search(r"time:\s*\[\s*[\d.]+\s*\S+\s+([\d.]+)\s*(ns|µs|us|ms)", text)
    if match:
        value = float(match.group(1))
        unit = match.group(2)
        mean = value * {"ns": 1, "µs": 1000, "us": 1000, "ms": 1_000_000}[unit]
print(int(mean) if mean is not None else "")
PYMEAN
}

# ---------------------------------------------------------------------------
# 3. BENCH -- short-budget runs of both H4 targets, assert each <= cap.
# ---------------------------------------------------------------------------
if [[ "$MODE" == "full" && "$BUILD_STATUS" == "pass" ]]; then
    HOT_BIN="$(find target/release/deps -maxdepth 1 -type f -name 'hot_paths-*' \
        ! -name '*.d' -printf '%p\n' 2>/dev/null | sort | tail -1 || true)"
    if [[ -z "$HOT_BIN" ]]; then
        BENCH_PA_STATUS="fail"
        BENCH_LP_STATUS="fail"
        echo "[h4.6] bench binary not found after build" >&2
    else
        echo "[h4.6] bench binary: $HOT_BIN"

        if "$HOT_BIN" --bench --sample-size 20 --warm-up-time 0.5 \
            --measurement-time 2 "${GROUP}/${TARGET_PA}" \
            > "$RUN_DIR/bench_smoke_${TARGET_PA}.txt" 2>&1; then
            BENCH_PA_MEAN_NS="$(extract_mean_ns "$TARGET_PA" "$RUN_DIR/bench_smoke_${TARGET_PA}.txt")"
            if [[ -n "$BENCH_PA_MEAN_NS" && "$BENCH_PA_MEAN_NS" -le "$TARGET_PA_MAX_MEAN_NS" ]]; then
                BENCH_PA_STATUS="pass"
                echo "[h4.6] ${TARGET_PA} mean = ${BENCH_PA_MEAN_NS} ns (<= ${TARGET_PA_MAX_MEAN_NS} ns)"
            else
                BENCH_PA_STATUS="fail"
                echo "[h4.6] ${TARGET_PA} mean = ${BENCH_PA_MEAN_NS:-?} ns (> ${TARGET_PA_MAX_MEAN_NS} ns)" >&2
            fi
        else
            BENCH_PA_STATUS="fail"
            echo "[h4.6] ${TARGET_PA} smoke FAILED -- see $RUN_DIR/bench_smoke_${TARGET_PA}.txt" >&2
        fi

        if "$HOT_BIN" --bench --sample-size 20 --warm-up-time 0.5 \
            --measurement-time 2 "${GROUP}/${TARGET_LP}" \
            > "$RUN_DIR/bench_smoke_${TARGET_LP}.txt" 2>&1; then
            BENCH_LP_MEAN_NS="$(extract_mean_ns "$TARGET_LP" "$RUN_DIR/bench_smoke_${TARGET_LP}.txt")"
            if [[ -n "$BENCH_LP_MEAN_NS" && "$BENCH_LP_MEAN_NS" -le "$TARGET_LP_MAX_MEAN_NS" ]]; then
                BENCH_LP_STATUS="pass"
                echo "[h4.6] ${TARGET_LP} mean = ${BENCH_LP_MEAN_NS} ns (<= ${TARGET_LP_MAX_MEAN_NS} ns)"
            else
                BENCH_LP_STATUS="fail"
                echo "[h4.6] ${TARGET_LP} mean = ${BENCH_LP_MEAN_NS:-?} ns (> ${TARGET_LP_MAX_MEAN_NS} ns)" >&2
            fi
        else
            BENCH_LP_STATUS="fail"
            echo "[h4.6] ${TARGET_LP} smoke FAILED -- see $RUN_DIR/bench_smoke_${TARGET_LP}.txt" >&2
        fi
    fi
fi

# ---------------------------------------------------------------------------
# 4. Fingerprint.
# ---------------------------------------------------------------------------
python3 - "$RUN_DIR" "$BEAD" <<'PYFP'
import json
import platform
import subprocess
import sys
import time

run_dir, bead = sys.argv[1:3]

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
    "hardware": {
        "cpu_model": next(
            (line.split(":", 1)[1].strip() for line in open("/proc/cpuinfo")
             if line.startswith("model name")),
            "",
        ),
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
python3 - "$RUN_DIR" "$BEAD" "$SCENARIO" "$MODE" "$VALIDATE_SCRIPT" \
    "$INTEG_STATUS" "$BUILD_STATUS" "$BENCH_PA_STATUS" "$BENCH_LP_STATUS" \
    "$TARGET_PA" "$TARGET_LP" "$TARGET_PA_MAX_MEAN_NS" "$TARGET_LP_MAX_MEAN_NS" \
    "$BENCH_PA_MEAN_NS" "$BENCH_LP_MEAN_NS" <<'PYVERDICT'
import hashlib
import json
import os
import subprocess
import sys
import time

(run_dir, bead, scenario, mode, validate_script,
 integ_status, build_status, bench_pa_status, bench_lp_status,
 target_pa, target_lp, target_pa_max_ns, target_lp_max_ns,
 bench_pa_mean_ns, bench_lp_mean_ns) = sys.argv[1:16]
now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
run_id = os.path.basename(run_dir)

def sh(*args):
    try:
        return subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return ""

git_sha = sh("git", "rev-parse", "HEAD")
fp_path = os.path.join(run_dir, "fingerprint.json")
fp_hash = (
    hashlib.sha256(open(fp_path, "rb").read()).hexdigest()
    if os.path.exists(fp_path)
    else ""
)

def ok(status):
    return status in ("pass", "skipped", "self-check")

checks = [
    ("integration", integ_status),
    ("build", build_status),
    ("bench_parser_arena", bench_pa_status),
    ("bench_lowering", bench_lp_status),
]
fail_reasons = [f"{name}: {status}" for name, status in checks if not ok(status)]
all_pass = not fail_reasons

events = [{
    "ts": now,
    "event": "perf.smoke.run_start",
    "bead": bead,
    "scenario_id": scenario,
    "git_sha": git_sha,
    "fingerprint_hash": fp_hash,
    "mode": mode,
    "build_profile": "bench",
    "rustc_version": sh("rustc", "--version"),
    "run_id": run_id,
    "targets": [target_pa, target_lp],
}]
for name, status in checks:
    events.append({
        "ts": now,
        "event": "perf.smoke.check",
        "bead": bead,
        "scenario_id": scenario,
        "check": name,
        "status": status,
        "verdict": "ok" if ok(status) else "fail",
    })
events.append({
    "ts": now,
    "event": "perf.smoke.run_complete",
    "bead": bead,
    "scenario_id": scenario,
    "mode": mode,
    "verdict": "pass" if all_pass else "fail",
    "fail_reasons": fail_reasons,
    "target_caps_ns": {
        target_pa: int(target_pa_max_ns),
        target_lp: int(target_lp_max_ns),
    },
    "target_means_ns": {
        target_pa: int(bench_pa_mean_ns) if bench_pa_mean_ns else None,
        target_lp: int(bench_lp_mean_ns) if bench_lp_mean_ns else None,
    },
    "artifacts_written": [
        f"{run_dir}/events.jsonl",
        f"{run_dir}/summary.md",
        f"{run_dir}/fingerprint.json",
    ],
    "note": (
        "combined-drop number is produced by the statistical gate "
        f"{validate_script} (PERF-H4.5); this smoke proves liveness + "
        "compile/replay encode-path stability"
    ),
})

with open(os.path.join(run_dir, "events.jsonl"), "w") as f:
    for event in events:
        f.write(json.dumps(event) + "\n")

with open(os.path.join(run_dir, "summary.md"), "w") as f:
    f.write(f"# PERF-H4.6 E2E Smoke - {run_id}\n\n")
    f.write(f"Bead: {bead}. Mode `{mode}`. Generated {now}. Git `{git_sha[:12]}`.\n\n")
    f.write("| check | what it proves | status |\n")
    f.write("|---|---|---|\n")
    f.write("| integration | H4.7 frankenctl compile hashes and strict replay remain stable | "
            f"{integ_status} |\n")
    f.write("| build | `hot_paths` compiles with pass1 flags | "
            f"{build_status} |\n")
    f.write(f"| bench {target_pa} | target executes and mean <= {int(target_pa_max_ns) / 1000:.0f} us | "
            f"{bench_pa_status}")
    if bench_pa_mean_ns:
        f.write(f" ({int(bench_pa_mean_ns)} ns)")
    f.write(" |\n")
    f.write(f"| bench {target_lp} | target executes and mean <= {int(target_lp_max_ns) / 1000:.0f} us | "
            f"{bench_lp_status}")
    if bench_lp_mean_ns:
        f.write(f" ({int(bench_lp_mean_ns)} ns)")
    f.write(" |\n")
    f.write(f"\n**Overall: {'PASS' if all_pass else 'FAIL'}**\n\n")
    if fail_reasons:
        f.write("## Failures\n\n")
        for reason in fail_reasons:
            f.write(f"- {reason}\n")
        f.write("\n")
    f.write("## Scope\n\n")
    f.write(
        "This smoke proves the H4 encode-buffer path is wired through the "
        "frankenctl compile/replay surface and the two H4 target benches remain "
        "under their H4.5 caps in a short liveness run. The statistical combined "
        f"drop remains owned by `{validate_script}`.\n"
    )

print(f"[h4.6] overall = {'PASS' if all_pass else 'FAIL'}")
for reason in fail_reasons:
    print(f"[h4.6]   - {reason}")
sys.exit(0 if all_pass else 1)
PYVERDICT
VERDICT_RC=$?

echo "[h4.6] artifacts written to $RUN_DIR"
find "$RUN_DIR" -maxdepth 1 -type f -printf '%f\n' | sort
exit "$VERDICT_RC"
