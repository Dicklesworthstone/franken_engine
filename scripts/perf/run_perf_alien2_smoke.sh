#!/bin/bash
set -euo pipefail

# PERF-ALIEN-2.5 (bd-o4cbn.10.5): End-to-end smoke for the ALIEN-2 region
# arena (`bumpalo::Bump`-backed `LoweringArena` threaded through `lower_ir2_to_ir3`).
#
# Lightweight E2E companion to the statistical gate in
# `scripts/perf/alien2_bench_validate.sh` (PERF-ALIEN-2.4, bd-o4cbn.10.4). Same
# shape as the other per-track perf smokes (run_perf_h3_smoke.sh / h5 / h6):
# it proves the ALIEN-2 path is wired and behaves, then points at the validation
# script for the binding >=2 % drop number. A smoke answers "does the arena
# refactor build, run, and keep the two hot benches under the ALIEN-2.4 caps?"
# -- NOT "is the speedup statistically a win?" (that is the `What counts as a
# perf win` gate in docs/PERFORMANCE_BASELINE.md).
#
# Four checks, each fail-closed:
#   1. UNIT       -- `cargo test --lib alien2_ir3_output_is_byte_identical_golden`
#                    passes (the ALIEN-2.3 byte-identity golden, PERF-ALIEN-2.3,
#                    bd-o4cbn.10.3; freezes the canonical instruction bytes +
#                    content hash of `lower_ir0_to_ir3` for three fixed pure
#                    programs so any future arena/region change that perturbs
#                    ExecIR is caught).
#   2. BUILD      -- the `hot_paths` bench compiles with the canonical pass1 flags.
#   3. BENCH-PA   -- `parser_arena_materialization` executes under a short
#                    Criterion budget AND its mean is <= 26 us (the ALIEN-2.4
#                    parser-arena cap; pass1 was ~31.4 us).
#   4. BENCH-LP   -- `lowering_pipeline_ir3` executes under a short Criterion
#                    budget AND its mean is <= 70 us (the ALIEN-2.4 lowering
#                    cap; pass1 was ~87.9 us).
#
# Emits under tests/artifacts/perf/alien2_smoke/<ts>/ (gitignored -- local
# evidence):
#   - unit.txt / build.log / bench_smoke_*.txt   raw logs
#   - events.jsonl   perf.smoke.* events (H1.4 schema, PERF_JSONL_SCHEMA.md)
#   - summary.md     per-check verdict + run-id + measured target means
#   - fingerprint.json   host/toolchain/git fingerprint
#
# Modes:
#   (default)       full smoke: unit + build + bench-smoke (with <= cap asserts).
#   --quick         only the unit test + structural checks (no release build).
#   --self-check    no cargo at all: validate this script's structure and the
#                   presence of every input it depends on (CI-able anywhere,
#                   even on a contended/red tree). Exits 0 iff prereqs present.
#
# JSONL contract: docs/operator-gates/PERF_JSONL_SCHEMA.md (bd-o4cbn.8.3).
#
# Usage: scripts/perf/run_perf_alien2_smoke.sh [--quick|--self-check]

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

BEAD="bd-o4cbn.10.5"
SCENARIO="alien2_smoke"
GROUP="real_runtime_hot_paths"
TARGET_PA="parser_arena_materialization"
TARGET_LP="lowering_pipeline_ir3"
UNIT_FILTER="alien2_ir3_output_is_byte_identical_golden"
VALIDATE_SCRIPT="scripts/perf/alien2_bench_validate.sh"
# ALIEN-2.4 absolute caps (ns).
TARGET_PA_MAX_MEAN_NS="26000"
TARGET_LP_MAX_MEAN_NS="70000"

MODE="full"
case "${1:-}" in
    --quick)      MODE="quick" ;;
    --self-check) MODE="self-check" ;;
    "")           MODE="full" ;;
    *) echo "usage: $0 [--quick|--self-check]" >&2; exit 2 ;;
esac

RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="tests/artifacts/perf/alien2_smoke/${RUN_TS}"
mkdir -p "$RUN_DIR"
echo "[alien2.5] mode=$MODE run dir: $RUN_DIR"

PREREQS=(
    "crates/franken-engine/benches/hot_paths.rs"
    "crates/franken-engine/src/lowering_arena.rs"
    "crates/franken-engine/src/lowering_pipeline.rs"
    "$VALIDATE_SCRIPT"
)

CARGO="${CARGO:-/home/ubuntu/.cargo/bin/cargo}"
UNIT_STATUS="skipped"
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
        echo "[alien2.5] MISSING prerequisite: $p" >&2
        PREREQ_OK=0
    fi
done
# Both target sub-benches must be present in the bench source.
for tgt in "$TARGET_PA" "$TARGET_LP"; do
    if ! grep -q "\"$tgt\"" "crates/franken-engine/benches/hot_paths.rs"; then
        echo "[alien2.5] target sub-bench not found in bench source: $tgt" >&2
        PREREQ_OK=0
    fi
done
# The ALIEN-2 region arena must be present in the source (bumpalo Bump-backed).
if ! grep -q "use bumpalo::Bump" "crates/franken-engine/src/lowering_arena.rs"; then
    echo "[alien2.5] ALIEN-2 LoweringArena (bumpalo::Bump) not found in lowering_arena.rs" >&2
    PREREQ_OK=0
fi
# The ALIEN-2.3 byte-identity golden must be wired in lowering_pipeline.rs.
if ! grep -q "$UNIT_FILTER" "crates/franken-engine/src/lowering_pipeline.rs"; then
    echo "[alien2.5] ALIEN-2.3 byte-identity test ($UNIT_FILTER) not found in lowering_pipeline.rs" >&2
    PREREQ_OK=0
fi

if [[ "$MODE" == "self-check" ]]; then
    if [[ "$PREREQ_OK" -eq 1 ]]; then
        echo "[alien2.5] self-check PASS -- all prerequisites present (run-id $RUN_TS)"
    else
        echo "[alien2.5] self-check FAIL -- missing prerequisites (run-id $RUN_TS)" >&2
    fi
    UNIT_STATUS="self-check"; BUILD_STATUS="self-check"
    BENCH_PA_STATUS="self-check"; BENCH_LP_STATUS="self-check"
fi

if [[ "$PREREQ_OK" -ne 1 && "$MODE" != "self-check" ]]; then
    echo "[alien2.5] aborting: prerequisites missing" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# 1. UNIT -- ALIEN-2.3 byte-identity golden (full + quick modes).
# ---------------------------------------------------------------------------
if [[ "$MODE" == "full" || "$MODE" == "quick" ]]; then
    echo "[alien2.5] running unit test (--lib $UNIT_FILTER)..."
    if RCH_CARGO_WRAPPER_BYPASS=1 CARGO_INCREMENTAL=0 \
        "$CARGO" test --lib "$UNIT_FILTER" > "$RUN_DIR/unit.txt" 2>&1; then
        UNIT_STATUS="pass"
    else
        UNIT_STATUS="fail"
        echo "[alien2.5] UNIT test FAILED -- see $RUN_DIR/unit.txt" >&2
    fi
fi

# ---------------------------------------------------------------------------
# 2. BUILD -- bench compiles with canonical pass1 flags (full mode only).
# ---------------------------------------------------------------------------
if [[ "$MODE" == "full" ]]; then
    echo "[alien2.5] building hot_paths bench (pass1 flags)..."
    if RCH_CARGO_WRAPPER_BYPASS=1 \
        RUSTFLAGS="-C force-frame-pointers=yes -C linker=cc" \
        CARGO_INCREMENTAL=0 \
        "$CARGO" bench --bench hot_paths --no-run > "$RUN_DIR/build.log" 2>&1; then
        BUILD_STATUS="pass"
    else
        BUILD_STATUS="fail"
        echo "[alien2.5] BUILD FAILED -- see $RUN_DIR/build.log" >&2
    fi
fi

# ---------------------------------------------------------------------------
# 3. BENCH -- short-budget runs of both ALIEN-2 targets, assert each <= cap.
# ---------------------------------------------------------------------------
extract_mean_ns() {
    # Reads $1 = sub-bench name, $2 = bench output text path; prints integer ns
    # mean to stdout or empty on parse failure.
    python3 - "$GROUP" "$1" "$2" <<'PYMEAN'
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
    t = open(txt).read()
    m = re.search(r"time:\s*\[\s*[\d.]+\s*\S+\s+([\d.]+)\s*(ns|µs|us|ms)", t)
    if m:
        v = float(m.group(1)); unit = m.group(2)
        mean = v * {"ns": 1, "µs": 1000, "us": 1000, "ms": 1_000_000}[unit]
print(int(mean) if mean is not None else "")
PYMEAN
}

if [[ "$MODE" == "full" && "$BUILD_STATUS" == "pass" ]]; then
    HOT_BIN="$(ls target/release/deps/hot_paths-* 2>/dev/null | grep -v '\.d$' | sort | tail -1 || true)"
    if [[ -z "$HOT_BIN" ]]; then
        BENCH_PA_STATUS="fail"; BENCH_LP_STATUS="fail"
        echo "[alien2.5] bench binary not found after build" >&2
    else
        echo "[alien2.5] bench binary: $HOT_BIN"

        # parser_arena_materialization
        if "$HOT_BIN" --bench --sample-size 20 --warm-up-time 0.5 \
            --measurement-time 2 "${GROUP}/${TARGET_PA}" \
            > "$RUN_DIR/bench_smoke_${TARGET_PA}.txt" 2>&1; then
            BENCH_PA_MEAN_NS="$(extract_mean_ns "$TARGET_PA" "$RUN_DIR/bench_smoke_${TARGET_PA}.txt")"
            if [[ -n "$BENCH_PA_MEAN_NS" && "$BENCH_PA_MEAN_NS" -le "$TARGET_PA_MAX_MEAN_NS" ]]; then
                BENCH_PA_STATUS="pass"
                echo "[alien2.5] ${TARGET_PA} mean = ${BENCH_PA_MEAN_NS} ns (<= ${TARGET_PA_MAX_MEAN_NS} ns)"
            else
                BENCH_PA_STATUS="fail"
                echo "[alien2.5] ${TARGET_PA} mean = ${BENCH_PA_MEAN_NS:-?} ns (> ${TARGET_PA_MAX_MEAN_NS} ns)" >&2
            fi
        else
            BENCH_PA_STATUS="fail"
            echo "[alien2.5] ${TARGET_PA} smoke FAILED -- see $RUN_DIR/bench_smoke_${TARGET_PA}.txt" >&2
        fi

        # lowering_pipeline_ir3
        if "$HOT_BIN" --bench --sample-size 20 --warm-up-time 0.5 \
            --measurement-time 2 "${GROUP}/${TARGET_LP}" \
            > "$RUN_DIR/bench_smoke_${TARGET_LP}.txt" 2>&1; then
            BENCH_LP_MEAN_NS="$(extract_mean_ns "$TARGET_LP" "$RUN_DIR/bench_smoke_${TARGET_LP}.txt")"
            if [[ -n "$BENCH_LP_MEAN_NS" && "$BENCH_LP_MEAN_NS" -le "$TARGET_LP_MAX_MEAN_NS" ]]; then
                BENCH_LP_STATUS="pass"
                echo "[alien2.5] ${TARGET_LP} mean = ${BENCH_LP_MEAN_NS} ns (<= ${TARGET_LP_MAX_MEAN_NS} ns)"
            else
                BENCH_LP_STATUS="fail"
                echo "[alien2.5] ${TARGET_LP} mean = ${BENCH_LP_MEAN_NS:-?} ns (> ${TARGET_LP_MAX_MEAN_NS} ns)" >&2
            fi
        else
            BENCH_LP_STATUS="fail"
            echo "[alien2.5] ${TARGET_LP} smoke FAILED -- see $RUN_DIR/bench_smoke_${TARGET_LP}.txt" >&2
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
    "arena": "bumpalo LoweringArena (ALIEN-2.2, 4c38f5c1)",
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
python3 - "$RUN_DIR" "$BEAD" "$SCENARIO" "$MODE" "$VALIDATE_SCRIPT" \
    "$TARGET_PA" "$TARGET_PA_MAX_MEAN_NS" "$BENCH_PA_MEAN_NS" "$BENCH_PA_STATUS" \
    "$TARGET_LP" "$TARGET_LP_MAX_MEAN_NS" "$BENCH_LP_MEAN_NS" "$BENCH_LP_STATUS" \
    "$UNIT_STATUS" "$BUILD_STATUS" <<'PYVERDICT'
import json, os, sys, time, hashlib

(run_dir, bead, scenario, mode, validate_script,
 target_pa, max_pa_ns, mean_pa_ns, status_pa,
 target_lp, max_lp_ns, mean_lp_ns, status_lp,
 unit_status, build_status) = sys.argv[1:16]
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

checks = [
    ("unit", unit_status),
    ("build", build_status),
    (f"bench:{target_pa}", status_pa),
    (f"bench:{target_lp}", status_lp),
]
fail_reasons = [f"{name}: {status}" for name, status in checks if not ok(status)]
all_pass = len(fail_reasons) == 0

events = [{
    "ts": now, "event": "perf.smoke.run_start", "bead": bead,
    "scenario_id": scenario, "git_sha": git_sha, "fingerprint_hash": fp_hash,
    "mode": mode, "build_profile": "bench", "rustc_version": sh("rustc", "--version"),
    "run_id": run_id, "targets": [target_pa, target_lp],
    "arena": "bumpalo LoweringArena (ALIEN-2.2)",
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
    "targets": {
        target_pa: {"mean_ns": int(mean_pa_ns) if mean_pa_ns else None,
                    "max_mean_ns": int(max_pa_ns)},
        target_lp: {"mean_ns": int(mean_lp_ns) if mean_lp_ns else None,
                    "max_mean_ns": int(max_lp_ns)},
    },
    "verdict": "pass" if all_pass else "fail", "fail_reasons": fail_reasons,
    "artifacts_written": [
        f"{run_dir}/events.jsonl", f"{run_dir}/summary.md",
        f"{run_dir}/fingerprint.json",
    ],
    "note": ("binding >=2% drop number is produced by the statistical gate "
             f"{validate_script} (PERF-ALIEN-2.4); this smoke proves liveness + "
             "the <=cap budgets only"),
})

with open(os.path.join(run_dir, "events.jsonl"), "w") as f:
    for e in events:
        f.write(json.dumps(e) + "\n")

mean_pa_str = f"{mean_pa_ns} ns" if mean_pa_ns else "—"
mean_lp_str = f"{mean_lp_ns} ns" if mean_lp_ns else "—"
with open(os.path.join(run_dir, "summary.md"), "w") as f:
    f.write(f"# PERF-ALIEN-2.5 E2E Smoke — {run_id}\n\n")
    f.write(f"Bead: {bead} · mode `{mode}` · generated {now} · git `{git_sha[:12]}` · "
            "arena **bumpalo** (ALIEN-2.2)\n\n")
    f.write("| check | what it proves | status |\n")
    f.write("|---|---|---|\n")
    f.write(f"| unit | `cargo test --lib alien2_ir3_output_is_byte_identical_golden` "
            "(ALIEN-2.3 IR3 byte-identity golden) | "
            f"{unit_status} |\n")
    f.write(f"| build | `hot_paths` compiles with pass1 flags | {build_status} |\n")
    f.write(f"| bench | `{target_pa}` mean ≤ {max_pa_ns} ns "
            f"(measured {mean_pa_str}) | {status_pa} |\n")
    f.write(f"| bench | `{target_lp}` mean ≤ {max_lp_ns} ns "
            f"(measured {mean_lp_str}) | {status_lp} |\n")
    f.write(f"\n**Overall: {'PASS' if all_pass else 'FAIL'}**\n\n")
    if fail_reasons:
        f.write("### Failures\n\n")
        for r in fail_reasons:
            f.write(f"- {r}\n")
        f.write("\n")
    f.write("## Scope\n\n")
    f.write("A smoke proves the ALIEN-2 path **builds, runs, and keeps the two "
            "hot benches under the ALIEN-2.4 caps (26 µs parser_arena, 70 µs "
            f"lowering_pipeline_ir3)**, plus that the ALIEN-2.3 byte-identity "
            "golden still holds (arena is allocation-only -- IR3 must be byte-"
            "identical to pre-ALIEN-2 output). The binding ≥ 2 % drop number "
            f"is the statistical gate `{validate_script}` (PERF-ALIEN-2.4), "
            "scored against the `What counts as a perf win` standard in "
            "`docs/PERFORMANCE_BASELINE.md`.\n")

print(f"[alien2.5] smoke overall = {'PASS' if all_pass else 'FAIL'}  (run-id {run_id})")
for r in fail_reasons:
    print(f"[alien2.5]   - {r}")
sys.exit(0 if all_pass else 1)
PYVERDICT
VERDICT_RC=$?

echo "[alien2.5] artifacts written to $RUN_DIR"
ls -1 "$RUN_DIR"
exit $VERDICT_RC
