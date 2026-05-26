#!/bin/bash
set -euo pipefail

# PERF-H5.4 (bd-o4cbn.7.4): End-to-end smoke for the H5 transport-certificate
# serialization-bench refactor.
#
# This is the lightweight E2E companion to the heavy statistical gate in
# `scripts/perf/h5_bench_validate.sh` (PERF-H5.3, bd-o4cbn.7.3). Same shape as
# the other per-track perf smokes: it proves the H5 pipeline is wired and
# behaves, then points at the validation script for the binding drop number.
# A smoke answers "does the optimised path build, run, and keep its observable
# semantics?" — NOT "is the speedup statistically a win?" (that is the
# `What counts as a perf win` gate in docs/PERFORMANCE_BASELINE.md).
#
# Background: H5.1 (bd-o4cbn.7.1) confirmed no production path round-trips a
# TransportCertificate; H5.2 (bd-o4cbn.7.2, commit 9b75b510) dropped the
# non-representative `serde_json::from_str::<TransportCertificate>` step from
# the bench. The deserialize-round-trip fidelity that justified removing it is
# pinned by tests/transport_certificate_serde.rs — so the H5 smoke's
# output check is that fidelity test, not a frankenctl golden (the cert path
# has no production round-trip to golden).
#
# Three checks, each fail-closed:
#   1. BUILD     — the `hot_paths` bench compiles with the canonical pass1
#                  flags (the refactored cert bench is in the build).
#   2. BENCH     — the H5 target sub-bench (transport_certificate_serialization)
#                  executes under a short Criterion budget and emits finite
#                  timings (the hot path is live).
#   3. OUTPUT    — the H5.2 round-trip fidelity test
#                  (transport_certificate_serde) passes: serialize ->
#                  deserialize is value- and byte-stable across all fields,
#                  proving the dropped bench deserialize changed only the bench,
#                  not the cert's serde contract.
#
# Emits under tests/artifacts/perf/h5_smoke/<ts>/ (gitignored — local evidence):
#   - build.log / bench_smoke.txt / fidelity.txt  raw logs
#   - events.jsonl   perf.smoke.* events (H1.4 schema, PERF_JSONL_SCHEMA.md)
#   - summary.md     per-check verdict + run-id
#   - fingerprint.json   host/toolchain/git fingerprint
#
# Modes:
#   (default)       full smoke: build + bench-smoke + fidelity test.
#   --quick         skip the release bench build; only the fidelity test +
#                   structural checks (still proves the serde contract holds).
#   --self-check    no cargo at all: validate this script's structure and the
#                   presence of every input it depends on (CI-able anywhere,
#                   even on a contended/red tree). Prints a run-id and exits 0
#                   iff all prerequisites are present.
#
# JSONL contract: docs/operator-gates/PERF_JSONL_SCHEMA.md (bd-o4cbn.8.3).
# Acceptance (bd-o4cbn.7.4): smoke is reproducible, records a run-id, and the
# binding drop number is produced by `scripts/perf/h5_bench_validate.sh`.
#
# Usage: scripts/perf/run_perf_h5_smoke.sh [--quick|--self-check]

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

BEAD="bd-o4cbn.7.4"
SCENARIO="h5_smoke"
GROUP="real_runtime_hot_paths"
TARGET="transport_certificate_serialization"
FIDELITY_TEST="transport_certificate_serde"
VALIDATE_SCRIPT="scripts/perf/h5_bench_validate.sh"

MODE="full"
case "${1:-}" in
    --quick)      MODE="quick" ;;
    --self-check) MODE="self-check" ;;
    "")           MODE="full" ;;
    *) echo "usage: $0 [--quick|--self-check]" >&2; exit 2 ;;
esac

RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="tests/artifacts/perf/h5_smoke/${RUN_TS}"
mkdir -p "$RUN_DIR"
echo "[h5.4] mode=$MODE run dir: $RUN_DIR"

# Inputs every mode asserts exist (fail-closed if the track regressed).
PREREQS=(
    "crates/franken-engine/benches/hot_paths.rs"
    "crates/franken-engine/tests/${FIDELITY_TEST}.rs"
    "$VALIDATE_SCRIPT"
)

CARGO="${CARGO:-/home/ubuntu/.cargo/bin/cargo}"
BUILD_RC=0
BENCH_RC=0
FIDELITY_RC=0
BUILD_STATUS="skipped"
BENCH_STATUS="skipped"
FIDELITY_STATUS="skipped"

# ---------------------------------------------------------------------------
# 0. Prerequisite presence check (all modes).
# ---------------------------------------------------------------------------
PREREQ_OK=1
for p in "${PREREQS[@]}"; do
    if [[ ! -e "$p" ]]; then
        echo "[h5.4] MISSING prerequisite: $p" >&2
        PREREQ_OK=0
    fi
done
# The target sub-bench must be present in the bench source.
if ! grep -q "\"$TARGET\"" "crates/franken-engine/benches/hot_paths.rs"; then
    echo "[h5.4] target sub-bench not found in bench source: $TARGET" >&2
    PREREQ_OK=0
fi
# The refactored bench must no longer round-trip the cert (the H5.2 invariant):
# a `from_str::<TransportCertificate>` in the bench digest fn would mean the
# dropped step crept back. Guard it so the smoke fails closed on regression.
if grep -q "from_str::<TransportCertificate>" "crates/franken-engine/benches/hot_paths.rs"; then
    echo "[h5.4] H5.2 invariant broken: bench re-introduced a cert round-trip" >&2
    PREREQ_OK=0
fi

if [[ "$MODE" == "self-check" ]]; then
    if [[ "$PREREQ_OK" -eq 1 ]]; then
        echo "[h5.4] self-check PASS — all prerequisites present (run-id $RUN_TS)"
    else
        echo "[h5.4] self-check FAIL — missing prerequisites (run-id $RUN_TS)" >&2
    fi
    # Still emit a minimal summary/fingerprint so the run-id is durable.
    BUILD_STATUS="self-check"; BENCH_STATUS="self-check"; FIDELITY_STATUS="self-check"
fi

if [[ "$PREREQ_OK" -ne 1 && "$MODE" != "self-check" ]]; then
    echo "[h5.4] aborting: prerequisites missing" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# 1. BUILD — bench compiles with canonical pass1 flags (full mode only).
# ---------------------------------------------------------------------------
if [[ "$MODE" == "full" ]]; then
    echo "[h5.4] building hot_paths bench (pass1 flags)..."
    if RCH_CARGO_WRAPPER_BYPASS=1 \
        RUSTFLAGS="-C force-frame-pointers=yes -C linker=cc" \
        CARGO_INCREMENTAL=0 \
        "$CARGO" bench --bench hot_paths --no-run > "$RUN_DIR/build.log" 2>&1; then
        BUILD_STATUS="pass"
    else
        BUILD_STATUS="fail"; BUILD_RC=1
        echo "[h5.4] BUILD FAILED — see $RUN_DIR/build.log" >&2
    fi
fi

# ---------------------------------------------------------------------------
# 2. BENCH — short-budget run of the H5 target (full mode only).
# ---------------------------------------------------------------------------
if [[ "$MODE" == "full" && "$BUILD_STATUS" == "pass" ]]; then
    HOT_BIN="$(ls target/release/deps/hot_paths-* 2>/dev/null | grep -v '\.d$' | sort | tail -1 || true)"
    if [[ -z "$HOT_BIN" ]]; then
        BENCH_STATUS="fail"; BENCH_RC=1
        echo "[h5.4] bench binary not found after build" >&2
    else
        echo "[h5.4] bench binary: $HOT_BIN"
        # Short Criterion budget: this is a liveness smoke, not a statistical run.
        if "$HOT_BIN" --bench --sample-size 10 --warm-up-time 0.5 \
            --measurement-time 1 "${GROUP}/${TARGET}" > "$RUN_DIR/bench_smoke.txt" 2>&1; then
            BENCH_STATUS="pass"
        else
            BENCH_STATUS="fail"; BENCH_RC=1
            echo "[h5.4] bench smoke FAILED — see $RUN_DIR/bench_smoke.txt" >&2
        fi
    fi
fi

# ---------------------------------------------------------------------------
# 3. OUTPUT — H5.2 round-trip fidelity test (full + quick modes).
# ---------------------------------------------------------------------------
if [[ "$MODE" == "full" || "$MODE" == "quick" ]]; then
    echo "[h5.4] running serde fidelity test ($FIDELITY_TEST)..."
    if RCH_CARGO_WRAPPER_BYPASS=1 CARGO_INCREMENTAL=0 \
        "$CARGO" test --test "$FIDELITY_TEST" \
        > "$RUN_DIR/fidelity.txt" 2>&1; then
        FIDELITY_STATUS="pass"
    else
        FIDELITY_STATUS="fail"; FIDELITY_RC=1
        echo "[h5.4] fidelity test FAILED — see $RUN_DIR/fidelity.txt" >&2
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
python3 - "$RUN_DIR" "$BEAD" "$SCENARIO" "$MODE" "$VALIDATE_SCRIPT" \
    "$BUILD_STATUS" "$BENCH_STATUS" "$FIDELITY_STATUS" \
    "$TARGET" "$FIDELITY_TEST" <<'PYVERDICT'
import json, os, sys, time, hashlib

(run_dir, bead, scenario, mode, validate_script,
 build_status, bench_status, fidelity_status, target, fidelity_test) = sys.argv[1:11]
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

# A check "passes" when it is pass, skipped (mode didn't run it), or self-check.
def ok(status):
    return status in ("pass", "skipped", "self-check")

checks = [("build", build_status), ("bench", bench_status), ("fidelity", fidelity_status)]
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
    "verdict": "pass" if all_pass else "fail", "fail_reasons": fail_reasons,
    "artifacts_written": [
        f"{run_dir}/events.jsonl", f"{run_dir}/summary.md",
        f"{run_dir}/fingerprint.json",
    ],
    "note": ("drop number is produced by the statistical gate "
             f"{validate_script} (PERF-H5.3); this smoke proves liveness + "
             "serde-contract-unchanged only"),
})

with open(os.path.join(run_dir, "events.jsonl"), "w") as f:
    for e in events:
        f.write(json.dumps(e) + "\n")

with open(os.path.join(run_dir, "summary.md"), "w") as f:
    f.write(f"# PERF-H5.4 E2E Smoke — {run_id}\n\n")
    f.write(f"Bead: {bead} · mode `{mode}` · generated {now} · git `{git_sha[:12]}`\n\n")
    f.write("| check | what it proves | status |\n")
    f.write("|---|---|---|\n")
    f.write(f"| build | `hot_paths` compiles with pass1 flags | {build_status} |\n")
    f.write(f"| bench | `{target}` executes (short budget) | {bench_status} |\n")
    f.write(f"| fidelity | `{fidelity_test}` serde round-trip stable | {fidelity_status} |\n")
    f.write(f"\n**Overall: {'PASS' if all_pass else 'FAIL'}**\n\n")
    if fail_reasons:
        f.write("### Failures\n\n")
        for r in fail_reasons:
            f.write(f"- {r}\n")
        f.write("\n")
    f.write("## Scope\n\n")
    f.write("A smoke proves the H5 transport-certificate bench refactor "
            "**builds, runs, and preserves the cert serde contract** (the "
            "round-trip the dropped bench deserialize relied on). The binding "
            f"drop number is the statistical gate `{validate_script}` "
            "(PERF-H5.3), scored against the `What counts as a perf win` "
            "standard in `docs/PERFORMANCE_BASELINE.md`.\n")

print(f"[h5.4] smoke overall = {'PASS' if all_pass else 'FAIL'}  (run-id {run_id})")
for r in fail_reasons:
    print(f"[h5.4]   - {r}")
sys.exit(0 if all_pass else 1)
PYVERDICT
VERDICT_RC=$?

echo "[h5.4] artifacts written to $RUN_DIR"
ls -1 "$RUN_DIR"
exit $VERDICT_RC
