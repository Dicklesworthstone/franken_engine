#!/bin/bash
set -euo pipefail

# PERF-H1.6 (bd-o4cbn.1.6): End-to-end smoke for the cached default
# evidence signing key win.
#
# The statistical authority remains scripts/perf/h1_bench_validate.sh
# (PERF-H1.4). This smoke proves the H1 path still builds, the H1.3
# signature golden still holds, replay-gate context is documented, and the
# evidence_ledger_bundle Criterion target stays under the H1 smoke cap.
#
# This script does not run Cargo locally. All Cargo test and bench commands are
# submitted directly through rch with RCH_REQUIRE_REMOTE=1.
#
# Modes:
#   (default)       full smoke: evidence-ledger lib tests + signature golden +
#                   remote Criterion smoke bench with mean <= 110 us.
#   --quick         tests only: skip the Criterion bench.
#   --self-check    no Cargo at all: validate prerequisites and emit artifacts.
#
# Usage: scripts/perf/run_perf_h1_smoke.sh [--quick|--self-check]

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

ISSUE_ID="bd-o4cbn.1.6"
BEAD_LABEL="PERF-H1.6"
SCENARIO="h1_smoke"
GROUP="real_runtime_hot_paths"
TARGET="evidence_ledger_bundle"
PASS1_DIR="tests/artifacts/perf/20260520T214829Z-prof-pass1"
PASS1_ESTIMATES="${PASS1_DIR}/criterion_${TARGET}_estimates.json"
VALIDATE_SCRIPT="scripts/perf/h1_bench_validate.sh"
TARGET_MAX_MEAN_NS="110000"
RUN_TS="${H1_SMOKE_RUN_TS:-$(date -u +%Y%m%dT%H%M%SZ)}"
RUN_DIR="tests/artifacts/perf/h1_smoke/${RUN_TS}"
CRITERION_HOME_DIR="${REPO_ROOT}/${RUN_DIR}/criterion"
CARGO_TARGET_DIR_DEFAULT="/tmp/rch_target_franken_engine_h1_smoke_${USER:-agent}_${RUN_TS}"
EFFECTIVE_CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$CARGO_TARGET_DIR_DEFAULT}"
RCH_EXEC_TIMEOUT_SECONDS="${RCH_EXEC_TIMEOUT_SECONDS:-5400}"
PASS1_RUSTFLAGS="-C force-frame-pointers=yes -C linker=cc"
UNIT_SEPARATOR=$'\037'
PASS1_ENCODED_RUSTFLAGS="-Cforce-frame-pointers=yes${UNIT_SEPARATOR}-Clinker=cc"
CARGO="${CARGO:-/home/ubuntu/.cargo/bin/cargo}"
EVENTS_FILE="${RUN_DIR}/events.jsonl"
SUMMARY_FILE="${RUN_DIR}/summary.md"
FINGERPRINT_FILE="${RUN_DIR}/fingerprint.json"
BENCH_STATS_FILE="${RUN_DIR}/bench_stats.json"

MODE="full"
case "${1:-}" in
    --quick) MODE="quick" ;;
    --self-check) MODE="self-check" ;;
    "") MODE="full" ;;
    *) echo "usage: $0 [--quick|--self-check]" >&2; exit 2 ;;
esac

mkdir -p "$RUN_DIR" "$CRITERION_HOME_DIR"
: > "$EVENTS_FILE"

log() {
    echo "[H1-smoke] $*"
}

fail_log() {
    log "[FAIL] $*"
}

append_event() {
    local event="$1"
    shift
    python3 - "$EVENTS_FILE" "$event" "$RUN_TS" "$BEAD_LABEL" "$ISSUE_ID" "$SCENARIO" "$@" <<'PY'
import json
import re
import sys
import time

path, event, run_ts, bead, issue_id, scenario = sys.argv[1:7]
data = {
    "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "event": event,
    "bead": bead,
    "issue_id": issue_id,
    "scenario": scenario,
    "run_id": run_ts,
}

def parse_value(value):
    if value == "true":
        return True
    if value == "false":
        return False
    if value == "null":
        return None
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    if re.fullmatch(r"-?\d+\.\d+", value):
        return float(value)
    return value

for item in sys.argv[7:]:
    if "=" not in item:
        continue
    key, value = item.split("=", 1)
    data[key] = parse_value(value)

with open(path, "a", encoding="utf-8") as fh:
    fh.write(json.dumps(data, sort_keys=True) + "\n")
PY
}

strip_ansi_file() {
    sed -E 's/\x1B\[[0-9;]*[[:alpha:]]//g' "$1"
}

reject_rch_local_fallback() {
    local log_path="$1"
    if grep -Eiq 'Remote execution failed: .*running locally|Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Failed to query daemon:.*running locally|Dependency preflight blocked remote execution|RCH-E326' < <(strip_ansi_file "$log_path"); then
        fail_log "rch reported local fallback or dependency-preflight failure in $log_path"
        return 1
    fi
}

run_rch_dry_run() {
    local label="$1"
    local out_path="$2"
    shift 2
    log "dry-run remote admission for ${label}"
    if ! RCH_REQUIRE_REMOTE=1 RCH_BUILD_TIMEOUT_SEC="$RCH_EXEC_TIMEOUT_SECONDS" \
        rch diagnose --dry-run --json -- "$@" > "$out_path"; then
        fail_log "rch dry-run command failed for ${label}; see $out_path"
        return 1
    fi
    python3 - "$out_path" "$label" <<'PY'
import json
import sys

path, label = sys.argv[1:3]
with open(path, "r", encoding="utf-8") as fh:
    report = json.load(fh)

data = report.get("data", {})
dry_run = data.get("dry_run", {})
classification = data.get("classification", {})
if dry_run.get("would_offload") is not True:
    reason = dry_run.get("reason") or classification.get("reason") or "unknown"
    raise SystemExit(f"{label}: rch dry-run would not offload: {reason}")
PY
}

run_rch_capture() {
    local label="$1"
    local log_path="$2"
    shift 2
    log "running ${label} through rch"
    set +e
    RCH_REQUIRE_REMOTE=1 RCH_BUILD_TIMEOUT_SEC="$RCH_EXEC_TIMEOUT_SECONDS" \
        timeout "$RCH_EXEC_TIMEOUT_SECONDS" rch exec -- "$@" 2>&1 | tee "$log_path"
    local -a pipe_status=("${PIPESTATUS[@]}")
    set -e
    local rch_status="${pipe_status[0]}"
    if ! reject_rch_local_fallback "$log_path"; then
        return 98
    fi
    return "$rch_status"
}

test_log_passed() {
    local log_path="$1"
    grep -q "test result: ok" < <(strip_ansi_file "$log_path") && ! cargo_log_has_source_failure "$log_path"
}

cargo_log_has_source_failure() {
    local log_path="$1"
    grep -Eq '^test result: FAILED|^error(\[|:)|panicked at|^failures:' < <(strip_ansi_file "$log_path")
}

cargo_log_has_remote_start() {
    local log_path="$1"
    grep -Eq 'Selected worker:|Executing command remotely:' < <(strip_ansi_file "$log_path")
}

cargo_log_has_remote_finish() {
    local log_path="$1"
    grep -Eq 'Remote command finished: exit=' < <(strip_ansi_file "$log_path")
}

classify_remote_cargo_log() {
    local log_path="$1"
    local rc="$2"
    if test_log_passed "$log_path"; then
        echo "pass"
    elif cargo_log_has_source_failure "$log_path"; then
        echo "source_failure"
    elif [[ "$rc" -eq 98 ]]; then
        echo "local_fallback_refused"
    elif cargo_log_has_remote_start "$log_path" && ! cargo_log_has_remote_finish "$log_path"; then
        echo "transport_timeout"
    else
        echo "missing_remote_proof"
    fi
}

remote_cargo_reason_code() {
    local status="$1"
    case "$status" in
        pass) echo "remote_command_exit_zero" ;;
        source_failure) echo "remote_source_diagnostic" ;;
        local_fallback_refused) echo "local_fallback_refused" ;;
        transport_timeout) echo "ssh_timeout_no_final_verdict" ;;
        missing_remote_proof) echo "missing_worker_or_command_evidence" ;;
        *) echo "unknown" ;;
    esac
}

status_is_ok() {
    case "$1" in
        pass|skipped|self-check) return 0 ;;
        *) return 1 ;;
    esac
}

golden_log_passed() {
    local log_path="$1"
    grep -Eq 'test evidence_ledger::tests::evidence_entry_signature_unchanged_post_cache \.\.\. ok' < <(strip_ansi_file "$log_path")
}

prepare_criterion_pass1() {
    local pass1_baseline_dir="${CRITERION_HOME_DIR}/${GROUP}/${TARGET}/pass1"
    mkdir -p "$pass1_baseline_dir"
    cp "$PASS1_ESTIMATES" "${pass1_baseline_dir}/estimates.json"
    python3 - "${pass1_baseline_dir}/benchmark.json" "$GROUP" "$TARGET" <<'PY'
import json
import sys

path, group, target = sys.argv[1:4]
payload = {
    "group_id": group,
    "function_id": target,
    "value_str": None,
    "throughput": None,
    "full_id": f"{group}/{target}",
    "directory_name": f"{group}/{target}",
    "title": f"{group}/{target}",
}
with open(path, "w", encoding="utf-8") as fh:
    json.dump(payload, fh)
PY
}

extract_bench_stats() {
    python3 - "$CRITERION_HOME_DIR" "$GROUP" "$TARGET" "$PASS1_ESTIMATES" "$TARGET_MAX_MEAN_NS" "$BENCH_STATS_FILE" <<'PY'
import json
import os
import sys

criterion_home, group, target, pass1_path, cap_ns, out_path = sys.argv[1:7]
target_root = os.path.join(criterion_home, group, target)
candidate_baselines = ["new", "h1_smoke", "post_h1"]
estimate_path = ""
for baseline in candidate_baselines:
    path = os.path.join(target_root, baseline, "estimates.json")
    if os.path.exists(path):
        estimate_path = path
        break
if not estimate_path:
    raise SystemExit(f"missing Criterion estimates under {target_root}")

with open(estimate_path, "r", encoding="utf-8") as fh:
    estimates = json.load(fh)
with open(pass1_path, "r", encoding="utf-8") as fh:
    pass1 = json.load(fh)

mean = float(estimates["mean"]["point_estimate"])
std = float(estimates["std_dev"]["point_estimate"])
pass1_mean = float(pass1["mean"]["point_estimate"])
ci = estimates["mean"]["confidence_interval"]
delta_pct = ((mean - pass1_mean) / pass1_mean) * 100.0
cv_pct = (std / mean) * 100.0 if mean else None

sample_path = os.path.join(os.path.dirname(estimate_path), "sample.json")
sample_count = None
if os.path.exists(sample_path):
    with open(sample_path, "r", encoding="utf-8") as fh:
        sample = json.load(fh)
    sample_count = len(sample.get("times", []))

payload = {
    "estimate_path": estimate_path,
    "mean_ns": mean,
    "std_dev_ns": std,
    "cv_pct": cv_pct,
    "ci95_lower_ns": float(ci["lower_bound"]),
    "ci95_upper_ns": float(ci["upper_bound"]),
    "pass1_mean_ns": pass1_mean,
    "delta_pct": delta_pct,
    "target_max_mean_ns": int(cap_ns),
    "sample_count": sample_count,
    "verdict": "pass" if mean <= int(cap_ns) else "fail",
}
with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2, sort_keys=True)
print(int(round(mean)))
PY
}

write_fingerprint() {
    python3 - "$FINGERPRINT_FILE" "$ISSUE_ID" "$RUN_TS" "$EFFECTIVE_CARGO_TARGET_DIR" "$CRITERION_HOME_DIR" "$PASS1_RUSTFLAGS" <<'PY'
import json
import os
import platform
import subprocess
import sys
import time

path, issue_id, run_ts, cargo_target_dir, criterion_home, rustflags = sys.argv[1:7]

def sh(*args):
    try:
        return subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return ""

payload = {
    "captured_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "run_id": run_ts,
    "bead": issue_id,
    "git_sha": sh("git", "rev-parse", "HEAD"),
    "git_dirty": bool(sh("git", "status", "--porcelain")),
    "kernel": platform.release(),
    "python": platform.python_version(),
    "rch": sh("rch", "--version"),
    "cargo_path": os.environ.get("CARGO", "/home/ubuntu/.cargo/bin/cargo"),
    "execution": {
        "mode": "rch_remote",
        "cargo_target_dir": cargo_target_dir,
        "criterion_home": criterion_home,
        "timeout_sec": os.environ.get("RCH_EXEC_TIMEOUT_SECONDS", ""),
    },
    "build_flags": {
        "RUSTFLAGS": rustflags,
        "CARGO_INCREMENTAL": "0",
    },
}
with open(path, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2, sort_keys=True)
PY
}

write_summary() {
    python3 - "$SUMMARY_FILE" "$RUN_TS" "$ISSUE_ID" "$MODE" "$UNIT_STATUS" "$GOLDEN_STATUS" "$BENCH_STATUS" "$BENCH_STATS_FILE" "$VALIDATE_SCRIPT" <<'PY'
import json
import os
import sys
import time

(
    path,
    run_ts,
    issue_id,
    mode,
    unit_status,
    golden_status,
    bench_status,
    bench_stats_path,
    validate_script,
) = sys.argv[1:10]

now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
bench = {}
if os.path.exists(bench_stats_path):
    with open(bench_stats_path, "r", encoding="utf-8") as fh:
        bench = json.load(fh)

def ok(status):
    return status in {"pass", "skipped", "self-check"}

overall = "PASS" if all(ok(s) for s in [unit_status, golden_status, bench_status]) else "FAIL"

with open(path, "w", encoding="utf-8") as fh:
    fh.write(f"# PERF-H1.6 E2E Smoke - {run_ts}\n\n")
    fh.write(f"Bead: `{issue_id}`. Mode: `{mode}`. Generated: {now}.\n\n")
    fh.write("| check | command or assertion | status |\n")
    fh.write("|---|---|---|\n")
    fh.write("| evidence ledger lib | `cargo test -p frankenengine-engine --lib evidence_ledger` through rch | "
             f"{unit_status} |\n")
    fh.write("| H1.3 signature golden | `evidence_entry_signature_unchanged_post_cache` observed in evidence-ledger lib run | "
             f"{golden_status} |\n")
    if bench:
        fh.write("| evidence_ledger_bundle smoke bench | "
                 f"mean {bench.get('mean_ns', 0):.1f} ns <= {bench.get('target_max_mean_ns')} ns; "
                 f"delta {bench.get('delta_pct', 0):.2f}% vs pass1 | {bench_status} |\n")
    else:
        fh.write("| evidence_ledger_bundle smoke bench | remote Criterion bench skipped or no estimates | "
                 f"{bench_status} |\n")
    fh.write(f"\n**Overall: {overall}**\n\n")
    if bench:
        fh.write("## Bench Stats\n\n")
        fh.write(f"- pass1 mean: {bench['pass1_mean_ns']:.1f} ns\n")
        fh.write(f"- smoke mean: {bench['mean_ns']:.1f} ns\n")
        fh.write(f"- smoke CI95: [{bench['ci95_lower_ns']:.1f}, {bench['ci95_upper_ns']:.1f}] ns\n")
        fh.write(f"- delta vs pass1: {bench['delta_pct']:.2f}%\n")
        fh.write(f"- CV: {bench['cv_pct']:.2f}%\n")
        fh.write(f"- sample count: {bench.get('sample_count')}\n")
    fh.write("\n## Scope\n\n")
    fh.write("This smoke is a liveness and cap gate. The statistical H1 win remains "
             f"`{validate_script}`, which enforces the full PERF-H1.4 criteria "
             "against the frozen pass1 baseline.\n")
PY
}

log "scenario=${SCENARIO}"
log "expected output: evidence ledger tests pass, H1.3 signature golden passes, ${TARGET} mean <= ${TARGET_MAX_MEAN_NS} ns"
log "timestamp=${RUN_TS}"
log "run dir: ${RUN_DIR}"
append_event "perf.profile.run_start" "target=${TARGET}" "mode=${MODE}" "threshold_ns=${TARGET_MAX_MEAN_NS}"

PREREQS=(
    "crates/franken-engine/benches/hot_paths.rs"
    "crates/franken-engine/src/evidence_ledger.rs"
    "$PASS1_ESTIMATES"
    "$VALIDATE_SCRIPT"
    "docs/PERFORMANCE_BASELINE.md"
)

PREREQ_OK=1
for path in "${PREREQS[@]}"; do
    if [[ ! -e "$path" ]]; then
        fail_log "missing prerequisite: $path"
        PREREQ_OK=0
    fi
done
if ! grep -q "\"${TARGET}\"" "crates/franken-engine/benches/hot_paths.rs"; then
    fail_log "target sub-bench not found in hot_paths.rs: ${TARGET}"
    PREREQ_OK=0
fi
if ! grep -q "DEFAULT_EVIDENCE_SIGNING_KEY: std::sync::LazyLock" "crates/franken-engine/src/evidence_ledger.rs"; then
    fail_log "cached default signing key LazyLock not found"
    PREREQ_OK=0
fi
if ! grep -q "fn evidence_entry_signature_unchanged_post_cache" "crates/franken-engine/src/evidence_ledger.rs"; then
    fail_log "H1.3 signature golden test not found"
    PREREQ_OK=0
fi
if ! command -v python3 >/dev/null 2>&1; then
    fail_log "python3 is required for artifact emission"
    PREREQ_OK=0
fi
if [[ "$MODE" != "self-check" ]] && ! command -v rch >/dev/null 2>&1; then
    fail_log "rch is required for remote-only Cargo execution"
    PREREQ_OK=0
fi

UNIT_STATUS="skipped"
GOLDEN_STATUS="skipped"
BENCH_STATUS="skipped"
UNIT_REASON=""
BENCH_REASON=""
BENCH_MEAN_NS=""

if [[ "$MODE" == "self-check" ]]; then
    if [[ "$PREREQ_OK" -eq 1 ]]; then
        log "self-check PASS"
        UNIT_STATUS="self-check"
        GOLDEN_STATUS="self-check"
        BENCH_STATUS="self-check"
    else
        log "self-check FAIL"
        UNIT_STATUS="fail"
        GOLDEN_STATUS="fail"
        BENCH_STATUS="fail"
    fi
    write_fingerprint
    append_event "perf.profile.sample_collected" "sub_bench=${TARGET}" "sample_count=0" "duration_sec=0" "mode=${MODE}"
    append_event "perf.profile.run_complete" "verdict=$([[ "$PREREQ_OK" -eq 1 ]] && echo pass || echo fail)" "mean_ns=null" "baseline_ns=null" "delta_pct=null"
    write_summary
    if [[ "$PREREQ_OK" -eq 1 ]]; then
        exit 0
    fi
    exit 1
fi

if [[ "$PREREQ_OK" -ne 1 ]]; then
    append_event "perf.profile.run_complete" "verdict=fail" "reason=missing prerequisite"
    write_fingerprint
    write_summary
    exit 1
fi

COMMON_ENV=(
    env
    RCH_CARGO_WRAPPER_BYPASS=1
    CARGO_BUILD_JOBS=1
    CARGO_INCREMENTAL=0
    CARGO_PROFILE_DEV_DEBUG=0
    CARGO_TARGET_DIR="$EFFECTIVE_CARGO_TARGET_DIR"
)
TEST_CMD=(
    "${COMMON_ENV[@]}"
    "$CARGO" test -p frankenengine-engine --lib evidence_ledger
)
BENCH_CMD=(
    env
    RCH_CARGO_WRAPPER_BYPASS=1
    CRITERION_HOME="$CRITERION_HOME_DIR"
    CARGO_ENCODED_RUSTFLAGS="$PASS1_ENCODED_RUSTFLAGS"
    CARGO_INCREMENTAL=0
    CARGO_TARGET_DIR="$EFFECTIVE_CARGO_TARGET_DIR"
    "$CARGO" bench -p frankenengine-engine --bench hot_paths --
    --sample-size 20
    --warm-up-time 0.5
    --measurement-time 2
    --baseline pass1
    "${GROUP}/${TARGET}"
)

run_rch_dry_run "evidence-ledger lib tests" "${RUN_DIR}/unit_rch_dry_run.json" "${TEST_CMD[@]}"
unit_rc=0
run_rch_capture "evidence-ledger lib tests" "${RUN_DIR}/unit.txt" "${TEST_CMD[@]}" || unit_rc=$?
UNIT_STATUS="$(classify_remote_cargo_log "${RUN_DIR}/unit.txt" "$unit_rc")"
UNIT_REASON="$(remote_cargo_reason_code "$UNIT_STATUS")"
if [[ "$UNIT_STATUS" == "pass" ]]; then
    log "evidence-ledger lib tests PASS"
else
    fail_log "evidence-ledger lib tests; status=${UNIT_STATUS}; reason=${UNIT_REASON}; rc=${unit_rc}; see ${RUN_DIR}/unit.txt"
    write_fingerprint
    append_event "perf.profile.sample_collected" "sub_bench=${TARGET}" "sample_count=0" "duration_sec=0" "mode=${MODE}"
    append_event "perf.profile.run_complete" "verdict=fail" "mean_ns=null" "baseline_ns=null" "delta_pct=null" "unit_status=${UNIT_STATUS}" "unit_reason=${UNIT_REASON}" "unit_rc=${unit_rc}" "golden_status=${GOLDEN_STATUS}" "bench_status=${BENCH_STATUS}"
    write_summary
    exit 1
fi

if golden_log_passed "${RUN_DIR}/unit.txt"; then
    GOLDEN_STATUS="pass"
    log "H1.3 signature golden PASS (covered by evidence-ledger lib tests)"
else
    GOLDEN_STATUS="fail"
    fail_log "H1.3 signature golden result not found in ${RUN_DIR}/unit.txt"
    write_fingerprint
    append_event "perf.profile.sample_collected" "sub_bench=${TARGET}" "sample_count=0" "duration_sec=0" "mode=${MODE}"
    append_event "perf.profile.run_complete" "verdict=fail" "mean_ns=null" "baseline_ns=null" "delta_pct=null" "unit_status=${UNIT_STATUS}" "golden_status=${GOLDEN_STATUS}" "bench_status=${BENCH_STATUS}"
    write_summary
    exit 1
fi

if [[ "$MODE" == "full" ]]; then
    prepare_criterion_pass1
    run_rch_dry_run "evidence_ledger_bundle Criterion smoke" "${RUN_DIR}/bench_rch_dry_run.json" "${BENCH_CMD[@]}"
    bench_rc=0
    run_rch_capture "evidence_ledger_bundle Criterion smoke" "${RUN_DIR}/bench_output.txt" "${BENCH_CMD[@]}" || bench_rc=$?
    if BENCH_MEAN_NS="$(extract_bench_stats)"; then
        if python3 - "$BENCH_STATS_FILE" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    stats = json.load(fh)
raise SystemExit(0 if stats["verdict"] == "pass" else 1)
PY
        then
            BENCH_STATUS="pass"
            log "${TARGET} mean ${BENCH_MEAN_NS} ns <= ${TARGET_MAX_MEAN_NS} ns"
        else
            BENCH_STATUS="fail"
            BENCH_REASON="threshold_exceeded"
            fail_log "${TARGET} mean exceeded ${TARGET_MAX_MEAN_NS} ns; see ${BENCH_STATS_FILE}"
        fi
    else
        BENCH_STATUS="$(classify_remote_cargo_log "${RUN_DIR}/bench_output.txt" "$bench_rc")"
        if [[ "$BENCH_STATUS" == "pass" ]]; then
            BENCH_STATUS="missing_remote_proof"
        fi
        BENCH_REASON="missing_criterion_estimates"
        if [[ "$BENCH_STATUS" == "source_failure" ]]; then
            BENCH_REASON="$(remote_cargo_reason_code "$BENCH_STATUS")"
        elif [[ "$BENCH_STATUS" == "local_fallback_refused" || "$BENCH_STATUS" == "transport_timeout" ]]; then
            BENCH_REASON="$(remote_cargo_reason_code "$BENCH_STATUS")"
        fi
        fail_log "missing Criterion estimates after bench; status=${BENCH_STATUS}; reason=${BENCH_REASON}; rc=${bench_rc}; see ${RUN_DIR}/bench_output.txt"
    fi
else
    BENCH_STATUS="skipped"
fi

write_fingerprint

sample_count="0"
duration_sec="0"
if [[ -s "$BENCH_STATS_FILE" ]]; then
    sample_count="$(python3 - "$BENCH_STATS_FILE" <<'PY'
import json
import sys
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    print(json.load(fh).get("sample_count") or 0)
PY
)"
    duration_sec="2"
fi
append_event "perf.profile.sample_collected" "sub_bench=${TARGET}" "sample_count=${sample_count}" "duration_sec=${duration_sec}" "mode=${MODE}"

if [[ -s "$BENCH_STATS_FILE" ]]; then
    python3 - "$EVENTS_FILE" "$RUN_TS" "$BEAD_LABEL" "$ISSUE_ID" "$SCENARIO" "$BENCH_STATS_FILE" "$UNIT_STATUS" "$GOLDEN_STATUS" "$BENCH_STATUS" <<'PY'
import json
import sys
import time

events_path, run_ts, bead, issue_id, scenario, stats_path, unit_status, golden_status, bench_status = sys.argv[1:10]
with open(stats_path, "r", encoding="utf-8") as fh:
    stats = json.load(fh)
all_pass = all(status in {"pass", "skipped", "self-check"} for status in [unit_status, golden_status, bench_status])
payload = {
    "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "event": "perf.profile.run_complete",
    "bead": bead,
    "issue_id": issue_id,
    "scenario": scenario,
    "run_id": run_ts,
    "verdict": "pass" if all_pass else "fail",
    "mean_ns": stats["mean_ns"],
    "baseline_ns": stats["pass1_mean_ns"],
    "delta_pct": stats["delta_pct"],
    "threshold_ns": stats["target_max_mean_ns"],
    "unit_status": unit_status,
    "golden_status": golden_status,
    "bench_status": bench_status,
}
with open(events_path, "a", encoding="utf-8") as fh:
    fh.write(json.dumps(payload, sort_keys=True) + "\n")
PY
else
    all_pass_word="fail"
    if status_is_ok "$UNIT_STATUS" && status_is_ok "$GOLDEN_STATUS" && status_is_ok "$BENCH_STATUS"; then
        all_pass_word="pass"
    fi
    append_event "perf.profile.run_complete" "verdict=${all_pass_word}" "mean_ns=null" "baseline_ns=null" "delta_pct=null" "unit_status=${UNIT_STATUS}" "unit_reason=${UNIT_REASON:-null}" "golden_status=${GOLDEN_STATUS}" "bench_status=${BENCH_STATUS}" "bench_reason=${BENCH_REASON:-null}"
fi

write_summary
log "artifacts written to ${RUN_DIR}"
if ! status_is_ok "$UNIT_STATUS" || ! status_is_ok "$GOLDEN_STATUS" || ! status_is_ok "$BENCH_STATUS"; then
    fail_log "H1 smoke did not pass"
    exit 1
fi
log "PASS H1 smoke"
