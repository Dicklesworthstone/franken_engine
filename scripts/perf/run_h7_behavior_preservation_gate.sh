#!/usr/bin/env bash
set -euo pipefail

# PERF-H7.3 (bd-o4cbn.3.3): behavior-preservation gate for the mimalloc global
# allocator (PERF-H7 / bd-o4cbn.3).
#
# Hypothesis under audit: switching the global allocator (glibc -> mimalloc on
# the frankenctl + bench binaries, per H7.1) is *observation-equivalent* — no
# unit-test result, replay outcome, metamorphic relation, or decision artifact
# should change. Allocators may legally reorder address values, but nothing the
# engine canonicalizes, hashes, or replays observes an address.
#
# This script orchestrates the five gates the bead enumerates, captures their
# logs, and renders a fail-closed verdict that separates two independent
# questions:
#
#   1. mimalloc observation-equivalence  (the actual H7.3 audit)  -- keyed on
#      the gates that probe allocator-*observable* behavior: the metamorphic
#      suite (must report zero divergences) and the replay-coverage gate.
#   2. overall tree health               (fail-closed across all five gates) --
#      `cargo fmt --check`, `cargo clippy -D warnings`, and `cargo test --lib`
#      can fail on PRE-EXISTING tree debt that is orthogonal to the allocator
#      (e.g. tree-wide fmt drift, the franken-engine-deterministic-derive E0107).
#      Those failures must NOT be misread as a mimalloc regression, but they DO
#      keep the overall gate red until resolved (the bead closes green only when
#      all five are clean).
#
# Usage:
#   scripts/perf/run_h7_behavior_preservation_gate.sh ci [RUN_DIR]
#       Run all five gates, capture logs under RUN_DIR, write summary.json +
#       SUMMARY.md, exit 0 iff every gate passed (fail-closed).
#   scripts/perf/run_h7_behavior_preservation_gate.sh verify RUN_DIR
#       Re-classify an existing RUN_DIR (its *.exit + metamorphic.log) without
#       re-running anything.
#   scripts/perf/run_h7_behavior_preservation_gate.sh selftest
#       Build-free self-check of the classifier + verdict logic. No cargo.
#
# Artifacts (RUN_DIR, default tests/artifacts/perf/h7_gates/<utc-ts>/ which is
# gitignored — logs are local evidence, this script is the committed harness):
#   <gate>.log    full stdout/stderr of each gate
#   <gate>.exit   the gate's exit code
#   summary.json  machine-readable per-gate status + the two verdicts
#   SUMMARY.md    human-readable summary
#
# Exit codes: 0 = overall PASS (all five green). 1 = overall FAIL. 2 = usage.

SCRIPT_NAME="$(basename "$0")"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Ordered gate identifiers. The command for each lives in gate_command().
GATES=(fmt clippy lib_test replay metamorphic)

gate_command() {
  case "$1" in
    fmt)         echo "cargo fmt --check" ;;
    clippy)      echo "cargo clippy --all-targets -- -D warnings" ;;
    lib_test)    echo "cargo test --lib -p frankenengine-engine" ;;
    replay)      echo "./scripts/run_replay_coverage_metric_gate.sh ci" ;;
    metamorphic) echo "cargo run -p franken-metamorphic --bin run_metamorphic_suite" ;;
    *)           echo "" ;;
  esac
}

# Gates whose pass/fail directly reflects allocator-observable behavior. If
# these are clean, mimalloc observation-equivalence is SUPPORTED even when the
# orthogonal tree-health gates (fmt/clippy/lib_test) fail on pre-existing debt.
is_allocator_observable_gate() {
  [[ "$1" == "replay" || "$1" == "metamorphic" ]]
}

# Extract the metamorphic divergence count from a metamorphic log. The suite
# prints a line like "divergences: 0" / "0 divergences" / "0/16000". Returns the
# integer, or -1 if it could not be determined (treated as a failure).
metamorphic_divergences() {
  local log="$1"
  [[ -f "$log" ]] || { echo "-1"; return; }
  local n
  n="$(grep -oiE 'divergences?[: ]+([0-9]+)' "$log" | grep -oE '[0-9]+' | head -n1 || true)"
  if [[ -z "$n" ]]; then
    n="$(grep -oE '\b([0-9]+)/[0-9]+\b' "$log" | head -n1 | cut -d/ -f1 || true)"
  fi
  [[ -n "$n" ]] && echo "$n" || echo "-1"
}

json_escape() { python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'; }

# classify RUN_DIR -> writes summary.json + SUMMARY.md into RUN_DIR.
# Returns 0 iff every gate passed (fail-closed); else 1.
classify() {
  local run_dir="$1"
  local overall_pass=1
  local rows_json=""
  local md="# PERF-H7.3 behavior-preservation gate\n\nRun dir: \`${run_dir}\`\n\n| gate | exit | status | kind |\n|------|------|--------|------|\n"

  # Divergence count is needed inside the loop: the metamorphic suite can exit 0
  # yet REPORT divergences, which must still fail its gate.
  local divergences
  divergences="$(metamorphic_divergences "${run_dir}/metamorphic.log")"

  for gate in "${GATES[@]}"; do
    local exit_code status kind="tree_health"
    is_allocator_observable_gate "$gate" && kind="allocator_observable"
    if [[ -f "${run_dir}/${gate}.exit" ]]; then
      exit_code="$(cat "${run_dir}/${gate}.exit")"
    else
      exit_code="missing"
    fi
    if [[ "$exit_code" == "0" ]]; then status="pass"; else status="fail"; overall_pass=0; fi
    # The metamorphic gate fails on ANY reported divergence (or an unparseable
    # count) even when the harness process itself exits 0.
    if [[ "$gate" == "metamorphic" && "$divergences" != "0" ]]; then
      status="fail"; overall_pass=0
    fi
    rows_json="${rows_json}{\"gate\":\"${gate}\",\"exit\":\"${exit_code}\",\"status\":\"${status}\",\"kind\":\"${kind}\"},"
    md="${md}| ${gate} | ${exit_code} | ${status} | ${kind} |\n"
  done
  rows_json="[${rows_json%,}]"

  # mimalloc observation-equivalence sub-verdict: SUPPORTED iff replay passed and
  # the metamorphic suite passed with zero divergences.
  local replay_exit metamorphic_exit mimalloc_verdict
  replay_exit="$(cat "${run_dir}/replay.exit" 2>/dev/null || echo missing)"
  metamorphic_exit="$(cat "${run_dir}/metamorphic.exit" 2>/dev/null || echo missing)"
  if [[ "$replay_exit" == "0" && "$metamorphic_exit" == "0" && "$divergences" == "0" ]]; then
    mimalloc_verdict="SUPPORTED"
  elif [[ "$metamorphic_exit" == "0" && "$divergences" =~ ^[1-9][0-9]*$ ]]; then
    mimalloc_verdict="REFUTED"
  else
    mimalloc_verdict="INDETERMINATE"
  fi

  local overall_verdict="FAIL"; [[ "$overall_pass" == "1" ]] && overall_verdict="PASS"

  python3 - "$run_dir" "$rows_json" "$overall_verdict" "$mimalloc_verdict" "$divergences" <<'PY'
import json, sys, os
run_dir, rows, overall, mimalloc, divergences = sys.argv[1:6]
summary = {
    "schema": "franken-engine.perf.h7-behavior-preservation.v1",
    "bead": "bd-o4cbn.3.3",
    "gates": json.loads(rows),
    "metamorphic_divergences": int(divergences) if divergences.lstrip("-").isdigit() else None,
    "mimalloc_observation_equivalence": mimalloc,
    "overall_verdict": overall,
}
with open(os.path.join(run_dir, "summary.json"), "w") as f:
    json.dump(summary, f, indent=2, sort_keys=True)
    f.write("\n")
PY

  md="${md}\n- **mimalloc observation-equivalence:** ${mimalloc_verdict} (metamorphic divergences: ${divergences}, replay exit: ${replay_exit})\n- **overall verdict (fail-closed):** ${overall_verdict}\n"
  printf '%b' "$md" > "${run_dir}/SUMMARY.md"

  echo "----------------------------------------------------------------"
  echo "PERF-H7.3 gate verdict: ${overall_verdict}"
  echo "  mimalloc observation-equivalence: ${mimalloc_verdict} (divergences=${divergences})"
  echo "  artifacts: ${run_dir}/{summary.json,SUMMARY.md}"
  echo "----------------------------------------------------------------"

  [[ "$overall_pass" == "1" ]]
}

run_ci() {
  local run_dir="$1"
  mkdir -p "$run_dir"
  cd "$ROOT_DIR"
  echo "PERF-H7.3 behavior-preservation gate — capturing into ${run_dir}"
  for gate in "${GATES[@]}"; do
    local cmd; cmd="$(gate_command "$gate")"
    echo ">>> [${gate}] ${cmd}"
    set +e
    bash -c "$cmd" >"${run_dir}/${gate}.log" 2>&1
    local rc=$?
    set -e
    echo "$rc" > "${run_dir}/${gate}.exit"
    echo "    exit=${rc} (log: ${run_dir}/${gate}.log)"
  done
  classify "$run_dir"
}

# --------------------------------------------------------------------------
# selftest: build-free validation of classify() + the two verdicts. Synthesizes
# three RUN_DIRs of fake gate results and asserts the expected verdicts.
# --------------------------------------------------------------------------
run_selftest() {
  local tmp; tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  local failures=0

  _expect() { # label expected_overall expected_mimalloc run_dir actual_rc
    local label="$1" exp_overall="$2" exp_mimalloc="$3" dir="$4" rc="$5"
    local got_overall="FAIL"; [[ "$rc" == "0" ]] && got_overall="PASS"
    local got_mimalloc; got_mimalloc="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["mimalloc_observation_equivalence"])' "${dir}/summary.json")"
    if [[ "$got_overall" == "$exp_overall" && "$got_mimalloc" == "$exp_mimalloc" ]]; then
      echo "  ok   ${label}: overall=${got_overall} mimalloc=${got_mimalloc}"
    else
      echo "  FAIL ${label}: overall=${got_overall} (want ${exp_overall}) mimalloc=${got_mimalloc} (want ${exp_mimalloc})"
      failures=$((failures+1))
    fi
  }

  # Case A: every gate green, zero divergences -> PASS / SUPPORTED.
  local a="${tmp}/all_green"; mkdir -p "$a"
  for g in "${GATES[@]}"; do echo 0 > "${a}/${g}.exit"; done
  echo "metamorphic relations checked; divergences: 0 (0/16000)" > "${a}/metamorphic.log"
  set +e; classify "$a" >/dev/null; local rc_a=$?; set -e
  _expect "all-green" PASS SUPPORTED "$a" "$rc_a"

  # Case B: orthogonal pre-existing tree debt (fmt+clippy red) but allocator-
  # observable gates clean -> overall FAIL (fail-closed) yet mimalloc SUPPORTED.
  local b="${tmp}/orthogonal_debt"; mkdir -p "$b"
  echo 1 > "${b}/fmt.exit"; echo 1 > "${b}/clippy.exit"; echo 0 > "${b}/lib_test.exit"
  echo 0 > "${b}/replay.exit"; echo 0 > "${b}/metamorphic.exit"
  echo "divergences: 0" > "${b}/metamorphic.log"
  set +e; classify "$b" >/dev/null; local rc_b=$?; set -e
  _expect "orthogonal-debt" FAIL SUPPORTED "$b" "$rc_b"

  # Case C: a genuine mimalloc-observable regression (metamorphic divergence)
  # -> overall FAIL and mimalloc REFUTED.
  local c="${tmp}/mimalloc_regression"; mkdir -p "$c"
  for g in "${GATES[@]}"; do echo 0 > "${c}/${g}.exit"; done
  echo "divergences: 3 (3/16000) — output differs under mimalloc" > "${c}/metamorphic.log"
  set +e; classify "$c" >/dev/null; local rc_c=$?; set -e
  _expect "mimalloc-regression" FAIL REFUTED "$c" "$rc_c"

  if [[ "$failures" -eq 0 ]]; then
    echo "selftest: PASS (3/3 cases)"
    return 0
  fi
  echo "selftest: FAIL (${failures} case(s))"
  return 1
}

mode="${1:-ci}"
case "$mode" in
  selftest) run_selftest ;;
  ci)
    run_id="${H7_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
    run_dir="${2:-${H7_RUN_DIR:-${ROOT_DIR}/tests/artifacts/perf/h7_gates/${run_id}}}"
    run_ci "$run_dir"
    ;;
  verify)
    [[ -n "${2:-}" ]] || { echo "usage: ${SCRIPT_NAME} verify RUN_DIR" >&2; exit 2; }
    classify "$2"
    ;;
  *)
    echo "usage: ${SCRIPT_NAME} [ci [RUN_DIR] | verify RUN_DIR | selftest]" >&2
    exit 2
    ;;
esac
