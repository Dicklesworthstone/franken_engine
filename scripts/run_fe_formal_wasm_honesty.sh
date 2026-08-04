#!/usr/bin/env bash
# CEI F.3 (bd-sde5e.6.3) gate — formal-verification + WASM-lane honesty invariant.
#
# Asserts the chosen F.1/F.2 outcomes stay honest (the "honesty-of-doc invariant"):
#
#   F.1 (formal verification, bd-sde5e.6.1): the 016-021 theorem-backed-compiler
#       claims are HYPOTHESIS because the verifiers are zero-capability (fail
#       closed). The matrix must keep 016-021 at hypothesis, and the G.10 decision
#       (docs/operator-gates/FE_CLAIM_016_021_PROMOTION_DECISION.md) must stay
#       STAY_HYPOTHESIS.
#
#   F.2 (WASM lane, bd-sde5e.6.2): the wasm_runtime_lane is two deliberately
#       bounded surfaces — a constant-return WASM export router and a native Rust
#       reactive signal graph — NOT a general WebAssembly interpreter. The module
#       doc must keep its no-execution wording, and the README must keep WASM
#       out-of-scope for the JS lane.
#
# This is the cross-surface (matrix + doc + README) drift check on top of the
# existing runtime gates (run_fe_claim_016_021_promotion_gate.sh enforces the
# promotion decision; the verify_* unit tests enforce fail-closed capability).
# Fails closed if any surface drifts toward over-claiming a formal-verification or
# WASM-execution capability the implementation does not have.
#
# Modes: ci | check   run the checks; fail closed on drift.
# Standard bundle under artifacts/fe_formal_wasm_honesty/<ts>/.
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
case "$mode" in
  ci | check) ;;
  *) echo "usage: run_fe_formal_wasm_honesty.sh [ci|check] [run_dir]" >&2; exit 2 ;;
esac

command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 2; }

matrix_json="docs/claim_to_proof_matrix_v1.json"
g10_doc="docs/operator-gates/FE_CLAIM_016_021_PROMOTION_DECISION.md"
wasm_src="crates/franken-engine/src/wasm_runtime_lane.rs"
readme="README.md"

artifact_root="${FE_FORMAL_WASM_HONESTY_ARTIFACT_ROOT:-artifacts/fe_formal_wasm_honesty}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
default_run_dir="${FE_FORMAL_WASM_HONESTY_REPLAY_RUN_DIR:-${artifact_root}/${timestamp}}"
run_dir="${2:-$default_run_dir}"
report_path="${run_dir}/honesty_report.txt"
manifest_path="${run_dir}/run_manifest.json"
commands_path="${run_dir}/commands.txt"
events_path="${run_dir}/events.jsonl"
trace_ids_path="${run_dir}/trace_ids.json"
step_logs_dir="${run_dir}/step_logs"
mkdir -p "$run_dir" "$step_logs_dir"
: >"$commands_path"; : >"$events_path"; : >"$report_path"

trace_id="trace-fe-formal-wasm-honesty-${timestamp}"
decision_id="decision-fe-formal-wasm-honesty-${timestamp}"
policy_id="policy-fe-formal-wasm-honesty-v1"
component="fe_formal_wasm_honesty_gate"
schema_ns="franken-engine.fe-formal-wasm-honesty-gate"

append_event() {
  jq -nc \
    --arg schema_version "${schema_ns}.event.v1" --arg trace_id "${trace_id}" \
    --arg decision_id "${decision_id}" --arg policy_id "${policy_id}" \
    --arg component "${component}" --arg event "$1" --arg outcome "$2" --arg detail "$3" \
    '{schema_version:$schema_version,trace_id:$trace_id,decision_id:$decision_id,
      policy_id:$policy_id,component:$component,event:$event,outcome:$outcome,
      detail:(if $detail=="" then null else $detail end)}' >>"${events_path}"
}

fail=0
note() { printf '%s\n' "$1" | tee -a "$report_path"; }
check() {
  if [[ "$1" -eq 0 ]]; then note "PASS  $2"; append_event check ok "$2"
  else note "FAIL  $2"; append_event check fail "$2"; fail=1; fi
}

append_event "gate.start" "info" "mode=${mode}"

for f in "$matrix_json" "$wasm_src" "$readme"; do
  [[ -f "$f" ]] || { note "FAIL  missing required file: $f"; fail=1; }
done

# A failed [[ ]] must record a FAIL, not abort under `set -e`.
set +e

# --- F.1: 016-021 stay HYPOTHESIS (zero-capability formal verification) ---
for n in 016 017 018 019 020 021; do
  st="$(jq -r --arg id "FE-CLAIM-${n}" '.claims[] | select(.claim_id==$id) | .allowed_state' "$matrix_json" 2>/dev/null)"
  [[ "$st" == "hypothesis" ]]
  check $? "matrix: FE-CLAIM-${n} allowed_state == hypothesis (got '${st}')"
done
if [[ -f "$g10_doc" ]]; then
  grep -qF "STAY_HYPOTHESIS" "$g10_doc"; check $? "G.10 decision doc: STAY_HYPOTHESIS"
fi

# --- F.2: WASM lane doc keeps its no-execution honesty ---
grep -qF "non-constant WASM function does not execute here" "$wasm_src"
check $? "wasm doc: 'non-constant WASM function does not execute here'"
grep -qF "out of scope for the JS lane" "$wasm_src"
check $? "wasm doc: WASM 'out of scope for the JS lane'"
# Single-line anchor: the full "not itself compiled to or executed as WebAssembly"
# sentence is wrapped across two doc lines, so match a unique single-line span.
grep -qF "the model runs as native Rust today" "$wasm_src"
check $? "wasm doc: signal graph 'runs as native Rust today' (not executed as WebAssembly)"
# No positive over-claim of a general WASM interpreter (the honest doc only ever
# says it is NOT one; a bare positive assertion is drift).
if grep -niE "is a general (web ?assembly|wasm) interpreter" "$wasm_src" \
   | grep -vniE "neither is a general|not a general" >/dev/null 2>&1; then
  over=1; else over=0; fi
[[ "$over" -eq 0 ]]
check $? "wasm doc: no bare 'is a general WebAssembly interpreter' over-claim"

# --- F.2: README keeps WASM out-of-scope ---
grep -qF "Out of scope for the JS lane" "$readme"
check $? "README: WASM 'Out of scope for the JS lane'"
grep -qF "not yet exposed via the JS module loader" "$readme"
check $? "README: WASM 'not yet exposed via the JS module loader'"

set -e

verdict=$([[ "$fail" -eq 0 ]] && echo "pass" || echo "fail")
report_sha="$(sha256sum "$report_path" | cut -d' ' -f1)"
events_sha="$(sha256sum "$events_path" | cut -d' ' -f1)"
git_rev="$(git rev-parse HEAD 2>/dev/null || echo unknown)"

jq -nc --arg schema_version "${schema_ns}.trace-ids.v1" --arg trace_id "${trace_id}" \
  --arg decision_id "${decision_id}" --arg policy_id "${policy_id}" --arg component "${component}" \
  '{schema_version:$schema_version,trace_id:$trace_id,decision_id:$decision_id,
    policy_id:$policy_id,component:$component}' >"$trace_ids_path"

jq -n --arg schema_version "${schema_ns}.run-manifest.v1" --arg mode "${mode}" \
  --arg verdict "${verdict}" --arg trace_id "${trace_id}" --arg git_rev "${git_rev}" \
  --arg report_sha256 "${report_sha}" --arg events_sha256 "${events_sha}" \
  --arg owning_bead "bd-sde5e.6.3" \
  '{schema_version:$schema_version,mode:$mode,verdict:$verdict,trace_id:$trace_id,
    git_rev:$git_rev,
    artifacts:{honesty_report:"honesty_report.txt",events:"events.jsonl",
               trace_ids:"trace_ids.json",commands:"commands.txt",step_logs:"step_logs"},
    content_hashes:{"honesty_report.txt":$report_sha256,"events.jsonl":$events_sha256},
    owning_bead:$owning_bead}' >"$manifest_path"

append_event "gate.end" "$verdict" "run_dir=${run_dir}"
echo "fe_formal_wasm_honesty_report=${report_path}"
echo "fe_formal_wasm_honesty_manifest=${manifest_path}"
echo "fe_formal_wasm_honesty_run_dir=${run_dir}"
echo "fe_formal_wasm_honesty_verdict=${verdict}"
[[ "$fail" -eq 0 ]] || exit 1
exit 0
