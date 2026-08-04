#!/usr/bin/env bash
# CEI D.3 (bd-sde5e.4.3) gate — Test262 posture cross-file consistency.
#
# Locks the *honest* Test262 posture against drift. The reframed wording from D.1
# (bd-sde5e.4.1) says the project runs a checked-in es2020-normative subset, NOT
# the full official tc39/test262 corpus (`full_suite_claim_allowed=false`,
# `full-suite conformance is TARGETED`). Three independent surfaces must agree:
#
#   1. docs/test262_compatibility_pass_rate_v1.json  (the measured posture)
#   2. docs/claim_to_proof_matrix_v1.json            (FE-CLAIM-TEST262 row)
#   3. README.md                                     (the claim wording)
#
# The existing scripts/e2e/test262_compatibility_pass_rate_replay.sh checks the
# posture JSON *internally* (schema, count-sum, pass-rate arithmetic). This gate
# is the missing CROSS-FILE check: it fails closed if any surface drifts toward
# claiming full-suite conformance that the measured evidence does not support, or
# if the matrix over-promotes FE-CLAIM-TEST262 above `target`.
#
# Modes:
#   ci | check   run the consistency checks; fail closed on any drift.
#
# Standard bundle under artifacts/test262_posture_consistency/<ts>/.
# Honors TEST262_POSTURE_CONSISTENCY_REPLAY_RUN_DIR for a pinned run dir.
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
case "$mode" in
  ci | check) ;;
  *)
    echo "usage: run_test262_posture_consistency.sh [ci|check] [run_dir]" >&2
    exit 2
    ;;
esac

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for the test262 posture consistency gate" >&2
  exit 2
fi

posture_json="docs/test262_compatibility_pass_rate_v1.json"
posture_md="docs/TEST262_COMPATIBILITY_POSTURE.md"
matrix_json="docs/claim_to_proof_matrix_v1.json"
readme="README.md"

artifact_root="${TEST262_POSTURE_CONSISTENCY_ARTIFACT_ROOT:-artifacts/test262_posture_consistency}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
default_run_dir="${TEST262_POSTURE_CONSISTENCY_REPLAY_RUN_DIR:-${artifact_root}/${timestamp}}"
run_dir="${2:-$default_run_dir}"
report_path="${run_dir}/consistency_report.txt"
manifest_path="${run_dir}/run_manifest.json"
commands_path="${run_dir}/commands.txt"
events_path="${run_dir}/events.jsonl"
trace_ids_path="${run_dir}/trace_ids.json"
step_logs_dir="${run_dir}/step_logs"
mkdir -p "$run_dir" "$step_logs_dir"
: >"$commands_path"
: >"$events_path"
: >"$report_path"

trace_id="trace-test262-posture-consistency-${timestamp}"
decision_id="decision-test262-posture-consistency-${timestamp}"
policy_id="policy-test262-posture-consistency-v1"
component="test262_posture_consistency_gate"
schema_ns="franken-engine.test262-posture-consistency-gate"

append_event() {
  jq -nc \
    --arg schema_version "${schema_ns}.event.v1" \
    --arg trace_id "${trace_id}" \
    --arg decision_id "${decision_id}" \
    --arg policy_id "${policy_id}" \
    --arg component "${component}" \
    --arg event "$1" --arg outcome "$2" --arg detail "$3" \
    '{schema_version:$schema_version,trace_id:$trace_id,decision_id:$decision_id,
      policy_id:$policy_id,component:$component,event:$event,outcome:$outcome,
      detail:(if $detail=="" then null else $detail end)}' >>"${events_path}"
}

fail=0
note() { printf '%s\n' "$1" | tee -a "$report_path"; }
check() {
  # check <ok:0|1> <label>
  if [[ "$1" -eq 0 ]]; then
    note "PASS  $2"
    append_event "check" "ok" "$2"
  else
    note "FAIL  $2"
    append_event "check" "fail" "$2"
    fail=1
  fi
}

append_event "gate.start" "info" "mode=${mode}"

# --- preflight: required files exist ---
for f in "$posture_json" "$matrix_json" "$readme"; do
  if [[ ! -f "$f" ]]; then
    note "FAIL  missing required file: $f"
    fail=1
  fi
done

# --- 1. posture JSON: provisional + full-suite NOT claimed ---
proof_state="$(jq -r '.proof_state // ""' "$posture_json" 2>/dev/null || echo "")"
# NB: do NOT use `// ""` here — jq's `//` treats the boolean `false` as empty and
# would yield "", masking the honest posture. Read the raw boolean.
full_suite="$(jq -r 'if has("full_suite_claim_allowed") then (.full_suite_claim_allowed|tostring) else "" end' "$posture_json" 2>/dev/null || echo "")"
denominator="$(jq -r '.denominator // 0' "$posture_json" 2>/dev/null || echo 0)"
passed="$(jq -r '.passed // 0' "$posture_json" 2>/dev/null || echo 0)"
failed="$(jq -r '.failed // 0' "$posture_json" 2>/dev/null || echo 0)"
skipped="$(jq -r '.skipped // 0' "$posture_json" 2>/dev/null || echo 0)"
waived="$(jq -r '.waived // 0' "$posture_json" 2>/dev/null || echo 0)"
timed_out="$(jq -r '.timed_out // 0' "$posture_json" 2>/dev/null || echo 0)"
crashed="$(jq -r '.crashed // 0' "$posture_json" 2>/dev/null || echo 0)"
pass_rate="$(jq -r '.pass_rate_millionths // 0' "$posture_json" 2>/dev/null || echo 0)"

# A failed test ([[ ... ]] returning 1) must record a FAIL, not abort the gate
# under `set -e`. Disable errexit across the check region; re-enable afterwards.
set +e

[[ "$full_suite" == "false" ]]; check $? "posture json: full_suite_claim_allowed == false (got '${full_suite}')"
[[ "$proof_state" == "checked_in_vectors_provisional" ]]; check $? "posture json: proof_state is provisional (got '${proof_state}')"

# count-sum + pass-rate arithmetic must be internally honest
counter_sum=$((passed + failed + skipped + waived + timed_out + crashed))
[[ "$denominator" -gt 0 && "$counter_sum" -eq "$denominator" ]]
check $? "posture json: counts sum to denominator (${counter_sum} == ${denominator})"
if [[ "$denominator" -gt 0 ]]; then
  expected_rate=$((passed * 1000000 / denominator))
else
  expected_rate=-1
fi
[[ "$expected_rate" -eq "$pass_rate" ]]
check $? "posture json: pass_rate_millionths matches passed/denominator (${expected_rate} == ${pass_rate})"

# --- 2. matrix: FE-CLAIM-TEST262 must be 'target' (never over-promoted to observed) ---
t262_state="$(jq -r '.claims[] | select(.claim_id=="FE-CLAIM-TEST262") | .allowed_state' "$matrix_json" 2>/dev/null || echo "")"
t262_wording="$(jq -r '.claims[] | select(.claim_id=="FE-CLAIM-TEST262") | .actual_wording_state' "$matrix_json" 2>/dev/null || echo "")"
[[ "$t262_state" == "target" || "$t262_state" == "hypothesis" ]]
check $? "matrix: FE-CLAIM-TEST262 allowed_state is target/hypothesis, not observed (got '${t262_state}')"
[[ "$t262_wording" == "target" || "$t262_wording" == "hypothesis" ]]
check $? "matrix: FE-CLAIM-TEST262 actual_wording_state is target/hypothesis (got '${t262_wording}')"

# --- 3. README: honest wording present, over-claim absent ---
grep -qF "full-suite conformance is TARGETED" "$readme"
check $? "README: contains 'full-suite conformance is TARGETED'"
grep -qF "full_suite_claim_allowed=false" "$readme"
check $? "README: contains 'full_suite_claim_allowed=false'"

# Forbidden over-claims: full Test262 conformance asserted as a present fact.
overclaim=0
if grep -niE "passes the (full|entire|complete) (official )?test262" "$readme" >/dev/null 2>&1; then overclaim=1; fi
if grep -niE "full (official )?test262 (suite )?conformance (is )?(OBSERVED|achieved|passing)" "$readme" >/dev/null 2>&1; then overclaim=1; fi
[[ "$overclaim" -eq 0 ]]
check $? "README: no full-suite Test262 conformance over-claim present"

# --- 4. posture MD doc: consistent provisional language ---
if [[ -f "$posture_md" ]]; then
  grep -qiE "provisional|not a full official Test262 pass-rate" "$posture_md"
  check $? "posture md: states provisional / not-full-official"
fi

# --- emit standard bundle ---
set -e
verdict=$([[ "$fail" -eq 0 ]] && echo "pass" || echo "fail")
report_sha="$(sha256sum "$report_path" | cut -d' ' -f1)"
events_sha="$(sha256sum "$events_path" | cut -d' ' -f1)"
git_rev="$(git rev-parse HEAD 2>/dev/null || echo unknown)"

jq -nc \
  --arg schema_version "${schema_ns}.trace-ids.v1" \
  --arg trace_id "${trace_id}" --arg decision_id "${decision_id}" \
  --arg policy_id "${policy_id}" --arg component "${component}" \
  '{schema_version:$schema_version,trace_id:$trace_id,decision_id:$decision_id,
    policy_id:$policy_id,component:$component}' >"$trace_ids_path"

jq -n \
  --arg schema_version "${schema_ns}.run-manifest.v1" \
  --arg mode "${mode}" --arg verdict "${verdict}" \
  --arg t262_state "${t262_state}" --arg full_suite "${full_suite}" \
  --argjson pass_rate_millionths "${pass_rate}" \
  --arg trace_id "${trace_id}" --arg git_rev "${git_rev}" \
  --arg report_sha256 "${report_sha}" --arg events_sha256 "${events_sha}" \
  --arg owning_bead "bd-sde5e.4.3" \
  '{schema_version:$schema_version,mode:$mode,verdict:$verdict,
    test262_matrix_state:$t262_state,full_suite_claim_allowed:$full_suite,
    pass_rate_millionths:$pass_rate_millionths,trace_id:$trace_id,git_rev:$git_rev,
    artifacts:{consistency_report:"consistency_report.txt",events:"events.jsonl",
               trace_ids:"trace_ids.json",commands:"commands.txt",step_logs:"step_logs"},
    content_hashes:{"consistency_report.txt":$report_sha256,"events.jsonl":$events_sha256},
    owning_bead:$owning_bead}' >"$manifest_path"

append_event "gate.end" "$verdict" "run_dir=${run_dir}"

echo "test262_posture_consistency_report=${report_path}"
echo "test262_posture_consistency_manifest=${manifest_path}"
echo "test262_posture_consistency_run_dir=${run_dir}"
echo "test262_posture_consistency_verdict=${verdict}"

[[ "$fail" -eq 0 ]] || exit 1
exit 0
