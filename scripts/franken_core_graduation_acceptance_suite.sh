#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${FRANKEN_CORE_ACCEPTANCE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-core-graduation-acceptance}"
run_id="${FRANKEN_CORE_ACCEPTANCE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${FRANKEN_CORE_ACCEPTANCE_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${FRANKEN_CORE_ACCEPTANCE_SOURCE_REVISION:-}"

contract_json="${root_dir}/docs/franken_core_graduation_contract_v1.json"
parity_json="${root_dir}/docs/franken_core_api_parity_ledger_v1.json"
validation_contract_json="${root_dir}/docs/franken_core_validation_impact_planner_v1.json"
status_contract_json="${root_dir}/docs/franken_core_status_truth_gate_v1.json"
no_mock_contract_json="${root_dir}/docs/franken_core_no_mock_graduation_drill_v1.json"
staged_contract_json="${root_dir}/docs/franken_core_staged_inclusion_rehearsal_v1.json"
golden_json="${root_dir}/scripts/testdata/franken_core_graduation_golden_reports/reports.json"
root_cargo="${root_dir}/Cargo.toml"
core_cargo="${root_dir}/crates/franken-core/Cargo.toml"
declare -a status_claim_files=()
original_args=("$@")

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/franken_core_graduation_acceptance_suite.sh [OPTIONS]

Options:
  --contract-json PATH
  --parity-json PATH
  --validation-contract-json PATH
  --status-contract-json PATH
  --no-mock-contract-json PATH
  --staged-contract-json PATH
  --golden-json PATH
  --root-cargo PATH
  --core-cargo PATH
  --status-claim-file PATH      May be repeated.
  --source-revision REV
  --output-dir DIR
  --skip-child-smokes

The suite is proof-only and does not edit manifests or run Cargo/RCH.
EOF
}

skip_child_smokes=false
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --contract-json) contract_json="${2:-}"; shift 2 ;;
    --parity-json) parity_json="${2:-}"; shift 2 ;;
    --validation-contract-json) validation_contract_json="${2:-}"; shift 2 ;;
    --status-contract-json) status_contract_json="${2:-}"; shift 2 ;;
    --no-mock-contract-json) no_mock_contract_json="${2:-}"; shift 2 ;;
    --staged-contract-json) staged_contract_json="${2:-}"; shift 2 ;;
    --golden-json) golden_json="${2:-}"; shift 2 ;;
    --root-cargo) root_cargo="${2:-}"; shift 2 ;;
    --core-cargo) core_cargo="${2:-}"; shift 2 ;;
    --status-claim-file) status_claim_files+=("${2:-}"); shift 2 ;;
    --source-revision) source_revision="${2:-}"; shift 2 ;;
    --output-dir) run_dir="${2:-}"; shift 2 ;;
    --skip-child-smokes) skip_child_smokes=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown option: %s\n' "$1" >&2; usage; exit 64 ;;
  esac
done

if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse --short HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
report_json="${run_dir}/acceptance_report.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_md="${run_dir}/report.md"
violations_jsonl="${run_dir}/violations.jsonl"
child_results_jsonl="${run_dir}/child_results.jsonl"
status_output_dir="${run_dir}/status_truth_gate"

: >"$events_path"
: >"$violations_jsonl"
: >"$child_results_jsonl"

printf './scripts/franken_core_graduation_acceptance_suite.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

append_violation() {
  local code="$1"
  local path="$2"
  local detail="$3"
  local remediation="$4"
  jq -nc --arg code "$code" --arg path "$path" --arg detail "$detail" --arg remediation "$remediation" \
    '{code:$code,path:$path,detail:$detail,remediation:$remediation}' >>"$violations_jsonl"
}

record_child() {
  local name="$1"
  local status="$2"
  jq -nc --arg name "$name" --arg status "$status" '{name:$name,status:$status}' >>"$child_results_jsonl"
}

toml_array_values() {
  local file="$1"
  local key="$2"
  awk -v key="$key" '
    BEGIN { state = 0 }
    {
      line = $0
      sub(/[[:space:]]*#.*/, "", line)
      if (state == 0 && line ~ "^[[:space:]]*" key "[[:space:]]*=") {
        state = 1
      }
      if (state == 1) {
        while (match(line, /"[^"]+"/)) {
          print substr(line, RSTART + 1, RLENGTH - 2)
          line = substr(line, RSTART + RLENGTH)
        }
        if (index($0, "]") > 0) {
          exit
        }
      }
    }
  ' "$file"
}

toml_array_contains() {
  local file="$1"
  local key="$2"
  local value="$3"
  if [[ ! -f "$file" ]]; then
    printf 'false\n'
  elif toml_array_values "$file" "$key" | grep -Fxq "$value"; then
    printf 'true\n'
  else
    printf 'false\n'
  fi
}

run_child_smoke() {
  local name="$1"
  shift
  set +e
  "$@" >/dev/null 2>"${run_dir}/${name}.stderr.log"
  local status=$?
  set -e
  if [[ "$status" -eq 0 ]]; then
    record_child "$name" "pass"
  else
    record_child "$name" "fail"
    append_violation "child_smoke_failed" "$name" "exit status ${status}" "Run and fix ${name}; stderr is in the acceptance output directory."
  fi
}

required_artifacts=(
  "$contract_json"
  "$parity_json"
  "$validation_contract_json"
  "$status_contract_json"
  "$no_mock_contract_json"
  "$staged_contract_json"
  "$golden_json"
)

for artifact in "${required_artifacts[@]}"; do
  if [[ ! -f "$artifact" ]]; then
    append_violation "missing_child_artifact" "$artifact" "required child artifact missing" "Restore the missing IDEA-WIZARD-V child artifact before acceptance."
  fi
done

if [[ "$skip_child_smokes" != "true" ]]; then
  run_child_smoke "graduation_contract" "${root_dir}/scripts/e2e/franken_core_graduation_contract_smoke.sh" check
  run_child_smoke "api_parity_ledger" "${root_dir}/scripts/e2e/franken_core_api_parity_ledger_smoke.sh" check
  run_child_smoke "validation_impact_planner" "${root_dir}/scripts/e2e/franken_core_validation_impact_planner_smoke.sh" check
  run_child_smoke "status_truth_gate" "${root_dir}/scripts/e2e/franken_core_status_truth_gate_smoke.sh" check
  run_child_smoke "no_mock_graduation_drill" "${root_dir}/scripts/e2e/franken_core_no_mock_graduation_drill_smoke.sh" check
  run_child_smoke "staged_inclusion_rehearsal" "${root_dir}/scripts/e2e/franken_core_staged_inclusion_rehearsal_smoke.sh" check
  run_child_smoke "golden_reports" "${root_dir}/scripts/e2e/franken_core_graduation_golden_reports_smoke.sh" check
fi

if [[ -f "$parity_json" ]]; then
  if ! jq -e '.summary.unclassified_row_count == 0 and all(.rows[]; .status != "unclassified")' "$parity_json" >/dev/null; then
    append_violation "unclassified_api_rows" "$parity_json" "API parity ledger contains unclassified rows" "Classify every parity row before acceptance."
  fi
fi

if [[ -f "$validation_contract_json" ]]; then
  if ! jq -e '
    (.required_change_classes | sort) == [
      "cargo_topology",
      "docs_only",
      "extension_host_adjacent",
      "franken_core_only",
      "franken_engine_api_adjacent",
      "script_only",
      "unknown_path"
    ]
  ' "$validation_contract_json" >/dev/null; then
    append_violation "unknown_validation_class" "$validation_contract_json" "validation planner class set drifted" "Restore the known validation class vocabulary before acceptance."
  fi
fi

if [[ -f "$golden_json" ]]; then
  if ! jq -e '
    ([.reports[].family] | sort) == [
      "api_parity_ledger",
      "graduation_contract",
      "negative_status_truth_gate_overclaim",
      "no_mock_graduation_drill",
      "staged_inclusion_rehearsal",
      "status_truth_gate",
      "validation_impact_planner"
    ]
  ' "$golden_json" >/dev/null; then
    append_violation "missing_golden_coverage" "$golden_json" "golden report coverage is incomplete" "Regenerate and review franken-core graduation goldens."
  fi
fi

status_cmd=(
  "${root_dir}/scripts/franken_core_status_truth_gate.sh"
  --root-cargo "$root_cargo"
  --core-cargo "$core_cargo"
  --source-revision "$source_revision"
  --output-dir "$status_output_dir"
)
for claim_file in "${status_claim_files[@]}"; do
  status_cmd+=(--claim-file "$claim_file")
done
set +e
"${status_cmd[@]}" >/dev/null 2>"${run_dir}/acceptance_status_truth.stderr.log"
status_truth_exit=$?
set -e
if [[ "$status_truth_exit" -ne 0 ]]; then
  append_violation "stale_docs_or_manifest_claim" "$status_output_dir/truth_report.json" "status truth gate exited ${status_truth_exit}" "Fix stale or contradictory franken-core docs/manifests before acceptance."
fi

members_contains_core="$(toml_array_contains "$root_cargo" "members" "crates/franken-core")"
exclude_contains_core="$(toml_array_contains "$root_cargo" "exclude" "crates/franken-core")"
root_workspace_state="unknown"
if [[ "$exclude_contains_core" == "true" && "$members_contains_core" == "false" ]]; then
  root_workspace_state="excluded_standalone"
elif [[ "$members_contains_core" == "true" && "$exclude_contains_core" == "false" ]]; then
  root_workspace_state="already_included"
else
  root_workspace_state="ambiguous"
fi
if [[ "$root_workspace_state" == "already_included" ]]; then
  append_violation "workspace_already_changed" "$root_cargo" "franken-core already appears as a workspace member" "This acceptance suite only approves readiness for a later explicit topology bead; it must not run after silent membership changes."
fi

violations_json="$(jq -s 'sort_by(.code, .path, .detail)' "$violations_jsonl")"
reason_codes_json="$(jq -s '[.[].code] | unique | sort' "$violations_jsonl")"
violation_count="$(jq -s 'length' "$violations_jsonl")"
child_results_json="$(jq -s 'sort_by(.name)' "$child_results_jsonl")"

decision="ready_for_explicit_workspace_membership_bead"
if [[ "$violation_count" -ne 0 ]]; then
  decision="remain_excluded"
fi

final_proof_commands_json="$(jq -n '[
  "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_franken_core_membership CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo check --all-targets",
  "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_franken_core_membership CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo clippy --all-targets -- -D warnings",
  "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_franken_core_membership CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test"
]')"

jq -n \
  --arg schema_version "franken-engine.franken-core-graduation-acceptance-report.v1" \
  --arg source_revision "$source_revision" \
  --arg decision "$decision" \
  --arg root_workspace_state "$root_workspace_state" \
  --argjson child_results "$child_results_json" \
  --argjson reason_codes "$reason_codes_json" \
  --argjson violation_count "$violation_count" \
  --argjson violations "$violations_json" \
  --argjson final_proof_commands "$final_proof_commands_json" \
  --arg report_json "$report_json" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_md "$report_md" \
  '{
    schema_version:$schema_version,
    source_revision:$source_revision,
    decision:$decision,
    root_workspace_state:$root_workspace_state,
    workspace_membership_complete:false,
    ready_for_explicit_change:($decision == "ready_for_explicit_workspace_membership_bead"),
    child_results:$child_results,
    reason_codes:$reason_codes,
    violation_count:$violation_count,
    violations:$violations,
    final_proof_commands:$final_proof_commands,
    next_recommendation:(if $decision == "ready_for_explicit_workspace_membership_bead" then "open a separate explicit workspace-membership bead if operators want to change Cargo.toml" else "keep crates/franken-core excluded and fix fail-closed violations" end),
    coordination_handling:{
      agent_mail_required:false,
      degraded_agent_mail_fallback:"use Beads assignment plus Git commits as the soft lock; record Agent Mail outage in handoff"
    },
    non_mutation_attestation:{
      mutates_root_cargo_toml:false,
      runs_cargo:false,
      runs_rch:false,
      changes_workspace_membership:false
    },
    artifact_paths:{
      acceptance_report_json:$report_json,
      events_jsonl:$events_path,
      commands_txt:$commands_path,
      report_md:$report_md
    }
  }' >"$report_json"

jq -nc --arg schema_version "franken-engine.franken-core-graduation-acceptance.event.v1" --arg event "acceptance_complete" --arg outcome "$decision" --arg source_revision "$source_revision" \
  '{schema_version:$schema_version,event:$event,outcome:$outcome,source_revision:$source_revision}' >>"$events_path"

{
  printf '# Franken-Core Graduation Acceptance\n\n'
  printf -- '- decision: `%s`\n' "$decision"
  printf -- '- root_workspace_state: `%s`\n' "$root_workspace_state"
  printf -- '- workspace_membership_complete: `false`\n'
  printf '\n## Final Proof Commands\n\n'
  jq -r '.final_proof_commands[] | "- " + .' "$report_json"
  if [[ "$violation_count" -ne 0 ]]; then
    printf '\n## Fail-Closed Violations\n\n'
    jq -r '.violations[] | "- " + .code + " at " + .path + " - " + .remediation' "$report_json"
  fi
} >"$report_md"

{
  printf '\nfinal proof commands:\n'
  jq -r '.final_proof_commands[] | "- " + .' "$report_json"
} >>"$commands_path"

if [[ "$decision" == "remain_excluded" ]]; then
  exit 42
fi
exit 0
