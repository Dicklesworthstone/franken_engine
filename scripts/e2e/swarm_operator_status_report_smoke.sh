#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
reporter="${root_dir}/scripts/swarm_operator_status_report.sh"
golden_dir="${root_dir}/scripts/testdata/goldens"

record_pass() {
  printf 'PASS swarm-operator-status %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-operator-status %s\n' "$1" >&2
}

canonicalize_status() {
  local status_path="$1"
  local tmp_root="$2"

  jq --arg tmp_root "$tmp_root" '
    def scrub:
      if type == "object" then
        with_entries(.value |= scrub)
      elif type == "array" then
        map(scrub)
      elif type == "string" then
        split($tmp_root) | join("[SMOKE_ROOT]")
      else
        .
      end;
    scrub
    | del(.artifact_paths)
  ' "$status_path"
}

compare_case_golden() {
  local case_name="$1"
  local actual_path="$2"
  local golden_path="$3"

  if [[ "${UPDATE_GOLDENS:-0}" == "1" ]]; then
    cp "$actual_path" "$golden_path"
    record_pass "updated golden ${case_name}"
    return 0
  fi

  if [[ ! -f "$golden_path" ]]; then
    record_failure "missing golden ${golden_path}"
    return 1
  fi

  if ! diff -u "$golden_path" "$actual_path"; then
    record_failure "golden drift for ${case_name}; set UPDATE_GOLDENS=1 only after reviewing the diff"
    return 1
  fi

  record_pass "golden matches ${case_name}"
}

write_healthy_fixtures() {
  local fixture_dir="$1"

  jq -n '[{id:"bd-p03vs", title:"Typed proof-evidence index", priority:1, status:"open", assignee:null}]' >"${fixture_dir}/ready.json"
  jq -n '[{id:"bd-0ub12", title:"Semantic dark matter scoring", priority:1, status:"in_progress", assignee:"CyanOak"}]' >"${fixture_dir}/in_progress.json"
  jq -n '{plan:{tracks:[{track_id:"track-B", items:[{id:"bd-p03vs", title:"Typed proof-evidence index", priority:1, status:"open"}]}]}}' >"${fixture_dir}/bv_plan.json"
  jq -n '[{path:"scripts/swarm_operator_status_report.sh", holder:"SandyThrush", exclusive:true}]' >"${fixture_dir}/reservations.json"
  jq -n '{decision:"admit", findings:[]}' >"${fixture_dir}/resource_decision.json"
  jq -n '{decision:"admit", commands:[{command_id:"script-check", display:"bash -n scripts/swarm_operator_status_report.sh"}], omitted_commands:[]}' >"${fixture_dir}/validation_plan.json"
  jq -n '{queries:[{name:"recent_failed_gates", row_count:0},{name:"proof_by_bead", row_count:2}]}' >"${fixture_dir}/proof_index.json"
  jq -n '[{bead_id:"bd-1onpa", artifact_id:"plan", status:"pass"}]' >"${fixture_dir}/proof_outcomes.json"
  jq -n '[]' >"${fixture_dir}/stale_evidence.json"
  jq -n '[]' >"${fixture_dir}/dirty_files.json"
}

write_degraded_fixtures() {
  local fixture_dir="$1"

  jq -n '[{id:"bd-4kwo8", title:"Dark matter board receipts", priority:1, status:"open", assignee:null}]' >"${fixture_dir}/ready.json"
  jq -n '[{id:"bd-0ub12", title:"Semantic dark matter scoring", priority:1, status:"in_progress", assignee:"CyanOak"}]' >"${fixture_dir}/in_progress.json"
  jq -n '{plan:{tracks:[{track_id:"track-A", items:[{id:"bd-blocked", title:"Blocked dependent bead", priority:1, status:"blocked"}]}]}}' >"${fixture_dir}/bv_plan.json"
  jq -n '[{path:"crates/franken-engine/src/semantic_dark_matter_engine.rs", holder:"CyanOak", exclusive:true}]' >"${fixture_dir}/reservations.json"
  jq -n '{decision:"defer", findings:[{signal:"active_compile_count", decision:"defer"}]}' >"${fixture_dir}/resource_decision.json"
  jq -n '{decision:"fail_closed", commands:[], omitted_commands:[{kind:"unknown_path_mapping", path:"unknown/path.rs"}]}' >"${fixture_dir}/validation_plan.json"
  jq -n '{queries:[]}' >"${fixture_dir}/proof_index.json"
  jq -n '[{bead_id:"bd-0ub12", artifact_id:"semantic-proof", status:"blocked"}]' >"${fixture_dir}/proof_outcomes.json"
  jq -n '[{artifact_id:"old-proof", stale:true, age_hours:72}]' >"${fixture_dir}/stale_evidence.json"
  jq -n '[{path:"crates/franken-engine/src/semantic_dark_matter_engine.rs", reserved:true, overlaps_ready:true}]' >"${fixture_dir}/dirty_files.json"
}

run_case() {
  local case_name="$1"
  local expected_status="$2"
  local agent_mail_status="$3"
  local rch_status="$4"
  local proof_index_status="$5"
  local tmp_root="$6"
  local fixture_dir="${tmp_root}/${case_name}-fixtures"
  local output_dir="${tmp_root}/${case_name}-out"
  local actual_path="${tmp_root}/${case_name}.actual.golden"
  local golden_path="${golden_dir}/swarm_operator_status_report_${case_name}.golden"

  mkdir -p "$fixture_dir"
  if [[ "$case_name" == "healthy" ]]; then
    write_healthy_fixtures "$fixture_dir"
  else
    write_degraded_fixtures "$fixture_dir"
  fi

  "$reporter" \
    --bead-id bd-jw854 \
    --source-revision smoke-rev \
    --output-dir "$output_dir" \
    --agent-mail-status "$agent_mail_status" \
    --rch-status "$rch_status" \
    --proof-index-status "$proof_index_status" \
    --ready-json "${fixture_dir}/ready.json" \
    --in-progress-json "${fixture_dir}/in_progress.json" \
    --bv-plan-json "${fixture_dir}/bv_plan.json" \
    --reservations-json "${fixture_dir}/reservations.json" \
    --resource-decision-json "${fixture_dir}/resource_decision.json" \
    --validation-plan-json "${fixture_dir}/validation_plan.json" \
    --proof-index-json "${fixture_dir}/proof_index.json" \
    --proof-outcomes-json "${fixture_dir}/proof_outcomes.json" \
    --stale-evidence-json "${fixture_dir}/stale_evidence.json" \
    --dirty-files-json "${fixture_dir}/dirty_files.json" >/dev/null

  jq -e --arg expected_status "$expected_status" '
    .schema_version == "franken-engine.swarm-operator-status-report.v1"
    and .status == $expected_status
    and .tui_ready == true
    and (.recommendations | length) >= 1
  ' "${output_dir}/status.json" >/dev/null
  record_pass "${case_name} report validates"

  canonicalize_status "${output_dir}/status.json" "$tmp_root" >"$actual_path"
  compare_case_golden "$case_name" "$actual_path" "$golden_path"
}

run_selftest() {
  local tmp_parent tmp_root

  tmp_parent="${SWARM_OPERATOR_STATUS_REPORT_SMOKE_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/swarm-operator-status.XXXXXX")"

  run_case "healthy" "healthy" "ok" "ok" "ok" "$tmp_root"
  run_case "degraded" "degraded" "missing" "missing" "missing" "$tmp_root"

  printf 'swarm_operator_status_report_smoke_artifacts=%s\n' "$tmp_root"
}

case "${1:-check}" in
  check|selftest)
    run_selftest
    ;;
  *)
    record_failure "unknown mode: ${1:-}"
    exit 64
    ;;
esac
