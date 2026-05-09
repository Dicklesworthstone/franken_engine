#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
bundle_script="${root_dir}/scripts/swarm_live_readonly_snapshot_bundle.sh"
profile_path="${root_dir}/docs/swarm_live_readonly_capture_profile_v1.json"
fixtures_path="${SWARM_LIVE_READONLY_SNAPSHOT_FIXTURES:-${root_dir}/scripts/testdata/swarm_live_readonly_snapshot/cases.json}"
mode="${1:-check}"
output_dir="${2:-${SWARM_LIVE_READONLY_SNAPSHOT_OUTPUT_DIR:-}}"
failures=0

record_pass() {
  printf 'PASS swarm-live-readonly-snapshot %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-live-readonly-snapshot %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_live_readonly_snapshot_bundle_smoke.sh [check|run|selftest] [output_dir]
EOF
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-live-readonly-snapshot-fixtures.v1"
    and (.cases | length >= 5)
    and (.cases | map(.case_id) | index("healthy") != null)
    and (.cases | map(.case_id) | index("missing_optional_sources") != null)
    and (.cases | map(.case_id) | index("stale_required_live_state") != null)
    and (.cases | map(.case_id) | index("malformed_required_rch_status") != null)
    and (.cases | map(.case_id) | index("rch_local_fallback_marker") != null)
    and (.cases | map(.case_id) | index("mutating_proof_transcript") != null)
    and all(.cases[]; has("inputs") and has("expected"))
  ' "$fixtures_path" >/dev/null
}

write_json_input() {
  local case_json="$1"
  local jq_path="$2"
  local output_path="$3"
  if jq -e "${jq_path} != null" <<<"$case_json" >/dev/null; then
    jq "$jq_path" <<<"$case_json" >"$output_path"
    printf '%s' "$output_path"
  fi
}

write_raw_input() {
  local case_json="$1"
  local jq_path="$2"
  local output_path="$3"
  if jq -e "${jq_path} != null" <<<"$case_json" >/dev/null; then
    jq -r "$jq_path" <<<"$case_json" >"$output_path"
    printf '%s' "$output_path"
  fi
}

add_arg_if_present() {
  local -n args_ref="$1"
  local flag="$2"
  local path="$3"
  if [[ -n "$path" ]]; then
    args_ref+=("$flag" "$path")
  fi
}

run_case() {
  local case_json="$1"
  local root="$2"
  local case_id case_dir out_dir swarm_ops br_ready br_in_progress br_sync bv_plan agent_mail rch_status rch_queue git_status git_diff resource_pressure proof_transcript
  local args=()

  case_id="$(jq -r '.case_id' <<<"$case_json")"
  case_dir="${root}/${case_id}"
  out_dir="${case_dir}/out"
  mkdir -p "$case_dir"

  swarm_ops="$(write_json_input "$case_json" '.inputs.swarm_ops_state' "${case_dir}/swarm_ops_state.json")"
  br_ready="$(write_json_input "$case_json" '.inputs.br_ready' "${case_dir}/br_ready.json")"
  br_in_progress="$(write_json_input "$case_json" '.inputs.br_in_progress' "${case_dir}/br_in_progress.json")"
  br_sync="$(write_json_input "$case_json" '.inputs.br_sync_status' "${case_dir}/br_sync_status.json")"
  bv_plan="$(write_json_input "$case_json" '.inputs.bv_plan' "${case_dir}/bv_plan.json")"
  agent_mail="$(write_json_input "$case_json" '.inputs.agent_mail_snapshot' "${case_dir}/agent_mail_snapshot.json")"
  rch_status="$(write_json_input "$case_json" '.inputs.rch_status' "${case_dir}/rch_status.json")"
  if jq -e '.inputs.rch_status_raw != null' <<<"$case_json" >/dev/null; then
    rch_status="$(write_raw_input "$case_json" '.inputs.rch_status_raw' "${case_dir}/rch_status.json")"
  fi
  rch_queue="$(write_json_input "$case_json" '.inputs.rch_queue' "${case_dir}/rch_queue.json")"
  git_status="$(write_json_input "$case_json" '.inputs.git_status' "${case_dir}/git_status.json")"
  git_diff="$(write_json_input "$case_json" '.inputs.git_diff_check' "${case_dir}/git_diff_check.json")"
  resource_pressure="$(write_json_input "$case_json" '.inputs.resource_pressure' "${case_dir}/resource_pressure.json")"
  proof_transcript="$(write_json_input "$case_json" '.inputs.proof_transcript' "${case_dir}/proof_transcript.json")"

  args=(--output-dir "$out_dir" --profile-json "$profile_path" --source-revision fixture-revision --now-ts "2026-05-09T12:00:00Z" --swarm-ops-state-json "$swarm_ops")
  add_arg_if_present args --br-ready-json "$br_ready"
  add_arg_if_present args --br-in-progress-json "$br_in_progress"
  add_arg_if_present args --br-sync-status-json "$br_sync"
  add_arg_if_present args --bv-plan-json "$bv_plan"
  add_arg_if_present args --agent-mail-json "$agent_mail"
  add_arg_if_present args --rch-status-json "$rch_status"
  add_arg_if_present args --rch-queue-json "$rch_queue"
  add_arg_if_present args --git-status-json "$git_status"
  add_arg_if_present args --git-diff-check-json "$git_diff"
  add_arg_if_present args --resource-pressure-json "$resource_pressure"
  add_arg_if_present args --proof-transcript-json "$proof_transcript"

  "$bundle_script" "${args[@]}" >/dev/null

  jq empty "${out_dir}/capture_profile.json" >/dev/null
  jq empty "${out_dir}/snapshot.json" >/dev/null
  jq empty "${out_dir}/swarm_ops_state_bundle.json" >/dev/null
  jq empty "${out_dir}/redaction_report.json" >/dev/null
  test -s "${out_dir}/events.jsonl"
  test -s "${out_dir}/commands.txt"
  test -s "${out_dir}/report.md"

  jq -e --argjson expected "$(jq '.expected' <<<"$case_json")" '
    .schema_version == "franken-engine.swarm-live-readonly-capture-bundle.v1"
    and .decision == $expected.decision
    and .fail_closed_reasons == $expected.fail_closed_reasons
    and .blocked_reasons == $expected.blocked_reasons
    and .degraded_reasons == $expected.degraded_reasons
    and .upstream_authority.canonical_live_state_bead_id == "bd-eozx0"
    and .upstream_authority.canonical_resource_lease_bead_id == "bd-x82vp"
    and .non_mutation_attestation.queries_live_agent_mail == false
    and .non_mutation_attestation.runs_rch_exec == false
    and (.sources | map(.component) | index("swarm_ops_state") != null)
  ' "${out_dir}/snapshot.json" >/dev/null || {
    record_failure "${case_id} snapshot mismatch"
    return
  }

  jq -e '
    .schema_version == "franken-engine.swarm-ops-state-bundle.v1"
    and .source_contract == "docs/swarm_ops_state_contract_v1.json"
    and (.source_components | type == "array")
  ' "${out_dir}/swarm_ops_state_bundle.json" >/dev/null || {
    record_failure "${case_id} swarm ops bundle mismatch"
    return
  }

  jq -s '
    length >= 13
    and all(.[]; has("trace_id") and has("component") and has("event") and has("outcome") and has("error_code") and has("evidence_path") and has("capture_source") and has("source_command_hash") and has("payload_hash"))
    and any(.[]; .component == "swarm_live_readonly_snapshot_bundle" and .event == "bundle_written")
  ' "${out_dir}/events.jsonl" >/dev/null || {
    record_failure "${case_id} event keys mismatch"
    return
  }

  record_pass "${case_id} bundle"
}

run_check() {
  bash -n "$bundle_script"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$profile_path" "$fixtures_path" >/dev/null
  if fixtures_shape_ok; then
    record_pass "fixture shape"
  else
    record_failure "fixture shape mismatch"
  fi
  grep -Fq 'docs/swarm_ops_state_contract_v1.json' "$bundle_script"
  grep -Fq 'docs/SWARM_RESOURCE_LEASE_PLANNER.md' "$bundle_script"
  grep -Fq 'rch exec' "$bundle_script"
  grep -Fq 'local_rch_fallback_marker' "$bundle_script"
  grep -Fq 'redaction_report.json' "$bundle_script"
}

run_all_cases() {
  local root="$1"
  mkdir -p "$root"
  while IFS= read -r case_json; do
    run_case "$case_json" "$root"
  done < <(jq -c '.cases[]' "$fixtures_path")
}

run_selftest() {
  local tmp_root fallback_snapshot redaction_report
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/swarm-live-readonly-snapshot.XXXXXX")"
  run_all_cases "$tmp_root"

  fallback_snapshot="${tmp_root}/rch_local_fallback_marker/out/snapshot.json"
  if jq -e '.decision == "fail_closed" and (.fail_closed_reasons | index("local_rch_fallback_marker") != null) and any(.sources[]; .component == "rch_status" and .local_fallback_observed == true)' "$fallback_snapshot" >/dev/null; then
    record_pass "selftest preserves local rch fallback marker"
  else
    record_failure "selftest did not preserve local rch fallback marker"
  fi

  redaction_report="${tmp_root}/healthy/out/redaction_report.json"
  if jq -e 'any(.sources[]; .component == "agent_mail_snapshot" and .redaction_applied == true)' "$redaction_report" >/dev/null; then
    record_pass "selftest redacts Agent Mail secret-shaped fields"
  else
    record_failure "selftest did not redact Agent Mail secret-shaped fields"
  fi
}

case "$mode" in
  check)
    run_check
    ;;
  run)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      if [[ -z "$output_dir" ]]; then
        output_dir="$(mktemp -d "${TMPDIR:-/tmp}/swarm-live-readonly-snapshot-run.XXXXXX")"
      fi
      run_all_cases "$output_dir"
    fi
    ;;
  selftest)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      run_selftest
    fi
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage
    record_failure "unknown mode: ${mode}"
    exit 64
    ;;
esac

if [[ "$failures" -ne 0 ]]; then
  exit 1
fi
