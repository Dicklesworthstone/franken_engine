#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_root="${RCH_FIRST_ERROR_CONVEYOR_DRILL_ROOT:-${TMPDIR:-/tmp}/franken-engine-rch-first-error-conveyor-drill}"
run_id="${RCH_FIRST_ERROR_CONVEYOR_DRILL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${RCH_FIRST_ERROR_CONVEYOR_DRILL_RUN_DIR:-${artifact_root}/${run_id}}"
mode="${1:-fixture}"
if [[ "$#" -gt 0 ]]; then
  shift
fi

fixtures_json="${root_dir}/scripts/testdata/rch_first_error_conveyor_no_mock_drill/cases.json"
replay_run_dir=""
scenario_filter=""
source_revision=""

cluster_script="${root_dir}/scripts/rch_compile_blocker_cluster.sh"
conveyor_script="${root_dir}/scripts/rch_first_error_conveyor.sh"

events_path=""
commands_path=""
case_results_path=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/rch_first_error_conveyor_no_mock_drill.sh [fixture|replay|check|selftest] [OPTIONS]

Options:
  --fixtures-json FILE
  --replay-run-dir DIR
  --scenario-id ID
  --output-dir DIR
  --source-revision REV
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --fixtures-json)
      fixtures_json="${2:-}"
      shift 2
      ;;
    --replay-run-dir)
      replay_run_dir="${2:-}"
      shift 2
      ;;
    --scenario-id)
      scenario_filter="${2:-}"
      shift 2
      ;;
    --output-dir)
      run_dir="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for the first-error conveyor no-mock drill\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for the first-error conveyor no-mock drill\n' >&2
  exit 2
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

refresh_paths() {
  events_path="${run_dir}/events.jsonl"
  commands_path="${run_dir}/commands.txt"
  case_results_path="${run_dir}/case_results.jsonl"
}

ensure_run_dir() {
  refresh_paths
  mkdir -p "$run_dir"
  : >"$events_path"
  : >"$commands_path"
  : >"$case_results_path"
}

log_command() {
  local rendered="" arg quoted
  for arg in "$@"; do
    printf -v quoted '%q' "$arg"
    rendered+="${rendered:+ }${quoted}"
  done
  printf '%s\n' "$rendered" >>"$commands_path"
}

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.rch-first-error-conveyor-no-mock-drill.event.v1" \
    --arg event_name "$1" \
    --arg scenario_id "$2" \
    --arg decision "$3" \
    --arg artifact_path "$4" \
    '{schema_version:$schema_version,event_name:$event_name,scenario_id:$scenario_id,decision:$decision,artifact_path:$artifact_path}' \
    >>"$events_path"
}

run_step() {
  local scenario_id="$1"
  local step_id="$2"
  local expected_codes="$3"
  shift 3
  local step_dir="${run_dir}/${scenario_id}/${step_id}"
  local stdout_path="${step_dir}/stdout.log"
  local stderr_path="${step_dir}/stderr.log"
  local exit_code expected
  mkdir -p "$step_dir"
  log_command "$@"
  set +e
  "$@" >"$stdout_path" 2>"$stderr_path"
  exit_code=$?
  set -e
  IFS=',' read -r -a expected_list <<<"$expected_codes"
  for expected in "${expected_list[@]}"; do
    if [[ "$exit_code" == "$expected" ]]; then
      write_event "step_complete" "$scenario_id" "$step_id" "$step_dir"
      return 0
    fi
  done
  printf 'scenario %s step %s expected exit %s, got %s\n' "$scenario_id" "$step_id" "$expected_codes" "$exit_code" >&2
  return "$exit_code"
}

write_case_inputs() {
  local case_json="$1"
  local input_dir="$2"

  mkdir -p "$input_dir"
  jq -r '.transcript_lines[]' <<<"$case_json" >"${input_dir}/transcript.txt"
  jq '.metadata' <<<"$case_json" >"${input_dir}/metadata.json"
  jq '.profile' <<<"$case_json" >"${input_dir}/profile.json"
  if jq -e 'has("beads_snapshot")' <<<"$case_json" >/dev/null; then
    jq '.beads_snapshot' <<<"$case_json" >"${input_dir}/beads.json"
  fi
  if jq -e 'has("reservations_snapshot")' <<<"$case_json" >/dev/null; then
    jq '.reservations_snapshot' <<<"$case_json" >"${input_dir}/reservations.json"
  fi
  if jq -e 'has("announcements_snapshot")' <<<"$case_json" >/dev/null; then
    jq '.announcements_snapshot' <<<"$case_json" >"${input_dir}/announcements.json"
  fi
}

run_conveyor_case() {
  local case_json="$1"
  local scenario_id scenario_dir input_dir cluster_dir conveyor_dir expected_exit
  local -a conveyor_cmd

  scenario_id="$(jq -r '.scenario_id' <<<"$case_json")"
  scenario_dir="${run_dir}/${scenario_id}"
  input_dir="${scenario_dir}/input"
  cluster_dir="${scenario_dir}/cluster"
  conveyor_dir="${scenario_dir}/conveyor"
  mkdir -p "$cluster_dir" "$conveyor_dir"
  write_case_inputs "$case_json" "$input_dir"

  run_step "$scenario_id" "cluster" "0,42" \
    bash "$cluster_script" \
    --transcript "${input_dir}/transcript.txt" \
    --metadata-json "${input_dir}/metadata.json" \
    --source-revision "$source_revision" \
    --case-id "$scenario_id" \
    --output-dir "$cluster_dir"

  conveyor_cmd=(
    bash "$conveyor_script"
    --clusters-json "${cluster_dir}/compile_blocker_clusters.json"
    --profile-json "${input_dir}/profile.json"
    --source-revision "$source_revision"
    --case-id "$scenario_id"
    --output-dir "$conveyor_dir"
  )
  if [[ -f "${input_dir}/beads.json" ]]; then
    conveyor_cmd+=(--beads-json "${input_dir}/beads.json")
  fi
  if [[ -f "${input_dir}/reservations.json" ]]; then
    conveyor_cmd+=(--reservations-json "${input_dir}/reservations.json")
  fi
  if [[ -f "${input_dir}/announcements.json" ]]; then
    conveyor_cmd+=(--announcements-json "${input_dir}/announcements.json")
  fi

  expected_exit="$(jq -r '.expected.exit_code' <<<"$case_json")"
  run_step "$scenario_id" "conveyor" "$expected_exit" "${conveyor_cmd[@]}"
  record_case_result "$case_json" "$scenario_dir"
  write_event "case_complete" "$scenario_id" "$(jq -r '.decision' "${conveyor_dir}/first_error_conveyor_plan.json")" "${conveyor_dir}/first_error_conveyor_plan.json"
}

record_case_result() {
  local case_json="$1"
  local scenario_dir="$2"

  jq -n \
    --slurpfile clusters "${scenario_dir}/cluster/compile_blocker_clusters.json" \
    --slurpfile plan "${scenario_dir}/conveyor/first_error_conveyor_plan.json" \
    --argjson expected "$(jq '.expected' <<<"$case_json")" \
    --arg scenario_id "$(jq -r '.scenario_id' <<<"$case_json")" \
    '
      ($clusters[0]) as $clusters_doc
      | ($plan[0]) as $plan_doc
      | {
          scenario_id: $scenario_id,
          cluster_decision: ($clusters_doc.decision // "unknown"),
          conveyor_decision: ($plan_doc.decision // "unknown"),
          primary_disposition: (($plan_doc.recommendations[0].disposition // null)),
          recommendation_count: ($plan_doc.summary.recommendation_count // 0),
          reason_codes: ([ $plan_doc.recommendations[]?.reason_codes[]? ] | unique),
          matched_beads: ([ $plan_doc.recommendations[]?.ownership_evidence.matched_beads[]?.id, $plan_doc.recommendations[]?.ownership_evidence.stale_beads[]?.id ] | unique),
          matched_reservations: ([ $plan_doc.recommendations[]?.ownership_evidence.active_reservations[]?.id ] | unique),
          matched_announcements: ([ $plan_doc.recommendations[]?.ownership_evidence.recent_announcements[]?.id ] | unique),
          expected_decision: $expected.decision,
          expected_disposition: $expected.primary_disposition,
          matches_expected: (
            ($plan_doc.decision == $expected.decision)
            and (($plan_doc.summary.recommendation_count // 0) == $expected.recommendation_count)
            and (($plan_doc.summary.block_current_bead_count // 0) == $expected.block_current_bead_count)
            and (($plan_doc.summary.new_bead_candidate_count // 0) == $expected.new_bead_candidate_count)
            and (($plan_doc.summary.duplicate_existing_bead_count // 0) == $expected.duplicate_existing_bead_count)
            and (($plan_doc.summary.defer_active_owner_count // 0) == $expected.defer_active_owner_count)
            and (($plan_doc.summary.insufficient_evidence_count // 0) == $expected.insufficient_evidence_count)
            and any($plan_doc.recommendations[]?; .disposition == $expected.primary_disposition)
            and (if ($expected.reason_code // null) == null then true else any($plan_doc.recommendations[]?; (.reason_codes // []) | index($expected.reason_code) != null) end)
            and (if ($expected.matched_bead_id // null) == null then true else (
              ([ $plan_doc.recommendations[]?.ownership_evidence.matched_beads[]?.id, $plan_doc.recommendations[]?.ownership_evidence.stale_beads[]?.id ] | index($expected.matched_bead_id)) != null
            ) end)
            and (if ($expected.matched_reservation_id // null) == null then true else (
              ([ $plan_doc.recommendations[]?.ownership_evidence.active_reservations[]?.id ] | index($expected.matched_reservation_id)) != null
            ) end)
            and (if ($expected.matched_announcement_id // null) == null then true else (
              ([ $plan_doc.recommendations[]?.ownership_evidence.recent_announcements[]?.id ] | index($expected.matched_announcement_id)) != null
            ) end)
            and all($plan_doc.recommendations[]?; (.evidence_paths | type) == "object" and ((.proposed_command // "") | length) > 0)
            and ($clusters_doc.non_mutation_attestation.runs_cargo == false)
            and ($clusters_doc.non_mutation_attestation.runs_rch == false)
            and ($clusters_doc.non_mutation_attestation.creates_beads == false)
            and ($clusters_doc.non_mutation_attestation.sends_agent_mail == false)
            and ($plan_doc.non_mutation_attestation.runs_cargo == false)
            and ($plan_doc.non_mutation_attestation.runs_rch == false)
            and ($plan_doc.non_mutation_attestation.creates_beads == false)
            and ($plan_doc.non_mutation_attestation.sends_agent_mail == false)
          ),
          artifact_paths: {
            cluster_json: $clusters_doc.artifact_paths.compile_blocker_clusters_json,
            conveyor_plan_json: $plan_doc.artifact_paths.first_error_conveyor_plan_json,
            conveyor_report_md: $plan_doc.artifact_paths.report_md,
            conveyor_events_jsonl: $plan_doc.artifact_paths.events_jsonl,
            conveyor_commands_txt: $plan_doc.artifact_paths.commands_txt
          }
        }
    ' >>"$case_results_path"
}

copy_primary_outputs() {
  local primary_scenario="$1"
  local scenario_dir="${run_dir}/${primary_scenario}/conveyor"
  cp "${scenario_dir}/first_error_conveyor_plan.json" "${run_dir}/first_error_conveyor_plan.json"
  cp "${scenario_dir}/report.md" "${run_dir}/report.md"
  cp "${scenario_dir}/proposed_commands.txt" "${run_dir}/proposed_commands.txt"
}

write_trace_ids() {
  jq -n \
    --slurpfile manifest "${run_dir}/run_manifest.json" \
    --slurpfile results "$case_results_path" \
    '{
      schema_version: "franken-engine.rch-first-error-conveyor-no-mock-drill-trace-ids.v1",
      run_id: $manifest[0].run_id,
      source_revision: $manifest[0].source_revision,
      traces: [
        $results[]
        | {
            trace_id: ("first-error-conveyor-drill/" + .scenario_id),
            scenario_id: .scenario_id,
            cluster_decision: .cluster_decision,
            conveyor_decision: .conveyor_decision,
            primary_disposition: .primary_disposition,
            artifact_paths: .artifact_paths
          }
      ]
    }' >"${run_dir}/trace_ids.json"
}

write_truth_gate_report() {
  jq -n \
    --slurpfile results "$case_results_path" \
    --slurpfile trace_ids "${run_dir}/trace_ids.json" \
    '($results) as $rows
      | {
          schema_version: "franken-engine.rch-first-error-conveyor-no-mock-drill-truth-gate.v1",
          decision: (if all($rows[]; .matches_expected == true) then "pass" else "fail_closed" end),
          replay_verified: false,
          required_coverage: {
            first_error_chain: any($rows[]; .scenario_id == "first_error_chain" and .matches_expected == true),
            blocked_golden_lane: any($rows[]; .scenario_id == "blocked_golden_lane" and .matches_expected == true),
            blocked_object_create_lane: any($rows[]; .scenario_id == "blocked_object_create_lane" and .matches_expected == true),
            fresh_active_owner: any($rows[]; .scenario_id == "fresh_active_owner" and .matches_expected == true),
            stale_owner: any($rows[]; .scenario_id == "stale_owner" and .matches_expected == true),
            local_fallback_contamination: any($rows[]; .scenario_id == "local_fallback_contamination" and .matches_expected == true)
          },
          case_count: ($rows | length),
          failed_cases: [ $rows[] | select(.matches_expected != true) | .scenario_id ],
          trace_count: ($trace_ids[0].traces | length),
          mutation_policy: {
            fixture_fed_only: true,
            replay_verification_only: true,
            mutates_br: false,
            creates_beads: false,
            sends_agent_mail: false,
            runs_cargo: false,
            runs_rch: false,
            mutates_remote_workers: false,
            changes_live_queue_policy: false
          }
        }' >"${run_dir}/truth_gate_report.json"
}

write_hash_index() {
  local base_dir="$1"
  local output_path="$2"
  local tsv_path="${output_path}.tsv"
  local file rel digest
  : >"$tsv_path"
  while IFS= read -r -d '' file; do
    rel="${file#"${base_dir}"/}"
    digest="$(sha256sum "$file" | awk '{print $1}')"
    printf '%s\t%s\n' "$digest" "$rel" >>"$tsv_path"
  done < <(find "$base_dir" -type f ! -name 'artifact_hashes.json' ! -name 'artifact_hashes.json.tsv' ! -name 'artifact_hashes.json.tmp' -print0 | sort -z)
  jq -R -s --arg schema_version "franken-engine.rch-first-error-conveyor-no-mock-drill-artifact-hashes.v1" '
    split("\n")
    | map(select(length > 0))
    | map(split("\t"))
    | {
        schema_version: $schema_version,
        hashes: map({sha256: .[0], path: .[1]})
      }
  ' "$tsv_path" >"${output_path}.tmp"
  mv "${output_path}.tmp" "$output_path"
}

run_fixture_mode() {
  local primary_scenario
  ensure_run_dir
  jq -n \
    --arg schema_version "franken-engine.rch-first-error-conveyor-no-mock-drill-manifest.v1" \
    --arg run_id "$run_id" \
    --arg source_revision "$source_revision" \
    --arg mode "fixture" \
    --arg fixtures_json "$fixtures_json" \
    '{schema_version:$schema_version,run_id:$run_id,source_revision:$source_revision,mode:$mode,fixtures_json:$fixtures_json}' \
    >"${run_dir}/run_manifest.json"

  while IFS= read -r case_json; do
    scenario_id="$(jq -r '.scenario_id' <<<"$case_json")"
    if [[ -n "$scenario_filter" && "$scenario_id" != "$scenario_filter" ]]; then
      continue
    fi
    run_conveyor_case "$case_json"
  done < <(jq -c '.cases[]' "$fixtures_json")

  primary_scenario="$(jq -r '.primary_scenario_id' "$fixtures_json")"
  if [[ -n "$scenario_filter" ]]; then
    primary_scenario="$scenario_filter"
  fi
  copy_primary_outputs "$primary_scenario"
  write_trace_ids
  write_truth_gate_report
  write_hash_index "$run_dir" "${run_dir}/artifact_hashes.json"

  if jq -e '.decision == "pass"' "${run_dir}/truth_gate_report.json" >/dev/null; then
    exit 0
  fi
  exit 42
}

run_replay_mode() {
  local required
  if [[ -z "$replay_run_dir" ]]; then
    printf 'replay mode requires --replay-run-dir\n' >&2
    exit 64
  fi
  mkdir -p "$run_dir"
  for required in run_manifest.json events.jsonl commands.txt case_results.jsonl trace_ids.json first_error_conveyor_plan.json report.md proposed_commands.txt artifact_hashes.json truth_gate_report.json; do
    if [[ ! -s "${replay_run_dir}/${required}" ]]; then
      printf 'replay source missing %s\n' "$required" >&2
      exit 42
    fi
  done
  write_hash_index "$replay_run_dir" "${run_dir}/replay_artifact_hashes.json"
  jq -n \
    --slurpfile prior_truth "${replay_run_dir}/truth_gate_report.json" \
    --slurpfile expected_hashes "${replay_run_dir}/artifact_hashes.json" \
    --slurpfile observed_hashes "${run_dir}/replay_artifact_hashes.json" \
    --arg replay_run_dir "$replay_run_dir" \
    '($expected_hashes[0].hashes | sort_by(.path)) as $expected
      | ($observed_hashes[0].hashes | sort_by(.path)) as $observed
      | ($expected == $observed) as $hashes_match
      | {
          schema_version: "franken-engine.rch-first-error-conveyor-no-mock-drill-truth-gate.v1",
          decision: (if ($prior_truth[0].decision == "pass" and $hashes_match) then "pass" else "fail_closed" end),
          replay_verified: ($prior_truth[0].decision == "pass" and $hashes_match),
          replay_run_dir: $replay_run_dir,
          required_coverage: $prior_truth[0].required_coverage,
          hash_count: ($expected | length),
          hashes_match: $hashes_match,
          failure_reasons: (if ($prior_truth[0].decision == "pass" and $hashes_match) then [] else [{code:"FE-RCH-FIRST-ERROR-DRILL-REPLAY-MISMATCH",detail:"source truth gate failed or artifact hashes changed"}] end),
          mutation_policy: $prior_truth[0].mutation_policy
        }' >"${run_dir}/truth_gate_report.json"
  if jq -e '.decision == "pass" and .replay_verified == true' "${run_dir}/truth_gate_report.json" >/dev/null; then
    exit 0
  fi
  exit 42
}

case "$mode" in
  fixture|selftest)
    run_fixture_mode
    ;;
  replay)
    run_replay_mode
    ;;
  check)
    bash -n "${BASH_SOURCE[0]}"
    bash -n "$cluster_script"
    bash -n "$conveyor_script"
    jq empty "$fixtures_json" >/dev/null
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage
    exit 64
    ;;
esac
