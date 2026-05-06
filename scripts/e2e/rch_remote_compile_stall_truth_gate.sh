#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
contract_json="${root_dir}/docs/rch_remote_compile_stall_bundle_contract_v1.json"
repro_harness="${root_dir}/scripts/e2e/rch_remote_compile_stall_repro_harness.sh"
default_suite_json="${root_dir}/scripts/testdata/rch_remote_compile_stall_truth_gate/cases.json"

output_dir=""
suite_json="$default_suite_json"

usage() {
  cat <<'USAGE'
usage: scripts/e2e/rch_remote_compile_stall_truth_gate.sh --output-dir DIR [options]

Options:
  --suite-json PATH  Deterministic truth-gate case suite

The gate composes the remote compile stall contract, bundle capture output, and
repro harness report. It is fixture-fed and evidence-only; it does not run RCH,
Cargo, mutate beads, release reservations, send Agent Mail, or change workers.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)
      output_dir="${2:-}"
      shift 2
      ;;
    --suite-json)
      suite_json="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 64
      ;;
  esac
done

if [[ -z "$output_dir" ]]; then
  usage >&2
  exit 64
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for the remote stall truth gate" >&2
  exit 2
fi

for path in "$contract_json" "$repro_harness" "$suite_json"; do
  if [[ ! -f "$path" ]]; then
    echo "required input missing: $path" >&2
    exit 66
  fi
done

mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"
report_path="${output_dir}/truth_gate_report.json"
events_path="${output_dir}/events.jsonl"
commands_path="${output_dir}/commands.txt"
summary_path="${output_dir}/summary.md"
case_results_path="${output_dir}/case_results.jsonl"
contract_check_path="${output_dir}/contract_check.json"

for artifact in "$report_path" "$events_path" "$commands_path" "$summary_path" "$case_results_path" "$contract_check_path"; do
  if [[ -e "$artifact" ]]; then
    echo "refusing to overwrite existing artifact: $artifact" >&2
    exit 73
  fi
done

printf 'scripts/e2e/rch_remote_compile_stall_truth_gate.sh --suite-json %q --output-dir %q\n' "$suite_json" "$output_dir" >"$commands_path"
: >"$case_results_path"

jq -e '
  .schema_version == "franken-engine.rch-remote-compile-stall-bundle-contract.v1"
  and .bundle_schema_version == "franken-engine.rch-remote-compile-stall-bundle.v1"
  and (.capture_decisions | index("captured"))
  and (.capture_decisions | index("captured_degraded"))
  and (.capture_decisions | index("fail_closed"))
  and (.truth_states | index("confirmed"))
  and (.truth_states | index("degraded"))
  and (.truth_states | index("blocked"))
  and (.truth_states | index("contaminated"))
  and (.required_bundle_fields | index("stall_subject"))
  and (.required_stall_subject_fields | index("stall_subject.progress_age_seconds"))
  and (.fail_closed_rules | map(test("local fallback"; "i")) | any)
  and .mutation_policy.mutates_br == false
  and .mutation_policy.releases_reservations == false
  and .mutation_policy.sends_agent_mail == false
  and .mutation_policy.mutates_remote_workers == false
' "$contract_json" >/dev/null

jq -n \
  --arg contract_json "$contract_json" \
  --arg suite_json "$suite_json" \
  --slurpfile contract "$contract_json" \
  --slurpfile suite "$suite_json" '
    {
      contract_json: $contract_json,
      suite_json: $suite_json,
      contract_schema_version: $contract[0].schema_version,
      suite_schema_version: $suite[0].schema_version,
      accepted_truth_states: $contract[0].truth_states,
      accepted_capture_decisions: $contract[0].capture_decisions,
      mutation_policy: $contract[0].mutation_policy,
      passed: true
    }
  ' >"$contract_check_path"

case_count="$(jq '.cases | length' "$suite_json")"
for ((case_index = 0; case_index < case_count; case_index++)); do
  case_doc="$(jq -c --argjson index "$case_index" '.cases[$index]' "$suite_json")"
  case_id="$(jq -r '.case_id' <<<"$case_doc")"
  fixture_rel="$(jq -r '.fixture_dir' <<<"$case_doc")"
  fixture_dir="${root_dir}/${fixture_rel#./}"
  case_output_dir="${output_dir}/cases/${case_id}"
  actual_exit=0
  bead_id=""
  harness_case_id=""
  command_log_path="${fixture_dir}/command_excerpt.txt"
  worker_inventory_path="${fixture_dir}/worker_inventory.json"
  operator_note_path="${fixture_dir}/operator_note.md"
  [[ -f "${fixture_dir}/bead_metadata.json" ]] || {
    echo "fixture bead metadata missing: ${fixture_dir}/bead_metadata.json" >&2
    exit 66
  }
  [[ -f "${fixture_dir}/queue.json" ]] || {
    echo "fixture queue missing: ${fixture_dir}/queue.json" >&2
    exit 66
  }
  [[ -f "${fixture_dir}/status.json" ]] || {
    echo "fixture status missing: ${fixture_dir}/status.json" >&2
    exit 66
  }
  [[ -f "$command_log_path" ]] || {
    echo "fixture command excerpt missing: $command_log_path" >&2
    exit 66
  }

  mkdir -p "$case_output_dir"
  bead_id="$(jq -r '.[0].id' "${fixture_dir}/bead_metadata.json")"
  harness_case_id="$(jq -r '.harness_case_id' <<<"$case_doc")"
  cmd=(
    "$repro_harness"
    --output-dir "$case_output_dir"
    --case-id "$harness_case_id"
    --bead-id "$bead_id"
    --bead-metadata-json "${fixture_dir}/bead_metadata.json"
    --queue-json "${fixture_dir}/queue.json"
    --status-json "${fixture_dir}/status.json"
    --command-log "$command_log_path"
  )
  [[ -f "$worker_inventory_path" ]] && cmd+=(--worker-inventory-json "$worker_inventory_path")
  [[ -f "$operator_note_path" ]] && cmd+=(--operator-note "$operator_note_path")

  {
    printf 'case[%s]=' "$case_id"
    printf '%q ' "${cmd[@]}"
    printf '\n'
  } >>"$commands_path"

  set +e
  "${cmd[@]}" >"${case_output_dir}/harness.stdout" 2>"${case_output_dir}/harness.stderr"
  actual_exit=$?
  set -e

  if [[ ! -f "${case_output_dir}/repro_report.json" || ! -f "${case_output_dir}/stall_bundle/stall_bundle.json" ]]; then
    jq -n \
      --argjson expected "$case_doc" \
      --argjson actual_exit "$actual_exit" \
      --arg detail "repro harness did not emit required report and bundle artifacts" '
        {
          case_id: $expected.case_id,
          passed: false,
          failures: [$detail],
          expected: $expected,
          actual: {exit_code:$actual_exit}
        }
      ' >>"$case_results_path"
    continue
  fi

  jq -n \
    --argjson expected "$case_doc" \
    --argjson actual_exit "$actual_exit" \
    --slurpfile report "${case_output_dir}/repro_report.json" \
    --slurpfile bundle "${case_output_dir}/stall_bundle/stall_bundle.json" \
    --slurpfile contract "$contract_json" '
      ($report[0]) as $report_doc
      | ($bundle[0]) as $bundle_doc
      | ($contract[0]) as $contract_doc
      | [
          if $actual_exit != $expected.expected_exit_code then "unexpected_harness_exit" else empty end,
          if ($report_doc.harness_exit_code // null) != $expected.expected_exit_code then "unexpected_report_exit" else empty end,
          if ($report_doc.final_verdict // "") != $expected.expected_final_verdict then "unexpected_final_verdict" else empty end,
          if ($report_doc.reason_code // "") != $expected.expected_reason_code then "unexpected_reason_code" else empty end,
          if (if ($report_doc | has("source_evidence")) then $report_doc.source_evidence else null end) != $expected.expected_source_evidence then "unexpected_source_evidence" else empty end,
          if ($report_doc.selected_worker // "") != $expected.expected_selected_worker then "unexpected_selected_worker" else empty end,
          if ($report_doc.stall_observation.truth_state // "") != $expected.expected_truth_state then "unexpected_report_truth_state" else empty end,
          if ($report_doc.stall_observation.capture_decision // "") != $expected.expected_capture_decision then "unexpected_report_capture_decision" else empty end,
          if ($bundle_doc.truth_state // "") != $expected.expected_truth_state then "unexpected_bundle_truth_state" else empty end,
          if ($bundle_doc.capture_decision // "") != $expected.expected_capture_decision then "unexpected_bundle_capture_decision" else empty end,
          if (if ($bundle_doc | has("local_fallback_observed")) then $bundle_doc.local_fallback_observed else null end) != $expected.expected_local_fallback_observed then "unexpected_local_fallback_flag" else empty end,
          if (($contract_doc.truth_states // []) | index($bundle_doc.truth_state // "") | not) then "truth_state_not_in_contract" else empty end,
          if (($contract_doc.capture_decisions // []) | index($bundle_doc.capture_decision // "") | not) then "capture_decision_not_in_contract" else empty end,
          if (($report_doc.artifact_paths.repro_report_json // "") | length) == 0 then "missing_repro_artifact_path" else empty end,
          if (($bundle_doc.artifact_paths.stall_bundle_json // "") | length) == 0 then "missing_bundle_artifact_path" else empty end,
          if (($bundle_doc.stall_subject.build_id // "") | length) == 0 then "missing_stall_subject_build_id" else empty end,
          if (($bundle_doc.stall_subject.worker_id // "") | length) == 0 then "missing_stall_subject_worker_id" else empty end,
          if (($bundle_doc.stall_subject.heartbeat.phase // "") | length) == 0 then "missing_stall_subject_heartbeat_phase" else empty end,
          if (($bundle_doc.stall_subject.progress_age_seconds // null) | type) != "number" then "missing_stall_subject_progress_age" else empty end
        ] as $failures
      | {
          case_id: $expected.case_id,
          fixture_dir: $expected.fixture_dir,
          category: $expected.category,
          passed: (($failures | length) == 0),
          failures: $failures,
          expected: $expected,
          actual: {
            exit_code: $actual_exit,
            final_verdict: $report_doc.final_verdict,
            reason_code: $report_doc.reason_code,
            source_evidence: $report_doc.source_evidence,
            selected_worker: $report_doc.selected_worker,
            truth_state: $bundle_doc.truth_state,
            capture_decision: $bundle_doc.capture_decision,
            local_fallback_observed: $bundle_doc.local_fallback_observed,
            progress_age_seconds: $bundle_doc.stall_subject.progress_age_seconds,
            heartbeat_age_seconds: $report_doc.stall_observation.heartbeat_age_seconds,
            artifact_paths: {
              repro_report_json: $report_doc.artifact_paths.repro_report_json,
              stall_bundle_json: $bundle_doc.artifact_paths.stall_bundle_json,
              events_jsonl: $report_doc.artifact_paths.events_jsonl,
              commands_txt: $report_doc.artifact_paths.commands_txt,
              summary_md: $report_doc.artifact_paths.summary_md
            }
          }
        }
    ' >>"$case_results_path"
done

# shellcheck disable=SC2094
jq -s \
  --slurpfile suite "$suite_json" \
  --slurpfile contract_check "$contract_check_path" \
  --arg report_path "$report_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg summary_path "$summary_path" '
    {
      schema_version: "franken-engine.rch-remote-compile-stall-truth-gate-report.v1",
      decision: (if all(.[]; .passed) then "pass" else "fail_closed" end),
      suite_schema_version: $suite[0].schema_version,
      contract_schema_version: $contract_check[0].contract_schema_version,
      case_count: length,
      passed_count: (map(select(.passed)) | length),
      failed_count: (map(select(.passed | not)) | length),
      required_coverage: {
        healthy_remote_completion: any(.[]; .category == "healthy_remote_completion" and .passed),
        explicit_timeout: any(.[]; .category == "explicit_timeout" and .passed),
        fresh_heartbeat_frozen_progress_stall: any(.[]; .category == "fresh_heartbeat_frozen_progress_stall" and .passed),
        local_fallback_contamination: any(.[]; .category == "local_fallback_contamination" and .passed)
      },
      contract_check: $contract_check[0],
      cases: .,
      mutation_policy: {
        fixture_fed_only: true,
        runs_cargo: false,
        runs_rch: false,
        mutates_br: false,
        releases_reservations: false,
        sends_agent_mail: false,
        mutates_remote_workers: false
      },
      artifact_paths: {
        truth_gate_report_json: $report_path,
        events_jsonl: $events_path,
        commands_txt: $commands_path,
        summary_md: $summary_path
      }
    }
  ' "$case_results_path" >"$report_path"

jq -e '
  .decision == "pass"
  and .required_coverage.healthy_remote_completion == true
  and .required_coverage.explicit_timeout == true
  and .required_coverage.fresh_heartbeat_frozen_progress_stall == true
  and .required_coverage.local_fallback_contamination == true
' "$report_path" >/dev/null || {
  jq -c '.cases[] | select(.passed | not)' "$report_path" >"$events_path"
  exit 42
}

jq -c '
  {
    schema_version: "franken-engine.rch-remote-compile-stall-truth-gate.event.v1",
    event: "remote_stall_truth_gate_passed",
    case_count: .case_count,
    passed_count: .passed_count,
    failed_count: .failed_count,
    required_coverage: .required_coverage
  }
' "$report_path" >"$events_path"

jq -r '
  "# RCH Remote Compile Stall Truth Gate",
  "",
  ("- Decision: `" + .decision + "`"),
  ("- Cases: `" + (.case_count | tostring) + "`"),
  ("- Passed: `" + (.passed_count | tostring) + "`"),
  ("- Failed: `" + (.failed_count | tostring) + "`"),
  "",
  "## Coverage",
  "",
  (.required_coverage | to_entries[] | "- `" + .key + "`: `" + (.value | tostring) + "`"),
  "",
  "## Cases",
  "",
  (.cases[] | "- `" + .case_id + "`: `" + .actual.final_verdict + "` / `" + .actual.truth_state + "`"),
  "",
  "## Artifacts",
  "",
  (.artifact_paths | to_entries[] | "- `" + .key + "`: `" + .value + "`")
' "$report_path" >"$summary_path"

printf 'rch_remote_compile_stall_truth_gate_report=%s\n' "$report_path"
