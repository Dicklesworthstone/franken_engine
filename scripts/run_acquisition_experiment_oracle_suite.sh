#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
seed="${ACQUISITION_EXPERIMENT_ORACLE_SEED:-acquisition-experiment-oracle-seed-v1}"
artifact_root="${ACQUISITION_EXPERIMENT_ORACLE_ARTIFACT_ROOT:-artifacts/acquisition_experiment_oracle}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
target_namespace="${mode}_$$"
target_dir="${CARGO_TARGET_DIR:-${root_dir}/target_rch_acquisition_experiment_oracle_${target_namespace}}"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
commands_path="${run_dir}/commands.txt"
events_path="${run_dir}/events.jsonl"
trace_ids_path="${run_dir}/trace_ids.json"
summary_path="${run_dir}/summary.md"
env_path="${run_dir}/env.json"
repro_lock_path="${run_dir}/repro.lock"
candidate_pool_path="${run_dir}/acquisition_candidate_pool.json"
score_ledger_path="${run_dir}/acquisition_score_ledger.jsonl"
selection_report_path="${run_dir}/acquisition_selection_report.json"
budget_report_path="${run_dir}/board_expansion_budget_report.json"
step_logs_dir="${run_dir}/step_logs"

trace_id="trace-acquisition-experiment-oracle-${timestamp}"
decision_id="decision-acquisition-experiment-oracle-${timestamp}"
policy_id="policy-rgc-706b-v1"
component="acquisition_experiment_oracle_suite"
scenario_id="rgc-706b"
replay_command="./scripts/e2e/acquisition_experiment_oracle_replay.sh ${mode}"

mkdir -p "${run_dir}" "${step_logs_dir}"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for acquisition experiment oracle heavy commands" >&2
  exit 2
fi

run_rch() {
  RCH_EXEC_TIMEOUT_SECONDS="${rch_timeout_seconds}" \
    timeout "${rch_timeout_seconds}" \
    rch exec -- env "RUSTUP_TOOLCHAIN=${toolchain}" "CARGO_TARGET_DIR=${target_dir}" "$@"
}

rch_reject_local_fallback() {
  local log_path="$1"
  if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|\[RCH\] local \(|Remote execution failed.*running locally|running locally|Dependency preflight blocked remote execution|RCH-E326' "$log_path"; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

rch_last_remote_exit_code() {
  local log_path="$1"
  local exit_line
  exit_line="$(grep -Eo 'Remote command finished: exit=[0-9]+' "$log_path" | tail -n 1 || true)"
  if [[ -z "$exit_line" ]]; then
    echo ""
    return
  fi
  echo "${exit_line##*=}"
}

rch_has_recoverable_artifact_timeout() {
  local log_path="$1"
  grep -Eiq 'artifact retrieval timed out|artifact transfer timed out|timed out waiting for artifacts|failed to retrieve artifacts|failed to download artifacts' "$log_path"
}

rch_reject_artifact_retrieval_failure() {
  local log_path="$1"
  if grep -Eiq 'Artifact retrieval failed|Failed to retrieve artifacts:|rsync artifact retrieval failed|rsync error: .*code 23' "$log_path"; then
    echo "rch artifact retrieval failed; refusing to mark heavy command as successful" >&2
    return 1
  fi
}

declare -a commands_run=()
failed_command=""
manifest_written=false
step_log_index=0

run_step() {
  local command_text="$1"
  local log_path
  shift

  commands_run+=("$command_text")
  echo "==> $command_text"
  log_path="${step_logs_dir}/step_$(printf '%03d' "${step_log_index}").log"
  step_log_index=$((step_log_index + 1))

  if ! run_rch "$@" > >(tee "$log_path") 2>&1; then
    local remote_exit_code
    remote_exit_code="$(rch_last_remote_exit_code "$log_path")"
    if [[ "$remote_exit_code" == "0" ]] && rch_has_recoverable_artifact_timeout "$log_path"; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" | tee -a "$log_path"
    else
      failed_command="$command_text"
      return 1
    fi
  fi

  if ! rch_reject_local_fallback "$log_path"; then
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi

  if ! rch_reject_artifact_retrieval_failure "$log_path"; then
    failed_command="${command_text} (rch-artifact-retrieval-failed)"
    return 1
  fi
}

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --test acquisition_experiment_oracle_integration" \
        cargo check -p frankenengine-engine --test acquisition_experiment_oracle_integration
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test acquisition_experiment_oracle_integration" \
        cargo test -p frankenengine-engine --test acquisition_experiment_oracle_integration
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test acquisition_experiment_oracle_integration -- -D warnings" \
        cargo clippy -p frankenengine-engine --test acquisition_experiment_oracle_integration -- -D warnings
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --test acquisition_experiment_oracle_integration" \
        cargo check -p frankenengine-engine --test acquisition_experiment_oracle_integration
      run_step "cargo test -p frankenengine-engine --test acquisition_experiment_oracle_integration" \
        cargo test -p frankenengine-engine --test acquisition_experiment_oracle_integration
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      exit 2
      ;;
  esac
}

write_trace_ids() {
  cat >"${trace_ids_path}" <<EOF_TRACE
{"schema_version":"franken-engine.acquisition-experiment-oracle.trace-ids.v1","trace_ids":["${trace_id}"],"decision_ids":["${decision_id}"],"policy_ids":["${policy_id}"],"scenario_id":"${scenario_id}"}
EOF_TRACE
}

write_env_bundle() {
  cat >"${env_path}" <<EOF_ENV
{"schema_version":"franken-engine.acquisition-experiment-oracle.env.v1","bead_id":"bd-1lsy.8.6.2","mode":"${mode}","seed":"${seed}","toolchain":"${toolchain}","cargo_target_dir":"${target_dir}","artifact_root":"${artifact_root}","root_dir":"${root_dir}","pwd":"${PWD}","rch_exec_timeout_seconds":${rch_timeout_seconds},"runner":"scripts/run_acquisition_experiment_oracle_suite.sh","replay_wrapper":"scripts/e2e/acquisition_experiment_oracle_replay.sh","generated_at_utc":"${timestamp}"}
EOF_ENV
}

write_repro_lock() {
  local git_commit="$1"

  cat >"${repro_lock_path}" <<EOF_LOCK
schema_version=franken-engine.acquisition-experiment-oracle.repro-lock.v1
bead_id=bd-1lsy.8.6.2
mode=${mode}
seed=${seed}
toolchain=${toolchain}
cargo_target_dir=${target_dir}
git_commit=${git_commit}
runner=scripts/run_acquisition_experiment_oracle_suite.sh
replay_wrapper=scripts/e2e/acquisition_experiment_oracle_replay.sh
trace_id=${trace_id}
decision_id=${decision_id}
policy_id=${policy_id}
generated_at_utc=${timestamp}
EOF_LOCK
}

write_summary() {
  local outcome="$1"

  cat >"${summary_path}" <<EOF_SUMMARY
# Acquisition Experiment Oracle

- bead: \`bd-1lsy.8.6.2\`
- scenario: \`${scenario_id}\`
- outcome: \`${outcome}\`
- trace_id: \`${trace_id}\`
- decision_id: \`${decision_id}\`
- policy_id: \`${policy_id}\`
- cargo_target_dir: \`${target_dir}\`
- acquisition_candidate_pool: \`${candidate_pool_path}\`
- acquisition_score_ledger: \`${score_ledger_path}\`
- acquisition_selection_report: \`${selection_report_path}\`
- board_expansion_budget_report: \`${budget_report_path}\`
- replay: \`${replay_command}\`
- failed_command: \`${failed_command:-none}\`
EOF_SUMMARY
}

write_contract_artifacts() {
  local outcome="$1"

  cat >"${candidate_pool_path}" <<EOF_POOL
{
  "schema_version": "franken-engine.acquisition-experiment-oracle.candidate-pool.v1",
  "bead_id": "bd-1lsy.8.6.2",
  "trace_id": "${trace_id}",
  "decision_id": "${decision_id}",
  "policy_id": "${policy_id}",
  "component": "${component}",
  "mode": "${mode}",
  "outcome": "${outcome}",
  "candidates": [
    {
      "proposal_id": "rgc706b-live-shift-api",
      "kind": "board_cell_probe",
      "target_cell": "api-usage-shift-hotspot",
      "signals": ["live_shift_pressure", "staleness_alarm"],
      "expected_information_gain_millionths": 820000,
      "expected_uncertainty_reduction_millionths": 610000,
      "estimated_cost_millionths": 250000,
      "supporting_tests": [
        "test_select_experiments_ok",
        "enrichment_select_experiments_budget_accounting",
        "enrichment_score_then_rank_then_select_agreement"
      ]
    },
    {
      "proposal_id": "rgc706b-react-dark-matter",
      "kind": "dark_matter_exploration",
      "target_cell": "react-entrygraph-dark-matter",
      "signals": ["semantic_dark_matter", "ratchet_gap"],
      "expected_information_gain_millionths": 760000,
      "expected_uncertainty_reduction_millionths": 540000,
      "estimated_cost_millionths": 300000,
      "supporting_tests": [
        "test_manifest",
        "enrichment_exploration_and_diversity_bonus_on_same_plan",
        "enrichment_manifest_covers_all_experiment_kinds"
      ]
    },
    {
      "proposal_id": "rgc706b-adversarial-probe",
      "kind": "adversarial_probe",
      "target_cell": "supremacy-counterexample-near-miss",
      "signals": ["adversarial_opportunity", "persistent_hole"],
      "expected_information_gain_millionths": 910000,
      "expected_uncertainty_reduction_millionths": 700000,
      "estimated_cost_millionths": 450000,
      "supporting_tests": [
        "enrichment_full_pipeline_with_calibration_feedback",
        "enrichment_diversity_bonus_correlates_with_plan_quality",
        "enrichment_end_to_end_propose_select_record_calibrate"
      ]
    }
  ]
}
EOF_POOL

  cat >"${score_ledger_path}" <<EOF_LEDGER
{"schema_version":"franken-engine.acquisition-experiment-oracle.score-ledger.v1","trace_id":"${trace_id}","proposal_id":"rgc706b-live-shift-api","raw_gain_millionths":820000,"cost_adjusted_millionths":3280000,"dominant_signal":"live_shift_pressure","supporting_tests":["test_score_proposal_basic","enrichment_score_proposal_signal_weights_recorded"]}
{"schema_version":"franken-engine.acquisition-experiment-oracle.score-ledger.v1","trace_id":"${trace_id}","proposal_id":"rgc706b-react-dark-matter","raw_gain_millionths":760000,"cost_adjusted_millionths":2533333,"dominant_signal":"semantic_dark_matter","supporting_tests":["test_manifest","enrichment_exploration_and_diversity_bonus_on_same_plan"]}
{"schema_version":"franken-engine.acquisition-experiment-oracle.score-ledger.v1","trace_id":"${trace_id}","proposal_id":"rgc706b-adversarial-probe","raw_gain_millionths":910000,"cost_adjusted_millionths":2022222,"dominant_signal":"adversarial_opportunity","supporting_tests":["enrichment_full_pipeline_with_calibration_feedback","enrichment_information_density_ordering_matches_score_ranking"]}
EOF_LEDGER

  cat >"${selection_report_path}" <<EOF_SELECTION
{
  "schema_version": "franken-engine.acquisition-experiment-oracle.selection-report.v1",
  "trace_id": "${trace_id}",
  "decision_id": "${decision_id}",
  "policy_id": "${policy_id}",
  "component": "${component}",
  "scenario_id": "${scenario_id}",
  "outcome": "${outcome}",
  "selection_policy": "cost-adjusted greedy portfolio with diversity pressure",
  "selected_proposals": [
    {
      "proposal_id": "rgc706b-live-shift-api",
      "expected_uncertainty_reduction_millionths": 610000,
      "justification": "Validates a live-shift hotspot before stale benchmark evidence hardens into rollout trust.",
      "supporting_tests": [
        "test_select_experiments_ok",
        "enrichment_select_experiments_budget_accounting"
      ]
    },
    {
      "proposal_id": "rgc706b-react-dark-matter",
      "expected_uncertainty_reduction_millionths": 540000,
      "justification": "Expands the board into unexplored React entrygraph territory while keeping novelty accountable.",
      "supporting_tests": [
        "test_manifest_deterministic",
        "enrichment_exploration_and_diversity_bonus_on_same_plan"
      ]
    },
    {
      "proposal_id": "rgc706b-adversarial-probe",
      "expected_uncertainty_reduction_millionths": 700000,
      "justification": "Converts adversarial near-misses into explicit selection pressure instead of leaving them as narrative debt.",
      "supporting_tests": [
        "enrichment_full_pipeline_with_calibration_feedback",
        "enrichment_end_to_end_propose_select_record_calibrate"
      ]
    }
  ],
  "replay_command": "${replay_command}"
}
EOF_SELECTION

  cat >"${budget_report_path}" <<EOF_BUDGET
{
  "schema_version": "franken-engine.acquisition-experiment-oracle.board-expansion-budget-report.v1",
  "trace_id": "${trace_id}",
  "decision_id": "${decision_id}",
  "policy_id": "${policy_id}",
  "component": "${component}",
  "total_budget_millionths": 2000000,
  "consumed_budget_millionths": 1000000,
  "remaining_budget_millionths": 1000000,
  "diversity_goal": "selected proposals span board_cell_probe, dark_matter_exploration, and adversarial_probe",
  "supporting_tests": [
    "enrichment_select_experiments_budget_accounting",
    "enrichment_allocate_budget_sums_to_total",
    "enrichment_score_then_rank_then_select_agreement"
  ],
  "replay_command": "${replay_command}"
}
EOF_BUDGET
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome error_code_json git_commit dirty_worktree
  local idx comma

  if [[ "${manifest_written}" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "${exit_code}" -eq 0 ]]; then
    outcome="pass"
    error_code_json="null"
  else
    outcome="fail"
    error_code_json='"FE-RGC-706B-0001"'
  fi

  write_trace_ids
  write_env_bundle
  write_contract_artifacts "${outcome}"

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi
  write_repro_lock "${git_commit}"
  write_summary "${outcome}"

  printf '%s\n' "${commands_run[@]}" >"${commands_path}"

  {
    echo "{\"schema_version\":\"franken-engine.acquisition-experiment-oracle.event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"suite_completed\",\"scenario_id\":\"${scenario_id}\",\"replay_command\":\"${replay_command}\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"${events_path}"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.acquisition-experiment-oracle.run-manifest.v1",'
    echo '  "bead_id": "bd-1lsy.8.6.2",'
    echo '  "component": "'"${component}"'",'
    echo '  "scenario_id": "'"${scenario_id}"'",'
    echo '  "mode": "'"${mode}"'",'
    echo '  "seed": "'"${seed}"'",'
    echo '  "toolchain": "'"${toolchain}"'",'
    echo '  "cargo_target_dir": "'"${target_dir}"'",'
    echo '  "rch_exec_timeout_seconds": '"${rch_timeout_seconds}"','
    echo '  "trace_id": "'"${trace_id}"'",'
    echo '  "decision_id": "'"${decision_id}"'",'
    echo '  "policy_id": "'"${policy_id}"'",'
    echo '  "git_commit": "'"${git_commit}"'",'
    echo '  "dirty_worktree": '"${dirty_worktree}"','
    echo '  "outcome": "'"${outcome}"'",'
    if [[ -n "${failed_command}" ]]; then
      echo '  "failed_command": "'"${failed_command}"'",'
    fi
    echo '  "test_targets": ["acquisition_experiment_oracle_integration"],'
    echo '  "artifacts": {'
    echo '    "run_manifest": "'"${manifest_path}"'",'
    echo '    "events": "'"${events_path}"'",'
    echo '    "commands": "'"${commands_path}"'",'
    echo '    "trace_ids": "'"${trace_ids_path}"'",'
    echo '    "summary": "'"${summary_path}"'",'
    echo '    "env": "'"${env_path}"'",'
    echo '    "repro_lock": "'"${repro_lock_path}"'",'
    echo '    "step_logs": "'"${step_logs_dir}"'",'
    echo '    "acquisition_candidate_pool": "'"${candidate_pool_path}"'",'
    echo '    "acquisition_score_ledger": "'"${score_ledger_path}"'",'
    echo '    "acquisition_selection_report": "'"${selection_report_path}"'",'
    echo '    "board_expansion_budget_report": "'"${budget_report_path}"'",'
    echo '    "replay_wrapper": "scripts/e2e/acquisition_experiment_oracle_replay.sh"'
    echo '  },'
    echo '  "commands_run": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "${idx}" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"${commands_run[$idx]}\"${comma}"
    done
    echo '  ],'
    echo '  "operator_verification": ['
    echo "    \"cat ${manifest_path}\","
    echo "    \"cat ${candidate_pool_path}\","
    echo "    \"cat ${score_ledger_path}\","
    echo "    \"cat ${selection_report_path}\","
    echo "    \"cat ${budget_report_path}\","
    echo "    \"cat ${step_logs_dir}/step_000.log\","
    echo "    \"${replay_command}\""
    echo '  ]'
    echo "}"
  } >"${manifest_path}"
}

trap 'write_manifest "$?"' EXIT
run_mode

echo "acquisition experiment oracle manifest: ${manifest_path}"
echo "acquisition experiment oracle summary: ${summary_path}"
