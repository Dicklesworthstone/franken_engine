#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_root="${IDEA_WIZARD_III_ACCEPTANCE_ROOT:-${TMPDIR:-/tmp}/franken-engine-idea-wizard-iii-acceptance}"
run_id="${IDEA_WIZARD_III_ACCEPTANCE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${IDEA_WIZARD_III_ACCEPTANCE_RUN_DIR:-${artifact_root}/${run_id}}"
mode="${1:-suite}"
if [[ "$#" -gt 0 ]]; then
  shift
fi

contract_path="${root_dir}/docs/idea_wizard_iii_acceptance_suite_contract_v1.json"
docs_path="${root_dir}/docs/IDEA_WIZARD_III_ACCEPTANCE_SUITE.md"
source_revision="${IDEA_WIZARD_III_ACCEPTANCE_SOURCE_REVISION:-}"
replay_run_dir=""
latest_from=""

run_manifest_path=""
acceptance_manifest_path=""
events_path=""
commands_path=""
step_results_path=""
closeout_evidence_path=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/idea_wizard_iii_acceptance_suite.sh [suite|replay|check|selftest] [OPTIONS]

Options:
  --replay-run-dir DIR
  --latest-from DIR
  --output-dir DIR
  --source-revision REV
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --replay-run-dir)
      replay_run_dir="${2:-}"
      shift 2
      ;;
    --latest-from)
      latest_from="${2:-}"
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
  printf 'jq is required for IDEA-WIZARD-III acceptance suite\n' >&2
  exit 2
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

refresh_paths() {
  run_manifest_path="${run_dir}/run_manifest.json"
  acceptance_manifest_path="${run_dir}/acceptance_manifest.json"
  events_path="${run_dir}/events.jsonl"
  commands_path="${run_dir}/commands.txt"
  step_results_path="${run_dir}/step_results.jsonl"
  closeout_evidence_path="${run_dir}/br_closeout_evidence.jsonl"
}

ensure_run_dir() {
  mkdir -p "$run_dir"
  run_dir="$(cd "$run_dir" && pwd)"
  refresh_paths
  : >"$events_path"
  : >"$commands_path"
  : >"$step_results_path"
  : >"$closeout_evidence_path"
}

record_pass() {
  printf 'PASS idea-wizard-iii-acceptance-suite %s\n' "$1"
}

render_command() {
  local rendered="" arg quoted
  for arg in "$@"; do
    printf -v quoted '%q' "$arg"
    rendered+="${rendered:+ }${quoted}"
  done
  printf '%s' "$rendered"
}

log_command() {
  render_command "$@" >>"$commands_path"
  printf '\n' >>"$commands_path"
}

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.idea-wizard-iii-acceptance-suite.event.v1" \
    --arg step_id "$1" \
    --arg event_name "$2" \
    --arg outcome "$3" \
    --arg artifact_path "$4" \
    '{schema_version:$schema_version,step_id:$step_id,event_name:$event_name,outcome:$outcome,artifact_path:$artifact_path}' \
    >>"$events_path"
}

run_step() {
  local step_id="$1"
  shift
  local step_dir="${run_dir}/step_logs/${step_id}"
  local stdout_path="${step_dir}/stdout.log"
  local stderr_path="${step_dir}/stderr.log"
  local rendered exit_code
  mkdir -p "$step_dir"
  rendered="$(render_command "$@")"
  printf '%s\n' "$rendered" >>"$commands_path"
  write_event "$step_id" "started" "running" "$step_dir"
  set +e
  "$@" >"$stdout_path" 2>"$stderr_path"
  exit_code=$?
  set -e
  jq -nc \
    --arg step_id "$step_id" \
    --arg command "$rendered" \
    --arg stdout "$stdout_path" \
    --arg stderr "$stderr_path" \
    --argjson exit_code "$exit_code" \
    '{step_id:$step_id,command:$command,exit_code:$exit_code,stdout:$stdout,stderr:$stderr}' \
    >>"$step_results_path"
  if [[ "$exit_code" -eq 0 ]]; then
    write_event "$step_id" "finished" "pass" "$stdout_path"
    return 0
  fi
  write_event "$step_id" "finished" "fail" "$stderr_path"
  printf 'acceptance step failed: %s (exit %s)\n' "$step_id" "$exit_code" >&2
  cat "$stderr_path" >&2
  return "$exit_code"
}

contract_rel_paths() {
  jq -r '.required_paths[]' "$contract_path"
}

json_rel_paths() {
  jq -r '.json_contracts_and_fixtures[]' "$contract_path"
}

child_bead_ids() {
  jq -r '.child_beads[]' "$contract_path"
}

verify_command_transcript_safe() {
  local transcript="$1"
  local pattern
  while IFS= read -r pattern; do
    [[ -n "$pattern" ]] || continue
    if grep -E "$pattern" "$transcript" >/dev/null 2>&1; then
      printf 'forbidden command pattern matched in %s: %s\n' "$transcript" "$pattern" >&2
      return 1
    fi
  done < <(jq -r '.forbidden_executed_command_patterns[]' "$contract_path")
}

write_closeout_summary() {
  local bead_id stdout_path state
  : >"$closeout_evidence_path"
  while IFS= read -r bead_id; do
    stdout_path="${run_dir}/step_logs/br-show-${bead_id}/stdout.log"
    if grep -Fq "CLOSED" "$stdout_path"; then
      state="closed"
    else
      state="not_closed"
    fi
    jq -nc \
      --arg bead_id "$bead_id" \
      --arg state "$state" \
      --arg stdout "$stdout_path" \
      '{bead_id:$bead_id,state:$state,evidence_stdout:$stdout}' \
      >>"$closeout_evidence_path"
  done < <(child_bead_ids)
}

run_suite() {
  local -a required_paths=()
  local -a json_paths=()
  local bead_id preserved_dir
  ensure_run_dir

  mapfile -t required_paths < <(contract_rel_paths)
  mapfile -t json_paths < <(json_rel_paths)

  run_step "tracked-required-paths" git -C "$root_dir" ls-files --error-unmatch "${required_paths[@]}"
  run_step "json-contracts-and-fixtures" jq empty "${json_paths[@]/#/${root_dir}/}"

  while IFS= read -r bead_id; do
    run_step "br-show-${bead_id}" br show "$bead_id"
  done < <(child_bead_ids)
  write_closeout_summary
  jq -s -e 'all(.[]; .state == "closed")' "$closeout_evidence_path" >/dev/null

  run_step "all-target-cargo-proof-shard-planner-selftest" \
    bash "${root_dir}/scripts/e2e/all_target_cargo_proof_shard_planner_smoke.sh" selftest
  run_step "rch-cache-miss-forensic-ledger-selftest" \
    bash "${root_dir}/scripts/e2e/rch_cache_miss_forensic_ledger_smoke.sh" selftest
  run_step "agent-mail-outage-continuity-bridge-selftest" \
    bash "${root_dir}/scripts/e2e/swarm_agent_mail_outage_continuity_bridge_smoke.sh" selftest
  run_step "objective-artifact-completion-audit-selftest" \
    bash "${root_dir}/scripts/e2e/objective_artifact_completion_audit_gate_smoke.sh" selftest
  run_step "swarm-handoff-capsule-generator-selftest" \
    bash "${root_dir}/scripts/e2e/swarm_handoff_capsule_generator_smoke.sh" selftest
  run_step "high-core-validation-pressure-dashboard-selftest" \
    bash "${root_dir}/scripts/e2e/high_core_validation_pressure_dashboard_smoke.sh" selftest
  run_step "idea-wizard-iii-operator-truth-selftest" \
    bash "${root_dir}/scripts/e2e/idea_wizard_iii_operator_runbook_truth_gate.sh" selftest

  preserved_dir="${run_dir}/preserved/degraded_coordination"
  run_step "degraded-coordination-check" \
    bash "${root_dir}/scripts/e2e/degraded_coordination_no_mock_drill.sh" check
  run_step "degraded-coordination-fixture" \
    bash "${root_dir}/scripts/e2e/degraded_coordination_no_mock_drill.sh" fixture --output-dir "$preserved_dir"
  run_step "degraded-coordination-replay" \
    bash "${root_dir}/scripts/e2e/degraded_coordination_no_mock_drill.sh" replay --replay-run-dir "$preserved_dir"

  verify_command_transcript_safe "$commands_path"
  write_manifests "$preserved_dir"
  record_pass "suite"
}

write_manifests() {
  local preserved_dir="$1"
  jq -s \
    --slurpfile closeouts "$closeout_evidence_path" \
    --arg schema_version "franken-engine.idea-wizard-iii-acceptance-manifest.v1" \
    --arg source_revision "$source_revision" \
    --arg run_dir "$run_dir" \
    --arg preserved_dir "$preserved_dir" \
    --arg preserved_manifest "${preserved_dir}/run_manifest.json" \
    --arg preserved_report "${preserved_dir}/drill_report.json" \
    '{
      schema_version:$schema_version,
      source_revision:$source_revision,
      run_dir:$run_dir,
      decision:(if all(.[]; .exit_code == 0) and all($closeouts[]; .state == "closed") then "accepted" else "blocked" end),
      step_count:length,
      failed_step_count:(map(select(.exit_code != 0)) | length),
      br_closeout_evidence:$closeouts,
      preserved_bundles:{
        degraded_coordination:{
          run_dir:$preserved_dir,
          run_manifest_json:$preserved_manifest,
          drill_report_json:$preserved_report,
          replayed_without_rerun:true
        }
      },
      rust_validation:{
        status:"not_required_source_only_surface",
        required:false,
        if_added_later_must_use:"rch exec -- env CARGO_TARGET_DIR="
      },
      mutation_policy:{
        advisory_only:true,
        proof_only:true,
        mutates_agent_mail:false,
        repairs_agent_mail_db:false,
        mutates_br:false,
        runs_cargo:false,
        runs_rch:false,
        queries_live_workers:false,
        mutates_live_workers:false,
        reruns_child_steps_during_replay:false
      },
      steps:.
    }' "$step_results_path" >"$acceptance_manifest_path"

  jq -n \
    --arg schema_version "franken-engine.idea-wizard-iii-acceptance-suite.run-manifest.v1" \
    --arg source_revision "$source_revision" \
    --arg run_dir "$run_dir" \
    --arg acceptance "$acceptance_manifest_path" \
    --arg events "$events_path" \
    --arg commands "$commands_path" \
    --arg steps "$step_results_path" \
    --arg closeouts "$closeout_evidence_path" \
    '{
      schema_version:$schema_version,
      source_revision:$source_revision,
      run_dir:$run_dir,
      artifacts:{
        acceptance_manifest_json:$acceptance,
        events_jsonl:$events,
        commands_txt:$commands,
        step_results_jsonl:$steps,
        br_closeout_evidence_jsonl:$closeouts
      },
      replay_verification_only:false,
      mutation_policy:{
        advisory_only:true,
        proof_only:true,
        mutates_agent_mail:false,
        repairs_agent_mail_db:false,
        mutates_br:false,
        runs_cargo:false,
        runs_rch:false,
        queries_live_workers:false,
        mutates_live_workers:false
      }
    }' >"$run_manifest_path"

  jq -e '
    .decision == "accepted"
    and .failed_step_count == 0
    and .preserved_bundles.degraded_coordination.replayed_without_rerun == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
  ' "$acceptance_manifest_path" >/dev/null
}

latest_bundle_dir() {
  local parent="$1"
  find "$parent" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' \
    | sort -n \
    | awk 'END {print $2}'
}

run_replay() {
  if [[ -n "$latest_from" ]]; then
    replay_run_dir="$(latest_bundle_dir "$latest_from")"
  fi
  if [[ -z "$replay_run_dir" ]]; then
    printf 'replay requires --replay-run-dir or --latest-from\n' >&2
    exit 64
  fi
  run_dir="$replay_run_dir"
  refresh_paths
  for required in "$run_manifest_path" "$acceptance_manifest_path" "$events_path" "$commands_path" "$step_results_path" "$closeout_evidence_path"; do
    if [[ ! -f "$required" ]]; then
      printf 'acceptance replay missing artifact: %s\n' "$required" >&2
      exit 1
    fi
  done
  jq empty "$run_manifest_path" "$acceptance_manifest_path"
  jq empty "$events_path" "$step_results_path" "$closeout_evidence_path"
  verify_command_transcript_safe "$commands_path"
  jq -e '
    .schema_version == "franken-engine.idea-wizard-iii-acceptance-suite.run-manifest.v1"
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_agent_mail == false
    and .mutation_policy.mutates_live_workers == false
  ' "$run_manifest_path" >/dev/null
  jq -e '
    .schema_version == "franken-engine.idea-wizard-iii-acceptance-manifest.v1"
    and .decision == "accepted"
    and .failed_step_count == 0
    and .preserved_bundles.degraded_coordination.replayed_without_rerun == true
    and .rust_validation.status == "not_required_source_only_surface"
    and all(.br_closeout_evidence[]; .state == "closed")
  ' "$acceptance_manifest_path" >/dev/null
  record_pass "replay"
}

run_check() {
  jq empty "$contract_path"
  bash -n "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "${BASH_SOURCE[0]}"
  fi
  jq -e '
    .schema_version == "franken-engine.idea-wizard-iii-acceptance-suite-contract.v1"
    and .bead_id == "bd-mwg76"
    and (.required_outputs | index("acceptance_manifest.json") != null)
    and (.child_beads | length) == 9
    and .rust_validation_policy.status == "not_required_source_only_surface"
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_agent_mail == false
    and .mutation_policy.mutates_live_workers == false
  ' "$contract_path" >/dev/null
  grep -Fq "Replay mode validates" "$docs_path"
  grep -Fq "not_required_source_only_surface" "$docs_path"
  record_pass "check"
}

run_selftest() {
  run_check
  run_suite
  replay_run_dir="$run_dir"
  run_replay
  record_pass "selftest"
}

case "$mode" in
  suite)
    run_suite
    ;;
  replay)
    run_replay
    ;;
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    printf 'unknown mode: %s\n' "$mode" >&2
    usage
    exit 64
    ;;
esac
