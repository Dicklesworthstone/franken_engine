#!/usr/bin/env bash
set -euo pipefail

artifact_root="${SWARM_CHECKPOINT_BUNDLE_PACKER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-checkpoint-bundle}"
run_id="${SWARM_CHECKPOINT_BUNDLE_PACKER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_CHECKPOINT_BUNDLE_PACKER_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

swarm_capacity_snapshot_json=""
swarm_capacity_forecast_json=""
swarm_admission_budget_plan_json=""
remote_proof_archive_pressure_scoreboard_json=""
stale_lock_recommendations_json=""
swarm_lease_exchange_cancellation_salvage_simulation_json=""
swarm_starvation_rescue_plan_json=""
swarm_operator_status_report_json=""

swarm_high_core_scenario_matrix_report_json=""
swarm_operator_slo_tuning_advisory_json=""
proof_economy_replay_trace_json=""

source_revision=""
now_epoch_seconds="$(date -u +%s)"
stale_after_seconds="1800"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_checkpoint_bundle_packer.sh [OPTIONS]

Build a deterministic checkpoint bundle and evidence ledger for SWARM-CTRL-XI.
The packer is fixture-fed only. It does not query live br, Agent Mail, rch, or
execute Cargo.

Required:
  --swarm-capacity-snapshot-json FILE
  --swarm-capacity-forecast-json FILE
  --swarm-admission-budget-plan-json FILE
  --remote-proof-archive-pressure-scoreboard-json FILE
  --stale-lock-recommendations-json FILE
  --swarm-lease-exchange-cancellation-salvage-simulation-json FILE
  --swarm-starvation-rescue-plan-json FILE
  --swarm-operator-status-report-json FILE

Optional:
  --swarm-high-core-scenario-matrix-report-json FILE
  --swarm-operator-slo-tuning-advisory-json FILE
  --proof-economy-replay-trace-json FILE
  --source-revision REV
  --now-epoch-seconds N
  --stale-after-seconds N
  --output-dir DIR

Artifacts:
  checkpoint_bundle.json
  run_manifest.json
  events.jsonl
  commands.txt
  summary.md

Exit codes:
  0  checkpoint bundle emitted; trust may still be degraded
  42 fail-closed bundle due to stale, contradictory, blocked, or local-fallback evidence
  64 invalid or missing required input path / malformed JSON / bad CLI usage
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --swarm-capacity-snapshot-json)
      swarm_capacity_snapshot_json="${2:-}"
      shift 2
      ;;
    --swarm-capacity-forecast-json)
      swarm_capacity_forecast_json="${2:-}"
      shift 2
      ;;
    --swarm-admission-budget-plan-json)
      swarm_admission_budget_plan_json="${2:-}"
      shift 2
      ;;
    --remote-proof-archive-pressure-scoreboard-json)
      remote_proof_archive_pressure_scoreboard_json="${2:-}"
      shift 2
      ;;
    --stale-lock-recommendations-json)
      stale_lock_recommendations_json="${2:-}"
      shift 2
      ;;
    --swarm-lease-exchange-cancellation-salvage-simulation-json)
      swarm_lease_exchange_cancellation_salvage_simulation_json="${2:-}"
      shift 2
      ;;
    --swarm-starvation-rescue-plan-json)
      swarm_starvation_rescue_plan_json="${2:-}"
      shift 2
      ;;
    --swarm-operator-status-report-json)
      swarm_operator_status_report_json="${2:-}"
      shift 2
      ;;
    --swarm-high-core-scenario-matrix-report-json)
      swarm_high_core_scenario_matrix_report_json="${2:-}"
      shift 2
      ;;
    --swarm-operator-slo-tuning-advisory-json)
      swarm_operator_slo_tuning_advisory_json="${2:-}"
      shift 2
      ;;
    --proof-economy-replay-trace-json)
      proof_economy_replay_trace_json="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    --now-epoch-seconds)
      now_epoch_seconds="${2:-}"
      shift 2
      ;;
    --stale-after-seconds)
      stale_after_seconds="${2:-}"
      shift 2
      ;;
    --output-dir)
      run_dir="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown option: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

is_int() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

if [[ -z "$swarm_capacity_snapshot_json" || -z "$swarm_capacity_forecast_json" || -z "$swarm_admission_budget_plan_json" || -z "$remote_proof_archive_pressure_scoreboard_json" || -z "$stale_lock_recommendations_json" || -z "$swarm_lease_exchange_cancellation_salvage_simulation_json" || -z "$swarm_starvation_rescue_plan_json" || -z "$swarm_operator_status_report_json" ]]; then
  printf 'swarm checkpoint bundle packer requires all eight required JSON inputs\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm checkpoint bundle packing\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for swarm checkpoint bundle packing\n' >&2
  exit 2
fi
if ! is_int "$now_epoch_seconds" || ! is_int "$stale_after_seconds"; then
  printf 'now/stale thresholds must be non-negative integers\n' >&2
  exit 64
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
checkpoint_path="${run_dir}/checkpoint_bundle.json"
checkpoint_tmp="${checkpoint_path}.tmp"
checkpoint_core_path="${run_dir}/checkpoint_bundle.core.json"
run_manifest_path="${run_dir}/run_manifest.json"
run_manifest_tmp="${run_manifest_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
summary_path="${run_dir}/summary.md"
summary_tmp="${summary_path}.tmp"
ledger_entries_jsonl="${run_dir}/artifact_ledger_entries.jsonl"
blockers_jsonl="${run_dir}/blockers.jsonl"
: >"$events_path"
: >"$ledger_entries_jsonl"
: >"$blockers_jsonl"

printf './scripts/swarm_checkpoint_bundle_packer.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-checkpoint-bundle.event.v1" \
    --arg event_name "$1" \
    --arg detail "$2" \
    --arg source_revision "$source_revision" \
    '{
      schema_version: $schema_version,
      event_name: $event_name,
      detail: $detail,
      source_revision: $source_revision
    }' >>"$events_path"
}

append_blocker() {
  local source_name="$1"
  local code="$2"
  local detail="$3"
  jq -nc \
    --arg source_name "$source_name" \
    --arg code "$code" \
    --arg detail "$detail" \
    '{source: $source_name, code: $code, detail: $detail}' >>"$blockers_jsonl"
}

normalize_required_json() {
  local path="$1"
  local label="$2"
  local schema_version="$3"
  local normalized_path="$4"

  if [[ ! -f "$path" ]]; then
    printf 'swarm checkpoint bundle packer missing %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf 'swarm checkpoint bundle packer invalid %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq -e --arg schema_version "$schema_version" '.schema_version == $schema_version' "$path" >/dev/null 2>&1; then
    printf 'swarm checkpoint bundle packer expected %s for %s\n' "$schema_version" "$label" >&2
    exit 64
  fi
  jq -cS . "$path" >"$normalized_path"
  write_event "required_input_normalized" "${label} normalized"
}

normalize_optional_json() {
  local path="$1"
  local label="$2"
  local schema_version="$3"
  local normalized_path="$4"

  if [[ -z "$path" ]]; then
    return 1
  fi
  if [[ ! -f "$path" ]]; then
    printf 'swarm checkpoint bundle packer missing optional %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf 'swarm checkpoint bundle packer invalid optional %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq -e --arg schema_version "$schema_version" '.schema_version == $schema_version' "$path" >/dev/null 2>&1; then
    printf 'swarm checkpoint bundle packer expected %s for optional %s\n' "$schema_version" "$label" >&2
    exit 64
  fi
  jq -cS . "$path" >"$normalized_path"
  write_event "optional_input_normalized" "${label} normalized"
  return 0
}

extract_epoch() {
  local normalized_path="$1"

  jq -r '
    (
      .generated_epoch_seconds
      // .captured_epoch_seconds
      // .snapshot_epoch_seconds
      // .generated_at_epoch_seconds
      // .decision_context.generated_epoch_seconds
      // null
    ) // ""
  ' "$normalized_path"
}

extract_decision() {
  local normalized_path="$1"

  jq -r '
    (
      .decision
      // .policy_decision
      // .verification_decision
      // .capture_decision
      // .summary.readiness
      // .summary.overall_state
      // .predictive_dashboard.capacity_forecast.summary.overall_state
      // .predictive_dashboard.starvation_rescue.top_recommendation_action
      // (if (.safe_to_reopen? | type) == "array" then "pass" else empty end)
      // (if .matrix_schema_version? != null then "pass" else empty end)
      // (if .summary.scenario_count? != null then "pass" else empty end)
      // (if .summary.recommendation_count? != null then "pass" else empty end)
      // (if .summary.replay_event_count? != null then "pass" else empty end)
      // .status
      // "unknown"
    ) | tostring
  ' "$normalized_path"
}

detect_local_fallback() {
  local normalized_path="$1"

  jq -e '
    [.. | scalars | tostring | ascii_downcase | select(test("local_fallback|fallback_to_local|running locally|rch-e326"))]
    | length > 0
  ' "$normalized_path" >/dev/null 2>&1
}

detect_contradiction() {
  local normalized_path="$1"

  jq -e '
    (.summary.ownership_fail_closed_count // 0) > 0
    or ([.. | scalars | tostring | ascii_downcase | select(test("contradictory"))] | length) > 0
  ' "$normalized_path" >/dev/null 2>&1
}

detect_manual_review() {
  local normalized_path="$1"

  jq -e '
    (.summary.manual_review_count // 0) > 0
    or (.summary.contact_first_count // 0) > 0
    or ([.. | scalars | tostring | ascii_downcase | select(test("manual_review|contact_first"))] | length) > 0
  ' "$normalized_path" >/dev/null 2>&1
}

decision_requires_fail_closed() {
  local decision="$1"

  case "$decision" in
    fail_closed|fail|blocked|missing|unknown)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

decision_is_degraded() {
  local decision="$1"

  case "$decision" in
    admit_narrow|defer|manual_review|degraded|brownout|overloaded|low)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

append_ledger_entry() {
  local key="$1"
  local schema_version="$2"
  local path="$3"
  local normalized_path="$4"
  local required="$5"
  local trust_state="$6"
  local freshness_state="$7"
  local decision="$8"

  jq -nc \
    --arg key "$key" \
    --arg schema_version "$schema_version" \
    --arg path "$path" \
    --arg normalized_path "$normalized_path" \
    --arg trust_state "$trust_state" \
    --arg freshness_state "$freshness_state" \
    --arg decision "$decision" \
    --argjson required "$required" \
    '{
      key: $key,
      entry: {
        schema_version: $schema_version,
        path: $path,
        normalized_path: (if $normalized_path == "" then null else $normalized_path end),
        trust_state: $trust_state,
        freshness_state: $freshness_state,
        required: $required,
        decision: $decision
      }
    }' >>"$ledger_entries_jsonl"
}

normalize_required_json "$swarm_capacity_snapshot_json" "swarm capacity snapshot" "franken-engine.swarm-capacity-snapshot.v1" "${run_dir}/swarm_capacity_snapshot.normalized.json"
normalize_required_json "$swarm_capacity_forecast_json" "swarm capacity forecast" "franken-engine.swarm-capacity-forecast.v1" "${run_dir}/swarm_capacity_forecast.normalized.json"
normalize_required_json "$swarm_admission_budget_plan_json" "swarm admission budget plan" "franken-engine.swarm-admission-budget-plan.v1" "${run_dir}/swarm_admission_budget_plan.normalized.json"
normalize_required_json "$remote_proof_archive_pressure_scoreboard_json" "remote proof archive pressure scoreboard" "franken-engine.remote-proof-archive-pressure-scoreboard.v1" "${run_dir}/remote_proof_archive_pressure_scoreboard.normalized.json"
normalize_required_json "$stale_lock_recommendations_json" "stale lock recommendations" "franken-engine.stale-lock-recommendations.v1" "${run_dir}/stale_lock_recommendations.normalized.json"
normalize_required_json "$swarm_lease_exchange_cancellation_salvage_simulation_json" "lease exchange cancellation salvage simulation" "franken-engine.swarm-lease-exchange-cancellation-salvage-simulation.v1" "${run_dir}/swarm_lease_exchange_cancellation_salvage_simulation.normalized.json"
normalize_required_json "$swarm_starvation_rescue_plan_json" "swarm starvation rescue plan" "franken-engine.swarm-starvation-rescue-plan.v1" "${run_dir}/swarm_starvation_rescue_plan.normalized.json"
normalize_required_json "$swarm_operator_status_report_json" "swarm operator status report" "franken-engine.swarm-operator-status-report.v1" "${run_dir}/swarm_operator_status_report.normalized.json"

normalize_optional_json "$swarm_high_core_scenario_matrix_report_json" "swarm high core scenario matrix report" "franken-engine.swarm-high-core-scenario-matrix-report.v1" "${run_dir}/swarm_high_core_scenario_matrix_report.normalized.json" || true
normalize_optional_json "$swarm_operator_slo_tuning_advisory_json" "swarm operator SLO tuning advisory" "franken-engine.swarm-operator-slo-tuning-advisory.v1" "${run_dir}/swarm_operator_slo_tuning_advisory.normalized.json" || true
normalize_optional_json "$proof_economy_replay_trace_json" "proof economy replay trace" "franken-engine.proof-economy-replay-trace.v1" "${run_dir}/proof_economy_replay_trace.normalized.json" || true

required_degraded_count=0
optional_degraded_count=0
manual_review_signal_count=0

process_required_artifact() {
  local key="$1"
  local schema_version="$2"
  local original_path="$3"
  local normalized_path="$4"

  local epoch decision freshness_state trust_state
  epoch="$(extract_epoch "$normalized_path")"
  decision="$(extract_decision "$normalized_path")"
  freshness_state="fresh"
  trust_state="primary"

  if [[ -z "$epoch" ]]; then
    freshness_state="missing_timestamp"
    append_blocker "$key" "missing_timestamp" "${key} does not expose a replayable generated timestamp."
  elif ! is_int "$epoch"; then
    freshness_state="invalid_timestamp"
    append_blocker "$key" "invalid_timestamp" "${key} generated timestamp is not numeric."
  elif (( now_epoch_seconds - epoch > stale_after_seconds )); then
    freshness_state="stale"
    append_blocker "$key" "stale_required_artifact" "${key} is older than the allowed checkpoint freshness window."
  fi

  if detect_local_fallback "$normalized_path"; then
    trust_state="local_fallback"
    append_blocker "$key" "local_fallback_heavy_proof_contamination" "${key} contains local-fallback heavy-proof evidence."
  fi

  if detect_contradiction "$normalized_path"; then
    trust_state="contradictory"
    append_blocker "$key" "contradictory_ownership" "${key} exposes contradictory ownership or reservation evidence."
  fi

  if decision_requires_fail_closed "$decision"; then
    if [[ "$trust_state" == "primary" ]]; then
      trust_state="degraded"
    fi
    append_blocker "$key" "decision_fail_closed" "${key} decision ${decision} is already beyond restore safety."
  elif decision_is_degraded "$decision"; then
    trust_state="degraded"
    required_degraded_count=$((required_degraded_count + 1))
  fi

  if detect_manual_review "$normalized_path"; then
    if [[ "$trust_state" == "primary" ]]; then
      trust_state="degraded"
      required_degraded_count=$((required_degraded_count + 1))
    fi
    manual_review_signal_count=$((manual_review_signal_count + 1))
  fi

  append_ledger_entry "$key" "$schema_version" "$original_path" "$normalized_path" true "$trust_state" "$freshness_state" "$decision"
}

process_optional_artifact() {
  local key="$1"
  local schema_version="$2"
  local original_path="$3"
  local normalized_path="$4"

  if [[ -z "$original_path" ]]; then
    optional_degraded_count=$((optional_degraded_count + 1))
    append_ledger_entry "$key" "$schema_version" "" "" false "missing" "missing" "missing"
    return 0
  fi

  local epoch decision freshness_state trust_state
  epoch="$(extract_epoch "$normalized_path")"
  decision="$(extract_decision "$normalized_path")"
  freshness_state="fresh"
  trust_state="optional"

  if [[ -z "$epoch" ]]; then
    freshness_state="missing_timestamp"
    trust_state="degraded"
    optional_degraded_count=$((optional_degraded_count + 1))
  elif ! is_int "$epoch"; then
    freshness_state="invalid_timestamp"
    trust_state="degraded"
    optional_degraded_count=$((optional_degraded_count + 1))
  elif (( now_epoch_seconds - epoch > stale_after_seconds )); then
    freshness_state="stale"
    trust_state="degraded"
    optional_degraded_count=$((optional_degraded_count + 1))
  fi

  if detect_local_fallback "$normalized_path"; then
    trust_state="degraded"
    optional_degraded_count=$((optional_degraded_count + 1))
  elif decision_requires_fail_closed "$decision" || decision_is_degraded "$decision"; then
    if [[ "$trust_state" != "degraded" ]]; then
      trust_state="degraded"
      optional_degraded_count=$((optional_degraded_count + 1))
    fi
  fi

  append_ledger_entry "$key" "$schema_version" "$original_path" "$normalized_path" false "$trust_state" "$freshness_state" "$decision"
}

process_required_artifact "swarm_capacity_snapshot" "franken-engine.swarm-capacity-snapshot.v1" "$swarm_capacity_snapshot_json" "${run_dir}/swarm_capacity_snapshot.normalized.json"
process_required_artifact "swarm_capacity_forecast" "franken-engine.swarm-capacity-forecast.v1" "$swarm_capacity_forecast_json" "${run_dir}/swarm_capacity_forecast.normalized.json"
process_required_artifact "swarm_admission_budget_plan" "franken-engine.swarm-admission-budget-plan.v1" "$swarm_admission_budget_plan_json" "${run_dir}/swarm_admission_budget_plan.normalized.json"
process_required_artifact "remote_proof_archive_pressure_scoreboard" "franken-engine.remote-proof-archive-pressure-scoreboard.v1" "$remote_proof_archive_pressure_scoreboard_json" "${run_dir}/remote_proof_archive_pressure_scoreboard.normalized.json"
process_required_artifact "stale_lock_recommendations" "franken-engine.stale-lock-recommendations.v1" "$stale_lock_recommendations_json" "${run_dir}/stale_lock_recommendations.normalized.json"
process_required_artifact "swarm_lease_exchange_cancellation_salvage_simulation" "franken-engine.swarm-lease-exchange-cancellation-salvage-simulation.v1" "$swarm_lease_exchange_cancellation_salvage_simulation_json" "${run_dir}/swarm_lease_exchange_cancellation_salvage_simulation.normalized.json"
process_required_artifact "swarm_starvation_rescue_plan" "franken-engine.swarm-starvation-rescue-plan.v1" "$swarm_starvation_rescue_plan_json" "${run_dir}/swarm_starvation_rescue_plan.normalized.json"
process_required_artifact "swarm_operator_status_report" "franken-engine.swarm-operator-status-report.v1" "$swarm_operator_status_report_json" "${run_dir}/swarm_operator_status_report.normalized.json"

process_optional_artifact "swarm_high_core_scenario_matrix_report" "franken-engine.swarm-high-core-scenario-matrix-report.v1" "$swarm_high_core_scenario_matrix_report_json" "${run_dir}/swarm_high_core_scenario_matrix_report.normalized.json"
process_optional_artifact "swarm_operator_slo_tuning_advisory" "franken-engine.swarm-operator-slo-tuning-advisory.v1" "$swarm_operator_slo_tuning_advisory_json" "${run_dir}/swarm_operator_slo_tuning_advisory.normalized.json"
process_optional_artifact "proof_economy_replay_trace" "franken-engine.proof-economy-replay-trace.v1" "$proof_economy_replay_trace_json" "${run_dir}/proof_economy_replay_trace.normalized.json"

blocker_count="$(jq -s 'length' "$blockers_jsonl")"
capture_decision="captured"
restore_readiness_hint="candidate"
if [[ "$blocker_count" -gt 0 ]]; then
  capture_decision="fail_closed"
  restore_readiness_hint="blocked"
elif [[ "$required_degraded_count" -gt 0 || "$optional_degraded_count" -gt 0 || "$manual_review_signal_count" -gt 0 ]]; then
  capture_decision="captured_degraded"
  restore_readiness_hint="manual_review"
fi

artifact_ledger_json="$(jq -s 'map({(.key): .entry}) | add' "$ledger_entries_jsonl")"
blockers_json="$(jq -s '.' "$blockers_jsonl")"
normalized_inputs_json="$(
  jq -nc \
    --arg swarm_capacity_snapshot_json "${run_dir}/swarm_capacity_snapshot.normalized.json" \
    --arg swarm_capacity_forecast_json "${run_dir}/swarm_capacity_forecast.normalized.json" \
    --arg swarm_admission_budget_plan_json "${run_dir}/swarm_admission_budget_plan.normalized.json" \
    --arg remote_proof_archive_pressure_scoreboard_json "${run_dir}/remote_proof_archive_pressure_scoreboard.normalized.json" \
    --arg stale_lock_recommendations_json "${run_dir}/stale_lock_recommendations.normalized.json" \
    --arg swarm_lease_exchange_cancellation_salvage_simulation_json "${run_dir}/swarm_lease_exchange_cancellation_salvage_simulation.normalized.json" \
    --arg swarm_starvation_rescue_plan_json "${run_dir}/swarm_starvation_rescue_plan.normalized.json" \
    --arg swarm_operator_status_report_json "${run_dir}/swarm_operator_status_report.normalized.json" \
    --arg swarm_high_core_scenario_matrix_report_json "$(if [[ -n "$swarm_high_core_scenario_matrix_report_json" ]]; then printf '%s' "${run_dir}/swarm_high_core_scenario_matrix_report.normalized.json"; fi)" \
    --arg swarm_operator_slo_tuning_advisory_json "$(if [[ -n "$swarm_operator_slo_tuning_advisory_json" ]]; then printf '%s' "${run_dir}/swarm_operator_slo_tuning_advisory.normalized.json"; fi)" \
    --arg proof_economy_replay_trace_json "$(if [[ -n "$proof_economy_replay_trace_json" ]]; then printf '%s' "${run_dir}/proof_economy_replay_trace.normalized.json"; fi)" \
    '{
      swarm_capacity_snapshot_json: $swarm_capacity_snapshot_json,
      swarm_capacity_forecast_json: $swarm_capacity_forecast_json,
      swarm_admission_budget_plan_json: $swarm_admission_budget_plan_json,
      remote_proof_archive_pressure_scoreboard_json: $remote_proof_archive_pressure_scoreboard_json,
      stale_lock_recommendations_json: $stale_lock_recommendations_json,
      swarm_lease_exchange_cancellation_salvage_simulation_json: $swarm_lease_exchange_cancellation_salvage_simulation_json,
      swarm_starvation_rescue_plan_json: $swarm_starvation_rescue_plan_json,
      swarm_operator_status_report_json: $swarm_operator_status_report_json,
      swarm_high_core_scenario_matrix_report_json: (if $swarm_high_core_scenario_matrix_report_json == "" then null else $swarm_high_core_scenario_matrix_report_json end),
      swarm_operator_slo_tuning_advisory_json: (if $swarm_operator_slo_tuning_advisory_json == "" then null else $swarm_operator_slo_tuning_advisory_json end),
      proof_economy_replay_trace_json: (if $proof_economy_replay_trace_json == "" then null else $proof_economy_replay_trace_json end)
    }'
)"

jq -n \
  --arg source_revision "$source_revision" \
  --arg capture_decision "$capture_decision" \
  --arg restore_readiness_hint "$restore_readiness_hint" \
  --argjson captured_epoch_seconds "$now_epoch_seconds" \
  --argjson stale_after_seconds "$stale_after_seconds" \
  --argjson blocker_count "$blocker_count" \
  --argjson required_degraded_count "$required_degraded_count" \
  --argjson optional_degraded_count "$optional_degraded_count" \
  --argjson manual_review_signal_count "$manual_review_signal_count" \
  --argjson blockers "$blockers_json" \
  --argjson artifact_ledger "$artifact_ledger_json" \
  --argjson normalized_inputs "$normalized_inputs_json" \
  '{
    source_revision: $source_revision,
    capture_decision: $capture_decision,
    restore_readiness_hint: $restore_readiness_hint,
    captured_epoch_seconds: $captured_epoch_seconds,
    stale_after_seconds: $stale_after_seconds,
    upstream_evidence: {
      required_count: 8,
      optional_count: 3,
      required_degraded_count: $required_degraded_count,
      optional_degraded_count: $optional_degraded_count,
      manual_review_signal_count: $manual_review_signal_count,
      blocker_count: $blocker_count
    },
    artifact_ledger: $artifact_ledger,
    blockers: $blockers,
    normalized_inputs: $normalized_inputs
  }' >"$checkpoint_core_path"

checkpoint_hash="$(jq -cS . "$checkpoint_core_path" | sha256sum | awk '{print $1}')"

jq -n \
  --arg schema_version "franken-engine.swarm-checkpoint-bundle.v1" \
  --arg checkpoint_id "swarm-checkpoint-${checkpoint_hash:0:16}" \
  --argjson core "$(jq -cS . "$checkpoint_core_path")" \
  --arg checkpoint_path "$checkpoint_path" \
  --arg run_manifest_path "$run_manifest_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg summary_path "$summary_path" \
  '{
    schema_version: $schema_version,
    checkpoint_id: $checkpoint_id,
    capture_decision: $core.capture_decision,
    restore_readiness_hint: $core.restore_readiness_hint,
    captured_epoch_seconds: $core.captured_epoch_seconds,
    stale_after_seconds: $core.stale_after_seconds,
    source_revision: $core.source_revision,
    upstream_evidence: $core.upstream_evidence,
    artifact_ledger: $core.artifact_ledger,
    blockers: $core.blockers,
    normalized_inputs: $core.normalized_inputs,
    artifact_paths: {
      checkpoint_bundle_json: $checkpoint_path,
      run_manifest_json: $run_manifest_path,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      summary_md: $summary_path
    }
  }' >"$checkpoint_tmp"
mv "$checkpoint_tmp" "$checkpoint_path"

jq -n \
  --arg schema_version "franken-engine.swarm-checkpoint-bundle.run-manifest.v1" \
  --arg checkpoint_id "$(jq -r '.checkpoint_id' "$checkpoint_path")" \
  --arg source_revision "$source_revision" \
  --arg capture_decision "$capture_decision" \
  --arg restore_readiness_hint "$restore_readiness_hint" \
  --argjson captured_epoch_seconds "$now_epoch_seconds" \
  --arg commands_path "$commands_path" \
  --arg events_path "$events_path" \
  --arg summary_path "$summary_path" \
  --arg checkpoint_path "$checkpoint_path" \
  --arg checkpoint_core_path "$checkpoint_core_path" \
  --argjson normalized_inputs "$normalized_inputs_json" \
  '{
    schema_version: $schema_version,
    component: "swarm_checkpoint_bundle_packer",
    checkpoint_id: $checkpoint_id,
    source_revision: $source_revision,
    capture_decision: $capture_decision,
    restore_readiness_hint: $restore_readiness_hint,
    captured_epoch_seconds: $captured_epoch_seconds,
    normalized_inputs: $normalized_inputs,
    artifact_paths: {
      checkpoint_bundle_json: $checkpoint_path,
      checkpoint_bundle_core_json: $checkpoint_core_path,
      commands_txt: $commands_path,
      events_jsonl: $events_path,
      summary_md: $summary_path
    }
  }' >"$run_manifest_tmp"
mv "$run_manifest_tmp" "$run_manifest_path"

{
  printf '# Swarm Checkpoint Bundle\n\n'
  printf -- "- Checkpoint id: \`%s\`\n" "$(jq -r '.checkpoint_id' "$checkpoint_path")"
  printf -- "- Capture decision: \`%s\`\n" "$capture_decision"
  printf -- "- Restore readiness hint: \`%s\`\n" "$restore_readiness_hint"
  printf -- "- Required degraded count: \`%s\`\n" "$required_degraded_count"
  printf -- "- Optional degraded count: \`%s\`\n" "$optional_degraded_count"
  printf -- "- Manual review signals: \`%s\`\n" "$manual_review_signal_count"
  printf -- "- Blocker count: \`%s\`\n\n" "$blocker_count"
  if [[ "$blocker_count" -eq 0 ]]; then
    printf 'No fail-closed blockers were detected.\n'
  else
    jq -r '.blockers[] | "- `" + .source + "` -> `" + .code + "`: " + .detail' "$checkpoint_path"
  fi
} >"$summary_tmp"
mv "$summary_tmp" "$summary_path"

write_event "checkpoint_bundle_emitted" "checkpoint bundle and run manifest emitted"
if [[ "$capture_decision" == "fail_closed" ]]; then
  write_event "checkpoint_bundle_fail_closed" "restore safety blockers prevent a trusted checkpoint"
else
  write_event "checkpoint_bundle_replayable" "checkpoint bundle emitted for advisory restore planning"
fi

printf 'swarm_checkpoint_bundle=%s\n' "$checkpoint_path"
printf 'swarm_checkpoint_run_manifest=%s\n' "$run_manifest_path"

if [[ "$capture_decision" == "fail_closed" ]]; then
  exit 42
fi
exit 0
