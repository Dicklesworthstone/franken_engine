#!/usr/bin/env bash
set -euo pipefail

artifact_root="${SWARM_AUTOPILOT_RESOURCE_LEASE_ALLOCATOR_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-autopilot-resource-lease-allocator}"
run_id="${SWARM_AUTOPILOT_RESOURCE_LEASE_ALLOCATOR_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_AUTOPILOT_RESOURCE_LEASE_ALLOCATOR_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

source_revision="${SWARM_AUTOPILOT_RESOURCE_LEASE_ALLOCATOR_SOURCE_REVISION:-unknown}"
operator_intent_policy_json=""
brownout_forecaster_json=""
queue_advisory_bundle_json=""
rch_rehabilitation_ledger_json=""
now_epoch_seconds="$(date -u +%s)"
stale_after_seconds="1800"
default_lease_duration_seconds="1800"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_autopilot_resource_lease_allocator.sh [OPTIONS]

Compose advisory-only resource lease recommendations from operator policy,
brownout forecast, queue/locality advisory, and RCH rehabilitation evidence.
This script is fixture-fed only and never mutates beads, reservations, Agent
Mail, Cargo, RCH, workers, or live queue policy.

Required inputs:
  --operator-intent-policy-json FILE
  --brownout-forecaster-json FILE
  --queue-advisory-bundle-json FILE
  --rch-rehabilitation-ledger-json FILE

Optional inputs:
  --source-revision REV
  --now-epoch-seconds N
  --stale-after-seconds N
  --default-lease-duration-seconds N
  --output-dir DIR

Artifacts:
  swarm_autopilot_resource_lease_plan.json
  swarm_autopilot_resource_scarcity_receipts.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  advisory lease plan emitted successfully
  42 contradictory, stale, contaminated, or incomplete evidence forced fail_closed
  64 invalid or missing required inputs
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --operator-intent-policy-json)
      operator_intent_policy_json="${2:-}"
      shift 2
      ;;
    --brownout-forecaster-json)
      brownout_forecaster_json="${2:-}"
      shift 2
      ;;
    --queue-advisory-bundle-json)
      queue_advisory_bundle_json="${2:-}"
      shift 2
      ;;
    --rch-rehabilitation-ledger-json)
      rch_rehabilitation_ledger_json="${2:-}"
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
    --default-lease-duration-seconds)
      default_lease_duration_seconds="${2:-}"
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
      printf 'unknown argument: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

is_int() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

for required_path in \
  "$operator_intent_policy_json" \
  "$brownout_forecaster_json" \
  "$queue_advisory_bundle_json" \
  "$rch_rehabilitation_ledger_json"; do
  if [[ -z "$required_path" ]]; then
    printf 'all required resource lease allocator inputs must be provided\n' >&2
    usage
    exit 64
  fi
done

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for the swarm autopilot resource lease allocator\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for the swarm autopilot resource lease allocator\n' >&2
  exit 2
fi
if ! is_int "$now_epoch_seconds" || ! is_int "$stale_after_seconds" || ! is_int "$default_lease_duration_seconds"; then
  printf 'time and lease-duration arguments must be non-negative integers\n' >&2
  exit 64
fi

mkdir -p "$run_dir"
plan_path="${run_dir}/swarm_autopilot_resource_lease_plan.json"
plan_tmp="${plan_path}.tmp"
plan_core="${run_dir}/swarm_autopilot_resource_lease_plan.core.json"
receipts_path="${run_dir}/swarm_autopilot_resource_scarcity_receipts.json"
receipts_tmp="${receipts_path}.tmp"
receipts_core="${run_dir}/swarm_autopilot_resource_scarcity_receipts.core.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
fail_closed_reasons_jsonl="${run_dir}/fail_closed_reasons.jsonl"

policy_normalized="${run_dir}/operator_intent_policy.normalized.json"
forecast_normalized="${run_dir}/brownout_forecaster.normalized.json"
queue_advisory_normalized="${run_dir}/queue_advisory_bundle.normalized.json"
rehab_normalized="${run_dir}/rch_rehabilitation_ledger.normalized.json"

printf './scripts/swarm_autopilot_resource_lease_allocator.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

: >"$events_path"
: >"$fail_closed_reasons_jsonl"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-autopilot-resource-lease-allocator.event.v1" \
    --arg trace_id "trace-swarm-autopilot-resource-lease-allocator-${run_id}" \
    --arg component "$1" \
    --arg event "$2" \
    --arg outcome "$3" \
    --arg error_code "$4" \
    --arg evidence_path "$5" \
    '{
      schema_version:$schema_version,
      trace_id:$trace_id,
      component:$component,
      event:$event,
      outcome:$outcome,
      error_code:(if $error_code == "" then null else $error_code end),
      evidence_path:$evidence_path
    }' >>"$events_path"
}

append_failure() {
  local code="$1"
  local source_id="$2"
  local detail="$3"
  local remediation_command="$4"
  jq -nc \
    --arg code "$code" \
    --arg source_id "$source_id" \
    --arg detail "$detail" \
    --arg remediation_command "$remediation_command" \
    '{code:$code,source_id:$source_id,detail:$detail,remediation_command:$remediation_command}' \
    >>"$fail_closed_reasons_jsonl"
  write_event "$source_id" "fail_closed_reason" "captured" "$code" "$source_id"
}

normalize_required_json() {
  local input_path="$1"
  local output_path="$2"
  local label="$3"
  if [[ ! -f "$input_path" ]]; then
    printf 'missing required %s JSON: %s\n' "$label" "$input_path" >&2
    exit 64
  fi
  if ! jq empty "$input_path" >/dev/null 2>&1; then
    printf 'invalid required %s JSON: %s\n' "$label" "$input_path" >&2
    exit 64
  fi
  jq -cS . "$input_path" >"$output_path"
  write_event "$label" "input_loaded" "captured" "" "$output_path"
}

check_shape() {
  local path="$1"
  local expr="$2"
  local code="$3"
  local source_id="$4"
  local detail="$5"
  local remediation="$6"
  if ! jq -e "$expr" "$path" >/dev/null 2>&1; then
    append_failure "$code" "$source_id" "$detail" "$remediation"
  fi
}

snapshot_epoch_for() {
  local file="$1"
  jq -r '
    if (.generated_epoch_seconds? | type) == "number" then
      .generated_epoch_seconds
    elif (.captured_epoch_seconds? | type) == "number" then
      .captured_epoch_seconds
    else
      0
    end
  ' "$file"
}

check_staleness() {
  local file="$1"
  local source_id="$2"
  local label="$3"
  local remediation="$4"
  local epoch age

  epoch="$(snapshot_epoch_for "$file")"
  if is_int "$epoch" && (( epoch > 0 )); then
    age=$((now_epoch_seconds - epoch))
    if (( age > stale_after_seconds )); then
      append_failure "FE-SWARM-AUTOPILOT-LEASE-STALE-EVIDENCE" "$source_id" "${label} age ${age}s exceeds ${stale_after_seconds}s" "$remediation"
    fi
  fi
}

normalize_required_json "$operator_intent_policy_json" "$policy_normalized" "operator_intent_policy"
normalize_required_json "$brownout_forecaster_json" "$forecast_normalized" "brownout_forecaster"
normalize_required_json "$queue_advisory_bundle_json" "$queue_advisory_normalized" "queue_advisory_bundle"
normalize_required_json "$rch_rehabilitation_ledger_json" "$rehab_normalized" "rch_rehabilitation_ledger"

if [[ "$source_revision" == "unknown" ]]; then
  source_revision="$(jq -r '.source_revision // empty' "$forecast_normalized")"
fi
if [[ -z "$source_revision" || "$source_revision" == "null" || "$source_revision" == "unknown" ]]; then
  source_revision="$(jq -r '.source_revision // empty' "$policy_normalized")"
fi
if [[ -z "$source_revision" || "$source_revision" == "null" || "$source_revision" == "unknown" ]]; then
  source_revision="unknown"
fi

check_shape "$policy_normalized" '
  type == "object"
  and .schema_version == "franken-engine.swarm-autopilot-operator-intent-policy.v1"
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.safe_mode_active | type) == "boolean")
  and ((.thresholds.reserve_urgent_rch_slack_slots // null) | type == "number")
  and ((.thresholds.fairness_skew_limit_millionths // null) | type == "number")
  and ((.thresholds.default_lease_duration_seconds // null) | type == "number")
  and ((.thresholds.proof_cache_cooldown_seconds // null) | type == "number")
  and ((.precedence_order // null) | type == "array")
  and .mutation_policy.advisory_only == true
  and .mutation_policy.proof_only == true
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
' "FE-SWARM-AUTOPILOT-LEASE-SCHEMA-DRIFT" "operator_intent_policy_json" \
  "operator intent policy is missing thresholds, safe-mode, precedence, or safety markers" \
  "Regenerate the operator intent policy before allocating scarce resources."

check_shape "$forecast_normalized" '
  type == "object"
  and .schema_version == "franken-engine.swarm-autopilot-brownout-forecaster.v1"
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.summary.overall_state // "") | (type == "string" and length > 0))
  and ((.summary.brownout_state // "") | (type == "string" and length > 0))
  and ((.forecasts.rch_slot_exhaustion.state // "") | (type == "string" and length > 0))
  and ((.forecasts.proof_cache_pressure.state // "") | (type == "string" and length > 0))
  and ((.forecasts.fairness_starvation_window.state // "") | (type == "string" and length > 0))
  and .mutation_policy.advisory_only == true
  and .mutation_policy.proof_only == true
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
' "FE-SWARM-AUTOPILOT-LEASE-SCHEMA-DRIFT" "brownout_forecaster_json" \
  "brownout forecaster is missing required category states or safety markers" \
  "Regenerate the brownout forecaster before allocating scarce resources."

check_shape "$queue_advisory_normalized" '
  type == "object"
  and .schema_version == "franken-engine.swarm-topology-aware-queue-advisory.v1"
  and ((.truth_state // "") | (type == "string" and length > 0))
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.reason_codes // null) | type == "array")
  and ((.worker_exclusions // null) | type == "array")
  and ((.candidate_lanes // null) | type == "array")
  and ((.candidate_lanes | length) > 0)
  and all(.candidate_lanes[]?;
    ((.lane_id // "") | (type == "string" and length > 0))
    and ((.title // "") | (type == "string" and length > 0))
    and ((.urgent | type) == "boolean")
    and ((.workload_class // "") | (type == "string" and length > 0))
    and ((.resource_demand.rch_slots // null) | type == "number")
    and ((.resource_demand.cpu_slots // null) | type == "number")
    and ((.resource_demand.memory_gib // null) | type == "number")
    and ((.fairness_skew_millionths // null) | type == "number")
  )
  and .mutation_policy.advisory_only == true
  and .mutation_policy.proof_only == true
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
' "FE-SWARM-AUTOPILOT-LEASE-SCHEMA-DRIFT" "queue_advisory_bundle_json" \
  "queue advisory bundle is missing candidate lanes, reason codes, or safety markers" \
  "Regenerate the topology-aware queue advisory before allocating scarce resources."

check_shape "$rehab_normalized" '
  type == "object"
  and .schema_version == "franken-engine.swarm-rch-stall-rehabilitation-ledger.v1"
  and ((.decision // "") | (type == "string" and length > 0))
  and ((.summary.available_slot_count // null) | type == "number")
  and ((.worker_receipts // null) | type == "array")
  and ((.worker_receipts | length) > 0)
  and all(.worker_receipts[]?;
    ((.worker_id // "") | (type == "string" and length > 0))
    and ((.classification // "") | (type == "string" and length > 0))
    and ((.latest_progress_age_seconds // null) | type == "number")
    and ((.latest_heartbeat_age_seconds // null) | type == "number")
    and ((.pressure_telemetry.slot_utilization_millionths // null) | type == "number")
  )
  and .mutation_policy.advisory_only == true
  and .mutation_policy.proof_only == true
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
' "FE-SWARM-AUTOPILOT-LEASE-MISSING-WORKER-PRESSURE" "rch_rehabilitation_ledger_json" \
  "rehabilitation ledger is missing worker pressure telemetry or safety markers" \
  "Refresh the RCH rehabilitation ledger before allocating scarce resources."

check_staleness "$policy_normalized" "operator_intent_policy_json" "operator intent policy" \
  "Refresh the operator intent policy before allocating scarce resources."
check_staleness "$forecast_normalized" "brownout_forecaster_json" "brownout forecast" \
  "Refresh the brownout forecaster before allocating scarce resources."
check_staleness "$queue_advisory_normalized" "queue_advisory_bundle_json" "queue advisory bundle" \
  "Refresh the queue advisory bundle before allocating scarce resources."
check_staleness "$rehab_normalized" "rch_rehabilitation_ledger_json" "rehabilitation ledger" \
  "Refresh the RCH rehabilitation ledger before allocating scarce resources."

if jq -e '.decision == "fail_closed" or .decision == "safe_mode"' "$policy_normalized" >/dev/null 2>&1; then
  append_failure "FE-SWARM-AUTOPILOT-LEASE-UPSTREAM-UNTRUSTED" "operator_intent_policy_json" \
    "fail_closed or safe_mode policy inputs are not promotable into lease allocations" \
    "Resolve policy conflicts before allocating scarce resources."
fi
if jq -e '.decision == "fail_closed"' "$forecast_normalized" >/dev/null 2>&1; then
  append_failure "FE-SWARM-AUTOPILOT-LEASE-UPSTREAM-UNTRUSTED" "brownout_forecaster_json" \
    "fail_closed brownout forecasts are not promotable into lease allocations" \
    "Refresh the brownout forecaster before allocating scarce resources."
fi
if jq -e '.decision == "fail_closed"' "$rehab_normalized" >/dev/null 2>&1; then
  append_failure "FE-SWARM-AUTOPILOT-LEASE-UPSTREAM-UNTRUSTED" "rch_rehabilitation_ledger_json" \
    "fail_closed rehabilitation evidence is not promotable into lease allocations" \
    "Refresh the rehabilitation ledger before allocating scarce resources."
fi
if jq -e '.decision == "blocked" or .decision == "fail_closed" or ((.reason_codes // []) | index("contradictory_locality") != null)' "$queue_advisory_normalized" >/dev/null 2>&1; then
  append_failure "FE-SWARM-AUTOPILOT-LEASE-CONTRADICTORY-QUEUE" "queue_advisory_bundle_json" \
    "contradictory or blocked queue locality evidence prevents scarcity allocation" \
    "Resolve contradictory queue locality evidence before allocating scarce resources."
fi
if jq -e '
  ((.fail_closed_reasons // []) | any(
    ((.code // "") | test("LOCAL-FALLBACK|local fallback"; "i"))
    or ((.detail // "") | test("LOCAL-FALLBACK|local fallback|contaminated"; "i"))
  ))
' "$forecast_normalized" >/dev/null 2>&1 \
  || jq -e '((.reason_codes // []) | index("local_fallback_contaminated") != null)' "$queue_advisory_normalized" >/dev/null 2>&1 \
  || jq -e '((.worker_receipts // []) | any((.reason_codes // []) | index("local_fallback_contaminated") != null))' "$rehab_normalized" >/dev/null 2>&1; then
  append_failure "FE-SWARM-AUTOPILOT-LEASE-LOCAL-FALLBACK" "local_fallback_state" \
    "local fallback contamination is present in required scarcity evidence" \
    "Discard contaminated local-fallback captures before allocating scarce resources."
fi

policy_sha="$(sha256sum "$policy_normalized" | awk '{print $1}')"
forecast_sha="$(sha256sum "$forecast_normalized" | awk '{print $1}')"
queue_sha="$(sha256sum "$queue_advisory_normalized" | awk '{print $1}')"
rehab_sha="$(sha256sum "$rehab_normalized" | awk '{print $1}')"

decision="pass"
truth_state="confirmed"
exit_code=0
if [[ -s "$fail_closed_reasons_jsonl" ]]; then
  decision="fail_closed"
  truth_state="unknown"
  exit_code=42
elif jq -e '.truth_state != "confirmed" or .decision != "pass"' "$queue_advisory_normalized" >/dev/null 2>&1; then
  truth_state="degraded"
fi

jq -n \
  --slurpfile policy "$policy_normalized" \
  --slurpfile forecast "$forecast_normalized" \
  --slurpfile queue "$queue_advisory_normalized" \
  --slurpfile rehab "$rehab_normalized" \
  --slurpfile fail_closed_reasons "$fail_closed_reasons_jsonl" \
  --arg source_revision "$source_revision" \
  --arg decision "$decision" \
  --arg truth_state "$truth_state" \
  --arg plan_path "$plan_path" \
  --arg receipts_path "$receipts_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --arg policy_sha "$policy_sha" \
  --arg forecast_sha "$forecast_sha" \
  --arg queue_sha "$queue_sha" \
  --arg rehab_sha "$rehab_sha" \
  --argjson now_epoch_seconds "$now_epoch_seconds" \
  --argjson default_lease_duration_seconds "$default_lease_duration_seconds" \
  '
  ($policy[0]) as $p |
  ($forecast[0]) as $f |
  ($queue[0]) as $q |
  ($rehab[0]) as $r |
  ($p.thresholds.default_lease_duration_seconds // $default_lease_duration_seconds) as $default_lease_seconds |
  ($p.thresholds.proof_cache_cooldown_seconds // 900) as $proof_cache_cooldown_seconds |
  ($p.thresholds.fairness_skew_limit_millionths // 600000) as $fairness_limit |
  ($p.thresholds.reserve_urgent_rch_slack_slots // 0) as $reserve_urgent_rch_slack_slots |
  ($f.forecasts.rch_slot_exhaustion.state // "unknown") as $rch_state |
  ($f.forecasts.proof_cache_pressure.state // "unknown") as $proof_cache_state |
  ($f.forecasts.fairness_starvation_window.state // "unknown") as $fairness_state |
  ($q.locality_bias_summary.cache_reuse_preferred // false) as $cache_reuse_preferred |
  ($q.worker_exclusions // []) as $worker_exclusions |
  ($r.summary.available_slot_count // 0) as $available_slot_count |
  ([
    ($p.artifact_paths.operator_intent_policy_json // ""),
    ($f.artifact_paths.swarm_autopilot_brownout_forecast_json // ""),
    ($q.artifact_paths.queue_advisory_bundle_json // ""),
    ($r.artifact_paths.ledger_json // "")
  ] | map(select(length > 0)) | unique) as $base_evidence_paths |
  (
    if $decision == "fail_closed" then
      ($q.candidate_lanes // []) | map({
        lane_id: .lane_id,
        title: .title,
        decision: "fail_closed",
        resource_class: "all",
        lease_duration_seconds: 0,
        preferred_workers: [],
        excluded_workers: $worker_exclusions,
        reason_codes: ["allocator_fail_closed"],
        evidence_paths: $base_evidence_paths,
        rollback_command: "# operator: do not apply any leases while evidence is fail_closed",
        remediation_command: "Refresh contradicted, stale, or contaminated evidence before allocating scarce resources."
      })
    else
      ($q.candidate_lanes // []) | map(
        . as $lane |
        if (($lane.urgent // false) and $reserve_urgent_rch_slack_slots > 0 and ($rch_state == "watch" or $rch_state == "brownout")) then
          {
            lane_id: $lane.lane_id,
            title: $lane.title,
            decision: "reserve",
            resource_class: "rch_slots",
            lease_duration_seconds: $default_lease_seconds,
            preferred_workers: ($q.locality_bias_summary.preferred_workers // []),
            excluded_workers: $worker_exclusions,
            reason_codes: ["urgent_rch_slack_protected", "policy_precedence_enforced"],
            evidence_paths: $base_evidence_paths,
            rollback_command: "# operator: reduce reserved urgent RCH slack after pressure cools",
            remediation_command: "Re-run the allocator when RCH-slot pressure returns to green."
          }
        elif ($rch_state == "brownout" and ($lane.workload_class // "") == "heavy" and (($lane.urgent // false) | not)) then
          {
            lane_id: $lane.lane_id,
            title: $lane.title,
            decision: "defer",
            resource_class: "rch_slots",
            lease_duration_seconds: 0,
            preferred_workers: [],
            excluded_workers: $worker_exclusions,
            reason_codes: ["rch_brownout_deferral", "nonurgent_heavy_fanout_capped"],
            evidence_paths: $base_evidence_paths,
            rollback_command: "# operator: admit the deferred heavy lane after the next green forecast",
            remediation_command: "Wait for free-slot recovery or drain completion before admitting this heavy lane."
          }
        elif (($lane.fairness_skew_millionths // 0) > $fairness_limit and ($fairness_state == "watch" or $fairness_state == "brownout")) then
          {
            lane_id: $lane.lane_id,
            title: $lane.title,
            decision: "rebalance",
            resource_class: "fairness_recovery",
            lease_duration_seconds: $default_lease_seconds,
            preferred_workers: ($q.locality_bias_summary.preferred_workers // []),
            excluded_workers: $worker_exclusions,
            reason_codes: ["fairness_recovery", "policy_precedence_enforced"],
            evidence_paths: $base_evidence_paths,
            rollback_command: "# operator: clear the fairness recovery lease after skew drops below threshold",
            remediation_command: "Re-run queue ranking after fairness skew recovers."
          }
        elif (($lane.needs_proof_cache_refresh // false) and $proof_cache_state == "brownout") then
          {
            lane_id: $lane.lane_id,
            title: $lane.title,
            decision: "cool",
            resource_class: "proof_cache",
            lease_duration_seconds: $proof_cache_cooldown_seconds,
            preferred_workers: ($q.locality_bias_summary.preferred_workers // []),
            excluded_workers: $worker_exclusions,
            reason_codes: ["proof_cache_cooling", "proof_pressure_guardrail"],
            evidence_paths: $base_evidence_paths,
            rollback_command: "# operator: re-enable proof-cache refresh when proof-cache pressure returns to green",
            remediation_command: "Reduce proof-cache refresh pressure before reheating this lane."
          }
        else
          {
            lane_id: $lane.lane_id,
            title: $lane.title,
            decision: "admit",
            resource_class: (if (($lane.prefers_warm_target // false) and $cache_reuse_preferred) then "warm_target" else "cpu_memory" end),
            lease_duration_seconds: $default_lease_seconds,
            preferred_workers: ($q.locality_bias_summary.preferred_workers // []),
            excluded_workers: $worker_exclusions,
            reason_codes: (
              ["balanced_capacity"]
              + (if (($lane.prefers_warm_target // false) and $cache_reuse_preferred) then ["warm_target_reuse"] else [] end)
            ),
            evidence_paths: $base_evidence_paths,
            rollback_command: "# operator: revoke the advisory lease by omitting the lane from the next allocation pass",
            remediation_command: "Re-run the allocator if pressure or policy thresholds change."
          }
        end
      )
    end
  ) as $allocations |
  {
    schema_version: "franken-engine.swarm-autopilot-resource-lease-plan.v1",
    source_revision: $source_revision,
    generated_epoch_seconds: $now_epoch_seconds,
    decision: $decision,
    truth_state: $truth_state,
    summary: {
      overall_state: (
        if $decision == "fail_closed" then "fail_closed"
        elif any($allocations[]; .decision == "defer") then "brownout_deferral"
        elif any($allocations[]; .decision == "rebalance") then "fairness_recovery"
        elif any($allocations[]; .decision == "cool") then "proof_cache_cooling"
        elif any($allocations[]; .decision == "reserve") then "urgent_protected"
        else "balanced"
        end
      ),
      admit_count: ($allocations | map(select(.decision == "admit")) | length),
      reserve_count: ($allocations | map(select(.decision == "reserve")) | length),
      defer_count: ($allocations | map(select(.decision == "defer")) | length),
      rebalance_count: ($allocations | map(select(.decision == "rebalance")) | length),
      cool_count: ($allocations | map(select(.decision == "cool")) | length),
      fail_closed_count: ($allocations | map(select(.decision == "fail_closed")) | length),
      available_slot_count: $available_slot_count
    },
    resolved_inputs: {
      operator_intent_policy_json: "provided",
      brownout_forecaster_json: "provided",
      queue_advisory_bundle_json: "provided",
      rch_rehabilitation_ledger_json: "provided"
    },
    fail_closed_reasons: $fail_closed_reasons,
    deterministic_replay_hash_basis: {
      operator_intent_policy_sha256: $policy_sha,
      brownout_forecaster_sha256: $forecast_sha,
      queue_advisory_bundle_sha256: $queue_sha,
      rch_rehabilitation_ledger_sha256: $rehab_sha
    },
    lease_allocations: $allocations,
    mutation_policy: {
      advisory_only: true,
      proof_only: true,
      fixture_fed_only: true,
      mutates_br: false,
      reassigns_beads: false,
      releases_reservations: false,
      sends_agent_mail: false,
      runs_cargo: false,
      runs_rch: false,
      mutates_remote_workers: false,
      changes_live_queue_policy: false
    }
  }
' >"$plan_core"

plan_hash="$(jq -cS . "$plan_core" | sha256sum | awk '{print $1}')"
allocation_id="lease-plan-${plan_hash:0:16}"

jq \
  --arg allocation_id "$allocation_id" \
  --arg plan_path "$plan_path" \
  --arg receipts_path "$receipts_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  '. + {
    allocation_id: $allocation_id,
    artifact_paths: {
      plan_json: $plan_path,
      receipts_json: $receipts_path,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $report_path
    }
  }' "$plan_core" >"$plan_tmp"
mv "$plan_tmp" "$plan_path"

jq -n \
  --slurpfile plan "$plan_path" \
  '
  ($plan[0]) as $plan |
  ($plan.lease_allocations | to_entries | map(
    .value + {
      receipt_id: ("lease-receipt-" + ((.key + 1) | tostring))
    }
  )) as $receipts |
  {
    schema_version: "franken-engine.swarm-autopilot-resource-scarcity-receipts.v1",
    source_revision: $plan.source_revision,
    generated_epoch_seconds: $plan.generated_epoch_seconds,
    allocation_id: $plan.allocation_id,
    summary: {
      total_receipts: ($receipts | length),
      admit_count: ($receipts | map(select(.decision == "admit")) | length),
      reserve_count: ($receipts | map(select(.decision == "reserve")) | length),
      defer_count: ($receipts | map(select(.decision == "defer")) | length),
      rebalance_count: ($receipts | map(select(.decision == "rebalance")) | length),
      cool_count: ($receipts | map(select(.decision == "cool")) | length),
      fail_closed_count: ($receipts | map(select(.decision == "fail_closed")) | length)
    },
    receipts: $receipts
  }
' >"$receipts_core"

receipt_hash="$(jq -cS . "$receipts_core" | sha256sum | awk '{print $1}')"
receipt_bundle_id="lease-receipts-${receipt_hash:0:16}"

jq \
  --arg receipt_bundle_id "$receipt_bundle_id" \
  --arg receipts_path "$receipts_path" \
  '. + {receipt_bundle_id: $receipt_bundle_id, artifact_path: $receipts_path}' \
  "$receipts_core" >"$receipts_tmp"
mv "$receipts_tmp" "$receipts_path"

jq -r '
  [
    "# Swarm Autopilot Resource Lease Allocator",
    "",
    "- Decision: " + .decision,
    "- Truth state: " + .truth_state,
    "- Overall state: " + .summary.overall_state,
    "- Allocation ID: " + .allocation_id,
    ""
  ]
  + (if (.fail_closed_reasons | length) > 0 then
      ["## Fail-Closed Reasons", ""] +
      (.fail_closed_reasons | map("- `" + .code + "` " + .detail))
    else
      ["## Lease Decisions", ""] +
      (.lease_allocations | map("- `" + .lane_id + "` " + .decision + " as " + .resource_class))
    end)
  | join("\n")
' "$plan_path" >"$report_path"

write_event "resource_lease_allocator" "plan_emitted" "$decision" "" "$plan_path"
write_event "resource_lease_allocator" "receipts_emitted" "captured" "" "$receipts_path"

exit "$exit_code"
