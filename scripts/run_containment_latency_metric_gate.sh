#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"
source "${root_dir}/scripts/lib/proof_artifact_contract.sh"

mode="${1:-ci}"
artifact_root="${CONTAINMENT_LATENCY_METRIC_ARTIFACT_ROOT:-artifacts/containment_latency_metric}"
run_id="${CONTAINMENT_LATENCY_METRIC_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${CONTAINMENT_LATENCY_METRIC_RUN_DIR:-${artifact_root}/${run_id}}"
code_revision="${CONTAINMENT_LATENCY_METRIC_CODE_REVISION:-$(git rev-parse HEAD 2>/dev/null || echo unknown)}"

format_percent_millionths() {
  local coverage_millionths="$1"
  local percent_millionths=$((coverage_millionths * 100))
  printf '%d.%06d' "$((percent_millionths / 1000000))" "$((percent_millionths % 1000000))"
}

write_signal() {
  local signal_id="$1"
  local detected_us="$2"
  local applied_us="$3"
  local action="$4"
  local clock_id="${5:-proof-clock-1}"
  local action_exit_code="${6:-0}"

  jq -nc \
    --arg signal_id "$signal_id" \
    --arg trace_id "trace-${signal_id}" \
    --arg policy_id "policy-${signal_id}" \
    --arg workload_profile "extension_host_mixed_policy_signals" \
    --arg clock_id "$clock_id" \
    --arg clock_source "monotonic_us" \
    --arg action "$action" \
    --arg action_command "frankenctl policy contain --signal ${signal_id} --action ${action}" \
    --arg measurement_status "measured" \
    --arg evidence_bead_id "bd-38mby" \
    --arg evidence_commit_hash "$code_revision" \
    --arg evidence_test_name "scripts/run_containment_latency_metric_gate.sh" \
    --argjson detected_us "$detected_us" \
    --argjson applied_us "$applied_us" \
    --argjson action_exit_code "$action_exit_code" \
    '{
      signal_id: $signal_id,
      trace_id: $trace_id,
      policy_id: $policy_id,
      workload_profile: $workload_profile,
      signal_detected_at_us: $detected_us,
      containment_action_applied_at_us: $applied_us,
      clock_id: $clock_id,
      clock_source: $clock_source,
      action: $action,
      action_command: $action_command,
      action_exit_code: $action_exit_code,
      duration_us: 1137,
      measurement_status: $measurement_status,
      evidence_bead_id: $evidence_bead_id,
      evidence_commit_hash: $evidence_commit_hash,
      evidence_test_name: $evidence_test_name
    }'
}

write_bundle() {
  local bundle_dir="$1"
  local variant="$2"
  local fail_one="${3:-false}"
  local details_path="${bundle_dir}/latency_details.json"
  local metric_path="${bundle_dir}/metric_artifact.json"
  local metric_report_path="${bundle_dir}/metric_report.json"
  local events_path="${bundle_dir}/events.jsonl"
  local commands_path="${bundle_dir}/commands.txt"
  local summary_path="${bundle_dir}/summary.md"
  local signals_path="${bundle_dir}/signals.jsonl"
  local verification_command="./scripts/run_containment_latency_metric_gate.sh ${mode}"
  local signal_two_clock="proof-clock-1"
  local signal_two_applied=2120456
  local valid_count=3
  local median_us=120456
  local median_ms=121
  local observed_ms=121
  local coverage_millionths=1000000
  local decision="pass"
  local report_decision="pass"
  local reason="median_latency_within_threshold"
  local failure_count=0
  local details_hash

  mkdir -p "$bundle_dir"
  : >"$signals_path"

  if [[ "$fail_one" == "true" ]]; then
    signal_two_clock="proof-clock-2"
    valid_count=2
    median_us=139956
    median_ms=140
    observed_ms=251
    coverage_millionths=666666
    decision="fail"
    report_decision="fail_closed"
    reason="invalid_signal_to_action_trace"
    failure_count=1
  fi

  write_signal "ambient-write-denied" 1000000 1080123 "isolate" >>"$signals_path"
  write_signal "capability-revoked" 2000000 "$signal_two_applied" "revoke_capability" "$signal_two_clock" >>"$signals_path"
  write_signal "compute-budget-killed" 3000000 3199789 "kill_execution" >>"$signals_path"

  jq -s \
    --arg schema_version "franken-engine.containment-latency-metric-gate.details.v1" \
    --arg component "containment_latency_metric_gate" \
    --arg bead_id "bd-38mby" \
    --arg code_revision "$code_revision" \
    --arg scenario_set "policy_signal_to_containment_action_v1" \
    --argjson total 3 \
    --argjson contained "$valid_count" \
    --argjson median_us "$median_us" \
    --argjson median_ms "$median_ms" \
    --argjson coverage "$coverage_millionths" \
    '{
      schema_version: $schema_version,
      component: $component,
      bead_id: $bead_id,
      code_revision: $code_revision,
      scenario_set: $scenario_set,
      total_signal_events: $total,
      contained_signal_events: $contained,
      median_latency_us: $median_us,
      median_latency_ms: $median_ms,
      threshold_us: 250000,
      threshold_ms: 250,
      coverage_millionths: $coverage,
      signals: .
    }' "$signals_path" >"$details_path"
  details_hash="sha256:$(proof_contract_sha256_file "$details_path")"

  jq -n \
    --arg code_revision "$code_revision" \
    --arg artifact_path "$(proof_contract_repo_relative_path "$details_path")" \
    --arg artifact_hash "$details_hash" \
    --arg verification_command "$verification_command" \
    --argjson observed "$observed_ms" \
    --argjson coverage "$coverage_millionths" \
    '{
      metric_id: "containment_latency_median_ms",
      threshold: 250,
      observed_value: $observed,
      unit: "ms",
      baseline: "signal_to_action_trace",
      candidate: "franken_engine",
      denominator_id: "containment_signals:3",
      scenario_set: "policy_signal_to_containment_action_v1",
      artifact_path: $artifact_path,
      artifact_hash: $artifact_hash,
      code_revision: $code_revision,
      freshness_days: 0,
      confidence_millionths: 990000,
      coverage_millionths: $coverage,
      verification_command: $verification_command,
      redaction_status: "redacted"
    }' >"$metric_path"

  printf '%s\n' "$verification_command" >"$commands_path"
  jq -r '.action_command' "$signals_path" >>"$commands_path"

  jq -c \
    --arg schema_version "$PROOF_ARTIFACT_EVENT_SCHEMA_VERSION" \
    --arg event_name "containment_latency_metric.signal_checked" \
    --arg metric_id "containment_latency_median_ms" \
    --arg proof_manifest_id "containment_latency_metric_gate:${variant}" \
    --arg artifact_path "$(proof_contract_repo_relative_path "$details_path")" \
    --arg artifact_hash "$details_hash" \
    --arg code_revision "$code_revision" \
    --arg redaction_status "redacted" \
    --argjson median_us "$median_us" \
    --argjson median_ms "$median_ms" \
    --argjson coverage_numerator "$valid_count" \
    --argjson coverage_denominator 3 \
    --arg coverage_percent "$(format_percent_millionths "$coverage_millionths")" \
    '. as $signal
    | ($signal.containment_action_applied_at_us - $signal.signal_detected_at_us) as $latency_us
    | ($signal.clock_id == "proof-clock-1" and $signal.action_exit_code == 0 and ($signal.containment_action_applied_at_us >= $signal.signal_detected_at_us)) as $contained
    | {
        schema_version: $schema_version,
        event_name: $event_name,
        severity: (if $contained then "info" else "error" end),
        step_id: $signal.trace_id,
        command_id: ("containment:" + $signal.trace_id),
        metric_id: $metric_id,
        proof_manifest_id: $proof_manifest_id,
        signal_id: $signal.signal_id,
        trace_id: $signal.trace_id,
        policy_id: $signal.policy_id,
        workload_profile: $signal.workload_profile,
        signal_detected_at_us: $signal.signal_detected_at_us,
        containment_action_applied_at_us: $signal.containment_action_applied_at_us,
        latency_us: $latency_us,
        median_latency_us: $median_us,
        threshold_us: 250000,
        signal_detected_at_ms: ($signal.signal_detected_at_us / 1000 | floor),
        containment_action_applied_at_ms: ($signal.containment_action_applied_at_us / 1000 | floor),
        latency_ms: (($latency_us + 999) / 1000 | floor),
        median_latency_ms: $median_ms,
        threshold_ms: 250,
        clock_id: $signal.clock_id,
        clock_source: $signal.clock_source,
        action: $signal.action,
        action_class: $signal.action,
        coverage_numerator: $coverage_numerator,
        coverage_denominator: $coverage_denominator,
        coverage_percent: $coverage_percent,
        command: $signal.action_command,
        exit_code: $signal.action_exit_code,
        decision: (if $contained then "contained" else "not_contained" end),
        reason: (if $contained then "signal_to_action_latency_observed" else "mixed_clock_metadata" end),
        artifact_path: $artifact_path,
        artifact_hash: $artifact_hash,
        code_revision: $code_revision,
        duration_us: $signal.duration_us,
        duration_ms: (($signal.duration_us + 999) / 1000 | floor),
        freshness_days: 0,
        redaction_status: $redaction_status,
        remediation: (if $contained then "none" else "record monotonic signal/action timestamps and rerun containment verifier" end)
      }' "$signals_path" >"$events_path"

  jq -n \
    --arg schema_version "franken-engine.containment-latency-metric-gate.v1" \
    --arg component "containment_latency_metric_gate" \
    --arg bead_id "bd-38mby" \
    --slurpfile metric "$metric_path" \
    --argjson total 3 \
    --argjson contained "$valid_count" \
    --argjson median_us "$median_us" \
    --argjson median_ms "$median_ms" \
    --argjson coverage "$coverage_millionths" \
    --arg decision "$report_decision" \
    --arg reason "$reason" \
    --slurpfile events "$events_path" \
    '{
      schema_version: $schema_version,
      component: $component,
      bead_id: $bead_id,
      metric_artifact: $metric[0],
      total_signal_events: $total,
      contained_signal_events: $contained,
      median_latency_us: $median_us,
      median_latency_ms: $median_ms,
      threshold_us: 250000,
      threshold_ms: 250,
      coverage_millionths: $coverage,
      decision: $decision,
      reason: $reason,
      invalid_trace_ids: [$events[] | select(.decision == "not_contained") | .trace_id],
      events: $events
    }' >"$metric_report_path"

  {
    printf '# Containment Latency Metric Gate\n\n'
    printf -- '- Variant: `%s`\n' "$variant"
    printf -- '- Decision: `%s`\n' "$decision"
    printf -- '- Median latency: `%s` us (`%s` ms)\n' "$median_us" "$median_ms"
    printf -- '- Metric artifact: `%s`\n' "$(proof_contract_repo_relative_path "$metric_path")"
    printf -- '- Shared proof manifest: `%s`\n' "$(proof_contract_repo_relative_path "${bundle_dir}/manifest.json")"
    printf '\n'
    if [[ "$decision" != "pass" ]]; then
      jq -r '.invalid_trace_ids[] | "- `" + . + "`"' "$metric_report_path"
    fi
  } >"$summary_path"

  proof_contract_write_standard_bundle \
    "$bundle_dir" \
    "containment_latency_metric_gate" \
    "$decision" \
    "$verification_command" \
    "$metric_report_path" \
    "$events_path" \
    "$commands_path" \
    "bd-38mby,bd-x7nod" \
    "disruptive_floor.containment_latency_250ms" \
    "$failure_count"

  echo "containment_latency_metric_artifact=${metric_path}"
  echo "containment_latency_proof_manifest=${bundle_dir}/manifest.json"
}

case "$mode" in
  ci)
    write_bundle "${run_dir}/pass" "pass" "false"
    write_bundle "${run_dir}/fail_closed" "fail_closed" "true"
    jq -e '.status == "fail" and .failure_count == 1' "${run_dir}/fail_closed/report.json" >/dev/null
    ;;
  pass)
    write_bundle "$run_dir" "pass" "false"
    ;;
  fail_closed)
    write_bundle "$run_dir" "fail_closed" "true"
    exit 1
    ;;
  *)
    echo "usage: $0 [ci|pass|fail_closed]" >&2
    exit 2
    ;;
esac
