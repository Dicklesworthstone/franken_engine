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

require_live_input() {
  if [[ -z "${CONTAINMENT_LATENCY_METRIC_INPUT:-}" ]]; then
    echo "missing live containment latency evidence: set CONTAINMENT_LATENCY_METRIC_INPUT to a measured metric input JSON file" >&2
    return 2
  fi
  if [[ ! -f "$CONTAINMENT_LATENCY_METRIC_INPUT" ]]; then
    echo "containment latency evidence file does not exist: ${CONTAINMENT_LATENCY_METRIC_INPUT}" >&2
    return 2
  fi
}

validate_live_input() {
  local input_path="$1"
  local reasons
  local clock_count

  if ! jq -e 'type == "object" and (.signals | type == "array") and (.signals | length > 0)' "$input_path" >/dev/null; then
    echo "invalid containment latency evidence: expected object with non-empty signals array" >&2
    return 1
  fi

  reasons="$(
    jq -r '
      .signals[]? as $signal
      | ($signal.signal_id // "<missing-signal-id>") as $signal_id
      | [
          (if (($signal.signal_detected_at_us | type) != "number") then "\($signal_id): missing numeric signal_detected_at_us" else empty end),
          (if (($signal.containment_action_applied_at_us | type) != "number") then "\($signal_id): missing numeric containment_action_applied_at_us" else empty end),
          (if (($signal.containment_action_applied_at_us | type) == "number" and ($signal.signal_detected_at_us | type) == "number" and $signal.containment_action_applied_at_us < $signal.signal_detected_at_us) then "\($signal_id): non-monotonic containment timestamp" else empty end),
          (if (($signal.clock_id // "") | tostring | test("^\\s*$")) then "\($signal_id): missing clock_id" else empty end),
          (if (($signal.clock_id // "") | tostring | test("^proof-clock")) then "\($signal_id): synthetic proof-clock clock_id" else empty end),
          (if (($signal.clock_source // "") != "monotonic_us") then "\($signal_id): clock_source must be monotonic_us" else empty end),
          (if (($signal.action_command // "") | tostring | test("^\\s*$")) then "\($signal_id): missing action_command" else empty end),
          (if (($signal.duration_us | type) != "number") then "\($signal_id): missing numeric duration_us" else empty end),
          (if (($signal.duration_us // null) == 1137) then "\($signal_id): synthetic duration_us=1137" else empty end),
          (if ([1000, 5000, 10000, 100000] | index($signal.duration_us // null)) then "\($signal_id): suspicious round duration_us" else empty end),
          (if (($signal.containment_action_applied_at_us | type) == "number" and ($signal.signal_detected_at_us | type) == "number" and (($signal.containment_action_applied_at_us - $signal.signal_detected_at_us) as $latency | ($latency == 80000 or $latency == 120000 or $latency == 200000))) then "\($signal_id): suspicious round latency_us" else empty end),
          (if (($signal.action_exit_code // null) != 0) then "\($signal_id): action_exit_code must be 0" else empty end),
          (if (($signal.measurement_status // "") != "measured") then "\($signal_id): measurement_status must be measured" else empty end),
          (if (($signal.evidence_bead_id // "") | tostring | test("^\\s*$")) then "\($signal_id): missing evidence_bead_id" else empty end),
          (if (($signal.evidence_commit_hash // "") | tostring | test("^\\s*$")) then "\($signal_id): missing evidence_commit_hash" else empty end),
          (if (($signal.evidence_test_name // "") | tostring | test("^\\s*$")) then "\($signal_id): missing evidence_test_name" else empty end),
          (if (($signal.evidence_test_name // "") | tostring | test("representative_fixture|run_containment_latency_metric_gate\\.sh")) then "\($signal_id): synthetic evidence_test_name" else empty end)
        ][]
    ' "$input_path"
  )"

  if [[ -n "$reasons" ]]; then
    echo "containment latency evidence rejected:" >&2
    echo "$reasons" >&2
    return 1
  fi

  clock_count="$(jq '[.signals[].clock_id] | unique | length' "$input_path")"
  if [[ "$clock_count" -ne 1 ]]; then
    echo "containment latency evidence rejected: mixed clock_id values" >&2
    return 1
  fi
}

checked_input_path() {
  require_live_input || return $?
  validate_live_input "$CONTAINMENT_LATENCY_METRIC_INPUT" || return $?
  printf '%s' "$CONTAINMENT_LATENCY_METRIC_INPUT"
}

write_bundle() {
  local bundle_dir="$1"
  local variant="$2"
  local input_path="$3"
  local details_path="${bundle_dir}/latency_details.json"
  local metric_path="${bundle_dir}/metric_artifact.json"
  local metric_report_path="${bundle_dir}/metric_report.json"
  local events_path="${bundle_dir}/events.jsonl"
  local commands_path="${bundle_dir}/commands.txt"
  local summary_path="${bundle_dir}/summary.md"
  local signals_path="${bundle_dir}/signals.jsonl"
  local verification_command="CONTAINMENT_LATENCY_METRIC_INPUT=$(proof_contract_repo_relative_path "$input_path") ./scripts/run_containment_latency_metric_gate.sh ${mode}"
  local input_code_revision
  local scenario_set
  local freshness_days
  local confidence_millionths
  local redaction_status
  local total
  local contained
  local median_us
  local median_ms
  local observed_ms
  local coverage_millionths
  local decision
  local report_decision
  local reason
  local failure_count
  local details_hash

  mkdir -p "$bundle_dir"
  jq -c '.signals[]' "$input_path" >"$signals_path"

  input_code_revision="$(jq -r '.code_revision // empty' "$input_path")"
  if [[ -z "$input_code_revision" ]]; then
    input_code_revision="$code_revision"
  fi
  scenario_set="$(jq -r '.scenario_set // "policy_signal_to_containment_action_v1"' "$input_path")"
  freshness_days="$(jq -r '.freshness_days // 0' "$input_path")"
  confidence_millionths="$(jq -r '.confidence_millionths // 990000' "$input_path")"
  redaction_status="$(jq -r '.redaction_status // "redacted"' "$input_path")"
  total="$(jq '.signals | length' "$input_path")"
  contained="$(jq --argjson threshold_us 250000 '[.signals[] | select((.containment_action_applied_at_us - .signal_detected_at_us) <= $threshold_us)] | length' "$input_path")"
  median_us="$(
    jq '[.signals[] | (.containment_action_applied_at_us - .signal_detected_at_us)] | sort | length as $len | (($len / 2) | floor) as $mid | if $len == 0 then 0 elif ($len % 2) == 1 then .[$mid] else ((.[($mid - 1)] + .[$mid]) / 2 | floor) end' "$input_path"
  )"
  median_ms=$(((median_us + 999) / 1000))
  observed_ms="$median_ms"
  coverage_millionths=$(((contained * 1000000) / total))
  if ((median_us <= 250000)); then
    decision="pass"
    report_decision="pass"
    reason="median_latency_within_threshold"
    failure_count=0
  else
    decision="fail"
    report_decision="fail_closed"
    reason="median_latency_exceeds_threshold"
    failure_count=1
  fi

  jq -s \
    --arg schema_version "franken-engine.containment-latency-metric-gate.details.v1" \
    --arg component "containment_latency_metric_gate" \
    --arg bead_id "bd-38mby" \
    --arg code_revision "$input_code_revision" \
    --arg scenario_set "$scenario_set" \
    --arg raw_evidence_input_path "$(proof_contract_repo_relative_path "$input_path")" \
    --argjson total "$total" \
    --argjson contained "$contained" \
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
      raw_evidence_input_path: $raw_evidence_input_path,
      signals: .
    }' "$signals_path" >"$details_path"
  details_hash="sha256:$(proof_contract_sha256_file "$details_path")"

  jq -n \
    --arg code_revision "$input_code_revision" \
    --arg artifact_path "$(proof_contract_repo_relative_path "$details_path")" \
    --arg artifact_hash "$details_hash" \
    --arg verification_command "$verification_command" \
    --arg scenario_set "$scenario_set" \
    --arg redaction_status "$redaction_status" \
    --argjson observed "$observed_ms" \
    --argjson coverage "$coverage_millionths" \
    --argjson freshness_days "$freshness_days" \
    --argjson confidence_millionths "$confidence_millionths" \
    --argjson total "$total" \
    '{
      metric_id: "containment_latency_median_ms",
      threshold: 250,
      observed_value: $observed,
      unit: "ms",
      baseline: "signal_to_action_trace",
      candidate: "franken_engine",
      denominator_id: ("containment_signals:" + ($total | tostring)),
      scenario_set: $scenario_set,
      artifact_path: $artifact_path,
      artifact_hash: $artifact_hash,
      code_revision: $code_revision,
      freshness_days: $freshness_days,
      confidence_millionths: $confidence_millionths,
      coverage_millionths: $coverage,
      verification_command: $verification_command,
      redaction_status: $redaction_status
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
    --arg code_revision "$input_code_revision" \
    --arg redaction_status "$redaction_status" \
    --argjson median_us "$median_us" \
    --argjson median_ms "$median_ms" \
    --argjson coverage_numerator "$contained" \
    --argjson coverage_denominator "$total" \
    --argjson freshness_days "$freshness_days" \
    --arg coverage_percent "$(format_percent_millionths "$coverage_millionths")" \
    '. as $signal
    | ($signal.containment_action_applied_at_us - $signal.signal_detected_at_us) as $latency_us
    | ($signal.action_exit_code == 0 and ($signal.containment_action_applied_at_us >= $signal.signal_detected_at_us) and $latency_us <= 250000) as $contained
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
        reason: (if $contained then "signal_to_action_latency_observed" elif $latency_us > 250000 then "latency_exceeds_threshold" else "invalid_signal_to_action_trace" end),
        artifact_path: $artifact_path,
        artifact_hash: $artifact_hash,
        code_revision: $code_revision,
        duration_us: $signal.duration_us,
        duration_ms: (($signal.duration_us + 999) / 1000 | floor),
        freshness_days: $freshness_days,
        redaction_status: $redaction_status,
        remediation: (if $contained then "none" else "record monotonic signal/action timestamps and rerun containment verifier" end)
      }' "$signals_path" >"$events_path"

  jq -n \
    --arg schema_version "franken-engine.containment-latency-metric-gate.v1" \
    --arg component "containment_latency_metric_gate" \
    --arg bead_id "bd-38mby" \
    --slurpfile metric "$metric_path" \
    --argjson total "$total" \
    --argjson contained "$contained" \
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
  [[ "$decision" == "pass" ]]
}

case "$mode" in
  ci)
    input_path="$(checked_input_path)"
    write_bundle "${run_dir}/measured" "measured" "$input_path"
    ;;
  pass)
    input_path="$(checked_input_path)"
    write_bundle "$run_dir" "pass" "$input_path"
    ;;
  fail_closed)
    input_path="$(checked_input_path)"
    if write_bundle "$run_dir" "fail_closed" "$input_path"; then
      echo "expected fail_closed containment latency evidence, but measured input passed" >&2
    fi
    exit 1
    ;;
  *)
    echo "usage: $0 [ci|pass|fail_closed]" >&2
    exit 2
    ;;
esac
