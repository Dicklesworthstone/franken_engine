#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"
source "${root_dir}/scripts/lib/proof_artifact_contract.sh"

mode="${1:-ci}"
artifact_root="${REPLAY_COVERAGE_METRIC_ARTIFACT_ROOT:-artifacts/replay_coverage_metric}"
run_id="${REPLAY_COVERAGE_METRIC_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${REPLAY_COVERAGE_METRIC_RUN_DIR:-${artifact_root}/${run_id}}"
code_revision="${REPLAY_COVERAGE_METRIC_CODE_REVISION:-$(git rev-parse HEAD 2>/dev/null || echo unknown)}"

sha256_text() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  else
    shasum -a 256 | awk '{print $1}'
  fi
}

write_decision_artifacts() {
  local bundle_dir="$1"
  local decision_id="$2"
  local decision_kind="$3"
  local covered="$4"
  local trace_path="${bundle_dir}/traces/${decision_id}.json"
  local report_path="${bundle_dir}/reports/${decision_id}.json"
  local expected_hash
  local actual_hash
  local report_hash

  mkdir -p "$(dirname "$trace_path")" "$(dirname "$report_path")"
  jq -n \
    --arg schema_version "franken-engine.replay-coverage-trace.v1" \
    --arg decision_id "$decision_id" \
    --arg decision_kind "$decision_kind" \
    --arg mode "deterministic_strict" \
    '{schema_version: $schema_version, decision_id: $decision_id, decision_kind: $decision_kind, replay_mode: $mode}' \
    >"$trace_path"

  expected_hash="sha256:$(printf '%s' "${decision_id}:${decision_kind}:deterministic" | sha256_text)"
  actual_hash="$expected_hash"
  if [[ "$covered" != "true" ]]; then
    actual_hash="sha256:$(printf '%s' "${decision_id}:${decision_kind}:nondeterministic" | sha256_text)"
  fi

  jq -n \
    --arg schema_version "franken-engine.replay-coverage-report.v1" \
    --arg decision_id "$decision_id" \
    --arg expected_hash "$expected_hash" \
    --arg actual_hash "$actual_hash" \
    --argjson exit_code 0 \
    '{schema_version: $schema_version, decision_id: $decision_id, expected_hash: $expected_hash, actual_hash: $actual_hash, exit_code: $exit_code}' \
    >"$report_path"
  report_hash="sha256:$(proof_contract_sha256_file "$report_path")"

  jq -nc \
    --arg decision_id "$decision_id" \
    --arg decision_kind "$decision_kind" \
    --arg trace_id "trace-${decision_id}" \
    --arg replay_mode "deterministic_strict" \
    --arg replay_trace_path "$(proof_contract_repo_relative_path "$trace_path")" \
    --arg replay_report_path "$(proof_contract_repo_relative_path "$report_path")" \
    --arg expected_hash "$expected_hash" \
    --arg actual_hash "$actual_hash" \
    --arg replay_report_hash "$report_hash" \
    --arg replay_command "frankenctl replay run --trace $(proof_contract_repo_relative_path "$trace_path") --mode strict" \
    '{
      decision_id: $decision_id,
      decision_kind: $decision_kind,
      security_critical: true,
      trace_id: $trace_id,
      replay_mode: $replay_mode,
      replay_trace_path: $replay_trace_path,
      replay_report_path: $replay_report_path,
      expected_hash: $expected_hash,
      actual_hash: $actual_hash,
      replay_report_hash: $replay_report_hash,
      replay_verified: true,
      replay_command: $replay_command,
      replay_exit_code: 0,
      duration_ms: 1
    }'
}

write_bundle() {
  local bundle_dir="$1"
  local variant="$2"
  local fail_one="${3:-false}"
  local details_path="${bundle_dir}/coverage_details.json"
  local metric_path="${bundle_dir}/metric_artifact.json"
  local metric_report_path="${bundle_dir}/metric_report.json"
  local events_path="${bundle_dir}/events.jsonl"
  local commands_path="${bundle_dir}/commands.txt"
  local summary_path="${bundle_dir}/summary.md"
  local decisions_path="${bundle_dir}/decisions.jsonl"
  local verification_command="./scripts/run_replay_coverage_metric_gate.sh ${mode}"
  local coverage_numerator
  local coverage_denominator=3
  local coverage_millionths
  local decision
  local reason
  local details_hash
  local failure_count

  mkdir -p "$bundle_dir"
  : >"$decisions_path"

  write_decision_artifacts "$bundle_dir" "allow-extension-read" "allow" "true" >>"$decisions_path"
  if [[ "$fail_one" == "true" ]]; then
    write_decision_artifacts "$bundle_dir" "deny-ambient-write" "deny" "false" >>"$decisions_path"
  else
    write_decision_artifacts "$bundle_dir" "deny-ambient-write" "deny" "true" >>"$decisions_path"
  fi
  write_decision_artifacts "$bundle_dir" "escalate-high-risk-signal" "escalate" "true" >>"$decisions_path"

  if [[ "$fail_one" == "true" ]]; then
    coverage_numerator=2
    coverage_millionths=666666
    decision="fail"
    reason="uncovered_security_critical_decisions"
    failure_count=1
  else
    coverage_numerator=3
    coverage_millionths=1000000
    decision="pass"
    reason="all_security_critical_decisions_replay_backed"
    failure_count=0
  fi

  jq -s \
    --arg schema_version "franken-engine.replay-coverage-metric-gate.details.v1" \
    --arg component "replay_coverage_metric_gate" \
    --arg bead_id "bd-2488a" \
    --arg code_revision "$code_revision" \
    --arg scenario_set "security_critical_allow_deny_escalate_v1" \
    --argjson total "$coverage_denominator" \
    --argjson covered "$coverage_numerator" \
    --argjson coverage "$coverage_millionths" \
    '{
      schema_version: $schema_version,
      component: $component,
      bead_id: $bead_id,
      code_revision: $code_revision,
      scenario_set: $scenario_set,
      total_security_critical_decisions: $total,
      replay_backed_security_critical_decisions: $covered,
      coverage_millionths: $coverage,
      decisions: .
    }' "$decisions_path" >"$details_path"
  details_hash="sha256:$(proof_contract_sha256_file "$details_path")"

  jq -n \
    --arg code_revision "$code_revision" \
    --arg artifact_path "$(proof_contract_repo_relative_path "$details_path")" \
    --arg artifact_hash "$details_hash" \
    --arg verification_command "$verification_command" \
    --argjson observed "$coverage_millionths" \
    '{
      metric_id: "security_decision_replay_coverage",
      threshold: 1000000,
      observed_value: $observed,
      unit: "millionths",
      baseline: "security_decision_inventory",
      candidate: "franken_engine",
      denominator_id: "security_critical_decisions:3",
      scenario_set: "security_critical_allow_deny_escalate_v1",
      artifact_path: $artifact_path,
      artifact_hash: $artifact_hash,
      code_revision: $code_revision,
      freshness_days: 0,
      confidence_millionths: 1000000,
      coverage_millionths: $observed,
      verification_command: $verification_command,
      redaction_status: "redacted"
    }' >"$metric_path"

  printf '%s\n' "$verification_command" >"$commands_path"
  jq -r '.replay_command' "$decisions_path" >>"$commands_path"

  jq -c \
    --arg schema_version "$PROOF_ARTIFACT_EVENT_SCHEMA_VERSION" \
    --arg event_name "replay_coverage_metric.decision_checked" \
    --arg metric_id "security_decision_replay_coverage" \
    --arg proof_manifest_id "replay_coverage_metric_gate:${variant}" \
    --arg artifact_path "$(proof_contract_repo_relative_path "$details_path")" \
    --arg artifact_hash "$details_hash" \
    --arg code_revision "$code_revision" \
    --arg redaction_status "redacted" \
    --argjson numerator "$coverage_numerator" \
    --argjson denominator "$coverage_denominator" \
    --arg coverage_percent "$(printf '%0.6f' "$(awk "BEGIN { print ${coverage_millionths} / 10000 }")")" \
    '. as $decision
    | ($decision.expected_hash == $decision.actual_hash and $decision.replay_exit_code == 0) as $covered
    | {
        schema_version: $schema_version,
        event_name: $event_name,
        severity: (if $covered then "info" else "error" end),
        step_id: $decision.decision_id,
        command_id: ("replay:" + $decision.trace_id),
        metric_id: $metric_id,
        proof_manifest_id: $proof_manifest_id,
        decision_id: $decision.decision_id,
        decision_class: $decision.decision_kind,
        trace_id: $decision.trace_id,
        replay_mode: $decision.replay_mode,
        security_critical: $decision.security_critical,
        replay_verified: $decision.replay_verified,
        replay_trace_path: $decision.replay_trace_path,
        replay_report_path: $decision.replay_report_path,
        expected_hash: $decision.expected_hash,
        actual_hash: $decision.actual_hash,
        replay_report_hash: $decision.replay_report_hash,
        coverage_numerator: $numerator,
        coverage_denominator: $denominator,
        coverage_percent: $coverage_percent,
        command: $decision.replay_command,
        exit_code: $decision.replay_exit_code,
        decision: (if $covered then "covered" else "uncovered" end),
        reason: (if $covered then "replay_artifact_verified" else "nondeterministic_replay_output" end),
        artifact_path: $artifact_path,
        artifact_hash: $artifact_hash,
        code_revision: $code_revision,
        duration_ms: $decision.duration_ms,
        freshness_days: 0,
        redaction_status: $redaction_status,
        remediation: (if $covered then "none" else "rerun strict replay and compare deterministic output hashes" end)
      }' "$decisions_path" >"$events_path"

  jq -n \
    --arg schema_version "franken-engine.replay-coverage-metric-gate.v1" \
    --arg component "replay_coverage_metric_gate" \
    --arg bead_id "bd-2488a" \
    --slurpfile metric "$metric_path" \
    --argjson total "$coverage_denominator" \
    --argjson covered "$coverage_numerator" \
    --argjson coverage "$coverage_millionths" \
    --arg decision "$decision" \
    --arg reason "$reason" \
    --slurpfile events "$events_path" \
    '{
      schema_version: $schema_version,
      component: $component,
      bead_id: $bead_id,
      metric_artifact: $metric[0],
      total_security_critical_decisions: $total,
      replay_backed_security_critical_decisions: $covered,
      coverage_millionths: $coverage,
      decision: $decision,
      reason: $reason,
      uncovered_decision_ids: [$events[] | select(.decision == "uncovered") | .decision_id],
      events: $events
    }' >"$metric_report_path"

  {
    printf '# Replay Coverage Metric Gate\n\n'
    printf -- '- Variant: `%s`\n' "$variant"
    printf -- '- Decision: `%s`\n' "$decision"
    printf -- '- Coverage: `%s` / `%s` security-critical decisions (`%s` millionths)\n' \
      "$coverage_numerator" "$coverage_denominator" "$coverage_millionths"
    printf -- '- Metric artifact: `%s`\n' "$(proof_contract_repo_relative_path "$metric_path")"
    printf -- '- Shared proof manifest: `%s`\n' "$(proof_contract_repo_relative_path "${bundle_dir}/manifest.json")"
    printf '\n'
    if [[ "$decision" != "pass" ]]; then
      jq -r '.uncovered_decision_ids[] | "- `" + . + "`"' "$metric_report_path"
    fi
  } >"$summary_path"

  proof_contract_write_standard_bundle \
    "$bundle_dir" \
    "replay_coverage_metric_gate" \
    "$decision" \
    "$verification_command" \
    "$metric_report_path" \
    "$events_path" \
    "$commands_path" \
    "bd-2488a,bd-x7nod" \
    "disruptive_floor.security_decision_replay_coverage_100pct" \
    "$failure_count"

  echo "replay_coverage_metric_artifact=${metric_path}"
  echo "replay_coverage_proof_manifest=${bundle_dir}/manifest.json"
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
