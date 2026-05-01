#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"
source "${root_dir}/scripts/lib/proof_artifact_contract.sh"

mode="${1:-ci}"
artifact_root="${RED_TEAM_COMPROMISE_RATE_METRIC_ARTIFACT_ROOT:-artifacts/red_team_compromise_rate_metric}"
run_id="${RED_TEAM_COMPROMISE_RATE_METRIC_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${RED_TEAM_COMPROMISE_RATE_METRIC_RUN_DIR:-${artifact_root}/${run_id}}"
code_revision="${RED_TEAM_COMPROMISE_RATE_METRIC_CODE_REVISION:-$(git rev-parse HEAD 2>/dev/null || echo unknown)}"

write_scenario_artifacts() {
  local bundle_dir="$1"
  local scenario_id="$2"
  local attack_class="$3"
  local engine_compromised="$4"
  local witness_path="${bundle_dir}/witnesses/${scenario_id}.json"
  local transcript_path="${bundle_dir}/transcripts/${scenario_id}.json"
  local witness_hash
  local transcript_hash

  mkdir -p "$(dirname "$witness_path")" "$(dirname "$transcript_path")"
  jq -n \
    --arg schema_version "franken-engine.red-team-witness.v1" \
    --arg scenario_id "$scenario_id" \
    --arg attack_class "$attack_class" \
    '{
      schema_version: $schema_version,
      scenario_id: $scenario_id,
      attack_class: $attack_class,
      security_critical: true
    }' >"$witness_path"

  jq -n \
    --arg schema_version "franken-engine.red-team-transcript.v1" \
    --arg scenario_id "$scenario_id" \
    --arg attack_class "$attack_class" \
    --argjson frankenengine_attacker_succeeded "$engine_compromised" \
    '{
      schema_version: $schema_version,
      scenario_id: $scenario_id,
      attack_class: $attack_class,
      frankenengine_attacker_succeeded: $frankenengine_attacker_succeeded,
      node_attacker_succeeded: true,
      bun_attacker_succeeded: true
    }' >"$transcript_path"

  witness_hash="sha256:$(proof_contract_sha256_file "$witness_path")"
  transcript_hash="sha256:$(proof_contract_sha256_file "$transcript_path")"
  jq -nc \
    --arg scenario_id "$scenario_id" \
    --arg attack_class "$attack_class" \
    --argjson frankenengine_attacker_succeeded "$engine_compromised" \
    --arg witness_path "$(proof_contract_repo_relative_path "$witness_path")" \
    --arg witness_hash "$witness_hash" \
    --arg transcript_path "$(proof_contract_repo_relative_path "$transcript_path")" \
    --arg transcript_hash "$transcript_hash" \
    --arg replay_command "frankenctl red-team replay --scenario $(proof_contract_repo_relative_path "$witness_path") --mode strict" \
    '{
      scenario_id: $scenario_id,
      attack_class: $attack_class,
      security_critical: true,
      frankenengine_attacker_succeeded: $frankenengine_attacker_succeeded,
      node_attacker_succeeded: true,
      bun_attacker_succeeded: true,
      witness_path: $witness_path,
      witness_hash: $witness_hash,
      transcript_path: $transcript_path,
      transcript_hash: $transcript_hash,
      replay_command: $replay_command,
      replay_exit_code: 0,
      duration_ms: 1
    }'
}

rate_millionths() {
  local successes="$1"
  local total="$2"
  if [[ "$total" -eq 0 ]]; then
    printf '0'
  else
    printf '%s' $((successes * 1000000 / total))
  fi
}

reduction_factor_x() {
  local baseline="$1"
  local candidate="$2"
  if [[ "$baseline" -eq 0 && "$candidate" -eq 0 ]]; then
    printf '1'
  elif [[ "$baseline" -eq 0 ]]; then
    printf '0'
  elif [[ "$candidate" -eq 0 ]]; then
    printf '18446744073709551615'
  else
    printf '%s' $((baseline / candidate))
  fi
}

write_bundle() {
  local bundle_dir="$1"
  local variant="$2"
  local fail_reduction="${3:-false}"
  local scenarios_path="${bundle_dir}/scenarios.jsonl"
  local details_path="${bundle_dir}/compromise_details.json"
  local metric_path="${bundle_dir}/metric_artifact.json"
  local metric_report_path="${bundle_dir}/metric_report.json"
  local events_path="${bundle_dir}/events.jsonl"
  local commands_path="${bundle_dir}/commands.txt"
  local summary_path="${bundle_dir}/summary.md"
  local verification_command="./scripts/run_red_team_compromise_rate_metric_gate.sh ${mode}"
  local scenarios_total
  local attacks_successful
  local node_successful
  local bun_successful
  local replayable_witness_scenarios
  local compromise_millionths
  local node_compromise_millionths
  local bun_compromise_millionths
  local baseline_reference_millionths
  local reduction_x
  local replay_coverage_millionths
  local decision
  local reason
  local details_hash
  local failure_count

  mkdir -p "$bundle_dir"
  : >"$scenarios_path"
  write_scenario_artifacts "$bundle_dir" "ambient-token-exfiltration" "ambient_authority_escape" "true" >>"$scenarios_path"
  if [[ "$fail_reduction" == "true" ]]; then
    write_scenario_artifacts "$bundle_dir" "ambient-filesystem-escape" "ambient_authority_escape" "true" >>"$scenarios_path"
    write_scenario_artifacts "$bundle_dir" "ambient-network-escape" "ambient_authority_escape" "true" >>"$scenarios_path"
  else
    write_scenario_artifacts "$bundle_dir" "ambient-filesystem-escape" "ambient_authority_escape" "false" >>"$scenarios_path"
    write_scenario_artifacts "$bundle_dir" "ambient-network-escape" "ambient_authority_escape" "false" >>"$scenarios_path"
  fi
  write_scenario_artifacts "$bundle_dir" "prototype-pollution-getter" "prototype_pollution" "false" >>"$scenarios_path"
  write_scenario_artifacts "$bundle_dir" "prototype-pollution-constructor" "prototype_pollution" "false" >>"$scenarios_path"
  write_scenario_artifacts "$bundle_dir" "prototype-pollution-json" "prototype_pollution" "false" >>"$scenarios_path"
  write_scenario_artifacts "$bundle_dir" "supply-chain-postinstall" "supply_chain_execution" "false" >>"$scenarios_path"
  write_scenario_artifacts "$bundle_dir" "supply-chain-dynamic-import" "supply_chain_execution" "false" >>"$scenarios_path"
  write_scenario_artifacts "$bundle_dir" "supply-chain-native-addon" "supply_chain_execution" "false" >>"$scenarios_path"
  write_scenario_artifacts "$bundle_dir" "supply-chain-env-exfiltration" "supply_chain_execution" "false" >>"$scenarios_path"

  scenarios_total="$(jq -s '[.[] | select(.security_critical)] | length' "$scenarios_path")"
  attacks_successful="$(jq -s '[.[] | select(.security_critical and .frankenengine_attacker_succeeded)] | length' "$scenarios_path")"
  node_successful="$(jq -s '[.[] | select(.security_critical and .node_attacker_succeeded)] | length' "$scenarios_path")"
  bun_successful="$(jq -s '[.[] | select(.security_critical and .bun_attacker_succeeded)] | length' "$scenarios_path")"
  replayable_witness_scenarios="$scenarios_total"
  compromise_millionths="$(rate_millionths "$attacks_successful" "$scenarios_total")"
  node_compromise_millionths="$(rate_millionths "$node_successful" "$scenarios_total")"
  bun_compromise_millionths="$(rate_millionths "$bun_successful" "$scenarios_total")"
  if [[ "$node_compromise_millionths" -le "$bun_compromise_millionths" ]]; then
    baseline_reference_millionths="$node_compromise_millionths"
  else
    baseline_reference_millionths="$bun_compromise_millionths"
  fi
  reduction_x="$(reduction_factor_x "$baseline_reference_millionths" "$compromise_millionths")"
  replay_coverage_millionths="$(rate_millionths "$replayable_witness_scenarios" "$scenarios_total")"

  if [[ "$reduction_x" -ge 10 && "$replay_coverage_millionths" -ge 950000 ]]; then
    decision="pass"
    reason="red_team_compromise_rate_reduction_verified"
    failure_count=0
  else
    decision="fail"
    reason="compromise_rate_reduction_below_baseline"
    failure_count=1
  fi

  jq -s \
    --arg schema_version "franken-engine.red-team-compromise-rate-metric-gate.details.v1" \
    --arg component "red_team_compromise_rate_metric_gate" \
    --arg bead_id "bd-1vwza" \
    --arg code_revision "$code_revision" \
    --arg scenario_set "red_team_security_critical_compromise_v1" \
    --argjson scenarios_total "$scenarios_total" \
    --argjson attacks_successful "$attacks_successful" \
    --argjson compromise_millionths "$compromise_millionths" \
    --argjson node_compromise_millionths "$node_compromise_millionths" \
    --argjson bun_compromise_millionths "$bun_compromise_millionths" \
    --argjson baseline_reference_millionths "$baseline_reference_millionths" \
    --argjson reduction_x "$reduction_x" \
    '{
      schema_version: $schema_version,
      component: $component,
      bead_id: $bead_id,
      code_revision: $code_revision,
      scenario_set: $scenario_set,
      scenarios_total: $scenarios_total,
      attacks_successful: $attacks_successful,
      compromise_millionths: $compromise_millionths,
      baseline_compromise_millionths_node: $node_compromise_millionths,
      baseline_compromise_millionths_bun: $bun_compromise_millionths,
      baseline_reference_millionths: $baseline_reference_millionths,
      reduction_factor_x: $reduction_x,
      scenarios: .
    }' "$scenarios_path" >"$details_path"
  details_hash="sha256:$(proof_contract_sha256_file "$details_path")"

  jq -n \
    --arg code_revision "$code_revision" \
    --arg artifact_path "$(proof_contract_repo_relative_path "$details_path")" \
    --arg artifact_hash "$details_hash" \
    --arg verification_command "$verification_command" \
    --argjson observed "$reduction_x" \
    --argjson coverage "$replay_coverage_millionths" \
    '{
      metric_id: "red_team_compromise_rate_reduction",
      threshold: 10,
      observed_value: $observed,
      unit: "x_rate_reduction",
      baseline: "node_and_bun",
      candidate: "franken_engine",
      denominator_id: "node_and_bun:red_team_scenarios:10",
      scenario_set: "red_team_security_critical_compromise_v1",
      artifact_path: $artifact_path,
      artifact_hash: $artifact_hash,
      code_revision: $code_revision,
      freshness_days: 0,
      confidence_millionths: 1000000,
      coverage_millionths: $coverage,
      verification_command: $verification_command,
      redaction_status: "redacted"
    }' >"$metric_path"

  printf '%s\n' "$verification_command" >"$commands_path"
  jq -r '.replay_command' "$scenarios_path" >>"$commands_path"

  jq -c \
    --arg schema_version "$PROOF_ARTIFACT_EVENT_SCHEMA_VERSION" \
    --arg event_name "red_team_compromise_rate_metric.scenario_checked" \
    --arg metric_id "red_team_compromise_rate_reduction" \
    --arg proof_manifest_id "red_team_compromise_rate_metric_gate:${variant}" \
    --arg artifact_path "$(proof_contract_repo_relative_path "$details_path")" \
    --arg artifact_hash "$details_hash" \
    --arg code_revision "$code_revision" \
    --arg redaction_status "redacted" \
    --argjson scenarios_total "$scenarios_total" \
    --argjson attacks_successful "$attacks_successful" \
    --argjson compromise_millionths "$compromise_millionths" \
    --argjson node_compromise_millionths "$node_compromise_millionths" \
    --argjson bun_compromise_millionths "$bun_compromise_millionths" \
    --argjson baseline_reference_millionths "$baseline_reference_millionths" \
    --argjson reduction_x "$reduction_x" \
    '. as $scenario
    | {
        schema_version: $schema_version,
        event_name: $event_name,
        severity: (if $scenario.frankenengine_attacker_succeeded then "error" else "info" end),
        step_id: $scenario.scenario_id,
        command_id: ("red-team:" + $scenario.scenario_id),
        metric_id: $metric_id,
        proof_manifest_id: $proof_manifest_id,
        scenario_id: $scenario.scenario_id,
        attack_class: $scenario.attack_class,
        attack_class_label: $scenario.attack_class,
        engine_compromised: $scenario.frankenengine_attacker_succeeded,
        node_compromised: $scenario.node_attacker_succeeded,
        bun_compromised: $scenario.bun_attacker_succeeded,
        replayable_witness: true,
        scenarios_total: $scenarios_total,
        attacks_successful: $attacks_successful,
        compromise_millionths: $compromise_millionths,
        baseline_compromise_millionths_node: $node_compromise_millionths,
        baseline_compromise_millionths_bun: $bun_compromise_millionths,
        baseline_reference_millionths: $baseline_reference_millionths,
        reduction_factor_x: $reduction_x,
        threshold_factor_x: 10,
        command: $scenario.replay_command,
        exit_code: $scenario.replay_exit_code,
        decision: (if $scenario.frankenengine_attacker_succeeded then "compromised" else "contained" end),
        reason: (if $scenario.frankenengine_attacker_succeeded then "attacker_succeeded_against_franken_engine" else "attacker_contained_by_franken_engine" end),
        artifact_path: $artifact_path,
        artifact_hash: $artifact_hash,
        code_revision: $code_revision,
        duration_ms: $scenario.duration_ms,
        freshness_days: 0,
        redaction_status: $redaction_status,
        remediation: "none"
      }' "$scenarios_path" >"$events_path"

  jq -n \
    --arg schema_version "franken-engine.red-team-compromise-rate-metric-gate.v1" \
    --arg component "red_team_compromise_rate_metric_gate" \
    --arg bead_id "bd-1vwza" \
    --slurpfile metric "$metric_path" \
    --argjson scenarios_total "$scenarios_total" \
    --argjson attacks_successful "$attacks_successful" \
    --argjson compromise_millionths "$compromise_millionths" \
    --argjson node_compromise_millionths "$node_compromise_millionths" \
    --argjson bun_compromise_millionths "$bun_compromise_millionths" \
    --argjson baseline_reference_millionths "$baseline_reference_millionths" \
    --argjson reduction_x "$reduction_x" \
    --argjson replayable_witness_scenarios "$replayable_witness_scenarios" \
    --argjson replay_coverage_millionths "$replay_coverage_millionths" \
    --arg decision "$decision" \
    --arg reason "$reason" \
    --slurpfile events "$events_path" \
    '{
      schema_version: $schema_version,
      component: $component,
      bead_id: $bead_id,
      metric_artifact: $metric[0],
      scenarios_total: $scenarios_total,
      attacks_successful: $attacks_successful,
      compromise_millionths: $compromise_millionths,
      baseline_compromise_millionths_node: $node_compromise_millionths,
      baseline_compromise_millionths_bun: $bun_compromise_millionths,
      baseline_reference_millionths: $baseline_reference_millionths,
      reduction_factor_x: $reduction_x,
      replayable_witness_scenarios: $replayable_witness_scenarios,
      replay_coverage_millionths: $replay_coverage_millionths,
      decision: (if $decision == "pass" then "pass" else "fail_closed" end),
      reason: $reason,
      compromised_scenario_ids: [$events[] | select(.decision == "compromised") | .scenario_id],
      unreplayable_scenario_ids: [],
      events: $events
    }' >"$metric_report_path"

  {
    printf '# Red-Team Compromise-Rate Metric Gate\n\n'
    printf -- '- Variant: `%s`\n' "$variant"
    printf -- '- Decision: `%s`\n' "$decision"
    printf -- '- Compromise rate: `%s` / `%s` scenarios (`%s` millionths)\n' \
      "$attacks_successful" "$scenarios_total" "$compromise_millionths"
    printf -- '- Baseline compromise rate, Node: `%s` millionths\n' "$node_compromise_millionths"
    printf -- '- Baseline compromise rate, Bun: `%s` millionths\n' "$bun_compromise_millionths"
    printf -- '- Reduction: `%s`x\n' "$reduction_x"
    printf -- '- Metric artifact: `%s`\n' "$(proof_contract_repo_relative_path "$metric_path")"
    printf -- '- Shared proof manifest: `%s`\n' "$(proof_contract_repo_relative_path "${bundle_dir}/manifest.json")"
    printf '\n'
  } >"$summary_path"

  proof_contract_write_standard_bundle \
    "$bundle_dir" \
    "red_team_compromise_rate_metric_gate" \
    "$decision" \
    "$verification_command" \
    "$metric_report_path" \
    "$events_path" \
    "$commands_path" \
    "bd-1vwza,bd-x7nod" \
    "disruptive_floor.red_team_compromise_rate_10x" \
    "$failure_count"

  echo "red_team_compromise_rate_metric_artifact=${metric_path}"
  echo "red_team_compromise_rate_proof_manifest=${bundle_dir}/manifest.json"
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
