#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"
source "${root_dir}/scripts/lib/proof_artifact_contract.sh"

mode="${1:-ci}"
pass_input="${2:-crates/franken-engine/tests/fixtures/production_feature_catalog_pass_v1.json}"
fail_input="${3:-crates/franken-engine/tests/fixtures/production_feature_catalog_fail_two_observed_v1.json}"
artifact_root="${PRODUCTION_FEATURE_CATALOG_ARTIFACT_ROOT:-artifacts/production_feature_catalog_gate}"
run_id="${PRODUCTION_FEATURE_CATALOG_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${PRODUCTION_FEATURE_CATALOG_RUN_DIR:-${artifact_root}/${run_id}}"
code_revision="${PRODUCTION_FEATURE_CATALOG_CODE_REVISION:-$(git rev-parse HEAD 2>/dev/null || echo unknown)}"

schema_version="franken-engine.production-feature-catalog-gate.v1"
component="production_feature_catalog_gate"
bead_id="bd-1qr4f"
claim_id="disruptive_floor.impossible_by_default_features_3"
required_observed=3

write_bundle() {
  local input_path="$1"
  local bundle_dir="$2"
  local variant="$3"
  local expected_exit="$4"
  local details_path="${bundle_dir}/catalog_details.json"
  local metric_path="${bundle_dir}/metric_artifact.json"
  local report_path="${bundle_dir}/catalog_report.json"
  local events_path="${bundle_dir}/events.jsonl"
  local commands_path="${bundle_dir}/commands.txt"
  local verification_command="./scripts/run_production_feature_catalog_gate.sh ${mode}"
  local max_freshness
  local total_features
  local observed_count
  local observed_total
  local invalid_observed_count
  local unsupported_json
  local decision
  local report_decision
  local reason
  local failure_count
  local details_hash
  local coverage_millionths

  if [[ ! -f "$input_path" ]]; then
    echo "production feature catalog input missing: $input_path" >&2
    exit 2
  fi
  jq empty "$input_path" >/dev/null

  mkdir -p "$bundle_dir"
  max_freshness="$(jq -r '.max_freshness_days' "$input_path")"
  total_features="$(jq -r '.features | length' "$input_path")"
  observed_total="$(jq -r '[.features[] | select(.state == "observed")] | length' "$input_path")"
  observed_count="$(jq -r --argjson max "$max_freshness" '
    def rationale_ok:
      (.impossible_by_default_rationale | ascii_downcase) as $r
      | (($r | contains("node")) and ($r | contains("bun")) and (($r | length) >= 40));
    def live_handle_ok:
      (.proof_kind == "live_proof_artifact")
      and ((.path // "") != "")
      and ((.sha256 // "") | test("^sha256:[0-9a-f]{64}$"))
      and ((.verification_command // "") != "")
      and ((.user_facing_workflow // "") != "")
      and ((.proof_manifest_id // "") != "")
      and ((.redaction_status // "") == "redacted");
    [.features[]
      | select(.state == "observed")
      | select(rationale_ok)
      | select((.freshness_days // 999999) <= $max)
      | select(any(.artifact_handles[]?; live_handle_ok))]
    | length' "$input_path")"
  invalid_observed_count="$(( observed_total - observed_count ))"
  unsupported_json="$(jq -c '[.features[] | select(.state != "observed") | .feature_id]' "$input_path")"

  if [[ "$invalid_observed_count" -gt 0 ]]; then
    decision="fail"
    report_decision="fail_closed"
    reason="observed_feature_validation_failed"
    failure_count=1
  elif [[ "$observed_count" -lt "$required_observed" ]]; then
    decision="fail"
    report_decision="fail_closed"
    reason="fewer_than_three_observed_features"
    failure_count=1
  else
    decision="pass"
    report_decision="pass"
    reason="observed_feature_catalog_satisfies_floor"
    failure_count=0
  fi
  coverage_millionths="$(( observed_count > required_observed ? 1000000 : observed_count * 1000000 / required_observed ))"

  jq \
    --arg schema_version "${schema_version}.details.v1" \
    --arg component "$component" \
    --arg bead_id "$bead_id" \
    --arg code_revision "$code_revision" \
    --argjson observed_count "$observed_count" \
    --argjson required_observed "$required_observed" \
    '. + {
      details_schema_version: $schema_version,
      component: $component,
      bead_id: $bead_id,
      code_revision: $code_revision,
      observed_feature_count: $observed_count,
      required_observed_feature_count: $required_observed
    }' "$input_path" >"$details_path"
  details_hash="sha256:$(proof_contract_sha256_file "$details_path")"

  jq -n \
    --arg metric_id "impossible_by_default_production_features" \
    --arg unit "feature_count" \
    --arg baseline "feature_catalog" \
    --arg candidate "franken_engine" \
    --arg denominator_id "production_features:${total_features}" \
    --arg scenario_set "impossible_by_default_production_feature_catalog_v1" \
    --arg artifact_path "$(proof_contract_repo_relative_path "$report_path")" \
    --arg artifact_hash "$details_hash" \
    --arg code_revision "$code_revision" \
    --arg verification_command "$verification_command" \
    --arg redaction_status "redacted" \
    --argjson threshold "$required_observed" \
    --argjson observed "$observed_count" \
    --argjson freshness "$max_freshness" \
    --argjson confidence "$(if [[ "$decision" == "pass" ]]; then echo 990000; else echo 0; fi)" \
    --argjson coverage "$coverage_millionths" \
    '{
      metric_id: $metric_id,
      threshold: $threshold,
      observed_value: $observed,
      unit: $unit,
      baseline: $baseline,
      candidate: $candidate,
      denominator_id: $denominator_id,
      scenario_set: $scenario_set,
      artifact_path: $artifact_path,
      artifact_hash: $artifact_hash,
      code_revision: $code_revision,
      freshness_days: $freshness,
      confidence_millionths: $confidence,
      coverage_millionths: $coverage,
      verification_command: $verification_command,
      redaction_status: $redaction_status
    }' >"$metric_path"

  {
    printf '%s\n' "$verification_command"
    jq -r '.features[].artifact_handles[]?.verification_command | select(length > 0)' "$input_path" | sort -u
  } >"$commands_path"

  jq -c \
    --arg schema_version "$PROOF_ARTIFACT_EVENT_SCHEMA_VERSION" \
    --arg event_name "production_feature_catalog.feature_checked" \
    --arg artifact_path "$(proof_contract_repo_relative_path "$details_path")" \
    --arg artifact_hash "$details_hash" \
    --arg code_revision "$code_revision" \
    --argjson max "$max_freshness" \
    'def rationale_ok:
      (.impossible_by_default_rationale | ascii_downcase) as $r
      | (($r | contains("node")) and ($r | contains("bun")) and (($r | length) >= 40));
    def live_handle_ok:
      (.proof_kind == "live_proof_artifact")
      and ((.path // "") != "")
      and ((.sha256 // "") | test("^sha256:[0-9a-f]{64}$"))
      and ((.verification_command // "") != "")
      and ((.user_facing_workflow // "") != "")
      and ((.proof_manifest_id // "") != "")
      and ((.redaction_status // "") == "redacted");
    .features[]
    | . as $feature
    | (($feature.artifact_handles // [])[0] // {}) as $artifact
    | ($feature.state == "observed"
       and rationale_ok
       and (($feature.freshness_days // 999999) <= $max)
       and any($feature.artifact_handles[]?; live_handle_ok)) as $counted
    | {
        schema_version: $schema_version,
        event_name: $event_name,
        severity: (if $counted or $feature.state != "observed" then "info" else "error" end),
        step_id: $feature.feature_id,
        command_id: ("feature-catalog:" + $feature.feature_id),
        feature_id: $feature.feature_id,
        feature_state: $feature.state,
        artifact_path: ($artifact.path // $artifact_path),
        artifact_hash: ($artifact.sha256 // $artifact_hash),
        verification_command: ($artifact.verification_command // ""),
        node_bun_rationale: $feature.impossible_by_default_rationale,
        freshness_days: $feature.freshness_days,
        proof_manifest_id: ($artifact.proof_manifest_id // ""),
        exit_code: 0,
        duration_ms: 0,
        code_revision: $code_revision,
        redaction_status: ($artifact.redaction_status // "redacted"),
        decision: (if $counted then "observed" else "not_observed" end),
        downgrade_text: $feature.downgrade_text,
        reason: (
          if $counted then "fresh_live_proof_artifact_observed"
          elif $feature.state != "observed" then "candidate_not_observed"
          elif (rationale_ok | not) then "invalid_node_bun_rationale"
          elif (($feature.artifact_handles // []) | length) == 0 then "missing_artifact_handles"
          elif (($feature.freshness_days // 999999) > $max) then "stale_artifact"
          else "observed_feature_lacks_live_proof"
          end
        ),
        remediation: (if $counted then "none" else "attach a fresh live proof artifact and rerun the catalog gate" end)
      }' "$input_path" >"$events_path"

  jq -n \
    --arg schema_version "$schema_version" \
    --arg component "$component" \
    --arg bead_id "$bead_id" \
    --arg decision "$report_decision" \
    --arg reason "$reason" \
    --argjson observed "$observed_count" \
    --argjson required "$required_observed" \
    --argjson allowed "$(if [[ "$decision" == "pass" ]]; then echo true; else echo false; fi)" \
    --slurpfile metric "$metric_path" \
    --argjson unsupported "$unsupported_json" \
    --slurpfile events "$events_path" \
    --arg downgrade "State production impossible-by-default feature count as a target until the feature catalog proves at least three live features." \
    '{
      schema_version: $schema_version,
      component: $component,
      bead_id: $bead_id,
      decision: $decision,
      reason: $reason,
      observed_feature_count: $observed,
      required_observed_feature_count: $required,
      observed_disruptive_floor_wording_allowed: $allowed,
      metric_artifact: $metric[0],
      unsupported_candidate_feature_ids: $unsupported,
      events: $events,
      downgrade_text: (if $allowed then "Production impossible-by-default feature count is observed with live proof artifacts." else $downgrade end)
    }' >"$report_path"

  proof_contract_write_standard_bundle \
    "$bundle_dir" \
    "$component" \
    "$decision" \
    "$verification_command" \
    "$report_path" \
    "$events_path" \
    "$commands_path" \
    "bd-1qr4f,bd-x7nod" \
    "$claim_id" \
    "$failure_count"

  echo "production_feature_catalog_report=${report_path}"
  echo "production_feature_catalog_metric_artifact=${metric_path}"
  echo "production_feature_catalog_proof_manifest=${bundle_dir}/manifest.json"

  if [[ "$expected_exit" == "fail" && "$decision" == "pass" ]]; then
    echo "expected fail-closed catalog but gate passed" >&2
    exit 1
  fi
  if [[ "$expected_exit" == "pass" && "$decision" != "pass" ]]; then
    echo "expected passing catalog but gate failed: $reason" >&2
    exit 1
  fi
}

case "$mode" in
  ci)
    write_bundle "$pass_input" "${run_dir}/pass" "pass" "pass"
    write_bundle "$fail_input" "${run_dir}/fail_closed" "fail_closed" "fail"
    jq -e '.status == "fail" and .failure_count == 1' "${run_dir}/fail_closed/report.json" >/dev/null
    ;;
  pass)
    write_bundle "$pass_input" "$run_dir" "pass" "pass"
    ;;
  fail_closed)
    write_bundle "$fail_input" "$run_dir" "fail_closed" "fail"
    exit 1
    ;;
  verify)
    verify_path="${2:-}"
    if [[ -z "$verify_path" || ! -f "$verify_path" ]]; then
      echo "usage: $0 verify <catalog_report.json>" >&2
      exit 2
    fi
    jq -e --arg schema "$schema_version" '.schema_version == $schema and (.metric_artifact.metric_id == "impossible_by_default_production_features")' "$verify_path" >/dev/null
    echo "production_feature_catalog_verified=${verify_path}"
    ;;
  *)
    echo "usage: $0 [ci|pass|fail_closed|verify] [pass_input] [fail_input]" >&2
    exit 2
    ;;
esac
