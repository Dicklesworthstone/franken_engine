#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"
source "${root_dir}/scripts/lib/proof_artifact_contract.sh"

mode="${1:-ci}"
artifact_root="${RGC_MODULE_COMPOSITION_DRIFT_GATE_ARTIFACT_ROOT:-artifacts/rgc_module_composition_drift_gate}"
run_id="${RGC_MODULE_COMPOSITION_DRIFT_GATE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${RGC_MODULE_COMPOSITION_DRIFT_GATE_RUN_DIR:-${artifact_root}/${run_id}}"
contract_path="${RGC_MODULE_COMPOSITION_CLAIM_LEDGER_PATH:-docs/rgc_module_composition_claim_ledger_v1.json}"
drift_root="${RGC_MODULE_COMPOSITION_ROOT_DIR:-${root_dir}}"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/composition_drift_report.json"
summary_path="${run_dir}/composition_drift_summary.md"
links_path="${run_dir}/claim_module_links.json"
statuses_path="${run_dir}/claim_statuses.json"
status_lines_path="${run_dir}/claim_statuses.jsonl"
gate_output_path="${run_dir}/drift_gate_output.log"
gate_summary_path="${run_dir}/gate_summary.json"

case "${mode}" in
  ci|check)
    checker_mode="check"
    ;;
  selftest)
    checker_mode="selftest"
    ;;
  *)
    echo "usage: $0 [ci|check|selftest]" >&2
    exit 64
    ;;
esac

mkdir -p "$run_dir"

contract_rel="$(proof_contract_repo_relative_path "$contract_path")"
drift_root_rel="$(proof_contract_repo_relative_path "$drift_root")"
rerun_command="./scripts/run_rgc_module_composition_drift_gate.sh ${mode}"
replay_command="./scripts/e2e/rgc_module_composition_drift_replay.sh ${mode} $(proof_contract_repo_relative_path "$run_dir")"
checker_command="RGC_MODULE_COMPOSITION_ROOT_DIR=${drift_root_rel} ./scripts/e2e/rgc_module_composition_drift_gate.sh ${checker_mode} ${contract_rel}"

printf '%s\n' "$rerun_command" >"$commands_path"
printf '%s\n' "$checker_command" >>"$commands_path"
printf '%s\n' "$replay_command" >>"$commands_path"

gate_exit_code=0
gate_output=""
if gate_output="$(RGC_MODULE_COMPOSITION_ROOT_DIR="${drift_root}" ./scripts/e2e/rgc_module_composition_drift_gate.sh "${checker_mode}" "${contract_path}" 2>&1)"; then
  gate_status="pass"
else
  gate_exit_code=$?
  gate_status="fail"
fi
printf '%s\n' "$gate_output" >"$gate_output_path"
gate_output_line_count="$(wc -l <"$gate_output_path" | tr -d '[:space:]')"

jq -n \
  --arg schema_version "franken-engine.module-composition-claim-links.v1" \
  --arg generated_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg contract_path "$(proof_contract_repo_relative_path "$contract_path")" \
  --arg drift_root "$(proof_contract_repo_relative_path "$drift_root")" \
  --arg verification_mode "$mode" \
  --arg checker_command "$checker_command" \
  --arg replay_command "$replay_command" \
  --slurpfile contract "$contract_path" \
  '{
    schema_version: $schema_version,
    generated_utc: $generated_utc,
    contract_path: $contract_path,
    drift_root: $drift_root,
    verification_mode: $verification_mode,
    checker_command: $checker_command,
    replay_command: $replay_command,
    claim_links: ($contract[0].claims | map({
      composition_id,
      parent_surface,
      proof_posture,
      source_path,
      primary_paths,
      child_substrates: (.child_substrates | map({
        surface_id,
        role,
        primary_paths
      }))
    }))
  }' >"$links_path"

json_array_from_matching_lines() {
  local prefix="$1"
  local composition_id="$2"
  local extracted=""

  extracted="$(grep -F "composition=${composition_id} " "$gate_output_path" | grep "^${prefix} composition-drift " || true)"
  if [[ -z "$extracted" ]]; then
    printf '[]'
  else
    printf '%s\n' "$extracted" | sed "s/^${prefix} composition-drift //" | jq -R 'select(length > 0)' | jq -s .
  fi
}

while IFS= read -r claim; do
  composition_id="$(jq -r '.composition_id' <<<"$claim")"
  parent_surface="$(jq -r '.parent_surface' <<<"$claim")"
  proof_posture="$(jq -r '.proof_posture' <<<"$claim")"
  source_path="$(jq -r '.source_path' <<<"$claim")"
  status_note="$(jq -r '.status_note // ""' <<<"$claim")"
  failure_diagnostics="$(json_array_from_matching_lines "FAIL" "$composition_id")"
  pass_diagnostics="$(json_array_from_matching_lines "PASS" "$composition_id")"
  failure_count="$(jq 'length' <<<"$failure_diagnostics")"

  if (( failure_count > 0 )); then
    claim_truth_status="unpublished"
    remediation_summary="Remediate the missing child-surface wiring or undeclared proxy path before presenting this claim as observed."
  elif [[ "$proof_posture" == "provisional" ]]; then
    claim_truth_status="provisional"
    remediation_summary="Follow the recorded provisional fallback beads before upgrading this claim to observed."
  else
    claim_truth_status="valid"
    remediation_summary="No remediation required while the linked child evidence remains present."
  fi

  jq -nc \
    --arg composition_id "$composition_id" \
    --arg parent_surface "$parent_surface" \
    --arg proof_posture "$proof_posture" \
    --arg source_path "$source_path" \
    --arg claim_truth_status "$claim_truth_status" \
    --arg status_note "$status_note" \
    --arg remediation_summary "$remediation_summary" \
    --arg verification_mode "$mode" \
    --argjson failure_diagnostics "$failure_diagnostics" \
    --argjson pass_diagnostics "$pass_diagnostics" \
    --argjson module_links "$(jq '{
      source_path,
      primary_paths,
      child_substrates: (.child_substrates | map({
        surface_id,
        role,
        primary_paths
      })),
      allowed_provisional_fallbacks
    }' <<<"$claim")" \
    '{
      composition_id: $composition_id,
      parent_surface: $parent_surface,
      proof_posture: $proof_posture,
      claim_truth_status: $claim_truth_status,
      source_path: $source_path,
      verification_mode: $verification_mode,
      module_links: $module_links,
      failure_diagnostics: $failure_diagnostics,
      pass_diagnostics: $pass_diagnostics,
      status_note: $status_note,
      remediation_summary: $remediation_summary
    }' >>"$status_lines_path"
done < <(jq -c '.claims[]' "$contract_path")

jq -s '.' "$status_lines_path" >"$statuses_path"

valid_count="$(jq '[.[] | select(.claim_truth_status == "valid")] | length' "$statuses_path")"
provisional_count="$(jq '[.[] | select(.claim_truth_status == "provisional")] | length' "$statuses_path")"
unpublished_count="$(jq '[.[] | select(.claim_truth_status == "unpublished")] | length' "$statuses_path")"
claim_ids_csv="$(jq -r '[.[] .composition_id] | join(",")' "$statuses_path" 2>/dev/null || true)"
if [[ -z "${claim_ids_csv}" ]]; then
  claim_ids_csv="$(jq -r '[.claims[].composition_id] | join(",")' "$contract_path")"
fi

jq -n \
  --arg schema_version "franken-engine.module-composition-drift-summary.v1" \
  --arg verification_mode "$mode" \
  --arg checker_mode "$checker_mode" \
  --arg gate_status "$gate_status" \
  --arg checker_command "$checker_command" \
  --arg contract_path "$(proof_contract_repo_relative_path "$contract_path")" \
  --arg drift_root "$(proof_contract_repo_relative_path "$drift_root")" \
  --arg gate_output_path "$(proof_contract_repo_relative_path "$gate_output_path")" \
  --arg claim_module_links_path "$(proof_contract_repo_relative_path "$links_path")" \
  --arg claim_statuses_path "$(proof_contract_repo_relative_path "$statuses_path")" \
  --arg replay_command "$replay_command" \
  --argjson gate_exit_code "$gate_exit_code" \
  --argjson gate_output_line_count "$gate_output_line_count" \
  --argjson valid_count "$valid_count" \
  --argjson provisional_count "$provisional_count" \
  --argjson unpublished_count "$unpublished_count" \
  '{
    schema_version: $schema_version,
    verification_mode: $verification_mode,
    checker_mode: $checker_mode,
    gate_status: $gate_status,
    gate_exit_code: $gate_exit_code,
    gate_output_line_count: $gate_output_line_count,
    checker_command: $checker_command,
    contract_path: $contract_path,
    drift_root: $drift_root,
    gate_output_path: $gate_output_path,
    claim_module_links_path: $claim_module_links_path,
    claim_statuses_path: $claim_statuses_path,
    replay_command: $replay_command,
    claim_truth_counts: {
      valid: $valid_count,
      provisional: $provisional_count,
      unpublished: $unpublished_count
    }
  }' >"$gate_summary_path"

claim_statuses_json="$(cat "$statuses_path")"
claim_module_links_json="$(cat "$links_path")"
gate_summary_json="$(cat "$gate_summary_path")"

jq -n \
  --arg schema_version "franken-engine.module-composition-drift-report.v1" \
  --arg generated_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg gate_name "module_composition_drift_gate" \
  --arg verification_mode "$mode" \
  --arg overall_status "$gate_status" \
  --arg contract_path "$(proof_contract_repo_relative_path "$contract_path")" \
  --arg drift_root "$(proof_contract_repo_relative_path "$drift_root")" \
  --arg replay_command "$replay_command" \
  --argjson gate_exit_code "$gate_exit_code" \
  --argjson gate_summary "$gate_summary_json" \
  --argjson claim_module_links "$claim_module_links_json" \
  --argjson claim_statuses "$claim_statuses_json" \
  '{
    schema_version: $schema_version,
    generated_utc: $generated_utc,
    gate_name: $gate_name,
    verification_mode: $verification_mode,
    overall_status: $overall_status,
    gate_exit_code: $gate_exit_code,
    contract_path: $contract_path,
    drift_root: $drift_root,
    replay_command: $replay_command,
    gate_summary: $gate_summary,
    claim_module_links: $claim_module_links,
    claim_statuses: $claim_statuses
  }' >"$report_path"

while IFS= read -r status_json; do
  composition_id="$(jq -r '.composition_id' <<<"$status_json")"
  parent_surface="$(jq -r '.parent_surface' <<<"$status_json")"
  claim_truth_status="$(jq -r '.claim_truth_status' <<<"$status_json")"
  proof_posture="$(jq -r '.proof_posture' <<<"$status_json")"
  source_path="$(jq -r '.source_path' <<<"$status_json")"
  failure_count="$(jq '.failure_diagnostics | length' <<<"$status_json")"
  jq -nc \
    --arg schema_version "$PROOF_ARTIFACT_EVENT_SCHEMA_VERSION" \
    --arg composition_id "$composition_id" \
    --arg parent_surface "$parent_surface" \
    --arg claim_truth_status "$claim_truth_status" \
    --arg proof_posture "$proof_posture" \
    --arg source_path "$source_path" \
    --arg links_path "$(proof_contract_repo_relative_path "$links_path")" \
    --arg statuses_path "$(proof_contract_repo_relative_path "$statuses_path")" \
    --arg report_path "$(proof_contract_repo_relative_path "$report_path")" \
    --arg verification_mode "$mode" \
    --argjson failure_count "$failure_count" \
    '{
      schema_version: $schema_version,
      event_name: "module_composition_drift.claim_assessed",
      severity: (if $claim_truth_status == "unpublished" then "error" elif $claim_truth_status == "provisional" then "warning" else "info" end),
      step_id: $composition_id,
      command_id: "module-composition-drift-gate",
      composition_id: $composition_id,
      parent_surface: $parent_surface,
      claim_truth_status: $claim_truth_status,
      proof_posture: $proof_posture,
      failure_count: $failure_count,
      source_path: $source_path,
      verification_mode: $verification_mode,
      claim_module_links_path: $links_path,
      claim_statuses_path: $statuses_path,
      source_report_path: $report_path
    }' >>"$events_path"
done <"$status_lines_path"

{
  printf '# Module Composition Drift Gate\n\n'
  printf -- '- Mode: `%s`\n' "$mode"
  printf -- '- Gate status: `%s`\n' "$gate_status"
  printf -- '- Contract: `%s`\n' "$(proof_contract_repo_relative_path "$contract_path")"
  printf -- '- Claim/module links: `%s`\n' "$(proof_contract_repo_relative_path "$links_path")"
  printf -- '- Machine report: `%s`\n' "$(proof_contract_repo_relative_path "$report_path")"
  printf -- '- Replay: `%s`\n' "$replay_command"
  printf '\n## Claim Truth Status\n\n'
  printf -- '- Valid: `%s`\n' "$valid_count"
  printf -- '- Provisional: `%s`\n' "$provisional_count"
  printf -- '- Unpublished: `%s`\n' "$unpublished_count"
  printf '\n## Interpretation\n\n'
  printf -- '- `valid`: observed claim with all required child evidence present and no undeclared proxy drift.\n'
  printf -- '- `provisional`: declared fallback state is still truthful, but the claim must not be presented as fully observed.\n'
  printf -- '- `unpublished`: missing child wiring or undeclared proxy drift blocks publication until remediated.\n'
  printf '\n## Claim Details\n\n'
  while IFS= read -r status_json; do
    composition_id="$(jq -r '.composition_id' <<<"$status_json")"
    claim_truth_status="$(jq -r '.claim_truth_status' <<<"$status_json")"
    parent_surface="$(jq -r '.parent_surface' <<<"$status_json")"
    remediation_summary="$(jq -r '.remediation_summary' <<<"$status_json")"
    printf '### `%s` — `%s`\n\n' "$composition_id" "$claim_truth_status"
    printf -- '- Parent surface: `%s`\n' "$parent_surface"
    printf -- '- Remediation: %s\n' "$remediation_summary"
    if (( "$(jq '.failure_diagnostics | length' <<<"$status_json")" > 0 )); then
      printf -- '- Failure diagnostics:\n'
      jq -r '.failure_diagnostics[]' <<<"$status_json" | while IFS= read -r line; do
        printf '  - `%s`\n' "$line"
      done
    elif [[ "$(jq -r '.proof_posture' <<<"$status_json")" == "provisional" ]]; then
      printf -- '- Status note: %s\n' "$(jq -r '.status_note' <<<"$status_json")"
    else
      printf -- '- Evidence status: all required parent evidence fragments matched.\n'
    fi
    printf '\n'
  done <"$status_lines_path"
} >"$summary_path"

proof_contract_write_standard_bundle \
  "$run_dir" \
  "module_composition_drift_gate" \
  "$gate_status" \
  "$rerun_command" \
  "$report_path" \
  "$events_path" \
  "$commands_path" \
  "bd-37q56,bd-tl6l7,bd-qg92c" \
  "$claim_ids_csv" \
  "$unpublished_count"

manifest_path="${run_dir}/manifest.json"
manifest_tmp_path="${run_dir}/manifest.with_links.json"
jq \
  --arg claim_module_links_json "$(proof_contract_repo_relative_path "$links_path")" \
  --arg claim_statuses_json "$(proof_contract_repo_relative_path "$statuses_path")" \
  --arg source_summary_md "$(proof_contract_repo_relative_path "$summary_path")" \
  --arg gate_output_log "$(proof_contract_repo_relative_path "$gate_output_path")" \
  --arg claim_module_links_sha256 "$(proof_contract_sha256_file "$links_path")" \
  --arg claim_statuses_sha256 "$(proof_contract_sha256_file "$statuses_path")" \
  --arg source_summary_sha256 "$(proof_contract_sha256_file "$summary_path")" \
  --arg gate_output_sha256 "$(proof_contract_sha256_file "$gate_output_path")" \
  '.artifact_paths.claim_module_links_json = $claim_module_links_json
   | .artifact_paths.claim_statuses_json = $claim_statuses_json
   | .artifact_paths.source_summary_md = $source_summary_md
   | .artifact_paths.gate_output_log = $gate_output_log
   | .generated_artifacts += [
       { path: $claim_module_links_json, sha256: (if $claim_module_links_sha256 == "" then null else $claim_module_links_sha256 end), role: "claim_module_links" },
       { path: $claim_statuses_json, sha256: (if $claim_statuses_sha256 == "" then null else $claim_statuses_sha256 end), role: "claim_truth_statuses" },
       { path: $source_summary_md, sha256: (if $source_summary_sha256 == "" then null else $source_summary_sha256 end), role: "source_human_report" },
       { path: $gate_output_log, sha256: (if $gate_output_sha256 == "" then null else $gate_output_sha256 end), role: "gate_output_log" }
     ]' \
  "$manifest_path" >"$manifest_tmp_path"
mv "$manifest_tmp_path" "$manifest_path"

echo "module_composition_drift_run_dir=$run_dir"
echo "module_composition_drift_report=$report_path"
echo "module_composition_drift_summary=$summary_path"
echo "module_composition_drift_manifest=$manifest_path"
echo "module_composition_drift_claim_links=$links_path"
echo "module_composition_drift_claim_statuses=$statuses_path"

if [[ "$gate_status" != "pass" ]]; then
  exit "$gate_exit_code"
fi
