#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
contract_json="${IDEA_WIZARD_XIII_CLAIM_PROMOTION_CONTRACT_JSON:-${root_dir}/docs/idea_wizard_xiii_claim_promotion_contract_v1.json}"
matrix_json="${IDEA_WIZARD_XIII_CLAIM_PROMOTION_MATRIX_JSON:-${root_dir}/docs/claim_to_proof_matrix_v1.json}"
artifact_root="${IDEA_WIZARD_XIII_CLAIM_PROMOTION_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-iwxiii-claim-promotion-contract}"
run_id="${IDEA_WIZARD_XIII_CLAIM_PROMOTION_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${IDEA_WIZARD_XIII_CLAIM_PROMOTION_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${IDEA_WIZARD_XIII_CLAIM_PROMOTION_SOURCE_REVISION:-}"
original_args=("$@")

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/idea_wizard_xiii_claim_promotion_contract_gate.sh [OPTIONS]

Options:
  --contract-json FILE
  --matrix-json FILE
  --source-revision REV
  --output-dir DIR
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --contract-json)
      contract_json="${2:-}"
      shift 2
      ;;
    --matrix-json)
      matrix_json="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    --output-dir)
      run_dir="${2:-}"
      shift 2
      ;;
    -h|--help|help)
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
  printf 'jq is required for claim-promotion contract validation\n' >&2
  exit 2
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse --short HEAD 2>/dev/null || printf unknown)"
fi
if [[ ! -f "$contract_json" ]]; then
  printf 'contract JSON not found: %s\n' "$contract_json" >&2
  exit 64
fi
if [[ ! -f "$matrix_json" ]]; then
  printf 'claim matrix JSON not found: %s\n' "$matrix_json" >&2
  exit 64
fi
jq empty "$contract_json" "$matrix_json"

mkdir -p "$run_dir"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/claim_promotion_contract_report.json"
report_tmp="${run_dir}/claim_promotion_contract_report.tmp.json"
report_md="${run_dir}/report.md"
manifest_path="${run_dir}/run_manifest.json"

for artifact_path in "$events_path" "$commands_path" "$report_path" "$report_tmp" "$report_md" "$manifest_path"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

: >"$events_path"
printf './scripts/idea_wizard_xiii_claim_promotion_contract_gate.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

jq -n \
  --slurpfile contract "$contract_json" \
  --slurpfile matrix "$matrix_json" \
  --arg schema_version "franken-engine.idea-wizard-xiii-claim-promotion-contract-report.v1" \
  --arg source_revision "$source_revision" \
  --arg contract_json "$contract_json" \
  --arg matrix_json "$matrix_json" \
  --arg report_path "$report_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_md "$report_md" \
  --arg manifest_path "$manifest_path" '
    def rank($state):
      if $state == "hypothesis" then 1
      elif $state == "target" then 2
      elif $state == "observed" then 3
      else 0
      end;
    def arr($v): if ($v | type) == "array" then $v else [] end;
    def has_all($row; $items):
      all($items[]; . as $item | (arr($row) | index($item)) != null);
    def event($claim_id; $status; $reason):
      {
        schema_version:"franken-engine.idea-wizard-xiii-claim-promotion-contract.event.v1",
        event:"claim_promotion_contract_checked",
        claim_id:$claim_id,
        status:$status,
        reason:$reason
      };
    ($contract[0]) as $contract_doc
    | ($matrix[0]) as $matrix_doc
    | ($contract_doc.claims // []) as $contract_claims
    | ($matrix_doc.claims // []) as $matrix_claims
    | ["FE-CLAIM-004","FE-CLAIM-005","FE-CLAIM-006"] as $required_ids
    | ($contract_doc.global_promotion_requirements // []) as $global_requirements
    | [
        if ($contract_doc.schema_version != "franken-engine.idea-wizard-xiii-claim-promotion-contract.v1")
        then {claim_id:"contract",status:"fail",reason:"unexpected contract schema_version"} else empty end,
        if ($matrix_doc.schema_version != "franken-engine.claim-to-proof-matrix.v1")
        then {claim_id:"matrix",status:"fail",reason:"unexpected claim matrix schema_version"} else empty end,
        if ((($contract_doc.current_policy.advisory_only != true) or ($contract_doc.current_policy.promotes_claims != false)))
        then {claim_id:"contract",status:"fail",reason:"contract must be advisory-only and non-promoting"} else empty end,
        if (($contract_doc.current_policy.required_heavy_cargo_prefix // "") != "rch exec -- env CARGO_TARGET_DIR=")
        then {claim_id:"contract",status:"fail",reason:"contract must require rch-wrapped heavy cargo guidance"} else empty end,
        if (has_all($global_requirements; ["fresh_pass_json_report","commands_txt","events_jsonl","run_manifest_json","human_report","no_local_heavy_cargo_transcript","rch_wrapped_heavy_rust_validation","stale_synthetic_missing_and_tampered_negative_fixtures"]) | not)
        then {claim_id:"contract",status:"fail",reason:"global promotion requirements are incomplete"} else empty end
      ] as $global_failures
    | def matrix_for($id):
        ($matrix_claims[]? | select(.claim_id == $id)) // null;
      def contract_for($id):
        ($contract_claims[]? | select(.claim_id == $id)) // null;
      def validate_claim($id):
        (matrix_for($id)) as $matrix_row
        | (contract_for($id)) as $contract_row
        | if ($matrix_row == null) then
            {claim_id:$id,status:"fail",reason:"claim missing from claim matrix"}
          elif ($contract_row == null) then
            {claim_id:$id,status:"fail",reason:"claim missing from promotion contract"}
          elif (($matrix_row.allowed_state // "") != ($contract_row.current_allowed_state // "")) then
            {claim_id:$id,status:"fail",reason:"matrix allowed_state does not match contract current_allowed_state"}
          elif (($matrix_row.actual_wording_state // "") != ($contract_row.current_actual_wording_state // "")) then
            {claim_id:$id,status:"fail",reason:"matrix actual wording state does not match contract"}
          elif (rank($matrix_row.actual_wording_state // "") > rank($contract_row.current_allowed_state // "")) then
            {claim_id:$id,status:"fail",reason:"README wording is stronger than the promotion contract allows"}
          elif (($matrix_row.downgrade_text // "") == "" and ($contract_row.downgrade_text_required // false) == true) then
            {claim_id:$id,status:"fail",reason:"downgraded claim lacks downgrade_text"}
          elif ((arr($contract_row.required_artifacts) | length) < 4) then
            {claim_id:$id,status:"fail",reason:"claim contract does not name enough required artifacts"}
          elif ((arr($contract_row.required_report_fields) | length) < 4) then
            {claim_id:$id,status:"fail",reason:"claim contract does not name enough required report fields"}
          elif (($contract_row.future_bead // "") == "") then
            {claim_id:$id,status:"fail",reason:"claim contract lacks future bead owner"}
          elif (($id == "FE-CLAIM-004") and (($contract_row.tee_policy // "") | test("remains_hypothesis") | not)) then
            {claim_id:$id,status:"fail",reason:"FE-CLAIM-004 must keep TEE downgraded without separate proof"}
          elif (($id == "FE-CLAIM-005") and ((arr($contract_row.required_artifacts) | index("partial_failure_degraded_fixture")) == null or (arr($contract_row.required_artifacts) | index("total_failure_degraded_fixture")) == null)) then
            {claim_id:$id,status:"fail",reason:"FE-CLAIM-005 must require partial and total failure degraded fixtures"}
          elif (($id == "FE-CLAIM-006") and ((arr($contract_row.required_artifacts) | map(select(test("ambient_.*_rejection_fixture"))) | length) < 3)) then
            {claim_id:$id,status:"fail",reason:"FE-CLAIM-006 must require ambient authority rejection fixtures"}
          else
            {claim_id:$id,status:"pass",reason:"promotion contract matches current downgraded matrix state"}
          end;
      ($required_ids | map(validate_claim(.))) as $claim_results
    | ($global_failures + ($claim_results | map(select(.status != "pass")))) as $failures
    | {
        schema_version:$schema_version,
        source_revision:$source_revision,
        decision:(if ($failures | length) == 0 then "pass" else "fail_closed" end),
        contract_json:$contract_json,
        matrix_json:$matrix_json,
        required_claim_ids:$required_ids,
        claim_results:$claim_results,
        failures:$failures,
        mutation_policy:{
          advisory_only:true,
          promotes_claims:false,
          rewrites_readme:false,
          mutates_beads:false,
          sends_agent_mail:false,
          repairs_agent_mail_db:false,
          runs_cargo:false,
          runs_rch:false
        },
        artifact_paths:{
          report_json:$report_path,
          events_jsonl:$events_path,
          commands_txt:$commands_path,
          report_md:$report_md,
          run_manifest_json:$manifest_path
        }
      }
  ' >"$report_tmp"
mv "$report_tmp" "$report_path"

jq -c '.claim_results[] | {
  schema_version:"franken-engine.idea-wizard-xiii-claim-promotion-contract.event.v1",
  event:"claim_promotion_contract_checked",
  claim_id,
  status,
  reason
}' "$report_path" >>"$events_path"
jq -c '.failures[] | {
  schema_version:"franken-engine.idea-wizard-xiii-claim-promotion-contract.event.v1",
  event:"claim_promotion_contract_failure",
  claim_id,
  status,
  reason
}' "$report_path" >>"$events_path"

jq -n \
  --arg schema_version "franken-engine.idea-wizard-xiii-claim-promotion-contract.run-manifest.v1" \
  --arg source_revision "$source_revision" \
  --arg report_path "$report_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg decision "$(jq -r '.decision' "$report_path")" \
  '{
    schema_version:$schema_version,
    source_revision:$source_revision,
    decision:$decision,
    artifacts:{
      report_json:$report_path,
      events_jsonl:$events_path,
      commands_txt:$commands_path
    },
    mutation_policy:{
      advisory_only:true,
      promotes_claims:false,
      rewrites_readme:false,
      runs_cargo:false,
      runs_rch:false
    }
  }' >"$manifest_path"

{
  printf '# IDEA-WIZARD-XIII Claim Promotion Contract Gate\n\n'
  jq -r '"- Decision: `" + .decision + "`"' "$report_path"
  jq -r '"- Claims checked: `" + (.claim_results | length | tostring) + "`\n"' "$report_path"
  jq -r '.claim_results[] | "- `" + .claim_id + "`: `" + .status + "` - " + .reason' "$report_path"
  if [[ "$(jq '.failures | length' "$report_path")" -ne 0 ]]; then
    printf '\n## Failures\n\n'
    jq -r '.failures[] | "- `" + .claim_id + "`: " + .reason' "$report_path"
  fi
} >"$report_md"

printf 'claim_promotion_contract_report=%s\n' "$report_path"
if [[ "$(jq -r '.decision' "$report_path")" != "pass" ]]; then
  exit 42
fi
