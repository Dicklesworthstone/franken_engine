#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
contract_json="${IDEA_WIZARD_XIII_CLAIM_PROMOTION_GATE_JSON:-${root_dir}/docs/idea_wizard_xiii_claim_promotion_gate_v1.json}"
readme_path="${IDEA_WIZARD_XIII_CLAIM_PROMOTION_README:-${root_dir}/README.md}"
transparency_report="${IDEA_WIZARD_XIII_TRANSPARENCY_REPORT:-}"
quarantine_report="${IDEA_WIZARD_XIII_QUARANTINE_REPORT:-}"
capability_report="${IDEA_WIZARD_XIII_CAPABILITY_REPORT:-}"
artifact_root="${IDEA_WIZARD_XIII_CLAIM_PROMOTION_GATE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-iwxiii-claim-promotion-gate}"
run_id="${IDEA_WIZARD_XIII_CLAIM_PROMOTION_GATE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${IDEA_WIZARD_XIII_CLAIM_PROMOTION_GATE_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${IDEA_WIZARD_XIII_CLAIM_PROMOTION_SOURCE_REVISION:-}"
original_args=("$@")

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/idea_wizard_xiii_claim_promotion_gate.sh [OPTIONS]

Options:
  --contract-json FILE
  --readme FILE
  --transparency-report FILE
  --quarantine-report FILE
  --capability-report FILE
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
    --readme)
      readme_path="${2:-}"
      shift 2
      ;;
    --transparency-report)
      transparency_report="${2:-}"
      shift 2
      ;;
    --quarantine-report)
      quarantine_report="${2:-}"
      shift 2
      ;;
    --capability-report)
      capability_report="${2:-}"
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
  printf 'jq is required for XIII claim-promotion gate validation\n' >&2
  exit 2
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse --short HEAD 2>/dev/null || printf unknown)"
fi
if [[ ! -f "$contract_json" ]]; then
  printf 'claim-promotion gate JSON not found: %s\n' "$contract_json" >&2
  exit 64
fi
jq empty "$contract_json"

mkdir -p "$run_dir"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/claim_promotion_gate_report.json"
report_tmp_path="${run_dir}/claim_promotion_gate_report.tmp.json"
operator_status_path="${run_dir}/operator_status.json"
report_md_path="${run_dir}/report.md"
manifest_path="${run_dir}/run_manifest.json"
normalized_transparency_path="${run_dir}/normalized_transparency_report.json"
normalized_quarantine_path="${run_dir}/normalized_quarantine_report.json"
normalized_capability_path="${run_dir}/normalized_capability_report.json"

for artifact_path in \
  "$events_path" \
  "$commands_path" \
  "$report_path" \
  "$report_tmp_path" \
  "$operator_status_path" \
  "$report_md_path" \
  "$manifest_path" \
  "$normalized_transparency_path" \
  "$normalized_quarantine_path" \
  "$normalized_capability_path"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

normalize_report() {
  local claim_id="$1"
  local input_path="$2"
  local output_path="$3"

  if [[ -z "$input_path" ]]; then
    jq -n \
      --arg claim_id "$claim_id" \
      '{claim_id:$claim_id, decision:"fail_closed", missing:true, missing_reason:"report path not supplied"}' >"$output_path"
    return
  fi
  if [[ ! -f "$input_path" ]]; then
    jq -n \
      --arg claim_id "$claim_id" \
      --arg artifact_path "$input_path" \
      '{claim_id:$claim_id, artifact_path:$artifact_path, decision:"fail_closed", missing:true, missing_reason:"report artifact is missing"}' >"$output_path"
    return
  fi
  if ! jq empty "$input_path" >/dev/null 2>&1; then
    jq -n \
      --arg claim_id "$claim_id" \
      --arg artifact_path "$input_path" \
      '{claim_id:$claim_id, artifact_path:$artifact_path, decision:"fail_closed", invalid_json:true, invalid_reason:"report is not valid JSON"}' >"$output_path"
    return
  fi

  jq --arg input_artifact_path "$input_path" '. + {input_artifact_path:$input_artifact_path}' "$input_path" >"$output_path"
}

normalize_report "FE-CLAIM-004" "$transparency_report" "$normalized_transparency_path"
normalize_report "FE-CLAIM-005" "$quarantine_report" "$normalized_quarantine_path"
normalize_report "FE-CLAIM-006" "$capability_report" "$normalized_capability_path"

readme_for_jq="$readme_path"
readme_missing=false
if [[ ! -f "$readme_path" ]]; then
  readme_for_jq="/dev/null"
  readme_missing=true
fi

: >"$events_path"
printf './scripts/idea_wizard_xiii_claim_promotion_gate.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

jq -n \
  --slurpfile contract "$contract_json" \
  --slurpfile transparency "$normalized_transparency_path" \
  --slurpfile quarantine "$normalized_quarantine_path" \
  --slurpfile capability "$normalized_capability_path" \
  --rawfile readme "$readme_for_jq" \
  --argjson readme_missing "$readme_missing" \
  --arg schema_version "franken-engine.idea-wizard-xiii-claim-promotion-gate.report.v1" \
  --arg source_revision "$source_revision" \
  --arg contract_json "$contract_json" \
  --arg readme_path "$readme_path" \
  --arg report_path "$report_path" \
  --arg operator_status_path "$operator_status_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_md_path "$report_md_path" \
  --arg manifest_path "$manifest_path" '
    def bad_marker($r):
      ([($r.evidence_freshness // ""), ($r.evidence_kind // ""), ($r.fixture_kind // ""), ($r.proof_origin // "")]
        | map(tostring)
        | join(" ")
        | test("stale|synthetic|missing|tampered"));
    def bad_evidence($r):
      (($r.missing // false) == true)
      or (($r.invalid_json // false) == true)
      or bad_marker($r);
    def report_path($r): ($r.input_artifact_path // $r.artifact_path // null);
    def fail_status($claim_id; $subset; $reasons; $downgrade; $r):
      {
        claim_id:$claim_id,
        status:"fail_closed",
        proven_subset_status:"fail_closed",
        promotion_subset:$subset,
        evidence_report:report_path($r),
        downgrade_text:$downgrade,
        readme_downgrade_preserved:false,
        reasons:$reasons
      };
    def status_obj($claim_id; $status; $proven_status; $subset; $reasons; $downgrade; $r; $readme_ok):
      {
        claim_id:$claim_id,
        status:$status,
        proven_subset_status:$proven_status,
        promotion_subset:$subset,
        evidence_report:report_path($r),
        downgrade_text:$downgrade,
        readme_downgrade_preserved:$readme_ok,
        reasons:$reasons
      };
    def readme_check($claim_id):
      if $readme_missing then
        {pass:false, reason:"README text is missing"}
      elif $claim_id == "FE-CLAIM-004" then
        if ($readme | test("Cryptographic governance[^\\n]*OBSERVED|Cryptographic decision receipts[^\\n]*OBSERVED")) then
          {pass:false, reason:"README overclaims cryptographic governance beyond the transparency-log subset"}
        elif (($readme | contains("Cryptographic governance"))
          and ($readme | contains("HYPOTHESIS"))
          and ($readme | contains("optional TEE attestation bindings"))
          and ($readme | contains("HYPOTHESIS until transparency-log and optional TEE"))) then
          {pass:true, reason:"README keeps cryptographic governance downgraded"}
        else
          {pass:false, reason:"README lacks required FE-CLAIM-004 downgrade text"}
        end
      elif $claim_id == "FE-CLAIM-005" then
        if ($readme | test("Fleet immune system[^\\n]*OBSERVED|Fleet quarantine convergence model[^\\n]*OBSERVED")) then
          {pass:false, reason:"README overclaims fleet convergence beyond the bounded live subset"}
        elif (($readme | contains("Fleet immune system"))
          and ($readme | contains("TARGETED"))
          and ($readme | contains("live runtime/CLI proof before bounded convergence SLOs are treated as observed"))
          and ($readme | contains("TARGETED/provisional"))) then
          {pass:true, reason:"README keeps fleet convergence bounded and targeted"}
        else
          {pass:false, reason:"README lacks required FE-CLAIM-005 downgrade text"}
        end
      elif $claim_id == "FE-CLAIM-006" then
        if ($readme | test("Capability-typed execution[^\\n]*OBSERVED|Capability-typed extension contract[^\\n]*OBSERVED")) then
          {pass:false, reason:"README overclaims capability-typed execution beyond the covered subset"}
        elif (($readme | contains("Capability-typed execution"))
          and ($readme | contains("HYPOTHESIS"))
          and ($readme | contains("not shipped"))
          and ($readme | contains("Selected runtime capability gates"))) then
          {pass:true, reason:"README keeps typed TS-to-IR downgraded"}
        else
          {pass:false, reason:"README lacks required FE-CLAIM-006 downgrade text"}
        end
      else
        {pass:false, reason:"unknown claim"}
      end;
    def fe004($r):
      (readme_check("FE-CLAIM-004")) as $readme
      | "decision_receipts_plus_transparency_log_only" as $subset
      | "Optional TEE attestation remains hypothesis without a separate live TEE report." as $downgrade
      | if ($readme.pass | not) then
          fail_status("FE-CLAIM-004"; $subset; [$readme.reason]; $downgrade; $r)
        elif bad_evidence($r) then
          fail_status("FE-CLAIM-004"; $subset; ["transparency-log proof report is missing, stale, synthetic, tampered, or invalid"]; $downgrade; $r)
        elif (($r.schema_version // "") != "franken-engine.idea-wizard-xiii-transparency-log-decision-receipt-proof.report.v1") then
          fail_status("FE-CLAIM-004"; $subset; ["unexpected transparency-log proof report schema"]; $downgrade; $r)
        elif (($r.claim_id // "") != "FE-CLAIM-004") then
          fail_status("FE-CLAIM-004"; $subset; ["transparency-log proof report claim_id mismatch"]; $downgrade; $r)
        elif (($r.decision // "") != "pass" or ($r.independent_verifier_verdict // "") != "pass") then
          fail_status("FE-CLAIM-004"; $subset; ["transparency-log proof report did not pass"]; $downgrade; $r)
        elif (($r.promotion_subset // "") != $subset or ($r.tee_attestation_state // "") != "not_promoted") then
          fail_status("FE-CLAIM-004"; $subset; ["transparency-log proof tried to promote an unsupported subset or TEE"]; $downgrade; $r)
        else
          status_obj("FE-CLAIM-004"; "degraded"; "green"; $subset; ["transparency-log decision receipt proof is green", "TEE attestation remains downgraded"]; $downgrade; $r; true)
        end;
    def fe005($r):
      (readme_check("FE-CLAIM-005")) as $readme
      | "live_quarantine_mesh_bounded_convergence_only" as $subset
      | "De-escalation and recovery semantics remain outside this promotion." as $downgrade
      | if ($readme.pass | not) then
          fail_status("FE-CLAIM-005"; $subset; [$readme.reason]; $downgrade; $r)
        elif bad_evidence($r) then
          fail_status("FE-CLAIM-005"; $subset; ["quarantine proof report is missing, stale, synthetic, tampered, or invalid"]; $downgrade; $r)
        elif (($r.schema_version // "") != "franken-engine.idea-wizard-xiii-quarantine-mesh-convergence-proof.report.v1") then
          fail_status("FE-CLAIM-005"; $subset; ["unexpected quarantine proof report schema"]; $downgrade; $r)
        elif (($r.claim_id // "") != "FE-CLAIM-005") then
          fail_status("FE-CLAIM-005"; $subset; ["quarantine proof report claim_id mismatch"]; $downgrade; $r)
        elif (($r.decision // "") != "pass" or ($r.replay_verifier_verdict // "") != "pass") then
          fail_status("FE-CLAIM-005"; $subset; ["quarantine proof report did not pass replay verification"]; $downgrade; $r)
        elif (($r.promotion_subset // "") != $subset
          or ((($r | has("permanent_ratchet")) and ($r.permanent_ratchet == true)) | not)
          or ((($r | has("de_escalation_supported")) and ($r.de_escalation_supported == false)) | not)) then
          fail_status("FE-CLAIM-005"; $subset; ["quarantine proof crossed the bounded convergence or de-escalation boundary"]; $downgrade; $r)
        else
          status_obj("FE-CLAIM-005"; "green"; "green"; $subset; ["live bounded quarantine convergence proof is green", "de-escalation remains out of scope"]; $downgrade; $r; true)
        end;
    def fe006($r):
      (readme_check("FE-CLAIM-006")) as $readme
      | "covered_capability_typed_input_subset_only" as $subset
      | "Typed TypeScript-to-IR onboarding remains hypothesis until a production compiler path ships." as $downgrade
      | if ($readme.pass | not) then
          fail_status("FE-CLAIM-006"; $subset; [$readme.reason]; $downgrade; $r)
        elif bad_evidence($r) then
          fail_status("FE-CLAIM-006"; $subset; ["capability-typed proof report is missing, stale, synthetic, tampered, or invalid"]; $downgrade; $r)
        elif (($r.schema_version // "") != "franken-engine.idea-wizard-xiii-capability-typed-ambient-authority-proof.report.v1") then
          fail_status("FE-CLAIM-006"; $subset; ["unexpected capability-typed proof report schema"]; $downgrade; $r)
        elif (($r.claim_id // "") != "FE-CLAIM-006") then
          fail_status("FE-CLAIM-006"; $subset; ["capability-typed proof report claim_id mismatch"]; $downgrade; $r)
        elif (($r.decision // "") != "pass" or ($r.runtime_enforcement_verdict // "") != "pass") then
          fail_status("FE-CLAIM-006"; $subset; ["capability-typed proof report did not pass runtime enforcement"]; $downgrade; $r)
        elif (($r.promotion_subset // "") != $subset or ($r.covered_input_subset // "") != "capability_typed_manifest_ir_hostcall_v1") then
          fail_status("FE-CLAIM-006"; $subset; ["capability-typed proof report covered an unsupported subset"]; $downgrade; $r)
        elif (($r.unsupported_contract.actual // "") != "fail_closed") then
          fail_status("FE-CLAIM-006"; $subset; ["unsupported typed TS-to-IR fixture did not fail closed"]; $downgrade; $r)
        elif (all(["filesystem","network","hostcall"][]; . as $ambient | (($r.denied_ambient_authority // []) | index($ambient)) != null) | not) then
          fail_status("FE-CLAIM-006"; $subset; ["capability-typed proof did not deny all ambient authority classes"]; $downgrade; $r)
        else
          status_obj("FE-CLAIM-006"; "degraded"; "green"; $subset; ["covered capability-typed manifest-to-IR subset is green", "full typed TS-to-IR remains downgraded"]; $downgrade; $r; true)
        end;
    ($contract[0]) as $contract_doc
    | ($transparency[0]) as $t
    | ($quarantine[0]) as $q
    | ($capability[0]) as $c
    | [fe004($t), fe005($q), fe006($c)] as $statuses
    | ($statuses | map(select(.status == "fail_closed"))) as $failures
    | {
        schema_version:$schema_version,
        source_revision:$source_revision,
        contract_json:$contract_json,
        readme_path:$readme_path,
        contract_schema_version:($contract_doc.schema_version // null),
        decision:(if ($failures | length) == 0 then "pass" else "fail_closed" end),
        claim_statuses:$statuses,
        summary:{
          green:($statuses | map(select(.status == "green")) | length),
          degraded:($statuses | map(select(.status == "degraded")) | length),
          fail_closed:($failures | length)
        },
        failures:$failures,
        mutation_policy:{
          promotes_claims:false,
          rewrites_readme:false,
          mutates_claim_matrix:false,
          runs_cargo:false,
          runs_rch:false,
          repairs_agent_mail_db:false
        },
        artifact_paths:{
          report_json:$report_path,
          operator_status_json:$operator_status_path,
          events_jsonl:$events_path,
          commands_txt:$commands_path,
          run_manifest_json:$manifest_path,
          report_md:$report_md_path
        }
      }
  ' >"$report_tmp_path"
mv "$report_tmp_path" "$report_path"

jq '{
  schema_version:"franken-engine.idea-wizard-xiii-claim-promotion-gate.operator-status.v1",
  source_revision,
  decision,
  summary,
  claim_statuses
}' "$report_path" >"$operator_status_path"

jq -c '.claim_statuses[] | {
  schema_version:"franken-engine.idea-wizard-xiii-claim-promotion-gate.event.v1",
  event:"claim_operator_status",
  claim_id,
  status,
  proven_subset_status,
  promotion_subset,
  reasons
}' "$report_path" >>"$events_path"
jq -c '.failures[] | {
  schema_version:"franken-engine.idea-wizard-xiii-claim-promotion-gate.event.v1",
  event:"claim_operator_status_failure",
  claim_id,
  status,
  reasons
}' "$report_path" >>"$events_path"

jq -n \
  --arg schema_version "franken-engine.idea-wizard-xiii-claim-promotion-gate.run-manifest.v1" \
  --arg source_revision "$source_revision" \
  --arg report_json "$report_path" \
  --arg operator_status_json "$operator_status_path" \
  --arg events_jsonl "$events_path" \
  --arg commands_txt "$commands_path" \
  --arg report_md "$report_md_path" \
  --arg decision "$(jq -r '.decision' "$report_path")" \
  '{
    schema_version:$schema_version,
    source_revision:$source_revision,
    decision:$decision,
    artifacts:{
      report_json:$report_json,
      operator_status_json:$operator_status_json,
      events_jsonl:$events_jsonl,
      commands_txt:$commands_txt,
      report_md:$report_md
    },
    mutation_policy:{
      promotes_claims:false,
      rewrites_readme:false,
      mutates_claim_matrix:false,
      runs_cargo:false,
      runs_rch:false,
      repairs_agent_mail_db:false
    }
  }' >"$manifest_path"

{
  printf '# IDEA-WIZARD-XIII Claim Promotion Gate\n\n'
  jq -r '"- Decision: `" + .decision + "`"' "$report_path"
  jq -r '"- Green: `" + (.summary.green | tostring) + "`, degraded: `" + (.summary.degraded | tostring) + "`, fail-closed: `" + (.summary.fail_closed | tostring) + "`\n"' "$report_path"
  jq -r '.claim_statuses[] | "- `" + .claim_id + "`: `" + .status + "` (`" + .proven_subset_status + "`) - " + (.reasons | join("; "))' "$report_path"
  if [[ "$(jq '.failures | length' "$report_path")" -ne 0 ]]; then
    printf '\n## Failures\n\n'
    jq -r '.failures[] | "- `" + .claim_id + "`: " + (.reasons | join("; "))' "$report_path"
  fi
} >"$report_md_path"

printf 'claim_promotion_gate_report=%s\n' "$report_path"
printf 'operator_status=%s\n' "$operator_status_path"
if [[ "$(jq -r '.decision' "$report_path")" != "pass" ]]; then
  exit 42
fi
