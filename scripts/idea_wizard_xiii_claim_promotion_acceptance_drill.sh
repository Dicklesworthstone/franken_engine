#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
contract_json="${IDEA_WIZARD_XIII_ACCEPTANCE_DRILL_JSON:-${root_dir}/docs/idea_wizard_xiii_claim_promotion_acceptance_drill_v1.json}"
gate_script="${IDEA_WIZARD_XIII_CLAIM_PROMOTION_GATE_SCRIPT:-${root_dir}/scripts/idea_wizard_xiii_claim_promotion_gate.sh}"
readme_path="${IDEA_WIZARD_XIII_ACCEPTANCE_README:-${root_dir}/README.md}"
transparency_report="${IDEA_WIZARD_XIII_TRANSPARENCY_REPORT:-}"
quarantine_report="${IDEA_WIZARD_XIII_QUARANTINE_REPORT:-}"
capability_report="${IDEA_WIZARD_XIII_CAPABILITY_REPORT:-}"
artifact_root="${IDEA_WIZARD_XIII_ACCEPTANCE_DRILL_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-iwxiii-claim-promotion-acceptance-drill}"
run_id="${IDEA_WIZARD_XIII_ACCEPTANCE_DRILL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${IDEA_WIZARD_XIII_ACCEPTANCE_DRILL_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${IDEA_WIZARD_XIII_ACCEPTANCE_SOURCE_REVISION:-}"
mode="${IDEA_WIZARD_XIII_ACCEPTANCE_DRILL_MODE:-live}"
original_args=("$@")

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/idea_wizard_xiii_claim_promotion_acceptance_drill.sh [OPTIONS]

Options:
  --contract-json FILE
  --gate-script FILE
  --readme FILE
  --transparency-report FILE
  --quarantine-report FILE
  --capability-report FILE
  --source-revision REV
  --output-dir DIR
  --mode live|fixture
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --contract-json)
      contract_json="${2:-}"
      shift 2
      ;;
    --gate-script)
      gate_script="${2:-}"
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
    --mode)
      mode="${2:-}"
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
  printf 'jq is required for XIII claim-promotion acceptance drill\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for XIII claim-promotion acceptance drill\n' >&2
  exit 2
fi
case "$mode" in
  live|fixture) ;;
  *)
    printf 'invalid --mode: %s\n' "$mode" >&2
    exit 64
    ;;
esac
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse --short HEAD 2>/dev/null || printf unknown)"
fi
if [[ ! -f "$contract_json" ]]; then
  printf 'acceptance drill contract JSON not found: %s\n' "$contract_json" >&2
  exit 64
fi
if [[ ! -x "$gate_script" ]]; then
  printf 'claim-promotion gate script is not executable: %s\n' "$gate_script" >&2
  exit 64
fi
jq empty "$contract_json"

mkdir -p "$run_dir"
gate_dir="${run_dir}/gate"
source_input_dir="${run_dir}/source_inputs"
mkdir -p "$gate_dir" "$source_input_dir"

events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
source_inputs_path="${run_dir}/source_inputs.json"
aggregate_report_path="${run_dir}/aggregate_report.json"
aggregate_tmp_path="${run_dir}/aggregate_report.tmp.json"
operator_summary_path="${run_dir}/operator_summary.md"
manifest_path="${run_dir}/run_manifest.json"
transparency_snapshot_path="${source_input_dir}/transparency_report.json"
quarantine_snapshot_path="${source_input_dir}/quarantine_report.json"
capability_snapshot_path="${source_input_dir}/capability_report.json"
readme_snapshot_path="${source_input_dir}/README.md"

for artifact_path in \
  "$events_path" \
  "$commands_path" \
  "$source_inputs_path" \
  "$aggregate_report_path" \
  "$aggregate_tmp_path" \
  "$operator_summary_path" \
  "$manifest_path" \
  "$transparency_snapshot_path" \
  "$quarantine_snapshot_path" \
  "$capability_snapshot_path" \
  "$readme_snapshot_path"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

write_event() {
  local event_name="$1"
  local status="$2"
  local detail="$3"
  jq -nc \
    --arg schema_version "franken-engine.idea-wizard-xiii-claim-promotion-acceptance-drill.event.v1" \
    --arg event "$event_name" \
    --arg status "$status" \
    --arg detail "$detail" \
    '{schema_version:$schema_version,event:$event,status:$status,detail:$detail}' >>"$events_path"
}

sha256_file_or_empty() {
  local path="$1"
  if [[ -f "$path" ]]; then
    sha256sum "$path" | awk '{print $1}'
  else
    printf ''
  fi
}

snapshot_json_input() {
  local input_path="$1"
  local snapshot_path="$2"
  local missing_reason="$3"
  if [[ -f "$input_path" ]] && jq empty "$input_path" >/dev/null 2>&1; then
    jq -S . "$input_path" >"$snapshot_path"
  else
    jq -n \
      --arg path "$input_path" \
      --arg reason "$missing_reason" \
      '{missing:true,path:$path,reason:$reason}' >"$snapshot_path"
  fi
}

snapshot_json_input "$transparency_report" "$transparency_snapshot_path" "transparency report missing or invalid"
snapshot_json_input "$quarantine_report" "$quarantine_snapshot_path" "quarantine report missing or invalid"
snapshot_json_input "$capability_report" "$capability_snapshot_path" "capability report missing or invalid"
if [[ -f "$readme_path" ]]; then
  awk '{print}' "$readme_path" >"$readme_snapshot_path"
else
  printf 'README missing: %s\n' "$readme_path" >"$readme_snapshot_path"
fi

: >"$events_path"
printf './scripts/idea_wizard_xiii_claim_promotion_acceptance_drill.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

jq -n \
  --arg transparency_report "$transparency_report" \
  --arg quarantine_report "$quarantine_report" \
  --arg capability_report "$capability_report" \
  --arg readme_path "$readme_path" \
  --arg transparency_snapshot "$transparency_snapshot_path" \
  --arg quarantine_snapshot "$quarantine_snapshot_path" \
  --arg capability_snapshot "$capability_snapshot_path" \
  --arg readme_snapshot "$readme_snapshot_path" \
  --arg transparency_sha256 "$(sha256_file_or_empty "$transparency_report")" \
  --arg quarantine_sha256 "$(sha256_file_or_empty "$quarantine_report")" \
  --arg capability_sha256 "$(sha256_file_or_empty "$capability_report")" \
  --arg readme_sha256 "$(sha256_file_or_empty "$readme_path")" \
  '{
    schema_version:"franken-engine.idea-wizard-xiii-claim-promotion-acceptance-drill.source-inputs.v1",
    reports:{
      transparency:{path:$transparency_report,snapshot:$transparency_snapshot,sha256:$transparency_sha256},
      quarantine:{path:$quarantine_report,snapshot:$quarantine_snapshot,sha256:$quarantine_sha256},
      capability:{path:$capability_report,snapshot:$capability_snapshot,sha256:$capability_sha256}
    },
    readme:{path:$readme_path,snapshot:$readme_snapshot,sha256:$readme_sha256}
  }' >"$source_inputs_path"

write_event "source_inputs_preserved" "pass" "source inputs snapshot bundle written"

set +e
"$gate_script" \
  --transparency-report "$transparency_report" \
  --quarantine-report "$quarantine_report" \
  --capability-report "$capability_report" \
  --readme "$readme_path" \
  --source-revision "$source_revision" \
  --output-dir "$gate_dir" >/dev/null 2>"${gate_dir}/gate.stderr"
gate_status=$?
set -e

if [[ -f "${gate_dir}/claim_promotion_gate_report.json" ]]; then
  write_event "claim_promotion_gate_ran" "pass" "claim promotion gate emitted a report"
else
  write_event "claim_promotion_gate_ran" "fail" "claim promotion gate did not emit a report"
  jq -n \
    --arg schema_version "franken-engine.idea-wizard-xiii-claim-promotion-gate.report.v1" \
    --arg source_revision "$source_revision" \
    --arg stderr_path "${gate_dir}/gate.stderr" \
    '{
      schema_version:$schema_version,
      source_revision:$source_revision,
      decision:"fail_closed",
      summary:{green:0,degraded:0,fail_closed:3},
      claim_statuses:[],
      failures:[{claim_id:"gate",status:"fail_closed",reasons:["claim promotion gate failed before report emission"],stderr:$stderr_path}]
    }' >"${gate_dir}/claim_promotion_gate_report.json"
fi

jq -n \
  --slurpfile contract "$contract_json" \
  --slurpfile source_inputs "$source_inputs_path" \
  --slurpfile gate "${gate_dir}/claim_promotion_gate_report.json" \
  --slurpfile transparency "$transparency_snapshot_path" \
  --slurpfile quarantine "$quarantine_snapshot_path" \
  --slurpfile capability "$capability_snapshot_path" \
  --arg schema_version "franken-engine.idea-wizard-xiii-claim-promotion-acceptance-drill.report.v1" \
  --arg source_revision "$source_revision" \
  --arg mode "$mode" \
  --argjson gate_exit "$gate_status" \
  --arg aggregate_report "$aggregate_report_path" \
  --arg operator_summary "$operator_summary_path" \
  --arg source_inputs_path "$source_inputs_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg run_manifest "$manifest_path" \
  --arg gate_report "${gate_dir}/claim_promotion_gate_report.json" \
  --arg gate_operator_status "${gate_dir}/operator_status.json" '
    def claim($statuses; $id): ($statuses[]? | select(.claim_id == $id)) // {};
    def has_reason($status; $needle): (($status.reasons // []) | join(" ") | contains($needle));
    def assertion($id; $status; $passed; $detail):
      {claim_id:$id,status:(if $passed then "pass" else "fail" end),passed:$passed,detail:$detail,operator_status:($status.status // "missing"),proven_subset_status:($status.proven_subset_status // "missing")};
    ($gate[0]) as $gate_report_doc
    | ($gate_report_doc.claim_statuses // []) as $statuses
    | (claim($statuses; "FE-CLAIM-004")) as $fe004
    | (claim($statuses; "FE-CLAIM-005")) as $fe005
    | (claim($statuses; "FE-CLAIM-006")) as $fe006
    | ($transparency[0]) as $t
    | ($quarantine[0]) as $q
    | ($capability[0]) as $c
    | [
        assertion("FE-CLAIM-004"; $fe004;
          (($fe004.status // "") == "degraded"
            and ($fe004.proven_subset_status // "") == "green"
            and ($fe004.promotion_subset // "") == "decision_receipts_plus_transparency_log_only"
            and has_reason($fe004; "TEE"));
          "receipt transparency proof must be green while TEE remains downgraded"),
        assertion("FE-CLAIM-005"; $fe005;
          (($fe005.status // "") == "green"
            and ($fe005.proven_subset_status // "") == "green"
            and ($fe005.promotion_subset // "") == "live_quarantine_mesh_bounded_convergence_only"
            and (($q.convergence_ms // 1) <= ($q.slo_threshold_ms // 0))
            and ((($q | has("permanent_ratchet")) and ($q.permanent_ratchet == true)) == true)
            and ((($q | has("de_escalation_supported")) and ($q.de_escalation_supported == false)) == true));
          "bounded quarantine convergence must be green, within SLO, and permanent-ratchet only"),
        assertion("FE-CLAIM-006"; $fe006;
          (($fe006.status // "") == "degraded"
            and ($fe006.proven_subset_status // "") == "green"
            and ($fe006.promotion_subset // "") == "covered_capability_typed_input_subset_only"
            and (($c.covered_input_subset // "") == "capability_typed_manifest_ir_hostcall_v1")
            and all(["filesystem","network","hostcall"][]; . as $ambient | (($c.denied_ambient_authority // []) | index($ambient)) != null)
            and (($c.unsupported_contract.actual // "") == "fail_closed"));
          "covered capability-typed subset must be green while full typed TS-to-IR remains downgraded")
      ] as $assertions
    | ($assertions | map(select(.passed | not))) as $assertion_failures
    | (($gate_report_doc.failures // []) + ($assertion_failures | map({claim_id, status:"fail_closed", reasons:[.detail]}))) as $failures
    | {
        schema_version:$schema_version,
        bead_id:"bd-ly6hp.6",
        source_revision:$source_revision,
        mode:$mode,
        decision:(if ($gate_report_doc.decision == "pass" and ($assertion_failures | length) == 0 and $gate_exit == 0) then "pass" else "fail_closed" end),
        gate_exit:$gate_exit,
        gate_decision:($gate_report_doc.decision // "fail_closed"),
        summary:{
          green:($gate_report_doc.summary.green // 0),
          degraded:($gate_report_doc.summary.degraded // 0),
          fail_closed:($gate_report_doc.summary.fail_closed // 0),
          assertion_failures:($assertion_failures | length)
        },
        source_inputs:$source_inputs[0],
        claim_assertions:$assertions,
        claim_statuses:($gate_report_doc.claim_statuses // []),
        failures:$failures,
        contract_schema_version:($contract[0].schema_version // null),
        mutation_policy:{
          promotes_claims:false,
          rewrites_readme:false,
          mutates_claim_matrix:false,
          runs_cargo:false,
          runs_rch:false,
          repairs_agent_mail_db:false
        },
        artifact_paths:{
          aggregate_report_json:$aggregate_report,
          operator_summary_md:$operator_summary,
          source_inputs_json:$source_inputs_path,
          events_jsonl:$events_path,
          commands_txt:$commands_path,
          run_manifest_json:$run_manifest,
          gate_report_json:$gate_report,
          gate_operator_status_json:$gate_operator_status
        }
      }
  ' >"$aggregate_tmp_path"
mv "$aggregate_tmp_path" "$aggregate_report_path"

jq -c '.claim_assertions[] | {
  schema_version:"franken-engine.idea-wizard-xiii-claim-promotion-acceptance-drill.event.v1",
  event:"claim_acceptance_assertion",
  claim_id,
  status,
  detail
}' "$aggregate_report_path" >>"$events_path"
jq -c '.failures[] | {
  schema_version:"franken-engine.idea-wizard-xiii-claim-promotion-acceptance-drill.event.v1",
  event:"claim_acceptance_failure",
  claim_id,
  status,
  reasons
}' "$aggregate_report_path" >>"$events_path"

{
  printf '# IDEA-WIZARD-XIII Claim Promotion Acceptance Drill\n\n'
  jq -r '"- Decision: `" + .decision + "`"' "$aggregate_report_path"
  jq -r '"- Mode: `" + .mode + "`"' "$aggregate_report_path"
  jq -r '"- Gate decision: `" + .gate_decision + "`"' "$aggregate_report_path"
  jq -r '"- Green: `" + (.summary.green | tostring) + "`, degraded: `" + (.summary.degraded | tostring) + "`, fail-closed: `" + (.summary.fail_closed | tostring) + "`\n"' "$aggregate_report_path"
  jq -r '.claim_assertions[] | "- `" + .claim_id + "`: `" + .status + "` - " + .detail' "$aggregate_report_path"
  if [[ "$(jq '.failures | length' "$aggregate_report_path")" -ne 0 ]]; then
    printf '\n## Failures\n\n'
    jq -r '.failures[] | "- `" + .claim_id + "`: " + (.reasons | join("; "))' "$aggregate_report_path"
  fi
} >"$operator_summary_path"

jq -n \
  --arg schema_version "franken-engine.idea-wizard-xiii-claim-promotion-acceptance-drill.run-manifest.v1" \
  --arg source_revision "$source_revision" \
  --arg mode "$mode" \
  --arg decision "$(jq -r '.decision' "$aggregate_report_path")" \
  --arg aggregate_report "$aggregate_report_path" \
  --arg operator_summary "$operator_summary_path" \
  --arg source_inputs "$source_inputs_path" \
  --arg events "$events_path" \
  --arg commands "$commands_path" \
  --arg gate_report "${gate_dir}/claim_promotion_gate_report.json" \
  '{
    schema_version:$schema_version,
    source_revision:$source_revision,
    mode:$mode,
    decision:$decision,
    artifacts:{
      aggregate_report_json:$aggregate_report,
      operator_summary_md:$operator_summary,
      source_inputs_json:$source_inputs,
      events_jsonl:$events,
      commands_txt:$commands,
      gate_report_json:$gate_report
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

printf 'acceptance_drill_report=%s\n' "$aggregate_report_path"
printf 'operator_summary=%s\n' "$operator_summary_path"
if [[ "$(jq -r '.decision' "$aggregate_report_path")" != "pass" ]]; then
  exit 42
fi
