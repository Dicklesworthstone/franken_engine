#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${IDEA_WIZARD_IV_ACCEPTANCE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-iw4-acceptance}"
run_id="${IDEA_WIZARD_IV_ACCEPTANCE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${IDEA_WIZARD_IV_ACCEPTANCE_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${IDEA_WIZARD_IV_ACCEPTANCE_SOURCE_REVISION:-}"
generated_at_utc="${IDEA_WIZARD_IV_ACCEPTANCE_GENERATED_AT_UTC:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
bead_id="${IDEA_WIZARD_IV_ACCEPTANCE_BEAD_ID:-bd-w06ui}"
original_args=("$@")

contract_json="${root_dir}/docs/idea_wizard_iv_saturation_convergence_v1.json"
child_artifacts_json=""
rch_transcript=""
replay_bundle_dir=""
run_lightweight_smokes="false"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/idea_wizard_iv_acceptance_suite.sh [OPTIONS]

Compose the IDEA-WIZARD-IV acceptance manifest. The suite is advisory-only and
does not execute Cargo or RCH.

Options:
  --contract-json FILE
  --child-artifacts-json FILE
  --rch-transcript FILE
  --replay-bundle-dir DIR
  --run-lightweight-smokes
  --source-revision REV
  --generated-at-utc TIMESTAMP
  --output-dir DIR
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --contract-json) contract_json="${2:-}"; shift 2 ;;
    --child-artifacts-json) child_artifacts_json="${2:-}"; shift 2 ;;
    --rch-transcript) rch_transcript="${2:-}"; shift 2 ;;
    --replay-bundle-dir) replay_bundle_dir="${2:-}"; shift 2 ;;
    --run-lightweight-smokes) run_lightweight_smokes="true"; shift ;;
    --source-revision) source_revision="${2:-}"; shift 2 ;;
    --generated-at-utc) generated_at_utc="${2:-}"; shift 2 ;;
    --output-dir) run_dir="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown option: %s\n' "$1" >&2; usage; exit 64 ;;
  esac
done

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for IW4 acceptance suite\n' >&2
  exit 2
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse --short HEAD 2>/dev/null || printf unknown)"
fi
if [[ ! -f "$contract_json" ]]; then
  printf 'contract JSON not found: %s\n' "$contract_json" >&2
  exit 64
fi
if ! jq empty "$contract_json" >/dev/null 2>&1; then
  printf 'contract JSON is malformed: %s\n' "$contract_json" >&2
  exit 64
fi
if [[ -n "$child_artifacts_json" ]]; then
  [[ -f "$child_artifacts_json" ]] || { printf 'child artifacts JSON not found: %s\n' "$child_artifacts_json" >&2; exit 64; }
  jq empty "$child_artifacts_json" >/dev/null || { printf 'child artifacts JSON is malformed\n' >&2; exit 64; }
fi
if [[ -n "$rch_transcript" && ! -f "$rch_transcript" ]]; then
  printf 'RCH transcript not found: %s\n' "$rch_transcript" >&2
  exit 64
fi

mkdir -p "$run_dir/step_logs"
manifest="${run_dir}/acceptance_manifest.json"
run_manifest="${run_dir}/run_manifest.json"
events="${run_dir}/events.jsonl"
commands="${run_dir}/commands.txt"
trace_ids="${run_dir}/trace_ids.json"
report_md="${run_dir}/report.md"
expected_artifacts="${run_dir}/expected_child_artifacts.json"
observed_artifacts="${run_dir}/observed_child_artifacts.jsonl"
smoke_results="${run_dir}/lightweight_smoke_results.jsonl"

for artifact_path in "$manifest" "$run_manifest" "$events" "$commands" "$trace_ids" "$report_md" "$expected_artifacts" "$observed_artifacts" "$smoke_results"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

: >"$events"
: >"$observed_artifacts"
: >"$smoke_results"
printf './scripts/idea_wizard_iv_acceptance_suite.sh' >"$commands"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands"
done
printf '\n\n# heavy validation guidance\n' >>"$commands"
printf 'rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_iw4_acceptance CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p frankenengine-engine saturation_convergence\n' >>"$commands"

if [[ -n "$child_artifacts_json" ]]; then
  jq -cS . "$child_artifacts_json" >"$expected_artifacts"
else
  jq -n '[
    {bead_id:"bd-vaths.1", paths:["docs/IDEA_WIZARD_IV_SATURATION_CONVERGENCE.md","docs/idea_wizard_iv_saturation_convergence_v1.json","scripts/e2e/idea_wizard_iv_saturation_convergence_contract_smoke.sh"]},
    {bead_id:"bd-vgj5t", paths:["docs/IDEA_WIZARD_IV_CLOSED_BEAD_PROOF_INTEGRITY.md","scripts/idea_wizard_iv_closed_bead_proof_integrity.sh","scripts/e2e/idea_wizard_iv_closed_bead_proof_integrity_smoke.sh"]},
    {bead_id:"bd-o9wbd", paths:["docs/IDEA_WIZARD_IV_COORDINATION_HEALTH_PACKET.md","scripts/idea_wizard_iv_coordination_health_packet.sh","scripts/e2e/idea_wizard_iv_coordination_health_packet_smoke.sh"]},
    {bead_id:"bd-k53rr", paths:["docs/IDEA_WIZARD_IV_VALIDATION_IMPACT_PLANNER.md","scripts/idea_wizard_iv_validation_impact_planner.sh","scripts/e2e/idea_wizard_iv_validation_impact_planner_smoke.sh"]},
    {bead_id:"bd-my2jw", paths:["docs/IDEA_WIZARD_IV_RESOURCE_PROOF_HEATMAP.md","scripts/idea_wizard_iv_resource_proof_heatmap.sh","scripts/e2e/idea_wizard_iv_resource_proof_heatmap_smoke.sh"]},
    {bead_id:"bd-aqijn", paths:["docs/IDEA_WIZARD_IV_ZERO_READY_SATURATION_DRILL.md","scripts/idea_wizard_iv_zero_ready_saturation_drill.sh","scripts/e2e/idea_wizard_iv_zero_ready_saturation_replay.sh","scripts/e2e/idea_wizard_iv_zero_ready_saturation_drill_smoke.sh"]},
    {bead_id:"bd-ks5p4", paths:["docs/IDEA_WIZARD_IV_OPERATOR_STATUS_TRUTH_GATE.md","scripts/idea_wizard_iv_operator_status_truth_gate.sh","scripts/e2e/idea_wizard_iv_operator_status_truth_gate_replay.sh","scripts/e2e/idea_wizard_iv_operator_status_truth_gate_smoke.sh"]},
    {bead_id:"bd-w06ui", paths:["docs/IDEA_WIZARD_IV_ACCEPTANCE_SUITE.md","scripts/idea_wizard_iv_acceptance_suite.sh","scripts/e2e/idea_wizard_iv_acceptance_suite_smoke.sh"]}
  ]' >"$expected_artifacts"
fi

while IFS=$'\t' read -r bead path; do
  [[ -z "$path" ]] && continue
  if [[ -e "$root_dir/$path" || -e "$path" ]]; then
    present=true
  else
    present=false
  fi
  jq -nc --arg bead_id "$bead" --arg path "$path" --argjson present "$present" '{bead_id:$bead_id,path:$path,present:$present}' >>"$observed_artifacts"
done < <(jq -r '.[] | .bead_id as $bead | (.paths // [])[] | [$bead, .] | @tsv' "$expected_artifacts")

run_smoke() {
  local id="$1"
  shift
  local log_path="${run_dir}/step_logs/${id}.log"
  set +e
  "$@" >"$log_path" 2>&1
  local status=$?
  set -e
  jq -nc --arg id "$id" --arg log_path "$log_path" --arg command "$*" --argjson exit_status "$status" '{id:$id,command:$command,exit_status:$exit_status,log_path:$log_path}' >>"$smoke_results"
}

if [[ "$run_lightweight_smokes" == "true" ]]; then
  run_smoke contract bash "$root_dir/scripts/e2e/idea_wizard_iv_saturation_convergence_contract_smoke.sh" check
  run_smoke closed_bead bash "$root_dir/scripts/e2e/idea_wizard_iv_closed_bead_proof_integrity_smoke.sh" check
  run_smoke coordination bash "$root_dir/scripts/e2e/idea_wizard_iv_coordination_health_packet_smoke.sh" check
  run_smoke validation bash "$root_dir/scripts/e2e/idea_wizard_iv_validation_impact_planner_smoke.sh" check
  run_smoke resource bash "$root_dir/scripts/e2e/idea_wizard_iv_resource_proof_heatmap_smoke.sh" check
  run_smoke zero_ready bash "$root_dir/scripts/e2e/idea_wizard_iv_zero_ready_saturation_drill_smoke.sh" check
  run_smoke operator bash "$root_dir/scripts/e2e/idea_wizard_iv_operator_status_truth_gate_smoke.sh" check
fi

jq -n \
  --slurpfile contract "$contract_json" \
  --slurpfile expected "$expected_artifacts" \
  --slurpfile observed "$observed_artifacts" \
  --slurpfile smoke "$smoke_results" \
  --arg schema_version "franken-engine.idea-wizard-iv-acceptance-manifest.v1" \
  --arg bead_id "$bead_id" \
  --arg source_revision "$source_revision" \
  --arg generated_at_utc "$generated_at_utc" \
  --arg rch_transcript "$rch_transcript" \
  --arg replay_bundle_dir "$replay_bundle_dir" \
  --arg manifest "$manifest" \
  --arg run_manifest "$run_manifest" \
  --arg events "$events" \
  --arg commands "$commands" \
  --arg trace_ids "$trace_ids" \
  --arg report_md "$report_md" '
    def reason($code; $detail; $action): {code:$code,detail:$detail,recommended_action:$action};
    ($contract[0] // {}) as $c
    | ($observed // []) as $obs
    | ($smoke // []) as $smokes
    | ([$obs[]? | select(.present == false)]) as $missing
    | ([$smokes[]? | select(.exit_status != 0)]) as $failed_smokes
    | ([
        if ($missing | length) > 0 then reason("missing_child_artifacts"; "one or more child artifacts are missing"; "Restore or implement missing child artifacts before closing parent.") else empty end,
        if ($failed_smokes | length) > 0 then reason("failed_lightweight_smoke"; "one or more lightweight smoke gates failed"; "Inspect step_logs and fix the failing child surface.") else empty end,
        if (($c.schema_version // "") != "franken-engine.idea-wizard-iv-saturation-convergence.v1") then reason("bad_contract_schema"; "IW4 contract schema is missing or malformed"; "Regenerate the contract JSON.") else empty end
      ]) as $base_failures
    | {
        schema_version:$schema_version,
        bead_id:$bead_id,
        source_revision:$source_revision,
        generated_at_utc:$generated_at_utc,
        child_beads:["bd-vaths.1","bd-vgj5t","bd-o9wbd","bd-k53rr","bd-my2jw","bd-aqijn","bd-ks5p4","bd-w06ui"],
        child_artifacts:$obs,
        validation_commands:(
          (($c.contract_validation_commands // [])
          + [($c.surfaces // [])[]?.validation_commands[]?]
          + ["rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_iw4_acceptance CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p frankenengine-engine saturation_convergence"])
          | unique
          | map({display:., rch_wrapped:(if test("cargo (check|test|clippy|build)") then startswith("rch exec -- env CARGO_TARGET_DIR=") else true end)})
        ),
        lightweight_smokes:$smokes,
        acceptance_decision:(if ($base_failures | length) > 0 then "fail_closed" else "green" end),
        residual_risks:(
          ["Heavy Cargo validation is emitted as RCH guidance and was not executed by this source-only suite."]
          + (if $rch_transcript == "" then ["No RCH transcript was supplied to this acceptance run."] else [] end)
          + (if $replay_bundle_dir == "" then ["No external preserved replay bundle directory was supplied."] else [] end)
        ),
        fail_closed_reasons:$base_failures,
        closeout_instructions:[
          "Run or preserve this acceptance manifest before closing the parent IW4 bead.",
          "If heavy validation is required, use the RCH-wrapped command in commands.txt and reject local fallback.",
          "Do not claim production-wide saturation; report only the preserved bundle decision."
        ],
        mutation_policy:{advisory_only:true,proof_only:true,closes_beads:false,mutates_br:false,runs_cargo:false,runs_rch:false,mutates_git:false},
        rch_policy:{runs_rch:false,emits_commands_only:true,required_heavy_cargo_prefix:"rch exec -- env CARGO_TARGET_DIR="},
        artifact_paths:{acceptance_manifest_json:$manifest,run_manifest_json:$run_manifest,events_jsonl:$events,commands_txt:$commands,trace_ids_json:$trace_ids,report_md:$report_md}
      }
  ' >"$manifest"

if [[ -n "$rch_transcript" ]] && grep -Eiq 'falling back to local|fallback to local|local fallback|running locally|\\[RCH\\] local' "$rch_transcript"; then
  tmp_manifest="${manifest}.local_fallback"
  jq '.acceptance_decision = "fail_closed" | .fail_closed_reasons += [{code:"local_fallback_contamination",detail:"RCH transcript contains local fallback marker",recommended_action:"Discard transcript and rerun remote-only validation."}]' "$manifest" >"$tmp_manifest"
  mv "$tmp_manifest" "$manifest"
fi

jq -n \
  --arg schema_version "franken-engine.idea-wizard-iv-acceptance-suite.run-manifest.v1" \
  --arg bead_id "$bead_id" \
  --arg source_revision "$source_revision" \
  --arg decision "$(jq -r '.acceptance_decision' "$manifest")" \
  --arg manifest "$manifest" \
  '{schema_version:$schema_version,bead_id:$bead_id,source_revision:$source_revision,decision:$decision,artifacts:{acceptance_manifest_json:$manifest}}' >"$run_manifest"
jq -n \
  --arg schema_version "franken-engine.idea-wizard-iv-acceptance-suite.trace-ids.v1" \
  --arg trace_id "iw4-acceptance-${run_id}" \
  --arg bead_id "$bead_id" \
  '{schema_version:$schema_version,trace_id:$trace_id,bead_id:$bead_id}' >"$trace_ids"
jq -c '.fail_closed_reasons[]? | {schema_version:"franken-engine.idea-wizard-iv-acceptance-suite.event.v1",event:"fail_closed_reason",outcome:"fail_closed",code:.code,detail:.detail}' "$manifest" >>"$events"

{
  printf '# IDEA-WIZARD-IV Acceptance Suite\n\n'
  printf -- "- Decision: \`%s\`\n" "$(jq -r '.acceptance_decision' "$manifest")"
  printf -- "- Child artifacts: \`%s\`\n" "$(jq '.child_artifacts | length' "$manifest")"
  printf -- "- Missing artifacts: \`%s\`\n\n" "$(jq '[.child_artifacts[] | select(.present == false)] | length' "$manifest")"
  printf '## Closeout Instructions\n\n'
  jq -r '.closeout_instructions[] | "- " + .' "$manifest"
} >"$report_md"

printf 'acceptance_manifest=%s\n' "$manifest"
if [[ "$(jq -r '.acceptance_decision' "$manifest")" == "fail_closed" ]]; then
  exit 42
fi
