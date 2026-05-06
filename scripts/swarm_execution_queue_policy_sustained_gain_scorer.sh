#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_EXECUTION_QUEUE_POLICY_SUSTAINED_GAIN_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-execution-queue-policy-sustained-gain}"
run_id="${SWARM_EXECUTION_QUEUE_POLICY_SUSTAINED_GAIN_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_EXECUTION_QUEUE_POLICY_SUSTAINED_GAIN_RUN_DIR:-${artifact_root}/${run_id}}"
generated_at="${SWARM_EXECUTION_QUEUE_POLICY_SUSTAINED_GAIN_GENERATED_AT:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
original_args=("$@")

adoption_receipt_json=""
adoption_snapshot_bundle_json=""
post_adoption_fidelity_score_receipt_json=""
post_adoption_drift_ledger_json=""
evidence_ownership_json=""
source_revision=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_execution_queue_policy_sustained_gain_scorer.sh \
  --adoption-receipt-json FILE \
  --adoption-snapshot-bundle-json FILE \
  --post-adoption-fidelity-score-receipt-json FILE \
  --post-adoption-drift-ledger-json FILE \
  --evidence-ownership-json FILE \
  [--source-revision REV] \
  [--output-dir DIR]

Scores whether an adopted execution queue policy sustained its promised benefit
over the receipt observation window. It never mutates br, Agent Mail, remote
workers, live queue settings, or historical outcomes.

Exit codes:
  0  scoring completed; verdict may be sustained, regression, or inconclusive
  42 fail-closed due to incomplete observation or ambiguous ownership evidence
  64 usage or missing tool/file errors
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --adoption-receipt-json)
      adoption_receipt_json="${2:-}"
      shift 2
      ;;
    --adoption-snapshot-bundle-json)
      adoption_snapshot_bundle_json="${2:-}"
      shift 2
      ;;
    --post-adoption-fidelity-score-receipt-json)
      post_adoption_fidelity_score_receipt_json="${2:-}"
      shift 2
      ;;
    --post-adoption-drift-ledger-json)
      post_adoption_drift_ledger_json="${2:-}"
      shift 2
      ;;
    --evidence-ownership-json)
      evidence_ownership_json="${2:-}"
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
    -h|--help)
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

for required_arg in \
  "$adoption_receipt_json" \
  "$adoption_snapshot_bundle_json" \
  "$post_adoption_fidelity_score_receipt_json" \
  "$post_adoption_drift_ledger_json" \
  "$evidence_ownership_json"; do
  if [[ -z "$required_arg" ]]; then
    printf 'all required sustained-gain inputs must be provided\n' >&2
    usage
    exit 64
  fi
done

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for sustained-gain scoring\n' >&2
  exit 64
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for sustained-gain scoring\n' >&2
  exit 64
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
receipt_path="${run_dir}/sustained_gain_receipt.json"
ledger_path="${run_dir}/post_adoption_drift_ledger.json"
evidence_hashes_path="${run_dir}/evidence_hashes.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
core_path="${run_dir}/sustained_gain.core.json"

adoption_normalized="${run_dir}/adoption_receipt.normalized.json"
snapshot_normalized="${run_dir}/adoption_snapshot_bundle.normalized.json"
fidelity_normalized="${run_dir}/post_adoption_fidelity_score_receipt.normalized.json"
drift_normalized="${run_dir}/post_adoption_drift_ledger.normalized.json"
ownership_normalized="${run_dir}/evidence_ownership.normalized.json"

printf './scripts/swarm_execution_queue_policy_sustained_gain_scorer.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"
: >"$events_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-execution-queue-policy-sustained-gain.event.v1" \
    --arg event_name "$1" \
    --arg detail "$2" \
    --arg source_revision "$source_revision" \
    '{schema_version:$schema_version,event_name:$event_name,detail:$detail,source_revision:$source_revision}' >>"$events_path"
}

json_input() {
  local path="$1"
  local output_path="$2"
  local label="$3"

  if [[ ! -f "$path" ]]; then
    printf 'required sustained-gain input not found: %s\n' "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf 'required sustained-gain input is not valid JSON: %s\n' "$path" >&2
    exit 64
  fi
  jq -cS . "$path" >"$output_path"
  write_event "input.loaded" "$label"
}

json_input "$adoption_receipt_json" "$adoption_normalized" "adoption_receipt_json"
json_input "$adoption_snapshot_bundle_json" "$snapshot_normalized" "adoption_snapshot_bundle_json"
json_input "$post_adoption_fidelity_score_receipt_json" "$fidelity_normalized" "post_adoption_fidelity_score_receipt_json"
json_input "$post_adoption_drift_ledger_json" "$drift_normalized" "post_adoption_drift_ledger_json"
json_input "$evidence_ownership_json" "$ownership_normalized" "evidence_ownership_json"

adoption_sha="$(sha256sum "$adoption_receipt_json" | awk '{print $1}')"
snapshot_sha="$(sha256sum "$adoption_snapshot_bundle_json" | awk '{print $1}')"
fidelity_sha="$(sha256sum "$post_adoption_fidelity_score_receipt_json" | awk '{print $1}')"
drift_sha="$(sha256sum "$post_adoption_drift_ledger_json" | awk '{print $1}')"
ownership_sha="$(sha256sum "$evidence_ownership_json" | awk '{print $1}')"

jq -n \
  --arg source_revision "$source_revision" \
  --arg generated_at "$generated_at" \
  --arg adoption_receipt_json "$adoption_receipt_json" \
  --arg adoption_snapshot_bundle_json "$adoption_snapshot_bundle_json" \
  --arg post_adoption_fidelity_score_receipt_json "$post_adoption_fidelity_score_receipt_json" \
  --arg post_adoption_drift_ledger_json "$post_adoption_drift_ledger_json" \
  --arg evidence_ownership_json "$evidence_ownership_json" \
  --arg receipt_path "$receipt_path" \
  --arg ledger_path "$ledger_path" \
  --arg evidence_hashes_path "$evidence_hashes_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --arg adoption_sha "$adoption_sha" \
  --arg snapshot_sha "$snapshot_sha" \
  --arg fidelity_sha "$fidelity_sha" \
  --arg drift_sha "$drift_sha" \
  --arg ownership_sha "$ownership_sha" \
  --slurpfile adoption "$adoption_normalized" \
  --slurpfile snapshot "$snapshot_normalized" \
  --slurpfile fidelity "$fidelity_normalized" \
  --slurpfile drift "$drift_normalized" \
  --slurpfile ownership "$ownership_normalized" \
  '
    def nonempty($value): (($value // "") | length) > 0;
    def bad($kind; $source; $label; $detail): {kind:$kind,source:$source,label:$label,detail:$detail};
    def evidence($kind; $path; $sha): {artifact_kind:$kind,path:$path,sha256:$sha};
    def clamp_millionths($n): if $n < 0 then 0 elif $n > 1000000 then 1000000 else $n end;
    def half_delta_floor($baseline; $delta): clamp_millionths($baseline + (($delta / 2) | floor));
    def unsafe_claim($doc):
      (($doc.automation_claim // "none") | test("automatic|automatically|live retuning|changes active queue|proves sustained gain"))
      or (($doc.sustained_gain_claim // false) == true);
    def rollback_drift($row):
      (($row.drift_class // "") | IN("proof_drift", "ownership_drift", "restore_drift"))
      or (($row.mismatch_class // "") | IN("proof_brownout_miss", "stale_owner_miss", "contradictory_evidence"));

    ($adoption[0]) as $adoption_doc
    | ($snapshot[0]) as $snapshot_doc
    | ($fidelity[0]) as $fidelity_doc
    | ($drift[0]) as $drift_doc
    | ($ownership[0]) as $ownership_doc
    | ($adoption_doc.adopted_policy_bundle_id // "") as $bundle_id
    | ($adoption_doc.adopted_candidate.candidate_id // "") as $candidate_id
    | ($snapshot_doc.normalized_inputs.rollback_comparator_receipt.current_fidelity_millionths // $snapshot_doc.normalized_inputs.current_policy_state.current_policy_metrics.overall_fidelity_millionths // 0) as $baseline_fidelity
    | ($adoption_doc.adopted_candidate.expected_fidelity_delta_millionths // 0) as $promised_delta
    | (half_delta_floor($baseline_fidelity; $promised_delta)) as $sustained_floor
    | ($fidelity_doc.overall_fidelity_millionths // 0) as $observed_fidelity
    | (($fidelity_doc.summary.row_count // 0) as $row_count | $row_count) as $sample_count
    | ($adoption_doc.observation_window.minimum_sample_count // 0) as $minimum_sample_count
    | ($adoption_doc.observation_window.duration_seconds // 0) as $window_seconds
    | ($adoption_doc.observation_window.monitored_metrics // []) as $monitored_metrics
    | ($drift_doc.rows // []) as $drift_rows
    | ([$drift_rows[]? | select(rollback_drift(.))]) as $rollback_rows
    | ($ownership_doc.rows // []) as $ownership_rows
    | ["adoption_receipt_json","adoption_snapshot_bundle_json","post_adoption_fidelity_score_receipt_json","post_adoption_drift_ledger_json"] as $required_owner_kinds
    | [
        (if (($adoption_doc.schema_version // "") != "franken-engine.swarm-execution-queue-policy-adoption-receipt.v1") then bad("bad_schema";"adoption_receipt_json";"schema_version";"unexpected adoption receipt schema") else empty end),
        (if (($snapshot_doc.schema_version // "") != "franken-engine.swarm-execution-queue-policy-adoption-snapshot-bundle.v1") then bad("bad_schema";"adoption_snapshot_bundle_json";"schema_version";"unexpected adoption snapshot schema") else empty end),
        (if (($fidelity_doc.schema_version // "") != "franken-engine.swarm-execution-queue-fidelity-score-receipt.v1") then bad("bad_schema";"post_adoption_fidelity_score_receipt_json";"schema_version";"unexpected fidelity receipt schema") else empty end),
        (if (($drift_doc.schema_version // "") != "franken-engine.swarm-execution-queue-drift-ledger.v1") then bad("bad_schema";"post_adoption_drift_ledger_json";"schema_version";"unexpected drift ledger schema") else empty end),
        (if (($ownership_doc.schema_version // "") != "franken-engine.swarm-execution-queue-policy-evidence-ownership.v1") then bad("bad_schema";"evidence_ownership_json";"schema_version";"unexpected evidence ownership schema") else empty end),
        (if (($adoption_doc.decision // "") == "admitted") then empty else bad("adoption_not_admitted";"adoption_receipt_json";"decision";"adoption receipt must be admitted before sustained-gain scoring") end),
        (if (($snapshot_doc.decision // "") == "admitted") then empty else bad("snapshot_not_admitted";"adoption_snapshot_bundle_json";"decision";"adoption snapshot must be admitted before sustained-gain scoring") end),
        (if (($fidelity_doc.decision // "") == "fail_closed" or ($drift_doc.decision // "") == "fail_closed") then bad("upstream_fail_closed";"post_adoption_fidelity_score_receipt_json";"decision";"post-adoption fidelity evidence already failed closed") else empty end),
        (if ($window_seconds >= 1800 and (($adoption_doc.observation_window.stop_on_missing_evidence // false) == true) and nonempty($adoption_doc.observation_window.starts_at)) then empty else bad("incomplete_observation_window";"adoption_receipt_json";"observation_window";"observation window is incomplete or too small") end),
        (if ($sample_count >= $minimum_sample_count and $sample_count >= 3) then empty else bad("insufficient_sample_count";"post_adoption_fidelity_score_receipt_json";"summary.row_count";"post-adoption samples do not satisfy the adoption receipt minimum") end),
        (if (($monitored_metrics | index("queue_fidelity_millionths")) != null and ($monitored_metrics | index("proof_drift_count")) != null and ($monitored_metrics | index("rollback_trigger_count")) != null) then empty else bad("missing_monitored_metrics";"adoption_receipt_json";"observation_window.monitored_metrics";"required monitored metrics are missing") end),
        (if (($snapshot_doc.adopted_policy_bundle_id // "") == $bundle_id and ($snapshot_doc.candidate_id // "") == $candidate_id) then empty else bad("adoption_snapshot_mismatch";"adoption_snapshot_bundle_json";$bundle_id;"snapshot bundle/candidate identity does not match adoption receipt") end),
        (if all($required_owner_kinds[]; . as $kind | any($ownership_rows[]?; (.artifact_kind // "") == $kind)) then empty else bad("missing_evidence_ownership";"evidence_ownership_json";"rows";"required artifact ownership rows are missing") end),
        ([ $ownership_rows[]? | select((.ambiguous_owner // false) == true or ((.owners // []) | length) != 1) | bad("ambiguous_evidence_ownership";"evidence_ownership_json";(.artifact_kind // "unknown");"evidence ownership is ambiguous") ][]?),
        ([ $ownership_rows[]? | select((.freshness_state // "fresh") != "fresh" or (.trust_state // "accepted") != "accepted") | bad("stale_or_rejected_evidence_ownership";"evidence_ownership_json";(.artifact_kind // "unknown");"evidence ownership row is stale or rejected") ][]?),
        (if unsafe_claim($adoption_doc) or unsafe_claim($snapshot_doc) or unsafe_claim($fidelity_doc) or unsafe_claim($drift_doc) or unsafe_claim($ownership_doc) then bad("unsafe_input_claim";"inputs";"automation_claim";"inputs must not claim automatic retuning or sustained gain") else empty end)
      ] as $fail_closed_reasons
    | (if ($fail_closed_reasons | length) > 0 then "fail_closed"
       elif (($rollback_rows | length) > 0) or ($observed_fidelity < $baseline_fidelity) then "regression_detected"
       elif ($observed_fidelity >= $sustained_floor) then "sustained_gain"
       else "inconclusive_drift"
       end) as $verdict
    | [
        evidence("adoption_receipt_json"; $adoption_receipt_json; $adoption_sha),
        evidence("adoption_snapshot_bundle_json"; $adoption_snapshot_bundle_json; $snapshot_sha),
        evidence("post_adoption_fidelity_score_receipt_json"; $post_adoption_fidelity_score_receipt_json; $fidelity_sha),
        evidence("post_adoption_drift_ledger_json"; $post_adoption_drift_ledger_json; $drift_sha),
        evidence("evidence_ownership_json"; $evidence_ownership_json; $ownership_sha)
      ] as $evidence_links
    | {
        evidence_hashes:{
          schema_version:"franken-engine.swarm-execution-queue-policy-sustained-gain-evidence-hashes.v1",
          source_revision:$source_revision,
          evidence_links:$evidence_links
        },
        sustained_gain_receipt:{
          schema_version:"franken-engine.swarm-execution-queue-policy-sustained-gain-receipt.v1",
          sustained_gain_receipt_id:"pending",
          source_revision:$source_revision,
          generated_at:$generated_at,
          verdict:$verdict,
          adopted_policy_bundle_id:$bundle_id,
          adoption_receipt_id:($adoption_doc.adoption_receipt_id // ""),
          candidate_id:$candidate_id,
          baseline_fidelity_millionths:$baseline_fidelity,
          promised_delta_millionths:$promised_delta,
          sustained_floor_millionths:$sustained_floor,
          observed_fidelity_millionths:$observed_fidelity,
          sample_count:$sample_count,
          observation_window:$adoption_doc.observation_window,
          rollback_drift_count:($rollback_rows | length),
          fail_closed_reasons:$fail_closed_reasons,
          evidence_links:$evidence_links,
          mutation_policy:{
            scoring_artifact_only:true,
            changes_active_queue:false,
            applies_live_retuning:false,
            mutates_br:false,
            sends_agent_mail:false,
            mutates_remote_workers:false,
            rewrites_historical_outcomes:false
          },
          artifact_paths:{
            sustained_gain_receipt_json:$receipt_path,
            post_adoption_drift_ledger_json:$ledger_path,
            evidence_hashes_json:$evidence_hashes_path,
            events_jsonl:$events_path,
            commands_txt:$commands_path,
            report_md:$report_path
          }
        },
        post_adoption_drift_ledger:{
          schema_version:"franken-engine.swarm-execution-queue-post-adoption-drift-ledger.v1",
          source_revision:$source_revision,
          generated_at:$generated_at,
          verdict:$verdict,
          adopted_policy_bundle_id:$bundle_id,
          adoption_receipt_id:($adoption_doc.adoption_receipt_id // ""),
          candidate_id:$candidate_id,
          drift_rows:($drift_rows | map({
            task_id:(.task_id // "unknown"),
            drift_class:(.drift_class // "unknown"),
            mismatch_class:(.mismatch_class // "unknown"),
            row_score_millionths:(.row_score_millionths // 0),
            rollback_relevant:rollback_drift(.),
            remediation:(.remediation // "inspect post-adoption row before trusting score")
          }) | sort_by(.task_id, .drift_class, .mismatch_class)),
          ownership_rows:($ownership_rows | map({
            artifact_kind:(.artifact_kind // "unknown"),
            owner:(.owners[0] // .owner // "unknown"),
            trust_state:(.trust_state // "unknown"),
            freshness_state:(.freshness_state // "unknown"),
            ambiguous_owner:(.ambiguous_owner // false)
          }) | sort_by(.artifact_kind)),
          fail_closed_reasons:$fail_closed_reasons,
          evidence_links:$evidence_links,
          mutation_policy:{
            scoring_artifact_only:true,
            changes_active_queue:false,
            applies_live_retuning:false,
            mutates_br:false,
            sends_agent_mail:false,
            mutates_remote_workers:false,
            rewrites_historical_outcomes:false
          }
        }
      }
  ' >"$core_path"

jq '.evidence_hashes' "$core_path" >"$evidence_hashes_path"
jq '.sustained_gain_receipt' "$core_path" >"$receipt_path"
jq '.post_adoption_drift_ledger' "$core_path" >"$ledger_path"

receipt_id="queue-policy-sustained-gain-$(jq -cS 'del(.sustained_gain_receipt_id)' "$receipt_path" | sha256sum | awk '{print $1}' | cut -c1-16)"
tmp_receipt="${receipt_path}.tmp"
jq --arg receipt_id "$receipt_id" '.sustained_gain_receipt_id = $receipt_id' "$receipt_path" >"$tmp_receipt"
mv "$tmp_receipt" "$receipt_path"

write_event "sustained_gain.written" "$(jq -r '.verdict + " / bundle=" + .adopted_policy_bundle_id + " / receipt=" + .sustained_gain_receipt_id' "$receipt_path")"

{
  printf '# Swarm Execution Queue Policy Sustained Gain\n\n'
  printf -- "- Verdict: \`%s\`\n" "$(jq -r '.verdict' "$receipt_path")"
  printf -- "- Receipt: \`%s\`\n" "$(jq -r '.sustained_gain_receipt_id' "$receipt_path")"
  printf -- "- Bundle: \`%s\`\n" "$(jq -r '.adopted_policy_bundle_id' "$receipt_path")"
  printf -- "- Candidate: \`%s\`\n" "$(jq -r '.candidate_id' "$receipt_path")"
  printf -- "- Observed fidelity: \`%s\`\n" "$(jq '.observed_fidelity_millionths' "$receipt_path")"
  printf -- "- Sustained floor: \`%s\`\n" "$(jq '.sustained_floor_millionths' "$receipt_path")"
  printf -- "- Rollback drift rows: \`%s\`\n" "$(jq '.rollback_drift_count' "$receipt_path")"
  printf -- "- Fail-closed reasons: \`%s\`\n\n" "$(jq '.fail_closed_reasons | length' "$receipt_path")"
  if [[ "$(jq '.fail_closed_reasons | length' "$receipt_path")" -ne 0 ]]; then
    printf '## Fail-Closed Reasons\n'
    jq -r '.fail_closed_reasons[] | "- `" + .kind + "` `" + .label + "`: " + .detail' "$receipt_path"
    printf '\n'
  fi
  printf '## Post-Adoption Drift Rows\n'
  jq -r '.drift_rows[]? | "- `" + .task_id + "` `" + .drift_class + "` rollback=`" + (.rollback_relevant | tostring) + "`: " + .remediation' "$ledger_path"
} >"$report_path"

printf 'sustained_gain_receipt_json=%s\n' "$receipt_path"
printf 'post_adoption_drift_ledger_json=%s\n' "$ledger_path"
printf 'sustained_gain_evidence_hashes_json=%s\n' "$evidence_hashes_path"
printf 'sustained_gain_report_md=%s\n' "$report_path"

if [[ "$(jq -r '.verdict' "$receipt_path")" == "fail_closed" ]]; then
  exit 42
fi
exit 0
