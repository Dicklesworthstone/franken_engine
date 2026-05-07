#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_AUTOPILOT_OPERATOR_INTENT_POLICY_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-autopilot-operator-intent-policy}"
run_id="${SWARM_AUTOPILOT_OPERATOR_INTENT_POLICY_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_AUTOPILOT_OPERATOR_INTENT_POLICY_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

intent_json=""
evidence_warehouse_json=""
forecaster_json=""
source_revision="${SWARM_AUTOPILOT_OPERATOR_INTENT_POLICY_SOURCE_REVISION:-}"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_autopilot_operator_intent_policy.sh [OPTIONS]

Compiles declarative swarm-operator intents into deterministic, verifiable
policy JSON. The compiler is advisory and proof-only: it does not mutate beads,
send Agent Mail, run Cargo or RCH, release reservations, or change live queue
policy.

Required:
  --intent-json FILE
  --evidence-warehouse-json FILE
  --forecaster-json FILE

Optional:
  --source-revision REV
  --output-dir DIR

Artifacts:
  operator_intent_policy.json
  verification_report.json
  counterexamples.json
  run_manifest.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0   policy emitted with pass or safe_mode decision
  42  fail-closed policy conflict or stale evidence
  64  invalid option or malformed input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --intent-json)
      intent_json="${2:-}"
      shift 2
      ;;
    --evidence-warehouse-json)
      evidence_warehouse_json="${2:-}"
      shift 2
      ;;
    --forecaster-json)
      forecaster_json="${2:-}"
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

if [[ -z "$intent_json" || -z "$evidence_warehouse_json" || -z "$forecaster_json" ]]; then
  printf 'intent JSON, evidence warehouse JSON, and forecaster JSON are required\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm autopilot operator intent policy compiler\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for swarm autopilot operator intent policy compiler\n' >&2
  exit 2
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
policy_path="${run_dir}/operator_intent_policy.json"
verification_path="${run_dir}/verification_report.json"
counterexamples_path="${run_dir}/counterexamples.json"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
core_path="${run_dir}/operator_intent_policy.core.json"
hash_basis_path="${run_dir}/operator_intent_policy.hash_basis.json"
intent_normalized="${run_dir}/intent.normalized.json"
warehouse_normalized="${run_dir}/evidence_warehouse.normalized.json"
forecaster_normalized="${run_dir}/forecaster.normalized.json"

: >"$events_path"
printf './scripts/swarm_autopilot_operator_intent_policy.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-autopilot-operator-intent-policy.event.v1" \
    --arg component "swarm_autopilot_operator_intent_policy" \
    --arg event "$1" \
    --arg outcome "$2" \
    --arg detail "$3" \
    --arg evidence_path "$4" \
    '{schema_version:$schema_version,component:$component,event:$event,outcome:$outcome,detail:$detail,evidence_path:$evidence_path}' \
    >>"$events_path"
}

normalize_required_json() {
  local input="$1"
  local output="$2"
  local label="$3"
  if [[ ! -f "$input" ]]; then
    printf 'missing %s JSON: %s\n' "$label" "$input" >&2
    exit 64
  fi
  if ! jq empty "$input" >/dev/null 2>&1; then
    printf 'invalid %s JSON: %s\n' "$label" "$input" >&2
    exit 64
  fi
  jq -cS . "$input" >"$output"
  write_event "input.loaded" "ok" "$label" "$input"
}

sha_file() {
  local path="$1"
  sha256sum "$path" | awk '{print $1}'
}

normalize_required_json "$intent_json" "$intent_normalized" "intent"
normalize_required_json "$evidence_warehouse_json" "$warehouse_normalized" "evidence warehouse"
normalize_required_json "$forecaster_json" "$forecaster_normalized" "forecaster"

jq -n \
  --slurpfile intent "$intent_normalized" \
  --slurpfile warehouse "$warehouse_normalized" \
  --slurpfile forecaster "$forecaster_normalized" \
  --arg source_revision "$source_revision" \
  --arg run_id "$run_id" \
  --arg intent_json "$intent_json" \
  --arg evidence_warehouse_json "$evidence_warehouse_json" \
  --arg forecaster_json "$forecaster_json" \
  --arg policy_path "$policy_path" \
  --arg verification_path "$verification_path" \
  --arg counterexamples_path "$counterexamples_path" \
  --arg manifest_path "$manifest_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" '
  def first_intent($intents; $type): ([$intents[]? | select(.intent_type == $type)] | .[0] // {});
  def has_intent($intents; $type): any($intents[]?; .intent_type == $type);
  def reason($code; $source; $detail; $remediation): {
    code:$code,
    source_id:$source,
    detail:$detail,
    remediation_text:$remediation
  };
  def counterexample($id; $kind; $inputs; $violation; $remediation): {
    counterexample_id:$id,
    code:"FE-SWARM-AUTOPILOT-POLICY-CONFLICT",
    kind:$kind,
    inputs:$inputs,
    observed_violation:$violation,
    remediation_text:$remediation
  };

  ($intent[0]) as $intent_doc
  | ($warehouse[0]) as $warehouse_doc
  | ($forecaster[0]) as $forecaster_doc
  | ($intent_doc.intents // []) as $intents
  | (($intent_doc.max_evidence_age_seconds // 900) | tonumber) as $max_evidence_age
  | ((first_intent($intents; "reserve_urgent_rch_slack").min_free_rch_slots // 1) | tonumber) as $min_free_rch_slots
  | ((first_intent($intents; "cap_nonurgent_heavy_fanout").max_nonurgent_heavy_lanes // 2) | tonumber) as $max_nonurgent_heavy_lanes
  | ((first_intent($intents; "protect_p1_latency").max_p1_latency_ms // 500) | tonumber) as $max_p1_latency_ms
  | ((first_intent($intents; "prefer_warm_cache_reuse").min_confidence_millionths // 700000) | tonumber) as $warm_cache_min_confidence_millionths
  | ((first_intent($intents; "bound_per_agent_fairness_skew").max_heavy_lanes_per_agent // 1) | tonumber) as $max_heavy_lanes_per_agent
  | ((first_intent($intents; "safe_mode_on_degraded").brownout_probability_millionths // 800000) | tonumber) as $safe_mode_brownout_probability_millionths
  | ((first_intent($intents; "avoid_drained_or_probe_workers").enabled // has_intent($intents; "avoid_drained_or_probe_workers")) == true) as $avoid_drained_or_probe_workers
  | (has_intent($intents; "safe_mode_on_degraded")) as $safe_mode_requested
  | (($warehouse_doc.run_identity.age_seconds // $warehouse_doc.freshness.age_seconds // 0) | tonumber) as $warehouse_age_seconds
  | (($forecaster_doc.forecast_age_seconds // $forecaster_doc.freshness.age_seconds // 0) | tonumber) as $forecaster_age_seconds
  | (($forecaster_doc.resource_limits.remote_rch_slots // $forecaster_doc.capacity.remote_rch_slots // 0) | tonumber) as $remote_rch_slots
  | (($forecaster_doc.predictions.p1_latency_ms // $forecaster_doc.predicted_p1_latency_ms // 0) | tonumber) as $predicted_p1_latency_ms
  | (($forecaster_doc.predictions.brownout_probability_millionths // $forecaster_doc.brownout_probability_millionths // 0) | tonumber) as $brownout_probability_millionths
  | ($forecaster_doc.worker_state.drained_worker_ids // []) as $drained_worker_ids
  | ($forecaster_doc.worker_state.probe_required_worker_ids // []) as $probe_required_worker_ids
  | ([
      if (($intent_doc.schema_version // "") != "franken-engine.swarm-autopilot-operator-intents.v1") then reason("FE-SWARM-AUTOPILOT-POLICY-SCHEMA-DRIFT"; "intent_json"; "operator intents schema is unexpected"; "Regenerate the intent bundle with schema franken-engine.swarm-autopilot-operator-intents.v1.") else empty end,
      if (($warehouse_doc.schema_version // "") != "franken-engine.swarm-autopilot-evidence-warehouse.v1") then reason("FE-SWARM-AUTOPILOT-POLICY-SCHEMA-DRIFT"; "evidence_warehouse_json"; "evidence warehouse schema is unexpected"; "Regenerate the warehouse with scripts/swarm_autopilot_evidence_warehouse.sh.") else empty end,
      if (($forecaster_doc.schema_version // "") != "franken-engine.swarm-autopilot-brownout-forecaster.v1") then reason("FE-SWARM-AUTOPILOT-POLICY-SCHEMA-DRIFT"; "forecaster_json"; "forecaster schema is unexpected"; "Regenerate the brownout forecaster bundle before compiling policy.") else empty end,
      if (($warehouse_doc.decision // "") != "pass") then reason("FE-SWARM-AUTOPILOT-POLICY-STALE-EVIDENCE"; "evidence_warehouse_json"; "evidence warehouse is not pass and cannot authorize policy influence"; "Refresh SWARM-OPS evidence and rerun the evidence warehouse.") else empty end,
      if ($warehouse_age_seconds > $max_evidence_age) then reason("FE-SWARM-AUTOPILOT-POLICY-STALE-EVIDENCE"; "evidence_warehouse_json"; "evidence warehouse age exceeds policy freshness bound"; "Refresh SWARM-OPS evidence and rerun the evidence warehouse.") else empty end,
      if ($forecaster_age_seconds > $max_evidence_age) then reason("FE-SWARM-AUTOPILOT-POLICY-STALE-EVIDENCE"; "forecaster_json"; "forecaster age exceeds policy freshness bound"; "Refresh the brownout forecaster before compiling policy.") else empty end,
      if (($forecaster_doc.decision // "") == "fail_closed") then reason("FE-SWARM-AUTOPILOT-POLICY-STALE-EVIDENCE"; "forecaster_json"; "forecaster is fail-closed"; "Repair forecaster inputs before policy can influence recommendations.") else empty end
    ] | unique_by([.code, .source_id, .detail])) as $failure_reasons
  | ([
      if ($remote_rch_slots > 0 and (($min_free_rch_slots + $max_nonurgent_heavy_lanes) > $remote_rch_slots)) then
        counterexample(
          "ce-rch-slack-vs-heavy-fanout";
          "reserve_urgent_rch_slack_vs_cap_nonurgent_heavy_fanout";
          {remote_rch_slots:$remote_rch_slots,min_free_rch_slots:$min_free_rch_slots,max_nonurgent_heavy_lanes:$max_nonurgent_heavy_lanes};
          "reserved urgent slack plus nonurgent heavy fanout exceeds remote RCH slot capacity";
          "Lower max_nonurgent_heavy_lanes or reserve fewer urgent RCH slots."
        )
      else empty end,
      if ($remote_rch_slots > 0 and $max_p1_latency_ms <= 250 and $predicted_p1_latency_ms > $max_p1_latency_ms and $max_nonurgent_heavy_lanes >= ($remote_rch_slots - $min_free_rch_slots)) then
        counterexample(
          "ce-p1-latency-vs-utilization";
          "protect_p1_latency_vs_utilization";
          {predicted_p1_latency_ms:$predicted_p1_latency_ms,max_p1_latency_ms:$max_p1_latency_ms,max_nonurgent_heavy_lanes:$max_nonurgent_heavy_lanes,remote_rch_slots:$remote_rch_slots,min_free_rch_slots:$min_free_rch_slots};
          "strict P1 latency target conflicts with saturating nonurgent heavy fanout";
          "Raise the P1 latency bound or lower nonurgent heavy fanout."
        )
      else empty end
    ] | unique_by(.counterexample_id)) as $counterexamples
  | ($safe_mode_requested and (($forecaster_doc.decision // "") == "warn" or $brownout_probability_millionths >= $safe_mode_brownout_probability_millionths)) as $safe_mode_active
  | (if ($failure_reasons | length) > 0 then "fail_closed" elif ($counterexamples | length) > 0 then "fail_closed" elif $safe_mode_active then "safe_mode" else "pass" end) as $decision
  | (if has_intent($intents; "bound_per_agent_fairness_skew") then
      ["bound_per_agent_fairness_skew","reserve_urgent_rch_slack","protect_p1_latency","avoid_drained_or_probe_workers","cap_nonurgent_heavy_fanout","prefer_warm_cache_reuse","safe_mode_on_degraded"]
    else
      ["reserve_urgent_rch_slack","protect_p1_latency","avoid_drained_or_probe_workers","cap_nonurgent_heavy_fanout","prefer_warm_cache_reuse","safe_mode_on_degraded"]
    end) as $precedence_order
  | {
      compiled_policy:{
        schema_version:"franken-engine.swarm-autopilot-operator-intent-policy.v1",
        source_revision:$source_revision,
        run_id:$run_id,
        decision:$decision,
        thresholds:{
          min_free_rch_slots:$min_free_rch_slots,
          max_nonurgent_heavy_lanes:$max_nonurgent_heavy_lanes,
          max_p1_latency_ms:$max_p1_latency_ms,
          warm_cache_min_confidence_millionths:$warm_cache_min_confidence_millionths,
          max_heavy_lanes_per_agent:$max_heavy_lanes_per_agent,
          safe_mode_brownout_probability_millionths:$safe_mode_brownout_probability_millionths
        },
        precedence_order:$precedence_order,
        fallback_behavior:{
          mode:(if $decision == "safe_mode" then "safe_mode" elif $decision == "fail_closed" then "no_policy_influence" else "normal" end),
          actions:(if $decision == "safe_mode" then ["defer_nonurgent_heavy_lanes","preserve_urgent_rch_slack","require_remote_only_evidence"] elif $decision == "fail_closed" then ["do_not_influence_recommendations","emit_counterexamples"] else ["apply_compiled_thresholds"] end),
          deterministic:true
        },
        worker_policy:{
          avoid_drained_or_probe_workers:$avoid_drained_or_probe_workers,
          drained_worker_ids:$drained_worker_ids,
          probe_required_worker_ids:$probe_required_worker_ids
        },
        conflict_diagnostics:$counterexamples,
        verification_summary:{
          evidence_warehouse_decision:($warehouse_doc.decision // "unknown"),
          forecaster_decision:($forecaster_doc.decision // "unknown"),
          brownout_probability_millionths:$brownout_probability_millionths,
          predicted_p1_latency_ms:$predicted_p1_latency_ms,
          failure_reason_count:($failure_reasons | length),
          conflict_count:($counterexamples | length),
          safe_mode_active:$safe_mode_active
        },
        artifact_paths:{
          policy_json:$policy_path,
          verification_report_json:$verification_path,
          counterexamples_json:$counterexamples_path,
          run_manifest_json:$manifest_path,
          events_jsonl:$events_path,
          commands_txt:$commands_path,
          report_md:$report_path,
          intent_json:$intent_json,
          evidence_warehouse_json:$evidence_warehouse_json,
          forecaster_json:$forecaster_json
        },
        mutation_policy:{
          advisory_only:true,
          proof_only:true,
          fixture_fed_only:true,
          mutates_br:false,
          reassigns_beads:false,
          releases_reservations:false,
          sends_agent_mail:false,
          runs_cargo:false,
          runs_rch:false,
          mutates_remote_workers:false,
          changes_live_queue_policy:false,
          pins_workers_automatically:false,
          writes_outside_output_dir:false
        }
      },
      verification_report:{
        schema_version:"franken-engine.swarm-autopilot-operator-intent-policy-verification.v1",
        bead_id:"bd-7dr9z",
        decision:$decision,
        failure_reasons:$failure_reasons,
        conflict_diagnostics:$counterexamples,
        safe_mode_reason:(if $safe_mode_active then reason("FE-SWARM-AUTOPILOT-POLICY-SAFE-MODE"; "forecaster_json"; "forecaster is degraded or brownout probability exceeds safe-mode threshold"; "Keep recommendations advisory and defer nonurgent heavy lanes until forecaster returns pass.") else null end),
        source_schemas:{
          intent:($intent_doc.schema_version // "missing"),
          evidence_warehouse:($warehouse_doc.schema_version // "missing"),
          forecaster:($forecaster_doc.schema_version // "missing")
        }
      },
      counterexamples:{
        schema_version:"franken-engine.swarm-autopilot-operator-intent-counterexamples.v1",
        bead_id:"bd-7dr9z",
        counterexamples:$counterexamples
      }
    }' >"$core_path"

jq 'del(.compiled_policy.run_id, .compiled_policy.artifact_paths)' "$core_path" | jq -cS . >"$hash_basis_path"
policy_hash="$(sha_file "$hash_basis_path")"
policy_id="opip-${policy_hash:0:16}"

jq --arg policy_id "$policy_id" --arg policy_hash "$policy_hash" \
  '.compiled_policy + {policy_id:$policy_id, policy_hash:$policy_hash}' "$core_path" >"$policy_path"
jq '.verification_report' "$core_path" >"$verification_path"
jq '.counterexamples' "$core_path" >"$counterexamples_path"
decision="$(jq -r '.decision' "$policy_path")"

jq -n \
  --arg schema_version "franken-engine.swarm-autopilot-operator-intent-policy-run-manifest.v1" \
  --arg bead_id "bd-7dr9z" \
  --arg run_id "$run_id" \
  --arg source_revision "$source_revision" \
  --arg decision "$decision" \
  --arg policy_id "$policy_id" \
  --arg policy_hash "$policy_hash" \
  --arg policy_path "$policy_path" \
  --arg verification_path "$verification_path" \
  --arg counterexamples_path "$counterexamples_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  '{
    schema_version:$schema_version,
    bead_id:$bead_id,
    run_id:$run_id,
    source_revision:$source_revision,
    decision:$decision,
    policy_id:$policy_id,
    policy_hash:$policy_hash,
    artifact_paths:{
      policy_json:$policy_path,
      verification_report_json:$verification_path,
      counterexamples_json:$counterexamples_path,
      events_jsonl:$events_path,
      commands_txt:$commands_path
    }
  }' >"$manifest_path"

{
  printf '# Swarm Autopilot Operator Intent Policy\n'
  printf '\n'
  printf -- "- policy_id: \`%s\`\n" "$policy_id"
  printf -- "- decision: \`%s\`\n" "$decision"
  printf -- "- policy_hash: \`%s\`\n" "$policy_hash"
  printf -- "- conflict_count: \`%s\`\n" "$(jq '.counterexamples | length' "$counterexamples_path")"
  if [[ "$decision" == "fail_closed" ]]; then
    printf '\n## Remediation\n\n'
    jq -r '.failure_reasons[]?.remediation_text, .conflict_diagnostics[]?.remediation_text' "$verification_path" | sed '/^null$/d; /^$/d; s/^/- /'
  elif [[ "$decision" == "safe_mode" ]]; then
    printf '\n## Safe Mode\n\n'
    jq -r '.safe_mode_reason.remediation_text // empty' "$verification_path" | sed 's/^/- /'
  fi
} >"$report_path"

write_event "operator_intent_policy.emitted" "$decision" "$policy_id" "$policy_path"

if [[ "$decision" == "fail_closed" ]]; then
  exit 42
fi
exit 0
