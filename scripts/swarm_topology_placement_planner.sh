#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_TOPOLOGY_PLACEMENT_PLANNER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-topology-placement-plan}"
run_id="${SWARM_TOPOLOGY_PLACEMENT_PLANNER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_TOPOLOGY_PLACEMENT_PLANNER_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

bead_id="${SWARM_TOPOLOGY_PLACEMENT_PLANNER_BEAD_ID:-bd-zp0m5}"
source_revision="${SWARM_TOPOLOGY_PLACEMENT_PLANNER_SOURCE_REVISION:-}"
placement_input_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_topology_placement_planner.sh --placement-input-json FILE [OPTIONS]

Consumes the normalized SWARM-SCALE-II topology placement input and emits an
advisory NUMA/warm-cache placement plan. The planner is fixture-fed: it does
not query live trackers, run validation, start workers, change queue policy,
pin workers, rebind hosts, or repair target directories.

Required:
  --placement-input-json FILE

Options:
  --bead-id ID
  --source-revision REV
  --output-dir DIR

Artifacts:
  swarm_topology_placement_plan.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  plan emitted; decision is pass or degraded
  42 fail-closed input truth prevents placement planning
  64 invalid option or malformed input
  75 blocked locality truth requires manual review before advice is useful
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --placement-input-json)
      placement_input_json="${2:-}"
      shift 2
      ;;
    --bead-id)
      bead_id="${2:-}"
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
      printf 'unknown option: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

if [[ -z "$placement_input_json" ]]; then
  printf 'swarm topology placement planner requires --placement-input-json\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm topology placement planning\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for swarm topology placement planning\n' >&2
  exit 2
fi
if [[ ! -f "$placement_input_json" ]]; then
  printf 'missing placement input JSON: %s\n' "$placement_input_json" >&2
  exit 64
fi
if ! jq empty "$placement_input_json" >/dev/null 2>&1; then
  printf 'invalid placement input JSON: %s\n' "$placement_input_json" >&2
  exit 64
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
plan_path="${run_dir}/swarm_topology_placement_plan.json"
plan_tmp="${plan_path}.tmp"
core_path="${run_dir}/swarm_topology_placement_plan.core.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
input_normalized="${run_dir}/swarm_topology_placement_input.normalized.json"
preflight_reasons_jsonl="${run_dir}/preflight_fail_closed_reasons.jsonl"

: >"$events_path"
: >"$preflight_reasons_jsonl"
printf './scripts/swarm_topology_placement_planner.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-topology-placement-planner.event.v1" \
    --arg component "swarm_topology_placement_planner" \
    --arg event "$1" \
    --arg outcome "$2" \
    --arg detail "$3" \
    --arg evidence_path "$4" \
    '{schema_version:$schema_version,component:$component,event:$event,outcome:$outcome,detail:$detail,evidence_path:$evidence_path}' \
    >>"$events_path"
}

append_preflight_reason() {
  jq -nc \
    --arg code "$1" \
    --arg source_id "$2" \
    --arg detail "$3" \
    '{code:$code,source_id:$source_id,detail:$detail}' >>"$preflight_reasons_jsonl"
}

jq -cS . "$placement_input_json" >"$input_normalized"
write_event "input.loaded" "ok" "loaded normalized topology placement input" "$placement_input_json"

if ! jq -e '
  .schema_version == "franken-engine.swarm-topology-placement-input.v1"
  and ((.decision // "") | type == "string" and length > 0)
  and ((.truth_state // "") | type == "string" and length > 0)
  and ((.host_identity.host_id // "") | type == "string" and length > 0)
  and ((.numa_summary.preferred_numa_nodes // []) | type == "array")
  and ((.placement_hints.preferred_worker_ids // []) | type == "array")
  and ((.warm_cache_residency.state // "") | type == "string" and length > 0)
  and ((.degraded_reasons // []) | type == "array")
  and ((.blocked_reasons // []) | type == "array")
  and ((.fail_closed_reasons // []) | type == "array")
' "$input_normalized" >/dev/null 2>&1; then
  append_preflight_reason "malformed_placement_input" "placement_input_json" "normalized placement input is missing required planner fields"
fi

if ! jq -e '
  .mutation_policy.fixture_fed_only == true
  and .mutation_policy.proof_only == true
  and .mutation_policy.advisory_only == true
  and .mutation_policy.mutates_br == false
  and .mutation_policy.reassigns_beads == false
  and .mutation_policy.releases_reservations == false
  and .mutation_policy.sends_agent_mail == false
  and .mutation_policy.queries_live_agent_mail == false
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
  and .mutation_policy.mutates_remote_workers == false
  and .mutation_policy.changes_live_queue_policy == false
  and .mutation_policy.pins_workers_automatically == false
  and .mutation_policy.rebinds_hosts_automatically == false
' "$input_normalized" >/dev/null 2>&1; then
  append_preflight_reason "unsafe_live_mutation_claim" "placement_input_json" "input mutation policy is missing or allows live mutation"
fi

jq -n \
  --slurpfile input "$input_normalized" \
  --slurpfile preflight "$preflight_reasons_jsonl" \
  --arg schema_version "franken-engine.swarm-topology-placement-plan.v1" \
  --arg source_revision "$source_revision" \
  --arg bead_id "$bead_id" \
  --arg input_path "$placement_input_json" \
  --arg plan_path "$plan_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" '
  def low($value): (($value // "") | tostring | ascii_downcase);
  def arr($value): if ($value | type) == "array" then $value else [] end;
  def unique_reasons: unique_by([.code, .source_id, .detail]);
  def first_or($rows; $fallback): if (($rows | length) > 0) then $rows[0] else $fallback end;
  def preferred_node($nodes): first_or($nodes; null);
  def topology_class($input; $decision; $warm_state):
    if $decision == "fail_closed" then "unknown"
    elif $decision == "blocked" then "blocked_contradictory_locality"
    elif $warm_state == "hot" and (low($input.placement_hints.recommended_topology_class) | contains("numa")) then "numa_hot_cache_preferred"
    elif $warm_state == "cold" then "numa_cache_cold_fallback"
    elif $decision == "degraded" then "partial_topology_balanced_remote"
    else ($input.placement_hints.recommended_topology_class // "portable_fallback")
    end;
  def target_row($rank; $lane_class; $worker_id; $numa_node; $hot_worker_ids; $hot_target_dirs; $warm_state; $plan_class):
    (($warm_state == "hot") and any($hot_worker_ids[]?; . == $worker_id)) as $cache_reuse
    | {
        rank: $rank,
        lane_class: $lane_class,
        worker_id: $worker_id,
        numa_node: $numa_node,
        shard_hint: ($lane_class + "-numa-" + (($numa_node // "unknown") | tostring) + "-shard-" + (($rank - 1) | tostring)),
        recommended_topology_class: $plan_class,
        cache_reuse: $cache_reuse,
        target_dir: (if $cache_reuse and (($hot_target_dirs | length) > 0) then ($hot_target_dirs[0].path // null) else null end),
        certainty: (if $cache_reuse then "confirmed" elif $warm_state == "cold" then "bounded_uncertain" else "partial" end),
        reason_codes: (
          ["numa_preferred"]
          + (if $cache_reuse then ["hot_cache_reuse"] else [] end)
          + (if $warm_state == "cold" then ["cache_cold_fallback"] else [] end)
          + (if ($warm_state == "missing_optional" or $warm_state == "stale") then ["partial_topology_or_cache_context"] else [] end)
        )
      };
  def cache_opportunities($decision; $warm_state; $hot_worker_ids; $hot_target_dirs; $target_workers):
    if ($decision == "fail_closed" or $decision == "blocked") then []
    elif $warm_state == "hot" and (($hot_worker_ids | length) > 0) then
      [{
        opportunity_id: "reuse_hot_cache",
        action: "prefer_hot_cache_worker_before_cold_recompute",
        certainty: "confirmed",
        worker_ids: $hot_worker_ids,
        target_dirs: $hot_target_dirs,
        reason_codes: ["hot_cache_reuse", "reuse_warm_target_dir"]
      }]
    elif $warm_state == "cold" then
      [{
        opportunity_id: "cache_cold_fallback",
        action: "prefer_numa_local_worker_without_cache_reuse_claim",
        certainty: "bounded_uncertain",
        worker_ids: $target_workers,
        target_dirs: [],
        reason_codes: ["cache_cold_fallback", "no_hot_cache_reuse_claim"]
      }]
    else
      [{
        opportunity_id: "cache_evidence_unavailable",
        action: "do_not_claim_warm_cache_reuse",
        certainty: "unknown",
        worker_ids: $target_workers,
        target_dirs: [],
        reason_codes: ["partial_topology_or_cache_context", "no_hot_cache_reuse_claim"]
      }]
    end;

  ($input[0] // {}) as $input_doc
  | (low($input_doc.decision)) as $input_decision
  | (low($input_doc.truth_state)) as $truth_state
  | (low($input_doc.warm_cache_residency.state)) as $warm_state
  | (arr($input_doc.degraded_reasons)) as $input_degraded
  | (arr($input_doc.blocked_reasons)) as $input_blocked
  | (arr($input_doc.fail_closed_reasons)) as $input_fail_closed
  | (arr($input_doc.placement_hints.preferred_worker_ids)) as $preferred_workers
  | (arr($input_doc.placement_hints.preferred_numa_nodes)) as $preferred_nodes
  | (arr($input_doc.warm_cache_residency.hot_worker_ids)) as $hot_worker_ids
  | (arr($input_doc.warm_cache_residency.hot_target_dirs)) as $hot_target_dirs
  | (if (($preflight | length) > 0) then $preflight else [] end
     + $input_fail_closed
     + (if $input_decision == "fail_closed" and (($input_fail_closed | length) == 0) then
          [{code:"input_fail_closed",source_id:"placement_input_json",detail:"normalized placement input decision is fail_closed"}]
        else [] end)
     | unique_reasons) as $fail_closed_reasons
  | ($input_blocked
     + (if $input_decision == "blocked" and (($input_blocked | length) == 0) then
          [{code:"input_locality_blocked",source_id:"placement_input_json",detail:"normalized placement input is blocked"}]
        else [] end)
     | unique_reasons) as $blocked_reasons
  | ($input_degraded
     + (if $input_decision == "degraded" then
          [{code:"partial_topology_or_cache_context",source_id:"placement_input_json",detail:"normalized input is degraded; planner must preserve partial confidence"}]
        else [] end)
     + (if ($warm_state == "missing_optional" or $warm_state == "stale") then
          [{code:"partial_topology_or_cache_context",source_id:"cache_residency_json",detail:"warm-cache residency is not current enough for reuse advice"}]
        else [] end)
     + (if (($preferred_workers | length) == 0) and (($fail_closed_reasons | length) == 0) and (($blocked_reasons | length) == 0) then
          [{code:"no_preferred_worker_hint",source_id:"placement_hints",detail:"normalized input did not provide a preferred worker target"}]
        else [] end)
     | unique_reasons) as $degraded_reasons
  | (if (($fail_closed_reasons | length) > 0) then "fail_closed"
     elif (($blocked_reasons | length) > 0) then "blocked"
     elif (($degraded_reasons | length) > 0) then "degraded"
     else "pass"
     end) as $decision
  | (if $decision == "fail_closed" then "fail_closed"
     elif $decision == "blocked" then "blocked"
     elif $decision == "degraded" then "partial"
     else "ready"
     end) as $placement_readiness
  | (if (($hot_worker_ids | length) > 0 and $warm_state == "hot") then $hot_worker_ids else $preferred_workers end) as $target_workers
  | (topology_class($input_doc; $decision; $warm_state)) as $plan_class
  | (preferred_node($preferred_nodes)) as $node
  | (if (($target_workers | length) == 0) or ($decision == "fail_closed") or ($decision == "blocked") then []
     else [
       target_row(1; "heavy"; $target_workers[0]; $node; $hot_worker_ids; $hot_target_dirs; $warm_state; $plan_class),
       target_row(2; "latency_sensitive"; $target_workers[0]; $node; $hot_worker_ids; $hot_target_dirs; $warm_state; $plan_class),
       target_row(3; "throughput_balanced"; $target_workers[(if (($target_workers | length) > 1) then 1 else 0 end)]; $node; $hot_worker_ids; $hot_target_dirs; $warm_state; $plan_class)
     ] end) as $recommended_targets
  | (cache_opportunities($decision; $warm_state; $hot_worker_ids; $hot_target_dirs; $target_workers)) as $cache_opportunities
  | {
      schema_version: $schema_version,
      source_revision: $source_revision,
      bead_id: $bead_id,
      source_input: {
        path: $input_path,
        schema_version: ($input_doc.schema_version // null),
        placement_input_id: ($input_doc.placement_input_id // null),
        decision: ($input_doc.decision // null),
        truth_state: ($input_doc.truth_state // null)
      },
      decision: $decision,
      placement_readiness: $placement_readiness,
      recommended_topology_class: $plan_class,
      recommended_worker_targets: $recommended_targets,
      warm_cache_residency_state: $warm_state,
      warm_cache_opportunities: $cache_opportunities,
      degraded_reasons: $degraded_reasons,
      blocked_reasons: $blocked_reasons,
      fail_closed_reasons: $fail_closed_reasons,
      locality_assumptions: [
        "Preferred NUMA nodes and workers are inherited from the normalized placement input.",
        "Warm-cache reuse is recommended only when residency evidence explicitly names hot workers.",
        "Cache-cold plans keep locality advice bounded and do not claim a warm target directory.",
        "The plan is advisory-only and must be adopted by a later operator or receipt surface before any live action."
      ],
      context: {
        host_identity: ($input_doc.host_identity // {}),
        numa_summary: ($input_doc.numa_summary // {}),
        worker_inventory: ($input_doc.worker_inventory // {}),
        upstream_context: ($input_doc.context // {})
      },
      summary: {
        target_count: ($recommended_targets | length),
        warm_cache_opportunity_count: ($cache_opportunities | length),
        heavy_target_count: ($recommended_targets | map(select(.lane_class == "heavy")) | length),
        latency_sensitive_target_count: ($recommended_targets | map(select(.lane_class == "latency_sensitive")) | length),
        fail_closed_count: ($fail_closed_reasons | length),
        blocked_count: ($blocked_reasons | length),
        degraded_count: ($degraded_reasons | length),
        certainty: (if any($cache_opportunities[]?; .certainty == "confirmed") then "confirmed_cache_reuse" elif $warm_state == "cold" then "bounded_cache_cold" elif $decision == "pass" then "topology_only" else $placement_readiness end)
      },
      operator_advisories: ($recommended_targets | map("# advisory-only " + .lane_class + " worker=" + .worker_id + " shard=" + .shard_hint + " cache_reuse=" + (.cache_reuse | tostring))),
      artifact_paths: {
        placement_input_json: $input_path,
        swarm_topology_placement_plan_json: $plan_path,
        events_jsonl: $events_path,
        commands_txt: $commands_path,
        report_md: $report_path
      },
      mutation_policy: {
        fixture_fed_only: true,
        proof_only: true,
        advisory_only: true,
        mutates_br: false,
        reassigns_beads: false,
        releases_reservations: false,
        sends_agent_mail: false,
        queries_live_agent_mail: false,
        runs_cargo: false,
        runs_rch: false,
        mutates_remote_workers: false,
        changes_live_queue_policy: false,
        pins_workers_automatically: false,
        rebinds_hosts_automatically: false,
        repairs_target_dirs_automatically: false
      }
    }' >"$core_path"

plan_hash="$(jq -cS 'del(.artifact_paths)' "$core_path" | sha256sum | awk '{print $1}')"
plan_id="swarm-topology-placement-plan-${plan_hash:0:16}"
jq --arg plan_id "$plan_id" --arg plan_hash "$plan_hash" \
  '. + {plan_id:$plan_id, hash_basis:{plan_hash:$plan_hash}}' \
  "$core_path" >"$plan_tmp"
mv "$plan_tmp" "$plan_path"

decision="$(jq -r '.decision' "$plan_path")"
write_event "plan.emitted" "$decision" "emitted advisory topology placement plan" "$plan_path"

{
  printf '# Swarm Topology Placement Plan\n\n'
  printf -- "- Decision: \`%s\`\n" "$decision"
  printf -- "- Placement readiness: \`%s\`\n" "$(jq -r '.placement_readiness' "$plan_path")"
  printf -- "- Recommended topology class: \`%s\`\n" "$(jq -r '.recommended_topology_class' "$plan_path")"
  printf -- "- Warm-cache state: \`%s\`\n" "$(jq -r '.warm_cache_residency_state' "$plan_path")"
  printf -- "- Worker targets: \`%s\`\n\n" "$(jq -r '.recommended_worker_targets | length' "$plan_path")"

  if [[ "$(jq '.warm_cache_opportunities | length' "$plan_path")" -gt 0 ]]; then
    printf '## Warm-Cache Opportunities\n'
    jq -r '.warm_cache_opportunities[] | "- `" + .opportunity_id + "` `" + .certainty + "`: " + .action' "$plan_path"
    printf '\n'
  fi
  if [[ "$(jq '.degraded_reasons | length' "$plan_path")" -gt 0 ]]; then
    printf '## Degraded Reasons\n'
    jq -r '.degraded_reasons[] | "- `" + .code + "` `" + .source_id + "`: " + .detail' "$plan_path"
    printf '\n'
  fi
  if [[ "$(jq '.blocked_reasons | length' "$plan_path")" -gt 0 ]]; then
    printf '## Blocked Reasons\n'
    jq -r '.blocked_reasons[] | "- `" + .code + "` `" + .source_id + "`: " + .detail' "$plan_path"
    printf '\n'
  fi
  if [[ "$(jq '.fail_closed_reasons | length' "$plan_path")" -gt 0 ]]; then
    printf '## Fail-Closed Reasons\n'
    jq -r '.fail_closed_reasons[] | "- `" + .code + "` `" + .source_id + "`: " + .detail' "$plan_path"
    printf '\n'
  fi
} >"$report_path"

printf 'swarm_topology_placement_plan_json=%s\n' "$plan_path"
printf 'swarm_topology_placement_report_md=%s\n' "$report_path"

case "$decision" in
  fail_closed)
    exit 42
    ;;
  blocked)
    exit 75
    ;;
  *)
    exit 0
    ;;
esac
