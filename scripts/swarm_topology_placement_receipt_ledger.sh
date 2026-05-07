#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_TOPOLOGY_PLACEMENT_RECEIPT_LEDGER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-topology-placement-receipt-ledger}"
run_id="${SWARM_TOPOLOGY_PLACEMENT_RECEIPT_LEDGER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_TOPOLOGY_PLACEMENT_RECEIPT_LEDGER_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

bead_id="${SWARM_TOPOLOGY_PLACEMENT_RECEIPT_LEDGER_BEAD_ID:-bd-cocup}"
source_revision="${SWARM_TOPOLOGY_PLACEMENT_RECEIPT_LEDGER_SOURCE_REVISION:-}"
reference_time="${SWARM_TOPOLOGY_PLACEMENT_RECEIPT_LEDGER_REFERENCE_TIME:-}"
ttl_seconds="${SWARM_TOPOLOGY_PLACEMENT_RECEIPT_LEDGER_TTL_SECONDS:-1800}"
placement_plan_json=""
adoption_observation_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_topology_placement_receipt_ledger.sh --placement-plan-json FILE [OPTIONS]

Consumes an advisory topology placement plan plus an optional adoption
observation and emits deterministic receipt/adoption-history ledger artifacts.
The ledger records recommended targets, locality/cache assumptions, validity
windows, and adoption/drift reason codes. It does not enforce placement, pin
workers, update queues, or mutate remote state.

Required:
  --placement-plan-json FILE

Optional:
  --adoption-observation-json FILE
  --reference-time RFC3339
  --ttl-seconds N
  --bead-id ID
  --source-revision REV
  --output-dir DIR

Artifacts:
  swarm_topology_placement_receipt.json
  swarm_topology_placement_evidence_ledger.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  receipt/ledger emitted for pass or degraded adoption state
  42 fail-closed malformed or unsafe input
  64 invalid option or bad time/threshold
  75 blocked plan is not adoptable
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --placement-plan-json)
      placement_plan_json="${2:-}"
      shift 2
      ;;
    --adoption-observation-json)
      adoption_observation_json="${2:-}"
      shift 2
      ;;
    --reference-time)
      reference_time="${2:-}"
      shift 2
      ;;
    --ttl-seconds)
      ttl_seconds="${2:-}"
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

is_int() {
  [[ "${1:-}" =~ ^[0-9]+$ ]]
}

if [[ -z "$placement_plan_json" ]]; then
  printf 'placement receipt ledger requires --placement-plan-json\n' >&2
  usage
  exit 64
fi
if ! is_int "$ttl_seconds"; then
  printf 'ttl seconds must be a non-negative integer, got: %s\n' "$ttl_seconds" >&2
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for topology placement receipt ledgers\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for topology placement receipt ledgers\n' >&2
  exit 2
fi
if [[ ! -f "$placement_plan_json" ]]; then
  printf 'missing placement plan JSON: %s\n' "$placement_plan_json" >&2
  exit 64
fi
if ! jq empty "$placement_plan_json" >/dev/null 2>&1; then
  printf 'invalid placement plan JSON: %s\n' "$placement_plan_json" >&2
  exit 64
fi
if [[ -n "$adoption_observation_json" ]]; then
  if [[ ! -f "$adoption_observation_json" ]]; then
    printf 'missing adoption observation JSON: %s\n' "$adoption_observation_json" >&2
    exit 64
  fi
  if ! jq empty "$adoption_observation_json" >/dev/null 2>&1; then
    printf 'invalid adoption observation JSON: %s\n' "$adoption_observation_json" >&2
    exit 64
  fi
fi
if [[ -z "$reference_time" ]]; then
  reference_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
fi
if ! date -u -d "$reference_time" +%s >/dev/null 2>&1; then
  printf 'reference time must be parseable by date -u -d: %s\n' "$reference_time" >&2
  exit 64
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

reference_epoch_seconds="$(date -u -d "$reference_time" +%s)"
expires_epoch_seconds=$((reference_epoch_seconds + ttl_seconds))
expires_at="$(date -u -d "@${expires_epoch_seconds}" +%Y-%m-%dT%H:%M:%SZ)"

mkdir -p "$run_dir"
receipt_path="${run_dir}/swarm_topology_placement_receipt.json"
ledger_path="${run_dir}/swarm_topology_placement_evidence_ledger.json"
receipt_core_path="${run_dir}/swarm_topology_placement_receipt.core.json"
ledger_core_path="${run_dir}/swarm_topology_placement_evidence_ledger.core.json"
receipt_tmp="${receipt_path}.tmp"
ledger_tmp="${ledger_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
plan_normalized="${run_dir}/swarm_topology_placement_plan.normalized.json"
observation_normalized="${run_dir}/adoption_observation.normalized.json"
preflight_reasons_jsonl="${run_dir}/preflight_fail_closed_reasons.jsonl"

: >"$events_path"
: >"$preflight_reasons_jsonl"
printf './scripts/swarm_topology_placement_receipt_ledger.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-topology-placement-receipt-ledger.event.v1" \
    --arg component "swarm_topology_placement_receipt_ledger" \
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

jq -cS . "$placement_plan_json" >"$plan_normalized"
if [[ -n "$adoption_observation_json" ]]; then
  jq -cS . "$adoption_observation_json" >"$observation_normalized"
else
  printf '{}\n' >"$observation_normalized"
fi
write_event "input.loaded" "ok" "loaded placement plan and optional adoption observation" "$placement_plan_json"

if ! jq -e '
  .schema_version == "franken-engine.swarm-topology-placement-plan.v1"
  and ((.decision // "") | type == "string" and length > 0)
  and ((.recommended_worker_targets // []) | type == "array")
  and ((.warm_cache_residency_state // "") | type == "string" and length > 0)
  and ((.warm_cache_opportunities // []) | type == "array")
  and ((.degraded_reasons // []) | type == "array")
  and ((.blocked_reasons // []) | type == "array")
  and ((.fail_closed_reasons // []) | type == "array")
' "$plan_normalized" >/dev/null 2>&1; then
  append_preflight_reason "malformed_placement_plan" "placement_plan_json" "placement plan is missing required receipt fields"
fi

if ! jq -e '
  .mutation_policy.fixture_fed_only == true
  and .mutation_policy.proof_only == true
  and .mutation_policy.advisory_only == true
  and .mutation_policy.mutates_br == false
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
  and .mutation_policy.mutates_remote_workers == false
  and .mutation_policy.changes_live_queue_policy == false
  and .mutation_policy.pins_workers_automatically == false
  and .mutation_policy.rebinds_hosts_automatically == false
' "$plan_normalized" >/dev/null 2>&1; then
  append_preflight_reason "unsafe_live_mutation_claim" "placement_plan_json" "placement plan mutation policy is missing or allows live mutation"
fi

if [[ -n "$adoption_observation_json" ]]; then
  if ! jq -e '
    .schema_version == "franken-engine.swarm-topology-placement-adoption-observation.v1"
    and ((.observed_at // "") | type == "string" and length > 0)
    and ((.host_id // "") | type == "string" and length > 0)
    and ((.worker_ids // []) | type == "array")
    and has("cache_reuse_observed")
    and (.cache_reuse_observed | type == "boolean")
  ' "$observation_normalized" >/dev/null 2>&1; then
    append_preflight_reason "malformed_adoption_observation" "adoption_observation_json" "adoption observation is missing required fields"
  fi
  observation_time="$(jq -r '.observed_at // ""' "$observation_normalized")"
  if ! date -u -d "$observation_time" +%s >/dev/null 2>&1; then
    append_preflight_reason "malformed_adoption_observation" "adoption_observation_json" "adoption observation observed_at is not parseable"
    observation_epoch_seconds="null"
  else
    observation_epoch_seconds="$(date -u -d "$observation_time" +%s)"
  fi
else
  observation_epoch_seconds="null"
fi

jq -n \
  --slurpfile plan "$plan_normalized" \
  --slurpfile observation "$observation_normalized" \
  --slurpfile preflight "$preflight_reasons_jsonl" \
  --arg schema_version "franken-engine.swarm-topology-placement-receipt.v1" \
  --arg source_revision "$source_revision" \
  --arg bead_id "$bead_id" \
  --arg reference_time "$reference_time" \
  --arg expires_at "$expires_at" \
  --arg placement_plan_json "$placement_plan_json" \
  --arg adoption_observation_json "$adoption_observation_json" \
  --arg receipt_path "$receipt_path" \
  --arg ledger_path "$ledger_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --argjson ttl_seconds "$ttl_seconds" \
  --argjson reference_epoch_seconds "$reference_epoch_seconds" \
  --argjson expires_epoch_seconds "$expires_epoch_seconds" \
  --argjson observation_epoch_seconds "$observation_epoch_seconds" '
  def low($value): (($value // "") | tostring | ascii_downcase);
  def arr($value): if ($value | type) == "array" then $value else [] end;
  def unique_reasons: unique_by([.code, .source_id, .detail]);
  ($plan[0] // {}) as $p
  | ($observation[0] // {}) as $o
  | (low($p.decision)) as $plan_decision
  | (arr($p.recommended_worker_targets)) as $targets
  | ($targets | map(.worker_id) | unique | sort) as $recommended_workers
  | (arr($o.worker_ids) | unique | sort) as $actual_workers
  | (($o | has("observed_at")) and (($o.observed_at // "") != "")) as $has_observation
  | (($observation_epoch_seconds != null) and ($observation_epoch_seconds > $expires_epoch_seconds)) as $expired
  | ($p.context.host_identity.host_id // $p.context.host_identity.host // null) as $expected_host_id
  | ($o.host_id // null) as $actual_host_id
  | (any($targets[]?; .cache_reuse == true)) as $expected_cache_reuse
  | (($o.cache_reuse_observed // false) == true) as $observed_cache_reuse
  | ([($actual_workers[]? as $worker | select(($recommended_workers | index($worker)) != null))] | length > 0) as $worker_matches
  | (($expected_host_id == null) or ($actual_host_id == null) or ($expected_host_id == $actual_host_id)) as $host_matches
  | (arr($p.fail_closed_reasons) + $preflight | unique_reasons) as $fail_closed_reasons
  | (arr($p.blocked_reasons)
     + (if $plan_decision == "blocked" then
          [{code:"blocked_plan_not_adoptable",source_id:"placement_plan_json",detail:"blocked placement plan cannot be adopted as a receipt target"}]
        else [] end)
     | unique_reasons) as $blocked_reasons
  | (arr($p.degraded_reasons)
     + (if $expired then [{code:"receipt_expired",source_id:"validity_window",detail:"adoption observation arrived after receipt expiry"}] else [] end)
     + (if ($has_observation | not) and ($plan_decision != "blocked") and ($plan_decision != "fail_closed") then [{code:"observation_missing",source_id:"adoption_observation_json",detail:"receipt has no observed adoption yet"}] else [] end)
     + (if $has_observation and ($host_matches | not) then [{code:"host_drift",source_id:"adoption_observation_json",detail:"observed host differs from placement plan host assumption"}] else [] end)
     + (if $has_observation and (($worker_matches | not) and (($recommended_workers | length) > 0)) then [{code:"worker_drift",source_id:"adoption_observation_json",detail:"observed worker was not one of the recommended placement targets"}] else [] end)
     + (if $has_observation and $expected_cache_reuse and ($observed_cache_reuse | not) then [{code:"cache_reuse_missing",source_id:"adoption_observation_json",detail:"plan recommended hot-cache reuse but observation did not confirm it"}] else [] end)
     | unique_reasons) as $degraded_reasons
  | (if (($fail_closed_reasons | length) > 0) or $plan_decision == "fail_closed" then "fail_closed"
     elif (($blocked_reasons | length) > 0) then "blocked"
     elif (($degraded_reasons | map(select(.code != "observation_missing")) | length) > 0) then "degraded"
     else "pass"
     end) as $decision
  | (if $decision == "fail_closed" then "fail_closed"
     elif $decision == "blocked" then "not_applicable"
     elif $expired then "expired"
     elif ($has_observation | not) then "pending_observation"
     elif (($host_matches | not) or ($worker_matches | not)) then "drifted"
     else "adopted"
     end) as $adoption_status
  | ([
      if $adoption_status == "adopted" then {code:"adopted_recommended_target",source_id:"adoption_observation_json",detail:"observation matched recommended worker and host assumptions"} else empty end,
      if $adoption_status == "expired" then {code:"receipt_expired",source_id:"validity_window",detail:"receipt validity window elapsed before observation"} else empty end,
      if ($p.warm_cache_residency_state // "") == "cold" then {code:"cache_cold_no_reuse_claim",source_id:"placement_plan_json",detail:"cache-cold plan did not claim warm-cache reuse"} else empty end,
      if $expected_cache_reuse and $observed_cache_reuse then {code:"cache_reuse_confirmed",source_id:"adoption_observation_json",detail:"observation confirmed hot-cache reuse"} else empty end
    ] + $degraded_reasons + $blocked_reasons + $fail_closed_reasons | unique_reasons) as $reason_rows
  | {
      schema_version: $schema_version,
      source_revision: $source_revision,
      bead_id: $bead_id,
      source_plan: {
        path: $placement_plan_json,
        schema_version: ($p.schema_version // null),
        plan_id: ($p.plan_id // null),
        decision: ($p.decision // null)
      },
      decision: $decision,
      adoption_status: $adoption_status,
      recommended_placement_targets: $targets,
      recommended_worker_ids: $recommended_workers,
      topology_locality_assumptions: ($p.locality_assumptions // []),
      cache_warmth_assumptions: {
        state: ($p.warm_cache_residency_state // "unknown"),
        opportunities: ($p.warm_cache_opportunities // [])
      },
      validity_window: {
        reference_time: $reference_time,
        reference_epoch_seconds: $reference_epoch_seconds,
        ttl_seconds: $ttl_seconds,
        expires_at: $expires_at,
        expires_epoch_seconds: $expires_epoch_seconds,
        expired_at_observation: $expired
      },
      adoption_observation: (if $has_observation then {
        path: $adoption_observation_json,
        observed_at: ($o.observed_at // null),
        observed_epoch_seconds: $observation_epoch_seconds,
        host_id: $actual_host_id,
        worker_ids: $actual_workers,
        cache_reuse_observed: $observed_cache_reuse
      } else null end),
      expected_host_id: $expected_host_id,
      degraded_reasons: $degraded_reasons,
      blocked_reasons: $blocked_reasons,
      fail_closed_reasons: $fail_closed_reasons,
      adoption_drift_reason_codes: ($reason_rows | map(.code) | unique | sort),
      adoption_drift_reasons: $reason_rows,
      artifact_paths: {
        placement_plan_json: $placement_plan_json,
        adoption_observation_json: (if $adoption_observation_json == "" then null else $adoption_observation_json end),
        swarm_topology_placement_receipt_json: $receipt_path,
        swarm_topology_placement_evidence_ledger_json: $ledger_path,
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
        enforces_placement_automatically: false
      }
    }' >"$receipt_core_path"

receipt_hash="$(jq -cS 'del(.artifact_paths)' "$receipt_core_path" | sha256sum | awk '{print $1}')"
receipt_id="swarm-topology-placement-receipt-${receipt_hash:0:16}"
jq --arg receipt_id "$receipt_id" --arg receipt_hash "$receipt_hash" \
  '. + {receipt_id:$receipt_id, hash_basis:{receipt_hash:$receipt_hash}}' \
  "$receipt_core_path" >"$receipt_tmp"
mv "$receipt_tmp" "$receipt_path"

jq -n \
  --slurpfile receipt "$receipt_path" \
  --arg schema_version "franken-engine.swarm-topology-placement-evidence-ledger.v1" \
  --arg source_revision "$source_revision" \
  --arg bead_id "$bead_id" \
  --arg ledger_path "$ledger_path" \
  --arg receipt_path "$receipt_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" '
  ($receipt[0]) as $r
  | {
      schema_version: $schema_version,
      source_revision: $source_revision,
      bead_id: $bead_id,
      decision: $r.decision,
      receipts: [$r],
      adoption_history: [{
        receipt_id: $r.receipt_id,
        plan_id: $r.source_plan.plan_id,
        adoption_status: $r.adoption_status,
        expected_host_id: $r.expected_host_id,
        expected_worker_ids: $r.recommended_worker_ids,
        observed: $r.adoption_observation,
        drift_reason_codes: $r.adoption_drift_reason_codes,
        validity_window: $r.validity_window
      }],
      summary: {
        receipt_count: 1,
        adopted_count: (if $r.adoption_status == "adopted" then 1 else 0 end),
        drifted_count: (if $r.adoption_status == "drifted" then 1 else 0 end),
        expired_count: (if $r.adoption_status == "expired" then 1 else 0 end),
        blocked_count: (if $r.decision == "blocked" then 1 else 0 end),
        fail_closed_count: (if $r.decision == "fail_closed" then 1 else 0 end)
      },
      artifact_paths: {
        swarm_topology_placement_evidence_ledger_json: $ledger_path,
        swarm_topology_placement_receipt_json: $receipt_path,
        events_jsonl: $events_path,
        commands_txt: $commands_path,
        report_md: $report_path
      },
      mutation_policy: $r.mutation_policy
    }' >"$ledger_core_path"

ledger_hash="$(jq -cS 'del(.artifact_paths)' "$ledger_core_path" | sha256sum | awk '{print $1}')"
ledger_id="swarm-topology-placement-ledger-${ledger_hash:0:16}"
jq --arg ledger_id "$ledger_id" --arg ledger_hash "$ledger_hash" \
  '. + {ledger_id:$ledger_id, hash_basis:{ledger_hash:$ledger_hash}}' \
  "$ledger_core_path" >"$ledger_tmp"
mv "$ledger_tmp" "$ledger_path"

decision="$(jq -r '.decision' "$receipt_path")"
write_event "receipt.emitted" "$decision" "emitted placement receipt and adoption ledger" "$receipt_path"

{
  printf '# Swarm Topology Placement Receipt Ledger\n\n'
  printf -- "- Decision: \`%s\`\n" "$decision"
  printf -- "- Adoption status: \`%s\`\n" "$(jq -r '.adoption_status' "$receipt_path")"
  printf -- "- Receipt: \`%s\`\n" "$receipt_path"
  printf -- "- Ledger: \`%s\`\n" "$ledger_path"
  printf -- "- Expires at: \`%s\`\n\n" "$(jq -r '.validity_window.expires_at' "$receipt_path")"

  if [[ "$(jq '.adoption_drift_reasons | length' "$receipt_path")" -gt 0 ]]; then
    printf '## Adoption / Drift Reasons\n'
    jq -r '.adoption_drift_reasons[] | "- `" + .code + "` `" + .source_id + "`: " + .detail' "$receipt_path"
    printf '\n'
  fi
} >"$report_path"

printf 'swarm_topology_placement_receipt_json=%s\n' "$receipt_path"
printf 'swarm_topology_placement_evidence_ledger_json=%s\n' "$ledger_path"
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
