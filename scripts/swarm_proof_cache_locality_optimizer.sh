#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_PROOF_CACHE_LOCALITY_OPTIMIZER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-proof-cache-locality-optimizer}"
run_id="${SWARM_PROOF_CACHE_LOCALITY_OPTIMIZER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_PROOF_CACHE_LOCALITY_OPTIMIZER_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

source_revision="${SWARM_PROOF_CACHE_LOCALITY_OPTIMIZER_SOURCE_REVISION:-}"
admission_budget_plan_json=""
warm_target_prefetch_roi_advisory_json=""
proof_cache_plan_json=""
archive_pressure_scoreboard_json=""
worker_truth_report_json=""
swarm_resource_envelope_json=""
swarm_topology_placement_plan_json=""
swarm_topology_placement_receipt_json=""
swarm_topology_placement_evidence_ledger_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_proof_cache_locality_optimizer.sh [OPTIONS]

Consumes SWARM-OPS proof-cache/archive/admission/worker evidence plus the
SWARM-SCALE-II topology placement plan, receipt, and ledger, then emits an
advisory proof-cache locality plan. The optimizer does not delete target dirs,
overwrite artifacts, run Cargo/RCH, pin workers, rebind hosts, or mutate queue
policy.

Required:
  --admission-budget-plan-json FILE
  --warm-target-prefetch-roi-advisory-json FILE
  --proof-cache-plan-json FILE
  --archive-pressure-scoreboard-json FILE
  --worker-truth-report-json FILE
  --swarm-resource-envelope-json FILE
  --swarm-topology-placement-plan-json FILE
  --swarm-topology-placement-receipt-json FILE
  --swarm-topology-placement-evidence-ledger-json FILE

Optional:
  --source-revision REV
  --output-dir DIR

Artifacts:
  locality_plan.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0   locality plan emitted; decision is pass or degraded
  42  fail-closed evidence prevents locality planning
  64  invalid option or malformed input
  75  trustworthy evidence blocks reuse/fresh-target advice
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --admission-budget-plan-json)
      admission_budget_plan_json="${2:-}"
      shift 2
      ;;
    --warm-target-prefetch-roi-advisory-json)
      warm_target_prefetch_roi_advisory_json="${2:-}"
      shift 2
      ;;
    --proof-cache-plan-json)
      proof_cache_plan_json="${2:-}"
      shift 2
      ;;
    --archive-pressure-scoreboard-json)
      archive_pressure_scoreboard_json="${2:-}"
      shift 2
      ;;
    --worker-truth-report-json)
      worker_truth_report_json="${2:-}"
      shift 2
      ;;
    --swarm-resource-envelope-json)
      swarm_resource_envelope_json="${2:-}"
      shift 2
      ;;
    --swarm-topology-placement-plan-json)
      swarm_topology_placement_plan_json="${2:-}"
      shift 2
      ;;
    --swarm-topology-placement-receipt-json)
      swarm_topology_placement_receipt_json="${2:-}"
      shift 2
      ;;
    --swarm-topology-placement-evidence-ledger-json)
      swarm_topology_placement_evidence_ledger_json="${2:-}"
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

if [[ -z "$admission_budget_plan_json" || -z "$warm_target_prefetch_roi_advisory_json" || -z "$proof_cache_plan_json" || -z "$archive_pressure_scoreboard_json" || -z "$worker_truth_report_json" || -z "$swarm_resource_envelope_json" || -z "$swarm_topology_placement_plan_json" || -z "$swarm_topology_placement_receipt_json" || -z "$swarm_topology_placement_evidence_ledger_json" ]]; then
  printf 'proof-cache locality optimizer requires all input JSON files\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for proof-cache locality optimization\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for proof-cache locality optimization\n' >&2
  exit 2
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
plan_path="${run_dir}/locality_plan.json"
plan_tmp="${plan_path}.tmp"
core_path="${run_dir}/locality_plan.core.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"

admission_normalized="${run_dir}/admission_budget_plan.normalized.json"
warm_roi_normalized="${run_dir}/warm_target_prefetch_roi_advisory.normalized.json"
proof_cache_normalized="${run_dir}/proof_cache_plan.normalized.json"
archive_normalized="${run_dir}/archive_pressure_scoreboard.normalized.json"
worker_truth_normalized="${run_dir}/worker_truth_report.normalized.json"
resource_envelope_normalized="${run_dir}/swarm_resource_envelope.normalized.json"
topology_plan_normalized="${run_dir}/swarm_topology_placement_plan.normalized.json"
topology_receipt_normalized="${run_dir}/swarm_topology_placement_receipt.normalized.json"
topology_ledger_normalized="${run_dir}/swarm_topology_placement_evidence_ledger.normalized.json"

: >"$events_path"
printf './scripts/swarm_proof_cache_locality_optimizer.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-proof-cache-locality-optimizer.event.v1" \
    --arg component "swarm_proof_cache_locality_optimizer" \
    --arg event "$1" \
    --arg outcome "$2" \
    --arg detail "$3" \
    --arg evidence_path "$4" \
    '{schema_version:$schema_version,component:$component,event:$event,outcome:$outcome,detail:$detail,evidence_path:$evidence_path}' \
    >>"$events_path"
}

normalize_required_json() {
  local input_path="$1"
  local output_path="$2"
  local label="$3"
  if [[ ! -f "$input_path" ]]; then
    printf 'proof-cache locality optimizer missing %s JSON: %s\n' "$label" "$input_path" >&2
    exit 64
  fi
  if ! jq empty "$input_path" >/dev/null 2>&1; then
    printf 'proof-cache locality optimizer invalid %s JSON: %s\n' "$label" "$input_path" >&2
    exit 64
  fi
  jq -cS . "$input_path" >"$output_path"
  write_event "input.loaded" "ok" "$label" "$input_path"
}

normalize_required_json "$admission_budget_plan_json" "$admission_normalized" "admission budget plan"
normalize_required_json "$warm_target_prefetch_roi_advisory_json" "$warm_roi_normalized" "warm target ROI advisory"
normalize_required_json "$proof_cache_plan_json" "$proof_cache_normalized" "proof cache plan"
normalize_required_json "$archive_pressure_scoreboard_json" "$archive_normalized" "archive pressure scoreboard"
normalize_required_json "$worker_truth_report_json" "$worker_truth_normalized" "worker truth report"
normalize_required_json "$swarm_resource_envelope_json" "$resource_envelope_normalized" "swarm resource envelope"
normalize_required_json "$swarm_topology_placement_plan_json" "$topology_plan_normalized" "topology placement plan"
normalize_required_json "$swarm_topology_placement_receipt_json" "$topology_receipt_normalized" "topology placement receipt"
normalize_required_json "$swarm_topology_placement_evidence_ledger_json" "$topology_ledger_normalized" "topology placement evidence ledger"

jq -n \
  --slurpfile admission "$admission_normalized" \
  --slurpfile warm "$warm_roi_normalized" \
  --slurpfile cache "$proof_cache_normalized" \
  --slurpfile archive "$archive_normalized" \
  --slurpfile worker "$worker_truth_normalized" \
  --slurpfile resource "$resource_envelope_normalized" \
  --slurpfile topology_plan "$topology_plan_normalized" \
  --slurpfile topology_receipt "$topology_receipt_normalized" \
  --slurpfile topology_ledger "$topology_ledger_normalized" \
  --arg schema_version "franken-engine.swarm-proof-cache-locality-plan.v1" \
  --arg source_revision "$source_revision" \
  --arg admission_budget_plan_json "$admission_budget_plan_json" \
  --arg warm_target_prefetch_roi_advisory_json "$warm_target_prefetch_roi_advisory_json" \
  --arg proof_cache_plan_json "$proof_cache_plan_json" \
  --arg archive_pressure_scoreboard_json "$archive_pressure_scoreboard_json" \
  --arg worker_truth_report_json "$worker_truth_report_json" \
  --arg swarm_resource_envelope_json "$swarm_resource_envelope_json" \
  --arg swarm_topology_placement_plan_json "$swarm_topology_placement_plan_json" \
  --arg swarm_topology_placement_receipt_json "$swarm_topology_placement_receipt_json" \
  --arg swarm_topology_placement_evidence_ledger_json "$swarm_topology_placement_evidence_ledger_json" \
  --arg plan_path "$plan_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" '
  def low($value): (($value // "") | tostring | ascii_downcase);
  def arr($value): if ($value | type) == "array" then $value else [] end;
  def uniq_reasons: unique_by([.code, .source_id, .detail]);
  def reason($code; $source; $detail): {code:$code,source_id:$source,detail:$detail};
  def mutates($doc):
    (($doc.mutation_policy.runs_cargo // false) == true)
    or (($doc.mutation_policy.runs_rch // false) == true)
    or (($doc.mutation_policy.mutates_remote_workers // false) == true)
    or (($doc.mutation_policy.changes_live_queue_policy // false) == true)
    or (($doc.mutation_policy.pins_workers_automatically // false) == true)
    or (($doc.mutation_policy.rebinds_hosts_automatically // false) == true)
    or (($doc.mutation_policy.deletes_or_overwrites_target_dirs // false) == true);
  def worker_schedulable($worker_id; $worker_doc):
    any(($worker_doc.worker_rows // [])[]?;
      (.worker_id == $worker_id)
      and ((.probe_schedulable // true) == true)
      and ((.daemon_status // "idle") | IN("idle", "available", "ok"))
    );
  def active_lock_matches($target_dir; $locks):
    any($locks[]?;
      (($target_dir // "") | length) > 0
      and (((.target_dir // .path // "") == $target_dir)
        or (($target_dir | startswith((.target_dir // .path // "___never___")))))
    );
  def rec($id; $action; $target_dir; $worker_id; $confidence; $manual; $reasons):
    {
      recommendation_id:$id,
      action:$action,
      target_dir:$target_dir,
      worker_id:$worker_id,
      confidence:$confidence,
      manual_confirmation_required:$manual,
      deletes_or_overwrites_artifacts:false,
      reason_codes:$reasons,
      advisory_command:("# advisory-only " + $action + " target=" + (($target_dir // "none") | tostring) + " worker=" + (($worker_id // "none") | tostring))
    };

  ($admission[0]) as $admission_doc
  | ($warm[0]) as $warm_doc
  | ($cache[0]) as $cache_doc
  | ($archive[0]) as $archive_doc
  | ($worker[0]) as $worker_doc
  | ($resource[0]) as $resource_doc
  | ($topology_plan[0]) as $topology_plan_doc
  | ($topology_receipt[0]) as $topology_receipt_doc
  | ($topology_ledger[0]) as $topology_ledger_doc
  | (arr($resource_doc.active_target_locks) + arr($warm_doc.active_target_locks) + arr($cache_doc.active_target_locks)) as $active_locks
  | (($warm_doc.warm_target_summary.target_dir // ($topology_plan_doc.recommended_worker_targets[0].target_dir // null))) as $target_dir
  | (($warm_doc.warm_target_summary.worker_id // ($topology_receipt_doc.recommended_worker_ids[0] // ($topology_plan_doc.recommended_worker_targets[0].worker_id // null)))) as $worker_id
  | (low($warm_doc.advisory)) as $warm_advisory
  | (low($warm_doc.recommended_action)) as $warm_action
  | (low($cache_doc.proof_cache_decision)) as $cache_decision
  | (low($archive_doc.advisory)) as $archive_advisory
  | (low($archive_doc.pressure_level)) as $archive_pressure
  | (low($resource_doc.decision)) as $resource_decision
  | (low($resource_doc.readiness)) as $resource_readiness
  | (low($topology_plan_doc.decision)) as $topology_plan_decision
  | (low($topology_receipt_doc.decision)) as $topology_receipt_decision
  | (low($topology_receipt_doc.adoption_status)) as $adoption_status
  | (($resource_doc.capacity_budget.remote_rch_slot_limit // $resource_doc.rch_slots.available // 0) | tonumber) as $remote_slots
  | (($resource_doc.memory_pressure.total_bytes // 0) | tonumber) as $memory_total
  | (($resource_doc.host_profile // (if $memory_total >= 274877906944 or $remote_slots >= 12 then "64c_256g" else "small_host" end))) as $host_profile
  | (arr($cache_doc.cache_hit_artifacts) | map(select(((.artifact_id // "") | length) == 0 or ((.artifact_path // "") | length) == 0))) as $bad_cache_hits
  | (
      [
        if (($admission_doc.schema_version // "") != "franken-engine.swarm-admission-budget-plan.v1") then reason("bad_schema"; "admission_budget_plan_json"; "admission budget plan schema is unexpected") else empty end,
        if (($warm_doc.schema_version // "") != "franken-engine.swarm-warm-target-prefetch-roi-advisory.v1") then reason("bad_schema"; "warm_target_prefetch_roi_advisory_json"; "warm-target ROI advisory schema is unexpected") else empty end,
        if (($cache_doc.schema_version // "") != "franken-engine.proof-reuse-cache-plan.v1") then reason("bad_schema"; "proof_cache_plan_json"; "proof cache plan schema is unexpected") else empty end,
        if (($archive_doc.schema_version // "") != "franken-engine.remote-proof-archive-pressure-scoreboard.v1") then reason("bad_schema"; "archive_pressure_scoreboard_json"; "archive pressure scoreboard schema is unexpected") else empty end,
        if (($worker_doc.schema_version // "") != "franken-engine.rch-worker-truth-parity-report.v1") then reason("bad_schema"; "worker_truth_report_json"; "worker truth report schema is unexpected") else empty end,
        if (($resource_doc.schema_version // "") != "franken-engine.swarm-resource-envelope.v1") then reason("bad_schema"; "swarm_resource_envelope_json"; "resource envelope schema is unexpected") else empty end,
        if (($topology_plan_doc.schema_version // "") != "franken-engine.swarm-topology-placement-plan.v1") then reason("missing_swarm_scale_ii_evidence"; "swarm_topology_placement_plan_json"; "topology placement plan is missing or wrong schema") else empty end,
        if (($topology_receipt_doc.schema_version // "") != "franken-engine.swarm-topology-placement-receipt.v1") then reason("missing_swarm_scale_ii_evidence"; "swarm_topology_placement_receipt_json"; "topology placement receipt is missing or wrong schema") else empty end,
        if (($topology_ledger_doc.schema_version // "") != "franken-engine.swarm-topology-placement-evidence-ledger.v1") then reason("missing_swarm_scale_ii_evidence"; "swarm_topology_placement_evidence_ledger_json"; "topology placement evidence ledger is missing or wrong schema") else empty end,
        if ($topology_plan_decision == "fail_closed" or $topology_receipt_decision == "fail_closed" or low($topology_ledger_doc.decision) == "fail_closed") then reason("swarm_scale_ii_fail_closed"; "swarm_topology_placement_receipt_json"; "SWARM-SCALE-II placement evidence is fail-closed") else empty end,
        if ($topology_plan_decision == "blocked" or $topology_receipt_decision == "blocked" or $adoption_status == "not_applicable") then reason("contradictory_topology_evidence"; "swarm_topology_placement_receipt_json"; "SWARM-SCALE-II placement evidence is blocked or not adoptable") else empty end,
        if (($worker_doc.decision // "") == "fail_closed" or (($worker_doc.findings // []) | length) > 0) then reason("worker_truth_drift"; "worker_truth_report_json"; "worker truth parity is fail-closed or has findings") else empty end,
        if ($worker_id != null and (worker_schedulable($worker_id; $worker_doc) | not)) then reason("worker_not_schedulable"; "worker_truth_report_json"; "recommended worker is not schedulable in worker truth evidence") else empty end,
        if ($archive_advisory == "fail_closed") then reason("archive_truth_fail_closed"; "archive_pressure_scoreboard_json"; "remote proof archive pressure scoreboard failed closed") else empty end,
        if (($bad_cache_hits | length) > 0) then reason("cache_hit_artifact_incomplete"; "proof_cache_plan_json"; "cache-hit artifacts must include artifact id and path") else empty end,
        if mutates($warm_doc) or mutates($resource_doc) or mutates($topology_plan_doc) or mutates($topology_receipt_doc) or mutates($topology_ledger_doc) then reason("unsafe_mutation_policy"; "input_artifacts"; "an upstream artifact claims live mutation or target overwrite authority") else empty end
      ] + arr($topology_plan_doc.fail_closed_reasons) + arr($topology_receipt_doc.fail_closed_reasons)
      | uniq_reasons
    ) as $fail_closed_reasons
  | (
      [
        if active_lock_matches($target_dir; $active_locks) then reason("active_target_pinned"; "active_target_locks"; "target dir has active build or preserve lock evidence") else empty end
      ] | uniq_reasons
    ) as $blocked_reasons
  | (
      [
        if ($archive_pressure | IN("high", "critical")) or ($resource_decision == "blocked") or ($resource_readiness | IN("defer", "blocked")) then reason("target_pressure_requires_cooling"; "swarm_resource_envelope_json"; "disk, memory, archive, or resource pressure blocks immediate warm-target reuse") else empty end,
        if ($archive_advisory | IN("compaction_first", "stale", "refresh_required")) then reason("stale_archive_evidence"; "archive_pressure_scoreboard_json"; "archive evidence needs refresh or compaction before reuse confidence is high") else empty end,
        if ($warm_advisory | IN("defer", "cool_archive")) or ($warm_action | contains("cool")) then reason("warm_target_cooling_required"; "warm_target_prefetch_roi_advisory_json"; "warm-target advisory asks for cooling or deferral") else empty end,
        if ($cache_decision | IN("refresh_required", "partial_refresh", "stale")) then reason("proof_cache_refresh_required"; "proof_cache_plan_json"; "proof cache requires refresh before reuse confidence is high") else empty end
      ] | uniq_reasons
    ) as $degraded_reasons
  | (
      ($cache_decision == "cache_hit")
      and (($cache_doc.cache_hit_artifacts // []) | length > 0)
      and ($warm_advisory | IN("reuse_hot_cache", "prefetch_recommended", "prefetch_archive"))
      and ($target_dir != null)
      and ($worker_id != null)
      and ($topology_plan_decision == "pass")
      and ($topology_receipt_decision == "pass")
      and ($adoption_status == "adopted")
    ) as $can_reuse_hot
  | (
      ($cache_decision | IN("refresh_required", "partial_refresh", "cache_miss", "cold"))
      or (($topology_plan_doc.warm_cache_residency_state // "") == "cold")
      or (($warm_doc.warm_target_summary.target_dir // null) == null)
    ) as $needs_fresh_target
  | (if ($fail_closed_reasons | length) > 0 then "fail_closed"
     elif ($blocked_reasons | length) > 0 then "blocked"
     elif ($degraded_reasons | length) > 0 then "degraded"
     else "pass"
     end) as $decision
  | (if $decision == "fail_closed" then
       [rec("manual-review-required"; "manual_review"; $target_dir; $worker_id; "none"; true; ($fail_closed_reasons | map(.code) | unique | sort))]
     elif $decision == "blocked" then
       [rec("preserve-active-target"; "preserve_active_target"; $target_dir; $worker_id; "blocked"; true; ($blocked_reasons | map(.code) | unique | sort))]
     elif any($degraded_reasons[]?; .code == "target_pressure_requires_cooling") then
       [rec("cool-target-manual"; "cool_target"; $target_dir; $worker_id; "bounded"; true; ($degraded_reasons | map(.code) | unique | sort))]
     elif any($degraded_reasons[]?; .code == "stale_archive_evidence") then
       [rec("refresh-archive-evidence"; "refresh_archive_evidence"; $target_dir; $worker_id; "partial"; true; ($degraded_reasons | map(.code) | unique | sort))]
     elif $can_reuse_hot then
       [rec("reuse-warm-target"; "reuse_warm_target"; $target_dir; $worker_id; "high"; false; ["topology_adopted", "proof_cache_hit", "worker_truth_pass"])]
     elif $needs_fresh_target then
       [rec("allocate-fresh-target"; "allocate_fresh_target"; null; $worker_id; "bounded"; false; ["cold_or_missing_cache", "avoid_overclaiming_reuse"])]
     else
       [rec("cool-target-before-reuse"; "cool_target"; $target_dir; $worker_id; "partial"; true; ["insufficient_reuse_confidence"])]
     end) as $recommendations
  | {
      schema_version: $schema_version,
      source_revision: $source_revision,
      decision: $decision,
      host_profile: $host_profile,
      target_dir: $target_dir,
      worker_id: $worker_id,
      topology_summary: {
        plan_decision: $topology_plan_decision,
        receipt_decision: $topology_receipt_decision,
        ledger_decision: (low($topology_ledger_doc.decision)),
        adoption_status: $adoption_status,
        recommended_topology_class: ($topology_plan_doc.recommended_topology_class // "unknown"),
        warm_cache_residency_state: ($topology_plan_doc.warm_cache_residency_state // "unknown"),
        placement_receipt_id: ($topology_receipt_doc.receipt_id // null)
      },
      proof_cache_summary: {
        proof_cache_decision: ($cache_doc.proof_cache_decision // "unknown"),
        cache_hit_count: (($cache_doc.cache_hit_artifacts // []) | length),
        refresh_count: (($cache_doc.required_refreshes // []) | length)
      },
      archive_summary: {
        advisory: ($archive_doc.advisory // "unknown"),
        pressure_level: ($archive_doc.pressure_level // "unknown"),
        recommended_action: ($archive_doc.recommended_action // "unknown")
      },
      resource_summary: {
        decision: ($resource_doc.decision // "unknown"),
        readiness: ($resource_doc.readiness // "unknown"),
        remote_rch_slot_limit: $remote_slots,
        memory_total_bytes: $memory_total
      },
      fail_closed_reasons: $fail_closed_reasons,
      blocked_reasons: $blocked_reasons,
      degraded_reasons: $degraded_reasons,
      recommendations: $recommendations,
      summary: {
        recommendation_count: ($recommendations | length),
        reuse_recommendation_count: ($recommendations | map(select(.action == "reuse_warm_target")) | length),
        fresh_target_recommendation_count: ($recommendations | map(select(.action == "allocate_fresh_target")) | length),
        cooling_recommendation_count: ($recommendations | map(select(.action == "cool_target")) | length),
        preserve_active_target_count: ($recommendations | map(select(.action == "preserve_active_target")) | length),
        fail_closed_count: ($fail_closed_reasons | length),
        blocked_count: ($blocked_reasons | length),
        degraded_count: ($degraded_reasons | length)
      },
      mutation_policy: {
        fixture_fed_only: true,
        proof_only: true,
        advisory_only: true,
        runs_cargo: false,
        runs_rch: false,
        mutates_br: false,
        sends_agent_mail: false,
        mutates_remote_workers: false,
        changes_live_queue_policy: false,
        pins_workers_automatically: false,
        rebinds_hosts_automatically: false,
        deletes_or_overwrites_target_dirs: false
      },
      upstream_artifact_paths: {
        admission_budget_plan_json: $admission_budget_plan_json,
        warm_target_prefetch_roi_advisory_json: $warm_target_prefetch_roi_advisory_json,
        proof_cache_plan_json: $proof_cache_plan_json,
        archive_pressure_scoreboard_json: $archive_pressure_scoreboard_json,
        worker_truth_report_json: $worker_truth_report_json,
        swarm_resource_envelope_json: $swarm_resource_envelope_json,
        swarm_topology_placement_plan_json: $swarm_topology_placement_plan_json,
        swarm_topology_placement_receipt_json: $swarm_topology_placement_receipt_json,
        swarm_topology_placement_evidence_ledger_json: $swarm_topology_placement_evidence_ledger_json
      },
      artifact_paths: {
        locality_plan_json: $plan_path,
        events_jsonl: $events_path,
        commands_txt: $commands_path,
        report_md: $report_path
      }
    }' >"$core_path"

plan_hash="$(jq -cS 'del(.artifact_paths)' "$core_path" | sha256sum | awk '{print $1}')"
plan_id="swarm-proof-cache-locality-${plan_hash:0:16}"
jq --arg plan_id "$plan_id" --arg plan_hash "$plan_hash" \
  '. + {plan_id:$plan_id, hash_basis:{plan_hash:$plan_hash}}' \
  "$core_path" >"$plan_tmp"
mv "$plan_tmp" "$plan_path"

decision="$(jq -r '.decision' "$plan_path")"
write_event "locality_plan.emitted" "$decision" "emitted proof-cache locality plan" "$plan_path"

{
  printf '# Swarm Proof Cache Locality Plan\n\n'
  printf -- "- Decision: \`%s\`\n" "$decision"
  printf -- "- Host profile: \`%s\`\n" "$(jq -r '.host_profile' "$plan_path")"
  printf -- "- Target dir: \`%s\`\n" "$(jq -r '.target_dir // "none"' "$plan_path")"
  printf -- "- Worker: \`%s\`\n" "$(jq -r '.worker_id // "none"' "$plan_path")"
  printf -- "- Recommendations: \`%s\`\n\n" "$(jq '.summary.recommendation_count' "$plan_path")"

  printf '## Recommendations\n'
  jq -r '.recommendations[] | "- `" + .action + "` target=`" + (.target_dir // "none") + "` worker=`" + (.worker_id // "none") + "` confidence=`" + .confidence + "` manual=`" + (.manual_confirmation_required | tostring) + "`"' "$plan_path"
  printf '\n'
  if [[ "$(jq '.fail_closed_reasons | length' "$plan_path")" -gt 0 ]]; then
    printf '## Fail-Closed Reasons\n'
    jq -r '.fail_closed_reasons[] | "- `" + .code + "` `" + .source_id + "`: " + .detail' "$plan_path"
    printf '\n'
  fi
  if [[ "$(jq '.blocked_reasons | length' "$plan_path")" -gt 0 ]]; then
    printf '## Blocked Reasons\n'
    jq -r '.blocked_reasons[] | "- `" + .code + "` `" + .source_id + "`: " + .detail' "$plan_path"
    printf '\n'
  fi
  if [[ "$(jq '.degraded_reasons | length' "$plan_path")" -gt 0 ]]; then
    printf '## Degraded Reasons\n'
    jq -r '.degraded_reasons[] | "- `" + .code + "` `" + .source_id + "`: " + .detail' "$plan_path"
    printf '\n'
  fi
} >"$report_path"

printf 'locality_plan_json=%s\n' "$plan_path"
printf 'locality_plan_report_md=%s\n' "$report_path"

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
