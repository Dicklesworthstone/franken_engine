#!/usr/bin/env bash
set -euo pipefail

artifact_root="${BUILD_STORM_QOS_BATCH_PLANNER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-build-storm-qos-batch-planner}"
run_id="${BUILD_STORM_QOS_BATCH_PLANNER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${BUILD_STORM_QOS_BATCH_PLANNER_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

pending_requests_json=""
resource_lease_plans_json=""
proof_cost_history_json=""
rch_workers_json=""
max_parallel_heavy="2"
max_per_agent_heavy="1"
default_retry_after_seconds="300"
stale_retry_after_seconds="45"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/build_storm_qos_batch_planner.sh --pending-requests-json FILE --resource-lease-plans-json FILE --proof-cost-history-json FILE --rch-workers-json FILE [OPTIONS]

Builds deterministic validation batches for heavy swarm proof storms. The
planner consumes fixtures only and never executes commands.

Required:
  --pending-requests-json FILE        Pending validation requests.
  --resource-lease-plans-json FILE    Resource lease planner receipts.
  --proof-cost-history-json FILE      Proof cost history rows.
  --rch-workers-json FILE             rch worker health snapshot.

Options:
  --output-dir DIR
  --max-parallel-heavy N              Global heavy-command batch cap.
  --max-per-agent-heavy N             Per-agent heavy-command cap.
  --default-retry-after-seconds N
  --stale-retry-after-seconds N

Writes build_storm_batch_plan.json, events.jsonl, commands.txt, and report.md.
Exit codes: 0 planned with admissions, 75 all requests deferred, 64 bad input.
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --pending-requests-json)
      pending_requests_json="${2:-}"
      shift 2
      ;;
    --resource-lease-plans-json)
      resource_lease_plans_json="${2:-}"
      shift 2
      ;;
    --proof-cost-history-json)
      proof_cost_history_json="${2:-}"
      shift 2
      ;;
    --rch-workers-json)
      rch_workers_json="${2:-}"
      shift 2
      ;;
    --output-dir)
      run_dir="${2:-}"
      shift 2
      ;;
    --max-parallel-heavy)
      max_parallel_heavy="${2:-}"
      shift 2
      ;;
    --max-per-agent-heavy)
      max_per_agent_heavy="${2:-}"
      shift 2
      ;;
    --default-retry-after-seconds)
      default_retry_after_seconds="${2:-}"
      shift 2
      ;;
    --stale-retry-after-seconds)
      stale_retry_after_seconds="${2:-}"
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
  [[ "$1" =~ ^[0-9]+$ ]]
}

for required in pending_requests_json resource_lease_plans_json proof_cost_history_json rch_workers_json; do
  if [[ -z "${!required}" ]]; then
    printf 'build storm planner missing required %s\n' "$required" >&2
    usage
    exit 64
  fi
done

if ! is_int "$max_parallel_heavy" ||
  ! is_int "$max_per_agent_heavy" ||
  ! is_int "$default_retry_after_seconds" ||
  ! is_int "$stale_retry_after_seconds"; then
  printf 'batch planner numeric options must be non-negative integers\n' >&2
  exit 64
fi

mkdir -p "$run_dir"
plan_path="${run_dir}/build_storm_batch_plan.json"
plan_tmp="${plan_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
pending_normalized="${run_dir}/pending_requests.normalized.json"
leases_normalized="${run_dir}/resource_lease_plans.normalized.json"
costs_normalized="${run_dir}/proof_cost_history.normalized.json"
workers_normalized="${run_dir}/rch_workers.normalized.json"
decisions_jsonl="${run_dir}/decisions.jsonl"
: >"$events_path"
: >"$decisions_jsonl"

printf './scripts/build_storm_qos_batch_planner.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

json_input() {
  local path="$1"
  local output_path="$2"
  local label="$3"

  if [[ ! -f "$path" ]]; then
    printf 'build storm planner missing %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null; then
    printf 'build storm planner invalid %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  jq -c . "$path" >"$output_path"
}

json_input "$pending_requests_json" "$pending_normalized" "pending requests"
json_input "$resource_lease_plans_json" "$leases_normalized" "resource lease plans"
json_input "$proof_cost_history_json" "$costs_normalized" "proof cost history"
json_input "$rch_workers_json" "$workers_normalized" "rch workers"

batch_id="$(
  jq -S -c -n \
    --slurpfile pending "$pending_normalized" \
    --slurpfile leases "$leases_normalized" \
    --slurpfile costs "$costs_normalized" \
    --slurpfile workers "$workers_normalized" \
    --argjson max_parallel_heavy "$max_parallel_heavy" \
    --argjson max_per_agent_heavy "$max_per_agent_heavy" \
    '{
      pending: $pending[0],
      leases: $leases[0],
      costs: $costs[0],
      workers: $workers[0],
      max_parallel_heavy: $max_parallel_heavy,
      max_per_agent_heavy: $max_per_agent_heavy
    }' |
    sha256sum |
    awk '{print "batch-" substr($1, 1, 16)}'
)"

idle_worker_count="$(
  jq '[.workers[]? | select((.status // "") as $s | $s == "idle" or $s == "available" or $s == "ok")] | length' \
    "$workers_normalized"
)"
if (( idle_worker_count < max_parallel_heavy )); then
  effective_max_parallel_heavy="$idle_worker_count"
else
  effective_max_parallel_heavy="$max_parallel_heavy"
fi

jq -n \
  --slurpfile pending "$pending_normalized" \
  --slurpfile leases "$leases_normalized" \
  --slurpfile costs "$costs_normalized" \
  --slurpfile workers "$workers_normalized" \
  --arg schema_version "franken-engine.build-storm-batch-plan.v1" \
  --arg batch_id "$batch_id" \
  --arg plan_path "$plan_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --argjson configured_max_parallel_heavy "$max_parallel_heavy" \
  --argjson max_parallel_heavy "$effective_max_parallel_heavy" \
  --argjson max_per_agent_heavy "$max_per_agent_heavy" \
  --argjson default_retry_after_seconds "$default_retry_after_seconds" \
  --argjson stale_retry_after_seconds "$stale_retry_after_seconds" \
  '
  def arr($x; $name): if ($x | type) == "array" then $x else ($x[$name] // []) end;
  def lease_rows: arr($leases[0]; "plans");
  def cost_rows: arr($costs[0]; "history");
  def req_rows: arr($pending[0]; "requests");
  def is_heavy($cmd; $heavy):
    ($heavy == true) or (($cmd // "") | test("(^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$)"));
  def lease_for($r):
    first(lease_rows[]? | select(
      ((.request_id // "") != "" and (.request_id // "") == ($r.request_id // ""))
      or ((.bead_id // "") != "" and (.bead_id // "") == ($r.bead_id // ""))
    )) // {};
  def cost_for($r):
    first(cost_rows[]? | select(
      ((.request_id // "") != "" and (.request_id // "") == ($r.request_id // ""))
      or ((.command_fingerprint // "") != "" and (.command_fingerprint // "") == ($r.command_fingerprint // ""))
      or ((.bead_id // "") != "" and (.bead_id // "") == ($r.bead_id // ""))
    )) // {};
  def normalize($r):
    (lease_for($r)) as $lease
    | (cost_for($r)) as $cost
    | ($r.command // $lease.requested_command // "") as $cmd
    | (is_heavy($cmd; ($r.heavy // $r.heavy_rust // false))) as $heavy
    | {
        request_id: ($r.request_id // (($r.agent_id // "unknown-agent") + ":" + ($r.bead_id // "unknown-bead") + ":" + ($cmd | tostring))),
        agent_id: ($r.agent_id // "unknown-agent"),
        bead_id: ($r.bead_id // ""),
        bead_priority: (($r.bead_priority // $r.priority // 3) | tonumber),
        command: $cmd,
        target_dir: ($r.target_dir // $lease.target_dir // ""),
        heavy: $heavy,
        docs_only: (($r.docs_only // false) == true),
        broad_check: (($r.broad_check // false) == true) or ($cmd | test("--all-targets|cargo[[:space:]]+test([[:space:]]|$)")),
        proof_refresh: (($r.proof_refresh // $r.fail_closed_proof_refresh // false) == true),
        fail_closed_proof_refresh: (($r.fail_closed_proof_refresh // false) == true),
        stale_proof_refresh: (($r.stale_proof_refresh // false) == true),
        wait_seconds: (($r.wait_seconds // $r.age_seconds // 0) | tonumber),
        submitted_order: (($r.submitted_order // 0) | tonumber),
        estimated_seconds: (($r.estimated_seconds // $cost.median_seconds // $cost.p95_seconds // 0) | tonumber),
        lease_decision: (($lease.lease_decision // $lease.decision // "admit") | ascii_downcase),
        lease_reason: ($lease.reason // "lease admitted"),
        priority_class: ("P" + ((($r.bead_priority // $r.priority // 3) | tonumber) | tostring))
      };
  def sort_key:
    [
      (if .fail_closed_proof_refresh then 0 elif .proof_refresh then 1 elif .docs_only then 4 else 2 end),
      (if .stale_proof_refresh then 0 else 1 end),
      .bead_priority,
      (if .broad_check then 1 else 0 end),
      (-.wait_seconds),
      .agent_id,
      .bead_id,
      .request_id
    ];
  def defer_obj($r; $reason; $retry):
    $r + {
      batch_decision: "defer",
      fairness_reason: $reason,
      retry_after_seconds: $retry
    };
  def admit_obj($r; $reason):
    $r + {
      batch_decision: "admit",
      fairness_reason: $reason,
      retry_after_seconds: 0
    };

  (req_rows | map(normalize(.)) | sort_by(sort_key)) as $sorted
  | reduce $sorted[] as $r (
      {admitted: [], deferred: [], heavy_used: 0, agent_heavy_counts: {}};
      if ($r.lease_decision | IN("admit", "admit_narrow")) | not then
        .deferred += [defer_obj($r; ("resource lease planner returned " + $r.lease_decision + ": " + $r.lease_reason); $default_retry_after_seconds)]
      elif $r.heavy and ($max_parallel_heavy == 0) then
        .deferred += [defer_obj($r; "all rch workers busy; no heavy validation slots available"; $default_retry_after_seconds)]
      elif $r.heavy and (.heavy_used >= $max_parallel_heavy) then
        .deferred += [defer_obj($r; "batch heavy capacity reached after higher-ranked validation requests"; (if $r.stale_proof_refresh then $stale_retry_after_seconds else $default_retry_after_seconds end))]
      elif $r.heavy and ((.agent_heavy_counts[$r.agent_id] // 0) >= $max_per_agent_heavy) then
        .deferred += [defer_obj($r; "agent fairness throttle prevents one agent from monopolizing heavy slots"; (if $r.stale_proof_refresh then $stale_retry_after_seconds else $default_retry_after_seconds end))]
      else
        .admitted += [admit_obj($r; (if $r.heavy then "admitted within heavy capacity and per-agent fairness budget" else "admitted as light validation outside heavy capacity" end))]
        | if $r.heavy then
            .heavy_used += 1
            | .agent_heavy_counts[$r.agent_id] = ((.agent_heavy_counts[$r.agent_id] // 0) + 1)
          else
            .
          end
      end
    ) as $state
  | ($state.deferred | map(.retry_after_seconds) | min // 0) as $retry_after
  | {
      schema_version: $schema_version,
      batch_id: $batch_id,
      stable_output_hash: "",
      batch_decision: (if ($state.admitted | length) > 0 then "planned" else "all_deferred" end),
      fairness_reason: (
        if ($state.admitted | length) == 0 then
          "all requests deferred by worker capacity, resource leases, or fairness gates"
        elif ($state.deferred | length) > 0 then
          "admitted highest-ranked requests while deferring lower-ranked or over-budget work"
        else
          "all pending requests fit within fairness and worker capacity"
        end
      ),
      max_parallel_heavy: $max_parallel_heavy,
      configured_max_parallel_heavy: $configured_max_parallel_heavy,
      max_per_agent_heavy: $max_per_agent_heavy,
      retry_after_seconds: $retry_after,
      admitted_commands: $state.admitted,
      deferred_commands: $state.deferred,
      rch_worker_snapshot: {
        total_workers: (arr($workers[0]; "workers") | length),
        idle_workers: $max_parallel_heavy
      },
      artifact_paths: {
        build_storm_batch_plan_json: $plan_path,
        events_jsonl: $events_path,
        commands_txt: $commands_path,
        report_md: $report_path
      }
    }
  ' >"$plan_tmp"
mv "$plan_tmp" "$plan_path"

stable_output_hash="$(
  jq -S -c 'del(.artifact_paths, .stable_output_hash)' "$plan_path" |
    sha256sum |
    awk '{print $1}'
)"
jq --arg stable_output_hash "$stable_output_hash" \
  '.stable_output_hash = $stable_output_hash' "$plan_path" >"$plan_tmp"
mv "$plan_tmp" "$plan_path"

{
  jq -c --arg batch_id "$batch_id" '
    .admitted_commands[]
    | {
        schema_version: "franken-engine.build-storm-batch-event.v1",
        event_name: "build_storm_qos_batch_planner.admitted",
        batch_id: $batch_id,
        request_id,
        agent_id,
        bead_id,
        fairness_reason
      }
  ' "$plan_path"
  jq -c --arg batch_id "$batch_id" '
    .deferred_commands[]
    | {
        schema_version: "franken-engine.build-storm-batch-event.v1",
        event_name: "build_storm_qos_batch_planner.deferred",
        batch_id: $batch_id,
        request_id,
        agent_id,
        bead_id,
        fairness_reason,
        retry_after_seconds
      }
  ' "$plan_path"
  jq -nc \
    --arg schema_version "franken-engine.build-storm-batch-event.v1" \
    --arg event_name "build_storm_qos_batch_planner.decision" \
    --arg batch_id "$batch_id" \
    --arg decision "$(jq -r '.batch_decision' "$plan_path")" \
    --argjson admitted "$(jq '.admitted_commands | length' "$plan_path")" \
    --argjson deferred "$(jq '.deferred_commands | length' "$plan_path")" \
    '{
      schema_version: $schema_version,
      event_name: $event_name,
      batch_id: $batch_id,
      batch_decision: $decision,
      admitted_count: $admitted,
      deferred_count: $deferred
    }'
} >>"$events_path"

{
  printf '# Build Storm QoS Batch Plan\n\n'
  printf "%s\n" "- Batch: \`${batch_id}\`"
  printf "%s\n" "- Decision: \`$(jq -r '.batch_decision' "$plan_path")\`"
  printf "%s\n" "- Admitted commands: \`$(jq '.admitted_commands | length' "$plan_path")\`"
  printf "%s\n" "- Deferred commands: \`$(jq '.deferred_commands | length' "$plan_path")\`"
  printf "%s\n" "- Max parallel heavy: \`$(jq '.max_parallel_heavy' "$plan_path")\`"
  printf "%s\n" "- Retry after seconds: \`$(jq '.retry_after_seconds' "$plan_path")\`"
} >"$report_path"

if [[ "$(jq -r '.batch_decision' "$plan_path")" == "all_deferred" ]]; then
  exit 75
fi
exit 0
