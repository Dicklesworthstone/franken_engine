#!/usr/bin/env bash
set -euo pipefail

artifact_root="${STICKY_WORKER_WARM_TARGET_LEASE_PLANNER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-sticky-worker-warm-target-lease-planner}"
run_id="${STICKY_WORKER_WARM_TARGET_LEASE_PLANNER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${STICKY_WORKER_WARM_TARGET_LEASE_PLANNER_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

agent_id=""
bead_id=""
suite_manifest_json=""
sticky_worker_state_json=""
rch_workers_json=""
reservation_snapshot_json=""
local_fallback_markers_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/sticky_worker_warm_target_lease_planner.sh --agent-id ID --bead-id ID --suite-manifest-json FILE --rch-workers-json FILE [OPTIONS]

Build a planning-only sticky-worker and warm-target lease plan for repeated
remote proof suites. This script consumes deterministic fixture snapshots and
never executes Cargo or queries live rch state.

Required:
  --agent-id ID
  --bead-id ID
  --suite-manifest-json FILE
  --rch-workers-json FILE

Optional:
  --sticky-worker-state-json FILE
  --reservation-snapshot-json FILE
  --local-fallback-markers-json FILE
  --output-dir DIR

Artifacts:
  sticky_worker_warm_target_plan.json
  sticky_worker_warm_target_summary.md
  commands.txt
  events.jsonl

Exit codes:
  0  admitted using sticky or fallback worker
  42 fail-closed due to local fallback evidence
  75 deferred because no safe warm-target assignment exists
  64 invalid or missing input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --agent-id)
      agent_id="${2:-}"
      shift 2
      ;;
    --bead-id)
      bead_id="${2:-}"
      shift 2
      ;;
    --suite-manifest-json)
      suite_manifest_json="${2:-}"
      shift 2
      ;;
    --sticky-worker-state-json)
      sticky_worker_state_json="${2:-}"
      shift 2
      ;;
    --rch-workers-json)
      rch_workers_json="${2:-}"
      shift 2
      ;;
    --reservation-snapshot-json)
      reservation_snapshot_json="${2:-}"
      shift 2
      ;;
    --local-fallback-markers-json)
      local_fallback_markers_json="${2:-}"
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

if [[ -z "$agent_id" || -z "$bead_id" || -z "$suite_manifest_json" || -z "$rch_workers_json" ]]; then
  printf 'sticky-worker planner requires --agent-id, --bead-id, --suite-manifest-json, and --rch-workers-json\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for sticky-worker warm-target planning\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for sticky-worker warm-target planning\n' >&2
  exit 2
fi

mkdir -p "$run_dir"
plan_path="${run_dir}/sticky_worker_warm_target_plan.json"
plan_tmp="${plan_path}.tmp"
summary_path="${run_dir}/sticky_worker_warm_target_summary.md"
summary_tmp="${summary_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
manifest_normalized="${run_dir}/suite_manifest.normalized.json"
sticky_state_normalized="${run_dir}/sticky_worker_state.normalized.json"
workers_normalized="${run_dir}/rch_workers.normalized.json"
reservations_normalized="${run_dir}/reservation_snapshot.normalized.json"
fallback_markers_normalized="${run_dir}/local_fallback_markers.normalized.json"
plan_core="${run_dir}/plan_core.json"
: >"$events_path"

printf './scripts/sticky_worker_warm_target_lease_planner.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  jq -nc \
    --arg event "$1" \
    --arg detail "$2" \
    '{event: $event, detail: $detail}' >>"$events_path"
}

json_input() {
  local path="$1"
  local default_json="$2"
  local output_path="$3"
  local label="$4"

  if [[ -z "$path" ]]; then
    printf '%s\n' "$default_json" >"$output_path"
    printf 'missing'
    return 0
  fi
  if [[ ! -f "$path" ]]; then
    printf 'sticky-worker planner missing %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf 'sticky-worker planner invalid %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  jq -cS . "$path" >"$output_path"
  printf 'provided'
}

if [[ ! -f "$suite_manifest_json" ]]; then
  printf 'sticky-worker planner missing suite manifest JSON: %s\n' "$suite_manifest_json" >&2
  exit 64
fi
if ! jq empty "$suite_manifest_json" >/dev/null 2>&1; then
  printf 'sticky-worker planner invalid suite manifest JSON: %s\n' "$suite_manifest_json" >&2
  exit 64
fi
if [[ ! -f "$rch_workers_json" ]]; then
  printf 'sticky-worker planner missing rch workers JSON: %s\n' "$rch_workers_json" >&2
  exit 64
fi
if ! jq empty "$rch_workers_json" >/dev/null 2>&1; then
  printf 'sticky-worker planner invalid rch workers JSON: %s\n' "$rch_workers_json" >&2
  exit 64
fi

jq -cS '
  {
    schema_version: (.schema_version // "unknown"),
    suite_id: (.suite_id // .suite // "unknown"),
    phases: (
      (.phases // .commands // [])
      | if type == "array" then . else [] end
      | map({
          phase: (.phase // .lane // .kind // "unknown"),
          command_id: (.command_id // .id // .phase // "unknown"),
          requested_command: (.requested_command // .command // ""),
          bead_id: (.bead_id // "")
        })
      | sort_by(.phase, .command_id, .requested_command)
    )
  }
' "$suite_manifest_json" >"$manifest_normalized"
write_event "suite_manifest_loaded" "normalized suite manifest"

sticky_state_status="$(json_input "$sticky_worker_state_json" '{"suite_id":"unknown","preferred_worker_id":"","warm_target_dir":"","last_successful_phase":""}' "$sticky_state_normalized" 'sticky worker state')"
reservations_status="$(json_input "$reservation_snapshot_json" '{"reservations":[]}' "$reservations_normalized" 'reservation snapshot')"
fallback_marker_status="$(json_input "$local_fallback_markers_json" '{"markers":[]}' "$fallback_markers_normalized" 'local fallback marker snapshot')"

jq -cS '
  {
    workers: (
      (.workers // [])
      | if type == "array" then . else [] end
      | map({
          worker_id: (.worker_id // .worker // "unknown"),
          status: (.status // "unknown"),
          cpu_slots_available: (.cpu_slots_available // .available_cpu_slots // 0),
          target_dir_root: (.target_dir_root // "/tmp")
        })
      | sort_by(.worker_id)
    )
  }
' "$rch_workers_json" >"$workers_normalized"
write_event "worker_snapshot_loaded" "normalized worker snapshot"

jq -n \
  --arg agent_id "$agent_id" \
  --arg bead_id "$bead_id" \
  --arg sticky_state_status "$sticky_state_status" \
  --arg reservations_status "$reservations_status" \
  --arg fallback_marker_status "$fallback_marker_status" \
  --slurpfile manifest "$manifest_normalized" \
  --slurpfile sticky "$sticky_state_normalized" \
  --slurpfile workers "$workers_normalized" \
  --slurpfile reservations "$reservations_normalized" \
  --slurpfile fallback_markers "$fallback_markers_normalized" '
  def worker_available($id):
    any(
      ($workers[0].workers // [])[]?;
      .worker_id == $id and ((.status == "idle") or (.status == "available") or (.status == "ok"))
    );
  def first_available_worker:
    first(
      ($workers[0].workers // [])[]?
      | select((.status == "idle") or (.status == "available") or (.status == "ok"))
    );
  def target_conflict($target):
    if ($target | length) == 0 then
      false
    else
      any(
        ($reservations[0].reservations // [])[]?;
        ((.target_dir // .path // .path_pattern // "") == $target)
        and ((.agent_id // .agent_name // .holder // "") != $agent_id)
      )
    end;
  def marker_hit:
    [
      ($fallback_markers[0].markers // [])[]?
      | select((.detected // false) == true)
    ];
  def phase_class($command):
    if ($command | test("(^|[[:space:]])cargo[[:space:]]+check([[:space:]]|$)")) then
      "check"
    elif ($command | test("(^|[[:space:]])cargo[[:space:]]+test([[:space:]]|$)")) then
      "test"
    elif ($command | test("(^|[[:space:]])cargo[[:space:]]+clippy([[:space:]]|$)")) then
      "clippy"
    else
      "other"
    end;
  def suite_slug:
    (($manifest[0].suite_id // "unknown") | gsub("[^A-Za-z0-9]+"; "_"));
  ($manifest[0]) as $manifest
  | ($sticky[0]) as $sticky
  | (marker_hit) as $markers
  | ($sticky.preferred_worker_id // "") as $sticky_worker_id
  | ($sticky.warm_target_dir // "") as $warm_target_dir
  | (worker_available($sticky_worker_id)) as $sticky_worker_available
  | (first_available_worker) as $fallback_worker
  | (
      if ($fallback_worker | type) == "object" then
        (($fallback_worker.target_dir_root // "/tmp") + "/rch_target_" + suite_slug + "_" + ($fallback_worker.worker_id // "worker"))
      else
        ""
      end
    ) as $fallback_target_dir
  | (
      if ($markers | length) > 0 then
        {
          plan_decision: "fail_closed",
          exit_code: 42,
          reason: "local fallback markers detected for suite",
          assigned_worker_id: null,
          assigned_target_dir: null,
          # rch-policy-waive: local_fallback_not_rejected reason=intentional classifier branch fails closed on preserved local fallback markers
          safe_alternatives: ["clear local-fallback evidence before reusing worker or target-dir"],
          phase_plans: []
        }
      elif ($sticky_worker_id | length) > 0 and $sticky_worker_available and ($warm_target_dir | length) > 0 and (target_conflict($warm_target_dir) | not) then
        {
          plan_decision: "admit_sticky",
          exit_code: 0,
          reason: "sticky worker is available and warm target-dir is uncontested",
          assigned_worker_id: $sticky_worker_id,
          assigned_target_dir: $warm_target_dir,
          safe_alternatives: [
            ("keep suite on worker " + $sticky_worker_id),
            ("reuse warm target-dir " + $warm_target_dir)
          ],
          phase_plans: (
            ($manifest.phases // [])
            | map({
                phase,
                command_id,
                command_class: phase_class(.requested_command),
                assigned_worker_id: $sticky_worker_id,
                assigned_target_dir: $warm_target_dir,
                requested_command
              })
          )
        }
      elif ($sticky_worker_id | length) > 0 and ($warm_target_dir | length) > 0 and target_conflict($warm_target_dir) then
        {
          plan_decision: "defer_conflicting_target_dir",
          exit_code: 75,
          reason: "warm target-dir is currently held by another agent",
          assigned_worker_id: null,
          assigned_target_dir: null,
          safe_alternatives: [
            "wait for the conflicting target-dir lease to clear",
            "mint a new cold target-dir in a separate planning pass"
          ],
          phase_plans: []
        }
      elif ($fallback_worker | type) == "object" and ($fallback_target_dir | length) > 0 and (target_conflict($fallback_target_dir) | not) then
        {
          plan_decision: "admit_fallback_worker",
          exit_code: 0,
          reason: "sticky worker is unavailable; rerouting to the first idle worker",
          assigned_worker_id: ($fallback_worker.worker_id // null),
          assigned_target_dir: $fallback_target_dir,
          safe_alternatives: [
            ("reroute suite to worker " + ($fallback_worker.worker_id // "unknown")),
            ("warm a fresh target-dir " + $fallback_target_dir)
          ],
          phase_plans: (
            ($manifest.phases // [])
            | map({
                phase,
                command_id,
                command_class: phase_class(.requested_command),
                assigned_worker_id: ($fallback_worker.worker_id // null),
                assigned_target_dir: $fallback_target_dir,
                requested_command
              })
          )
        }
      else
        {
          plan_decision: "defer_worker_unavailable",
          exit_code: 75,
          reason: "no eligible idle worker exists for sticky or fallback assignment",
          assigned_worker_id: null,
          assigned_target_dir: null,
          safe_alternatives: [
            "retry once an idle worker snapshot is available",
            "split the suite into separate proof lanes if stickiness is not required"
          ],
          phase_plans: []
        }
      end
    ) as $decision
  | {
      schema_version: "franken-engine.sticky-worker-warm-target-lease-plan.v1",
      agent_id: $agent_id,
      bead_id: $bead_id,
      suite_id: ($manifest.suite_id // "unknown"),
      input_status: {
        suite_manifest: "provided",
        sticky_worker_state: $sticky_state_status,
        reservation_snapshot: $reservations_status,
        local_fallback_markers: $fallback_marker_status
      },
      sticky_worker_requested: {
        preferred_worker_id: (if ($sticky_worker_id | length) > 0 then $sticky_worker_id else null end),
        warm_target_dir: (if ($warm_target_dir | length) > 0 then $warm_target_dir else null end),
        sticky_worker_available: $sticky_worker_available
      },
      fallback_worker_candidate: (
        if ($fallback_worker | type) == "object" then
          {
            worker_id: ($fallback_worker.worker_id // null),
            warm_target_dir: (if ($fallback_target_dir | length) > 0 then $fallback_target_dir else null end)
          }
        else
          null
        end
      ),
      local_fallback_marker_count: ($markers | length),
      local_fallback_markers: $markers,
      manifest_phase_count: (($manifest.phases // []) | length),
      plan_decision: $decision.plan_decision,
      reason: $decision.reason,
      assigned_worker_id: $decision.assigned_worker_id,
      assigned_target_dir: $decision.assigned_target_dir,
      phase_plans: $decision.phase_plans,
      safe_alternatives: $decision.safe_alternatives,
      exit_code: $decision.exit_code
    }
' >"$plan_core"

input_hash="$(
  jq -n \
    --slurpfile manifest "$manifest_normalized" \
    --slurpfile sticky "$sticky_state_normalized" \
    --slurpfile workers "$workers_normalized" \
    --slurpfile reservations "$reservations_normalized" \
    --slurpfile markers "$fallback_markers_normalized" '
      {
        suite_manifest: ($manifest[0]),
        sticky_worker_state: ($sticky[0]),
        worker_snapshot: ($workers[0]),
        reservation_snapshot: ($reservations[0]),
        local_fallback_markers: ($markers[0])
      }
    ' | jq -cS . | sha256sum | awk '{print $1}'
)"
plan_hash="$(jq -cS . "$plan_core" | sha256sum | awk '{print $1}')"

jq \
  --arg input_hash "$input_hash" \
  --arg plan_hash "$plan_hash" \
  --arg plan_path "$plan_path" \
  --arg summary_path "$summary_path" \
  --arg commands_path "$commands_path" \
  --arg events_path "$events_path" '
  . + {
    hash_basis: {
      input_hash: $input_hash,
      plan_hash: $plan_hash
    },
    artifact_paths: {
      sticky_worker_warm_target_plan_json: $plan_path,
      sticky_worker_warm_target_summary_md: $summary_path,
      commands_txt: $commands_path,
      events_jsonl: $events_path
    }
  }
' "$plan_core" >"$plan_tmp"
mv "$plan_tmp" "$plan_path"

{
  printf '# Sticky Worker Warm Target Lease Planner\n\n'
  printf -- '- Decision: %s\n' "$(jq -r '.plan_decision' "$plan_path")"
  printf -- '- Reason: %s\n' "$(jq -r '.reason' "$plan_path")"
  printf -- '- Suite ID: %s\n' "$(jq -r '.suite_id' "$plan_path")"
  printf -- '- Assigned worker: %s\n' "$(jq -r '.assigned_worker_id // "none"' "$plan_path")"
  printf -- '- Assigned target-dir: %s\n' "$(jq -r '.assigned_target_dir // "none"' "$plan_path")"
  printf -- '- Manifest phases: %s\n' "$(jq -r '.manifest_phase_count' "$plan_path")"
  printf -- '- Local fallback markers: %s\n' "$(jq -r '.local_fallback_marker_count' "$plan_path")"
  printf -- "- Input hash: \`%s\`\n" "$(jq -r '.hash_basis.input_hash' "$plan_path")"
  printf -- "- Plan hash: \`%s\`\n" "$(jq -r '.hash_basis.plan_hash' "$plan_path")"
  printf '\n## Phase Plans\n\n'
  jq -r '
    if (.phase_plans | length) == 0 then
      "_No phases admitted in this plan._"
    else
      (
        [
          "| Phase | Class | Worker | Target Dir |",
          "| --- | --- | --- | --- |"
        ]
        + (
          .phase_plans
          | map(
              "| \(.phase) | \(.command_class) | \(.assigned_worker_id) | \(.assigned_target_dir) |"
            )
        )
      ) | join("\n")
    end
  ' "$plan_path"
} >"$summary_tmp"
mv "$summary_tmp" "$summary_path"

write_event "plan_written" "wrote sticky-worker warm-target lease planner artifacts"

exit "$(jq -r '.exit_code' "$plan_path")"
