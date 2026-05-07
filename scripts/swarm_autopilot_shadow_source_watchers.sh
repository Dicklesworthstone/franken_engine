#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="${SWARM_AUTOPILOT_SHADOW_SOURCE_WATCHERS_OUTPUT_DIR:-${TMPDIR:-/tmp}/franken-engine-shadow-source-watchers/$(date -u +%Y%m%dT%H%M%SZ)}"
generated_epoch_seconds="$(date -u +%s)"
freshness_window_seconds="300"
source_revision=""
live_lite="false"
original_args=("$@")

br_queue_json=""
bv_robot_plan_json=""
agent_mail_json=""
rch_status_json=""
git_state_json=""
artifact_bundles_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_autopilot_shadow_source_watchers.sh [OPTIONS]

Normalizes one-shot shadow-daemon source snapshots. Fixture JSON inputs are
preferred for tests. --live-lite may collect read-only br/bv/git snapshots, but
the script never mutates br, Agent Mail, rch, git, workers, or queue policy and
never runs Cargo or rch workloads.

Inputs:
  --br-queue-json FILE
  --bv-robot-plan-json FILE
  --agent-mail-json FILE
  --rch-status-json FILE
  --git-state-json FILE
  --artifact-bundles-json FILE
  --live-lite

Options:
  --source-revision REV
  --generated-epoch-seconds N
  --freshness-window-seconds N
  --output-dir DIR

Artifacts:
  source_snapshots.jsonl
  source_snapshot_summary.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  artifacts written; decision is pass or degraded
  42 artifacts written; decision is fail_closed
  64 invalid arguments or malformed JSON input
EOF
}

is_int() {
  [[ "${1:-}" =~ ^[0-9]+$ ]]
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --br-queue-json)
      br_queue_json="${2:-}"
      shift 2
      ;;
    --bv-robot-plan-json)
      bv_robot_plan_json="${2:-}"
      shift 2
      ;;
    --agent-mail-json)
      agent_mail_json="${2:-}"
      shift 2
      ;;
    --rch-status-json)
      rch_status_json="${2:-}"
      shift 2
      ;;
    --git-state-json)
      git_state_json="${2:-}"
      shift 2
      ;;
    --artifact-bundles-json)
      artifact_bundles_json="${2:-}"
      shift 2
      ;;
    --live-lite)
      live_lite="true"
      shift
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    --generated-epoch-seconds)
      generated_epoch_seconds="${2:-}"
      shift 2
      ;;
    --freshness-window-seconds)
      freshness_window_seconds="${2:-}"
      shift 2
      ;;
    --output-dir)
      output_dir="${2:-}"
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

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for shadow source watchers\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for shadow source watchers\n' >&2
  exit 2
fi
if ! is_int "$generated_epoch_seconds" || ! is_int "$freshness_window_seconds"; then
  printf 'generated and freshness timestamps must be non-negative integers\n' >&2
  exit 64
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$output_dir"
raw_dir="${output_dir}/raw"
mkdir -p "$raw_dir"

snapshots_path="${output_dir}/source_snapshots.jsonl"
summary_path="${output_dir}/source_snapshot_summary.json"
events_path="${output_dir}/events.jsonl"
commands_path="${output_dir}/commands.txt"
report_path="${output_dir}/report.md"

: >"$snapshots_path"
: >"$events_path"

printf './scripts/swarm_autopilot_shadow_source_watchers.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-autopilot-shadow-source-watchers.event.v1" \
    --arg event_name "$1" \
    --arg source_key "$2" \
    --arg source_revision "$source_revision" \
    --argjson generated_epoch_seconds "$generated_epoch_seconds" \
    '{
      schema_version: $schema_version,
      event_name: $event_name,
      source_key: $source_key,
      source_revision: $source_revision,
      generated_epoch_seconds: $generated_epoch_seconds
    }' >>"$events_path"
}

write_degraded_live_source() {
  local path="$1"
  local source_kind="$2"
  local reason="$3"
  jq -n \
    --arg source_kind "$source_kind" \
    --arg reason "$reason" \
    '{
      schema_version: "franken-engine.swarm-autopilot-shadow-live-source.v1",
      source_kind: $source_kind,
      fresh: true,
      degraded: true,
      error_codes: ["FE-SWARM-AUTOPILOT-SHADOW-DEGRADED-SOURCE"],
      reason: $reason
    }' >"$path"
}

collect_live_lite() {
  if [[ -z "$br_queue_json" ]]; then
    local br_ready="${raw_dir}/br_ready.json"
    local br_in_progress="${raw_dir}/br_in_progress.json"
    local br_blocked="${raw_dir}/br_blocked.json"
    br ready --json >"$br_ready"
    br list --status in_progress --json >"$br_in_progress"
    br blocked --json >"$br_blocked"
    br_queue_json="${raw_dir}/br_queue.json"
    jq -n \
      --slurpfile ready "$br_ready" \
      --slurpfile in_progress "$br_in_progress" \
      --slurpfile blocked "$br_blocked" \
      '{
        schema_version: "franken-engine.swarm-autopilot-shadow-br-queue-live.v1",
        fresh: true,
        degraded: false,
        ready: $ready[0],
        in_progress: $in_progress[0],
        blocked: $blocked[0],
        error_codes: []
      }' >"$br_queue_json"
  fi

  if [[ -z "$bv_robot_plan_json" ]]; then
    bv_robot_plan_json="${raw_dir}/bv_robot_plan.json"
    if ! bv --recipe actionable --robot-plan >"$bv_robot_plan_json"; then
      write_degraded_live_source "$bv_robot_plan_json" "bv_robot_plan_json" "bv robot plan unavailable"
    fi
  fi

  if [[ -z "$git_state_json" ]]; then
    git_state_json="${raw_dir}/git_state.json"
    git -C "$root_dir" status --short --branch | jq -Rn '
      [inputs] as $lines
      | {
          schema_version: "franken-engine.swarm-autopilot-shadow-git-state-live.v1",
          fresh: true,
          degraded: false,
          lines: $lines,
          dirty: any($lines[]; startswith("##") | not),
          error_codes: []
        }
    ' >"$git_state_json"
  fi
}

validate_json_file() {
  local path="$1"
  local source_key="$2"
  if [[ ! -f "$path" ]]; then
    printf 'missing %s input file: %s\n' "$source_key" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf 'malformed %s JSON input: %s\n' "$source_key" "$path" >&2
    exit 64
  fi
}

normalize_source() {
  local source_key="$1"
  local source_kind="$2"
  local input_path="$3"
  local canonical present raw_payload_ref hash hash_prefix

  if [[ -n "$input_path" ]]; then
    validate_json_file "$input_path" "$source_key"
    canonical="$(jq -cS . "$input_path")"
    present="true"
    raw_payload_ref="$input_path"
  else
    canonical="$(jq -cn --arg source_kind "$source_kind" '{missing:true, source_kind:$source_kind}')"
    present="false"
    raw_payload_ref="missing:${source_kind}"
  fi

  hash="$(printf '%s' "$canonical" | sha256sum | awk '{print $1}')"
  hash_prefix="${hash:0:12}"

  jq -nc \
    --arg source_key "$source_key" \
    --arg source_kind "$source_kind" \
    --arg source_id "${source_key}-${hash_prefix}" \
    --arg schema_version "franken-engine.swarm-autopilot-shadow-source-snapshot.v1" \
    --arg content_hash "sha256:${hash}" \
    --arg raw_payload_ref "$raw_payload_ref" \
    --argjson payload "$canonical" \
    --argjson present "$present" \
    --argjson collected_epoch_seconds "$generated_epoch_seconds" \
    --argjson freshness_window_seconds "$freshness_window_seconds" \
    '
      def payload_codes($payload):
        (
          ($payload.error_codes // [])
          + (($payload.errors // []) | map(if type == "object" then (.code // empty) else . end))
        )
        | map(select(type == "string"))
        | unique;

      (($payload.local_fallback // $payload.rch_local_fallback // $payload.status.local_fallback // false) == true) as $local_fallback
      | (
          if ($present | not) then
            false
          elif (($payload.fresh // true) == false) or (($payload.stale // false) == true) then
            false
          else
            true
          end
        ) as $fresh
      | (
          if ($present | not) then
            true
          elif $local_fallback then
            true
          elif (($payload.degraded // $payload.status.degraded // $payload.health.degraded // false) == true) then
            true
          elif ($fresh | not) then
            true
          elif ((payload_codes($payload) | length) > 0) then
            true
          else
            false
          end
        ) as $degraded
      | (
          []
          + (if ($present | not) then ["FE-SWARM-AUTOPILOT-SHADOW-MISSING-SOURCE"] else [] end)
          + (if ($present and ($fresh | not)) then ["FE-SWARM-AUTOPILOT-SHADOW-STALE-SOURCE"] else [] end)
          + (if ($present and $degraded and $fresh and ($local_fallback | not) and ((payload_codes($payload) | length) == 0)) then ["FE-SWARM-AUTOPILOT-SHADOW-DEGRADED-SOURCE"] else [] end)
          + (if ($source_kind == "rch_status_snapshot_json" and $local_fallback) then ["FE-SWARM-AUTOPILOT-SHADOW-RCH-LOCAL-FALLBACK"] else [] end)
          + payload_codes($payload)
        ) | unique as $error_codes
      | {
          source_key: $source_key,
          source_id: $source_id,
          source_kind: $source_kind,
          schema_version: $schema_version,
          content_hash: $content_hash,
          collected_epoch_seconds: $collected_epoch_seconds,
          freshness_window_seconds: $freshness_window_seconds,
          fresh: $fresh,
          degraded: $degraded,
          present: $present,
          raw_payload_ref: $raw_payload_ref,
          local_fallback_contamination: ($source_kind == "rch_status_snapshot_json" and $local_fallback),
          error_codes: $error_codes,
          payload_summary: {
            payload_type: ($payload | type),
            item_count: (
              if ($payload | type) == "array" then
                ($payload | length)
              elif (($payload.items? // null) | type) == "array" then
                ($payload.items | length)
              else
                null
              end
            )
          }
        }
    ' >>"$snapshots_path"
  write_event "source_normalized" "$source_key"
}

if [[ "$live_lite" == "true" ]]; then
  collect_live_lite
fi

normalize_source "br_queue" "br_queue_snapshot_json" "$br_queue_json"
normalize_source "bv_robot_plan" "bv_robot_plan_json" "$bv_robot_plan_json"
normalize_source "agent_mail" "agent_mail_snapshot_json" "$agent_mail_json"
normalize_source "rch_status" "rch_status_snapshot_json" "$rch_status_json"
normalize_source "git_state" "git_state_snapshot_json" "$git_state_json"
normalize_source "artifact_bundles" "artifact_bundle_snapshot_json" "$artifact_bundles_json"

jq -s \
  --arg schema_version "franken-engine.swarm-autopilot-shadow-source-summary.v1" \
  --arg source_revision "$source_revision" \
  --argjson generated_epoch_seconds "$generated_epoch_seconds" \
  --arg snapshots_path "$snapshots_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  '
    ([.[] | .error_codes[]?] | unique) as $codes
    | (any(.[]; .local_fallback_contamination == true)) as $contaminated
    | (any(.[]; .present == false)) as $missing
    | (any(.[]; .present == true and .fresh == false)) as $stale
    | (($codes | index("FE-SWARM-AUTOPILOT-SHADOW-CONTRADICTORY-OWNERSHIP")) != null) as $contradictory
    | (any(.[]; .degraded == true)) as $degraded
    | {
        schema_version: $schema_version,
        source_revision: $source_revision,
        generated_epoch_seconds: $generated_epoch_seconds,
        truth_state: (
          if $contaminated then
            "contaminated"
          elif ($missing or $stale or $contradictory) then
            "blocked"
          elif $degraded then
            "degraded"
          else
            "confirmed"
          end
        ),
        decision: (
          if ($contaminated or $missing or $stale or $contradictory) then
            "fail_closed"
          elif $degraded then
            "degraded"
          else
            "pass"
          end
        ),
        source_snapshot_status: (reduce .[] as $snapshot ({}; .[$snapshot.source_key] = $snapshot)),
        source_snapshot_ids: [.[] | .source_id],
        error_codes: $codes,
        mutation_policy: {
          advisory_only: true,
          proof_only: true,
          mutates_br: false,
          reassigns_beads: false,
          releases_reservations: false,
          sends_agent_mail: false,
          runs_cargo: false,
          runs_rch: false,
          mutates_git: false,
          mutates_remote_workers: false,
          changes_live_queue_policy: false
        },
        artifact_paths: {
          source_snapshots_jsonl: $snapshots_path,
          events_jsonl: $events_path,
          commands_txt: $commands_path,
          report_md: $report_path
        }
      }
  ' "$snapshots_path" >"$summary_path"

summary_decision="$(jq -r '.decision' "$summary_path")"
summary_truth_state="$(jq -r '.truth_state' "$summary_path")"

cat >"$report_path" <<EOF
# Shadow Source Watchers

- truth_state: ${summary_truth_state}
- decision: ${summary_decision}
- source_snapshots: ${snapshots_path}
- summary: ${summary_path}
EOF

printf 'swarm_autopilot_shadow_source_watchers_artifacts=%s\n' "$output_dir"
if [[ "$summary_decision" == "fail_closed" ]]; then
  exit 42
fi
