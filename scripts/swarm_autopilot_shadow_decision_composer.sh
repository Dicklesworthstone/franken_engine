#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_AUTOPILOT_SHADOW_DECISION_COMPOSER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-shadow-decision-composer}"
run_id="${SWARM_AUTOPILOT_SHADOW_DECISION_COMPOSER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_AUTOPILOT_SHADOW_DECISION_COMPOSER_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${SWARM_AUTOPILOT_SHADOW_DECISION_COMPOSER_SOURCE_REVISION:-unknown}"
now_epoch_seconds="$(date -u +%s)"
freshness_window_seconds="300"
max_recommendations="16"
journal_events_jsonl=""
existing_autopilot_inputs=()
original_args=("$@")

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_autopilot_shadow_decision_composer.sh [OPTIONS]

Compose advisory-only shadow-daemon operator decisions from normalized journal
events and existing autopilot output artifacts. The composer writes artifacts
only under --output-dir and never mutates br, Agent Mail, rch, git, workers, or
queue policy.

Required inputs:
  --journal-events-jsonl FILE

Optional inputs:
  --existing-autopilot-json FILE  May be repeated.
  --source-revision REV
  --now-epoch-seconds N
  --freshness-window-seconds N
  --max-recommendations N
  --output-dir DIR

Artifacts:
  shadow_status.json
  recommendations.json
  operator_notice.md
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  artifacts written; decision is pass or degraded
  42 artifacts written; decision is blocked or fail_closed
  64 invalid or malformed input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --journal-events-jsonl)
      journal_events_jsonl="${2:-}"
      shift 2
      ;;
    --existing-autopilot-json)
      existing_autopilot_inputs+=("${2:-}")
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    --now-epoch-seconds)
      now_epoch_seconds="${2:-}"
      shift 2
      ;;
    --freshness-window-seconds)
      freshness_window_seconds="${2:-}"
      shift 2
      ;;
    --max-recommendations)
      max_recommendations="${2:-}"
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

is_int() {
  [[ "${1:-}" =~ ^[0-9]+$ ]]
}

if [[ -z "$journal_events_jsonl" ]]; then
  printf 'missing required --journal-events-jsonl\n' >&2
  usage
  exit 64
fi

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for shadow decision composer\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for shadow decision composer\n' >&2
  exit 2
fi
if ! is_int "$now_epoch_seconds" || ! is_int "$freshness_window_seconds" || ! is_int "$max_recommendations"; then
  printf 'time and cap arguments must be non-negative integers\n' >&2
  exit 64
fi
if [[ ! -f "$journal_events_jsonl" ]]; then
  printf 'missing journal events JSONL: %s\n' "$journal_events_jsonl" >&2
  exit 64
fi
if ! jq -s empty "$journal_events_jsonl" >/dev/null 2>&1; then
  printf 'malformed journal events JSONL: %s\n' "$journal_events_jsonl" >&2
  exit 64
fi

if [[ "$source_revision" == "unknown" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
shadow_status_path="${run_dir}/shadow_status.json"
recommendations_path="${run_dir}/recommendations.json"
notice_path="${run_dir}/operator_notice.md"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
existing_outputs_path="${run_dir}/existing_autopilot_outputs.json"

printf './scripts/swarm_autopilot_shadow_decision_composer.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"
: >"$events_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-autopilot-shadow-decision-composer.event.v1" \
    --arg shadow_run_id "$run_id" \
    --arg event_name "$1" \
    --arg outcome "$2" \
    --arg detail "$3" \
    '{
      schema_version: $schema_version,
      shadow_run_id: $shadow_run_id,
      event_name: $event_name,
      outcome: $outcome,
      detail: $detail
    }' >>"$events_path"
}

existing_outputs_jsonl="${run_dir}/existing_autopilot_outputs.jsonl"
: >"$existing_outputs_jsonl"
for input_path in "${existing_autopilot_inputs[@]}"; do
  if [[ ! -f "$input_path" ]]; then
    printf 'missing existing autopilot JSON: %s\n' "$input_path" >&2
    exit 64
  fi
  if ! jq empty "$input_path" >/dev/null 2>&1; then
    printf 'malformed existing autopilot JSON: %s\n' "$input_path" >&2
    exit 64
  fi
  hash="$(jq -cS . "$input_path" | sha256sum | awk '{print $1}')"
  jq -nc \
    --arg path "$input_path" \
    --arg content_hash "sha256:${hash}" \
    --arg schema_version "$(jq -r '.schema_version // "unknown"' "$input_path")" \
    '{path:$path, schema_version:$schema_version, content_hash:$content_hash}' >>"$existing_outputs_jsonl"
done
jq -s '.' "$existing_outputs_jsonl" >"$existing_outputs_path"

write_event "inputs_loaded" "captured" "$journal_events_jsonl"

# shellcheck disable=SC2094
jq -s \
  --slurpfile existing "$existing_outputs_path" \
  --arg shadow_run_id "$run_id" \
  --arg source_revision "$source_revision" \
  --argjson now_epoch_seconds "$now_epoch_seconds" \
  --argjson default_freshness_window_seconds "$freshness_window_seconds" \
  --argjson max_recommendations "$max_recommendations" \
  --arg shadow_status_path "$shadow_status_path" \
  --arg recommendations_path "$recommendations_path" \
  --arg notice_path "$notice_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  '
    def source_key:
      .source_key // (
        if .source_kind == "br_queue_snapshot_json" then "br_queue"
        elif .source_kind == "bv_robot_plan_json" then "bv_robot_plan"
        elif .source_kind == "agent_mail_snapshot_json" then "agent_mail"
        elif .source_kind == "rch_status_snapshot_json" then "rch_status"
        elif .source_kind == "git_state_snapshot_json" then "git_state"
        elif .source_kind == "artifact_bundle_snapshot_json" then "artifact_bundles"
        else (.source_kind // "unknown")
        end
      );
    def event_payload:
      if (.normalized_payload? | type) == "object" or (.normalized_payload? | type) == "array" then
        .normalized_payload
      elif (.payload? | type) == "object" or (.payload? | type) == "array" then
        .payload
      elif (.normalized_payload_json? | type) == "string" then
        (.normalized_payload_json | fromjson? // {})
      else
        {}
      end;
    def event_codes:
      ((.error_codes // []) + ((event_payload.error_codes // []) | map(tostring))) | unique;
    def as_source_snapshot:
      {
        source_key: source_key,
        source_id: (.source_id // (.journal_event_id // source_key | tostring)),
        source_kind: (.source_kind // "unknown"),
        schema_version: (.schema_version // "unknown"),
        content_hash: (.content_hash // .payload_content_hash // .normalized_payload_hash // "sha256:unknown"),
        collected_epoch_seconds: (.collected_epoch_seconds // ((.collected_timestamp_ms? // 0) / 1000 | floor)),
        freshness_window_seconds: (.freshness_window_seconds // $default_freshness_window_seconds),
        fresh: (.fresh // true),
        degraded: (.degraded // ((event_codes | length) > 0)),
        raw_payload_ref: (.raw_payload_ref // .source_locator // "journal-events-jsonl"),
        local_fallback_contamination: (.local_fallback_contamination // false),
        error_codes: event_codes,
        payload: event_payload
      };
    def status_for($sources; $key):
      ($sources | map(select(.source_key == $key)) | sort_by(.collected_epoch_seconds, .source_id) | last) // null;
    def payload_for($sources; $key):
      (status_for($sources; $key).payload // {});
    def arr($value):
      if ($value | type) == "array" then $value else [] end;
    def br_ready($br):
      arr($br.ready // $br.ready_issues // $br.items // (if ($br | type) == "array" then $br else [] end));
    def br_in_progress($br):
      arr($br.in_progress.issues // $br.in_progress // []);
    def boolish($value): ($value == true or $value == "true");
    def rec($sources; $id; $rank; $class; $command; $codes; $source_keys; $degradation):
      {
        recommendation_id: $id,
        rank: $rank,
        action_class: $class,
        command_text: $command,
        executes_mutation: false,
        remediation_only: true,
        source_event_ids: ($source_keys | map(status_for($sources; .).source_id) | map(select(. != null))),
        source_hashes: ($source_keys | map(status_for($sources; .).content_hash) | map(select(. != null))),
        source_collected_epoch_seconds: ($source_keys | map(status_for($sources; .).collected_epoch_seconds) | map(select(. != null))),
        degradation_state: $degradation,
        reason_codes: $codes,
        evidence_paths: [$shadow_status_path, $recommendations_path, $events_path]
      };

    ([.[] | as_source_snapshot] | sort_by(.source_key, .source_id)) as $sources
    | ["br_queue","bv_robot_plan","agent_mail","rch_status","git_state","artifact_bundles"] as $required
    | ($sources | map(.source_key) | unique) as $present_keys
    | ($required - $present_keys) as $missing_sources
    | ([ $sources[] | select((.fresh | not) or (($now_epoch_seconds - .collected_epoch_seconds) > .freshness_window_seconds)) | .source_key ] | unique) as $stale_sources
    | ([ $sources[] | .error_codes[]? ] | unique) as $source_error_codes
    | (any($sources[]; .local_fallback_contamination == true) or (($source_error_codes | index("FE-SWARM-AUTOPILOT-SHADOW-RCH-LOCAL-FALLBACK")) != null)) as $rch_contaminated
    | (($source_error_codes | index("FE-SWARM-AUTOPILOT-SHADOW-CONTRADICTORY-OWNERSHIP")) != null) as $contradictory_ownership
    | (($source_error_codes | index("FE-SWARM-AUTOPILOT-SHADOW-UNSUPPORTED-MUTATION")) != null) as $unsupported_mutation
    | (any($sources[]; .degraded == true)) as $source_degraded
    | (payload_for($sources; "git_state")) as $git_payload
    | (payload_for($sources; "agent_mail")) as $mail_payload
    | (payload_for($sources; "artifact_bundles")) as $artifact_payload
    | (payload_for($sources; "br_queue")) as $br_payload
    | (br_ready($br_payload)) as $ready_items
    | (br_in_progress($br_payload)) as $in_progress_items
    | ([ $in_progress_items[]? | select((.updated_epoch_seconds? // $now_epoch_seconds) + 3600 < $now_epoch_seconds) ]) as $stalled_beads
    | ([ $mail_payload.active_reservations[]? | select((.stale == true) or ((.expires_epoch_seconds? // $now_epoch_seconds) < $now_epoch_seconds)) ]) as $stale_reservations
    | (boolish($git_payload.dirty // false)) as $dirty_worktree
    | (((arr($artifact_payload.no_mock_proof_artifacts // [])) | length) == 0) as $missing_no_mock
    | (
        (if ($ready_items | length) == 0 and ($in_progress_items | length) == 0 then
          [rec($sources; "shadow-rec-observe-idle-queue"; 10; "observe_idle_queue"; "br ready --json"; ["FE-SWARM-AUTOPILOT-SHADOW-IDLE-QUEUE"]; ["br_queue","bv_robot_plan"]; "none")]
        else [] end)
        + (if ($in_progress_items | length) > 0 then
          [rec($sources; "shadow-rec-continue-owned-lane"; 20; "continue_owned_lane"; ("br show " + (($in_progress_items[0].id // "UNKNOWN") | tostring) + " --json"); ["FE-SWARM-AUTOPILOT-SHADOW-ACTIVE-LANE"]; ["br_queue","bv_robot_plan"]; "none")]
        else [] end)
        + (if ($stalled_beads | length) > 0 then
          [rec($sources; "shadow-rec-review-stalled-bead"; 30; "review_stalled_bead"; ("br show " + (($stalled_beads[0].id // "UNKNOWN") | tostring) + " --json"); ["FE-SWARM-AUTOPILOT-SHADOW-STALED-BEAD"]; ["br_queue","agent_mail"]; "degraded")]
        else [] end)
        + (if ($stale_reservations | length) > 0 then
          [rec($sources; "shadow-rec-review-stale-reservation"; 40; "review_stale_reservation"; "br list --status=in_progress --json"; ["FE-SWARM-AUTOPILOT-SHADOW-STALE-RESERVATION"]; ["agent_mail"]; "degraded")]
        else [] end)
        + (if $rch_contaminated then
          [rec($sources; "shadow-rec-rerun-rch-remote-proof"; 50; "rerun_rch_remote_proof"; "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_shadow cargo check --workspace"; ["FE-SWARM-AUTOPILOT-SHADOW-RCH-LOCAL-FALLBACK"]; ["rch_status"]; "contaminated")]
        else [] end)
        + (if $contradictory_ownership then
          [rec($sources; "shadow-rec-reconcile-ownership"; 60; "reconcile_bead_ownership"; "br show <conflicted-bead> --json && br list --status=in_progress --json"; ["FE-SWARM-AUTOPILOT-SHADOW-CONTRADICTORY-OWNERSHIP"]; ["br_queue","agent_mail"]; "blocked")]
        else [] end)
        + (if $dirty_worktree then
          [rec($sources; "shadow-rec-inspect-dirty-worktree"; 70; "inspect_dirty_worktree"; "git status --short --branch"; ["FE-SWARM-AUTOPILOT-SHADOW-DIRTY-WORKTREE"]; ["git_state"]; "degraded")]
        else [] end)
        + (if $missing_no_mock then
          [rec($sources; "shadow-rec-request-no-mock-proof"; 80; "request_no_mock_proof"; "bash scripts/e2e/swarm_autopilot_no_mock_drill_smoke.sh check"; ["FE-SWARM-AUTOPILOT-SHADOW-MISSING-NO-MOCK-PROOF"]; ["artifact_bundles"]; "degraded")]
        else [] end)
        + (if $source_degraded and (($source_error_codes | index("FE-SWARM-AUTOPILOT-SHADOW-DEGRADED-SOURCE")) != null) then
          [rec($sources; "shadow-rec-refresh-degraded-sources"; 90; "refresh_degraded_sources"; "bash scripts/e2e/swarm_autopilot_shadow_source_watchers_smoke.sh check"; ["FE-SWARM-AUTOPILOT-SHADOW-DEGRADED-SOURCE"]; ["agent_mail","rch_status"]; "degraded")]
        else [] end)
      ) as $raw_recommendations
    | ($raw_recommendations | unique_by(.recommendation_id) | sort_by(.rank, .recommendation_id) | .[0:$max_recommendations]) as $recommendations
    | (
        (if ($missing_sources | length) > 0 then ["FE-SWARM-AUTOPILOT-SHADOW-MISSING-SOURCE"] else [] end)
        + (if ($stale_sources | length) > 0 then ["FE-SWARM-AUTOPILOT-SHADOW-STALE-SOURCE"] else [] end)
        + (if ($stalled_beads | length) > 0 then ["FE-SWARM-AUTOPILOT-SHADOW-STALED-BEAD"] else [] end)
        + (if ($stale_reservations | length) > 0 then ["FE-SWARM-AUTOPILOT-SHADOW-STALE-RESERVATION"] else [] end)
        + $source_error_codes
        + (if $dirty_worktree then ["FE-SWARM-AUTOPILOT-SHADOW-DIRTY-WORKTREE"] else [] end)
        + (if $missing_no_mock then ["FE-SWARM-AUTOPILOT-SHADOW-MISSING-NO-MOCK-PROOF"] else [] end)
      | unique) as $error_codes
    | (
        if $rch_contaminated or $unsupported_mutation then "contaminated"
        elif (($missing_sources | length) > 0) or (($stale_sources | length) > 0) or $contradictory_ownership then "blocked"
        elif $source_degraded or $dirty_worktree or (($stale_reservations | length) > 0) or (($stalled_beads | length) > 0) or $missing_no_mock then "degraded"
        else "confirmed"
        end
      ) as $truth_state
    | (
        if $truth_state == "contaminated" then "fail_closed"
        elif $truth_state == "blocked" then "fail_closed"
        elif $truth_state == "degraded" then "degraded"
        else "pass"
        end
      ) as $decision
    | {
        schema_version: "franken-engine.swarm-autopilot-shadow-status.v1",
        shadow_run_id: $shadow_run_id,
        source_revision: $source_revision,
        generated_epoch_seconds: $now_epoch_seconds,
        truth_state: $truth_state,
        decision: $decision,
        source_snapshot_status: (reduce $sources[] as $source ({}; .[$source.source_key] = ($source | del(.payload)))),
        source_snapshot_ids: ($sources | map(.source_id)),
        advisory_recommendations: $recommendations,
        rejected_mutation_claims: (
          if $unsupported_mutation then
            [{claim_id:"unsupported-mutation-claim", rejection_error_code:"FE-SWARM-AUTOPILOT-SHADOW-UNSUPPORTED-MUTATION", executed:false}]
          else [] end
        ),
        existing_autopilot_outputs: $existing[0],
        stale_sources: $stale_sources,
        missing_sources: $missing_sources,
        error_codes: $error_codes,
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
          changes_live_queue_policy: false,
          writes_outside_output_dir: false
        },
        sibling_reuse: {
          persistence: "/dp/frankensqlite",
          tui: "/dp/frankentui",
          service_api: "/dp/fastapi_rust"
        },
        artifact_paths: {
          shadow_status_json: $shadow_status_path,
          recommendations_json: $recommendations_path,
          operator_notice_md: $notice_path,
          events_jsonl: $events_path,
          commands_txt: $commands_path,
          report_md: $report_path
        }
      }
  ' "$journal_events_jsonl" >"$shadow_status_path"

# shellcheck disable=SC2094
jq \
  --arg shadow_run_id "$run_id" \
  --arg shadow_status_path "$shadow_status_path" \
  --arg recommendations_path "$recommendations_path" \
  '{
    schema_version: "franken-engine.swarm-autopilot-shadow-recommendations.v1",
    shadow_run_id: $shadow_run_id,
    truth_state: .truth_state,
    decision: .decision,
    recommendations: .advisory_recommendations,
    mutation_policy: .mutation_policy,
    source_snapshot_ids: .source_snapshot_ids,
    error_codes: .error_codes,
    artifact_paths: {
      shadow_status_json: $shadow_status_path,
      recommendations_json: $recommendations_path
    }
  }' "$shadow_status_path" >"$recommendations_path"

truth_state="$(jq -r '.truth_state' "$shadow_status_path")"
decision="$(jq -r '.decision' "$shadow_status_path")"
top_action="$(jq -r '.advisory_recommendations[0].action_class // "none"' "$shadow_status_path")"

cat >"$notice_path" <<EOF
# Shadow Autopilot Operator Notice

- truth_state: ${truth_state}
- decision: ${decision}
- top_action: ${top_action}
- advisory_only: true
- proof_only: true
- daemon_mutation: none
EOF

cat >"$report_path" <<EOF
# Shadow Decision Composer

- shadow_status: ${shadow_status_path}
- recommendations: ${recommendations_path}
- operator_notice: ${notice_path}
- events: ${events_path}
EOF

write_event "artifacts_written" "$decision" "$shadow_status_path"
printf 'swarm_autopilot_shadow_decision_composer_artifacts=%s\n' "$run_dir"

if [[ "$decision" == "fail_closed" || "$decision" == "blocked" ]]; then
  exit 42
fi
