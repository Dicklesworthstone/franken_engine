#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_LIVE_READONLY_SNAPSHOT_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-live-readonly-snapshot}"
run_id="${SWARM_LIVE_READONLY_SNAPSHOT_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_LIVE_READONLY_SNAPSHOT_RUN_DIR:-${artifact_root}/${run_id}}"
profile_json="${SWARM_LIVE_READONLY_CAPTURE_PROFILE:-${root_dir}/docs/swarm_live_readonly_capture_profile_v1.json}"
source_revision="${SWARM_LIVE_READONLY_SOURCE_REVISION:-}"
now_ts="${SWARM_LIVE_READONLY_NOW_TS:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

swarm_ops_state_json=""
br_ready_json=""
br_in_progress_json=""
br_sync_status_json=""
bv_plan_json=""
agent_mail_json=""
rch_status_json=""
rch_queue_json=""
git_status_json=""
git_diff_check_json=""
resource_pressure_json=""
proof_transcript_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_live_readonly_snapshot_bundle.sh --swarm-ops-state-json FILE [OPTIONS]

Assembles a deterministic, read-only SWARM live snapshot bundle from fixture
or operator-supplied JSON inputs. The script does not query live services, run
Cargo, run rch exec, mutate beads, send Agent Mail, or change workers.

Required:
  --swarm-ops-state-json FILE     bd-eozx0-compatible live state JSON

Optional:
  --output-dir DIR
  --profile-json FILE
  --source-revision REV
  --now-ts ISO8601_Z
  --br-ready-json FILE
  --br-in-progress-json FILE
  --br-sync-status-json FILE
  --bv-plan-json FILE
  --agent-mail-json FILE
  --rch-status-json FILE
  --rch-queue-json FILE
  --git-status-json FILE
  --git-diff-check-json FILE
  --resource-pressure-json FILE
  --proof-transcript-json FILE

Writes:
  capture_profile.json
  snapshot.json
  swarm_ops_state_bundle.json
  events.jsonl
  commands.txt
  redaction_report.json
  report.md
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --output-dir)
      run_dir="${2:-}"
      shift 2
      ;;
    --profile-json)
      profile_json="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    --now-ts)
      now_ts="${2:-}"
      shift 2
      ;;
    --swarm-ops-state-json)
      swarm_ops_state_json="${2:-}"
      shift 2
      ;;
    --br-ready-json)
      br_ready_json="${2:-}"
      shift 2
      ;;
    --br-in-progress-json)
      br_in_progress_json="${2:-}"
      shift 2
      ;;
    --br-sync-status-json)
      br_sync_status_json="${2:-}"
      shift 2
      ;;
    --bv-plan-json)
      bv_plan_json="${2:-}"
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
    --rch-queue-json)
      rch_queue_json="${2:-}"
      shift 2
      ;;
    --git-status-json)
      git_status_json="${2:-}"
      shift 2
      ;;
    --git-diff-check-json)
      git_diff_check_json="${2:-}"
      shift 2
      ;;
    --resource-pressure-json)
      resource_pressure_json="${2:-}"
      shift 2
      ;;
    --proof-transcript-json)
      proof_transcript_json="${2:-}"
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

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm live read-only snapshot bundles\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for source command and payload hashes\n' >&2
  exit 2
fi
if [[ -z "$swarm_ops_state_json" ]]; then
  printf 'missing required --swarm-ops-state-json\n' >&2
  usage
  exit 64
fi
if [[ ! -f "$profile_json" ]]; then
  printf 'missing capture profile JSON: %s\n' "$profile_json" >&2
  exit 64
fi
jq empty "$profile_json" >/dev/null

if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi
now_epoch="$(date -u -d "$now_ts" +%s 2>/dev/null || true)"
if [[ -z "$now_epoch" ]]; then
  printf 'invalid --now-ts, expected ISO8601 timestamp accepted by date -d: %s\n' "$now_ts" >&2
  exit 64
fi

raw_dir="${run_dir}/raw"
redacted_dir="${run_dir}/redacted"
mkdir -p "$raw_dir" "$redacted_dir"

capture_profile_path="${run_dir}/capture_profile.json"
snapshot_path="${run_dir}/snapshot.json"
swarm_ops_bundle_path="${run_dir}/swarm_ops_state_bundle.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
redaction_report_path="${run_dir}/redaction_report.json"
report_path="${run_dir}/report.md"
sources_jsonl="${run_dir}/sources.jsonl"

: >"$events_path"
: >"$commands_path"
: >"$sources_jsonl"

sha256_file() {
  sha256sum "$1" | awk '{print $1}'
}

sha256_text() {
  printf '%s' "$1" | sha256sum | awk '{print $1}'
}

redact_json() {
  local input="$1"
  local output="$2"
  jq '
    def redact:
      walk(
        if type == "object" then
          with_entries(
            if (.key | test("(token|secret|password|cookie|auth|key)"; "i")) then
              .value = "<REDACTED>"
            else
              .
            end
          )
        else
          .
        end
      );
    redact
  ' "$input" >"$output"
}

age_seconds_for() {
  local captured_at="$1"
  local captured_epoch
  if [[ -z "$captured_at" || "$captured_at" == "null" ]]; then
    printf ''
    return 0
  fi
  captured_epoch="$(date -u -d "$captured_at" +%s 2>/dev/null || true)"
  if [[ -z "$captured_epoch" ]]; then
    printf ''
    return 0
  fi
  printf '%s' "$((now_epoch - captured_epoch))"
}

write_event() {
  local component="$1"
  local event="$2"
  local outcome="$3"
  local error_code="$4"
  local evidence_path="$5"
  local capture_source="$6"
  local source_command_hash="$7"
  local payload_hash="$8"

  jq -cn \
    --arg schema_version "franken-engine.swarm-live-readonly-capture-event.v1" \
    --arg trace_id "trace-swarm-live-readonly-${run_id}" \
    --arg component "$component" \
    --arg event "$event" \
    --arg outcome "$outcome" \
    --arg error_code "$error_code" \
    --arg evidence_path "$evidence_path" \
    --arg capture_source "$capture_source" \
    --arg source_command_hash "$source_command_hash" \
    --arg payload_hash "$payload_hash" \
    '{
      schema_version: $schema_version,
      trace_id: $trace_id,
      component: $component,
      event: $event,
      outcome: $outcome,
      error_code: (if $error_code == "" then null else $error_code end),
      evidence_path: $evidence_path,
      capture_source: $capture_source,
      source_command_hash: $source_command_hash,
      payload_hash: $payload_hash
    }' >>"$events_path"
}

process_source() {
  local component="$1"
  local input_path="$2"
  local required="$3"
  local freshness_window="$4"
  local mutation_class="$5"
  local command_text="$6"
  local maps_to="$7"
  local raw_path="${raw_dir}/${component}.json"
  local redacted_path="${redacted_dir}/${component}.json"
  local command_hash payload_hash redacted_hash captured_at age_seconds freshness_state trust_state reason_code error_code outcome redaction_applied malformed local_fallback mutating_command dirty_unowned_count

  command_hash="$(sha256_text "$command_text")"
  malformed="false"
  local_fallback="false"
  mutating_command="false"
  dirty_unowned_count="0"
  captured_at=""
  age_seconds=""
  freshness_state="fresh"
  trust_state="trusted"
  reason_code=""
  error_code=""
  outcome="captured"

  if [[ -z "$input_path" ]]; then
    jq -n --arg component "$component" --arg now_ts "$now_ts" \
      '{missing: true, component: $component, captured_at: $now_ts}' >"$raw_path"
    cp "$raw_path" "$redacted_path"
    freshness_state="missing"
    if [[ "$required" == "true" ]]; then
      trust_state="fail_closed"
      reason_code="missing_required_source"
      error_code="FE-SWARM-LIVE-MISSING-REQUIRED"
      outcome="fail_closed"
    else
      trust_state="degraded"
      reason_code="missing_${component}"
      error_code="FE-SWARM-LIVE-MISSING-OPTIONAL"
      outcome="degraded"
    fi
  elif [[ ! -f "$input_path" ]]; then
    jq -n --arg component "$component" --arg input_path "$input_path" --arg now_ts "$now_ts" \
      '{missing: true, component: $component, input_path: $input_path, captured_at: $now_ts}' >"$raw_path"
    cp "$raw_path" "$redacted_path"
    freshness_state="missing"
    trust_state="fail_closed"
    reason_code="missing_input_file"
    error_code="FE-SWARM-LIVE-MISSING-FILE"
    outcome="fail_closed"
  else
    cp "$input_path" "$raw_path"
    if jq empty "$raw_path" >/dev/null 2>&1; then
      redact_json "$raw_path" "$redacted_path"
      captured_at="$(jq -r '.captured_at // .capture_ts // .captured_ts // empty' "$raw_path")"
      age_seconds="$(age_seconds_for "$captured_at")"
      if [[ -z "$age_seconds" ]]; then
        freshness_state="missing"
        trust_state="degraded"
        reason_code="missing_capture_timestamp"
        error_code="FE-SWARM-LIVE-MISSING-CAPTURE-TS"
        outcome="degraded"
      elif (( age_seconds < 0 || age_seconds > freshness_window )); then
        freshness_state="stale"
        if [[ "$required" == "true" ]]; then
          trust_state="fail_closed"
          reason_code="stale_required_source"
          error_code="FE-SWARM-LIVE-STALE-REQUIRED"
          outcome="fail_closed"
        else
          trust_state="degraded"
          reason_code="stale_${component}"
          error_code="FE-SWARM-LIVE-STALE-OPTIONAL"
          outcome="degraded"
        fi
      fi
    else
      malformed="true"
      jq -n --arg component "$component" --arg input_path "$input_path" --arg now_ts "$now_ts" \
        '{malformed: true, component: $component, input_path: $input_path, captured_at: $now_ts}' >"$redacted_path"
      freshness_state="missing"
      trust_state="fail_closed"
      reason_code="malformed_source"
      error_code="FE-SWARM-LIVE-MALFORMED-SOURCE"
      outcome="fail_closed"
    fi
  fi

  if jq empty "$raw_path" >/dev/null 2>&1; then
    if jq -e 'any(..; ((type == "object" and (.local_fallback_observed? == true)) or (type == "string" and test("\\[RCH\\][[:space:]]+local|local fallback"; "i"))))' "$raw_path" >/dev/null; then
      local_fallback="true"
    fi
  elif grep -Eiq '\[RCH\][[:space:]]+local|local fallback' "$raw_path"; then
    local_fallback="true"
  fi
  if [[ "$local_fallback" == "true" ]]; then
    trust_state="fail_closed"
    reason_code="local_rch_fallback_marker"
    error_code="FE-SWARM-LIVE-RCH-LOCAL-FALLBACK"
    outcome="fail_closed"
  fi
  if [[ "$component" == "proof_transcript" ]] && grep -Eiq 'br update|br close|br reopen|git add|git commit|git reset|cargo (build|check|test|clippy|bench|run)|rch exec|rm -rf' "$raw_path"; then
    mutating_command="true"
    trust_state="fail_closed"
    reason_code="mutating_command_observed"
    error_code="FE-SWARM-LIVE-MUTATING-COMMAND"
    outcome="fail_closed"
  fi
  if [[ "$component" == "git_status" ]] && jq empty "$raw_path" >/dev/null 2>&1; then
    dirty_unowned_count="$(jq '[.. | objects | select((.class? // .ownership? // "") == "unowned")] | length' "$raw_path")"
    if (( dirty_unowned_count > 0 )) && [[ "$trust_state" == "trusted" ]]; then
      trust_state="blocked"
      reason_code="dirty_unowned_paths"
      error_code="FE-SWARM-LIVE-DIRTY-UNOWNED"
      outcome="blocked"
    fi
  fi

  payload_hash="$(sha256_file "$raw_path")"
  redacted_hash="$(sha256_file "$redacted_path")"
  if [[ "$payload_hash" == "$redacted_hash" ]]; then
    redaction_applied="false"
  else
    redaction_applied="true"
  fi

  printf 'component=%s mutation_class=%s command_hash=%s payload_hash=%s redacted_payload_hash=%s command=%q\n' \
    "$component" "$mutation_class" "$command_hash" "$payload_hash" "$redacted_hash" "$command_text" >>"$commands_path"

  jq -cn \
    --arg component "$component" \
    --arg maps_to "$maps_to" \
    --arg command "$command_text" \
    --arg mutation_class "$mutation_class" \
    --arg required "$required" \
    --arg freshness_state "$freshness_state" \
    --arg trust_state "$trust_state" \
    --arg reason_code "$reason_code" \
    --arg error_code "$error_code" \
    --arg captured_at "$captured_at" \
    --argjson age_seconds "${age_seconds:-null}" \
    --argjson freshness_window_seconds "$freshness_window" \
    --arg raw_path "${raw_path#"$root_dir"/}" \
    --arg redacted_path "${redacted_path#"$root_dir"/}" \
    --arg source_command_hash "$command_hash" \
    --arg payload_hash "$payload_hash" \
    --arg redacted_payload_hash "$redacted_hash" \
    --argjson redaction_applied "$redaction_applied" \
    --argjson malformed "$malformed" \
    --argjson local_fallback_observed "$local_fallback" \
    --argjson mutating_command_observed "$mutating_command" \
    --argjson dirty_unowned_count "$dirty_unowned_count" \
    '{
      component: $component,
      maps_to_swarm_ops_component: $maps_to,
      command: $command,
      mutation_class: $mutation_class,
      required: ($required == "true"),
      freshness_state: $freshness_state,
      trust_state: $trust_state,
      reason_code: (if $reason_code == "" then null else $reason_code end),
      error_code: (if $error_code == "" then null else $error_code end),
      captured_at: (if $captured_at == "" then null else $captured_at end),
      age_seconds: $age_seconds,
      freshness_window_seconds: $freshness_window_seconds,
      raw_path: $raw_path,
      redacted_path: $redacted_path,
      source_command_hash: $source_command_hash,
      payload_hash: $payload_hash,
      redacted_payload_hash: $redacted_payload_hash,
      redaction_applied: $redaction_applied,
      malformed: $malformed,
      local_fallback_observed: $local_fallback_observed,
      mutating_command_observed: $mutating_command_observed,
      dirty_unowned_count: $dirty_unowned_count
    }' >>"$sources_jsonl"

  write_event "$component" "source_normalized" "$outcome" "$error_code" "${raw_path#"$root_dir"/}" "$component" "$command_hash" "$payload_hash"
}

process_source "swarm_ops_state" "$swarm_ops_state_json" "true" "300" "input_file_only" "bd-eozx0-compatible live state JSON" "swarm_ops_state_bundle"
process_source "br_ready" "$br_ready_json" "false" "300" "read_only" "br ready --json" "br_ready"
process_source "br_in_progress" "$br_in_progress_json" "false" "300" "read_only" "br list --status=in_progress --json" "br_ready"
process_source "br_sync_status" "$br_sync_status_json" "false" "300" "read_only_status" "br sync --status --json" "br_ready"
process_source "bv_plan" "$bv_plan_json" "false" "300" "read_only" "bv --recipe actionable --robot-plan" "bv_plan"
process_source "agent_mail_snapshot" "$agent_mail_json" "false" "300" "input_file_only" "operator-supplied Agent Mail snapshot JSON file" "agent_mail"
process_source "rch_status" "$rch_status_json" "false" "120" "read_only" "rch status --workers --jobs --json" "rch"
process_source "rch_queue" "$rch_queue_json" "false" "120" "read_only" "rch queue --json" "rch"
process_source "git_status" "$git_status_json" "false" "300" "read_only" "git status --short" "git"
process_source "git_diff_check" "$git_diff_check_json" "false" "300" "read_only" "git diff --check -- <paths>" "git"
process_source "resource_pressure" "$resource_pressure_json" "false" "120" "input_file_only" "operator-supplied resource pressure JSON file" "rch"
process_source "proof_transcript" "$proof_transcript_json" "false" "86400" "input_file_only" "operator-supplied prior proof transcript file" "proof_cache_locality"

jq \
  --arg captured_at "$now_ts" \
  --arg source_revision "$source_revision" \
  '. + {
    captured_at: $captured_at,
    source_revision: $source_revision,
    bundle_writer: "scripts/swarm_live_readonly_snapshot_bundle.sh"
  }' "$profile_json" >"$capture_profile_path"

jq -s \
  --arg schema_version "franken-engine.swarm-live-readonly-redaction-report.v1" \
  --arg generated_at "$now_ts" \
  --arg profile_path "${capture_profile_path#"$root_dir"/}" \
  '{
    schema_version: $schema_version,
    generated_at: $generated_at,
    capture_profile: $profile_path,
    sources: map({
      component,
      raw_path,
      redacted_path,
      payload_hash,
      redacted_payload_hash,
      redaction_applied,
      malformed
    }),
    redaction_rules: [
      "agent_mail_tokens",
      "absolute_home_paths",
      "environment_secrets",
      "large_stdout"
    ]
  }' "$sources_jsonl" >"$redaction_report_path"

jq -s \
  --arg schema_version "franken-engine.swarm-live-readonly-capture-bundle.v1" \
  --arg swarm_ops_schema_version "franken-engine.swarm-ops-state-bundle.v1" \
  --arg source_revision "$source_revision" \
  --arg generated_at "$now_ts" \
  --arg run_id "$run_id" \
  --arg capture_profile_path "${capture_profile_path#"$root_dir"/}" \
  --arg snapshot_path "${snapshot_path#"$root_dir"/}" \
  --arg swarm_ops_bundle_path "${swarm_ops_bundle_path#"$root_dir"/}" \
  --arg events_path "${events_path#"$root_dir"/}" \
  --arg commands_path "${commands_path#"$root_dir"/}" \
  --arg redaction_report_path "${redaction_report_path#"$root_dir"/}" \
  --arg report_path "${report_path#"$root_dir"/}" \
  '
    def reason_list($state):
      map(select(.trust_state == $state and .reason_code != null) | .reason_code) | unique;
    . as $sources
    | (reason_list("fail_closed")) as $fail_closed_reasons
    | (reason_list("blocked")) as $blocked_reasons
    | (reason_list("degraded")) as $degraded_reasons
    | (if ($fail_closed_reasons | length) > 0 then "fail_closed"
       elif ($blocked_reasons | length) > 0 then "blocked"
       elif ($degraded_reasons | length) > 0 then "degraded"
       else "pass"
       end) as $decision
    | {
        schema_version: $schema_version,
        run_id: $run_id,
        generated_at: $generated_at,
        source_revision: $source_revision,
        decision: $decision,
        fail_closed_reasons: $fail_closed_reasons,
        blocked_reasons: $blocked_reasons,
        degraded_reasons: $degraded_reasons,
        upstream_authority: {
          canonical_live_state_bead_id: "bd-eozx0",
          canonical_live_state_contract: "docs/swarm_ops_state_contract_v1.json",
          canonical_resource_lease_bead_id: "bd-x82vp",
          canonical_resource_lease_runbook: "docs/SWARM_RESOURCE_LEASE_PLANNER.md"
        },
        non_mutation_attestation: {
          fixture_fed_only: true,
          proof_only: true,
          advisory_only: true,
          mutates_br: false,
          sends_agent_mail: false,
          queries_live_agent_mail: false,
          runs_cargo: false,
          runs_rch_exec: false,
          mutates_remote_workers: false,
          writes_outside_output_dir: false,
          creates_scheduler: false
        },
        sources: $sources,
        artifact_paths: {
          capture_profile_json: $capture_profile_path,
          snapshot_json: $snapshot_path,
          swarm_ops_state_bundle_json: $swarm_ops_bundle_path,
          events_jsonl: $events_path,
          commands_txt: $commands_path,
          redaction_report_json: $redaction_report_path,
          report_md: $report_path
        },
        swarm_ops_state_bundle: {
          schema_version: $swarm_ops_schema_version,
          produced_by: "scripts/swarm_live_readonly_snapshot_bundle.sh",
          source_contract: "docs/swarm_ops_state_contract_v1.json",
          decision: $decision,
          source_components: ($sources | map({
            component: .maps_to_swarm_ops_component,
            capture_source: .component,
            freshness_state,
            trust_state,
            error_code,
            evidence_path: .redacted_path,
            source_command_hash,
            payload_hash
          }))
        }
      }
  ' "$sources_jsonl" >"$snapshot_path"

jq '.swarm_ops_state_bundle' "$snapshot_path" >"$swarm_ops_bundle_path"

summary_decision="$(jq -r '.decision' "$snapshot_path")"
summary_error_code="$(jq -r '(.sources[] | select(.error_code != null) | .error_code) // ""' "$snapshot_path" | sed -n '1p')"
write_event "swarm_live_readonly_snapshot_bundle" "bundle_written" "$summary_decision" "$summary_error_code" "${snapshot_path#"$root_dir"/}" "summary" "$(sha256_text summary)" "$(sha256_file "$snapshot_path")"

cat >"$report_path" <<EOF
# SWARM Live Read-Only Snapshot Bundle

- decision: ${summary_decision}
- snapshot: ${snapshot_path}
- swarm ops bundle: ${swarm_ops_bundle_path}
- events: ${events_path}
- commands: ${commands_path}
- redaction report: ${redaction_report_path}
- canonical live state: bd-eozx0 / docs/swarm_ops_state_contract_v1.json
- canonical resource lease planner: bd-x82vp / docs/SWARM_RESOURCE_LEASE_PLANNER.md

This bundle is fixture-fed, proof-only, advisory-only, and non-mutating.
EOF

printf 'swarm live read-only snapshot bundle: %s\n' "$snapshot_path"
