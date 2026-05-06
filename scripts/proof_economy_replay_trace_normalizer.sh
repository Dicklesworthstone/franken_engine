#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${PROOF_ECONOMY_REPLAY_TRACE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-proof-economy-replay-trace}"
run_id="${PROOF_ECONOMY_REPLAY_TRACE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${PROOF_ECONOMY_REPLAY_TRACE_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

br_ready_json=""
br_in_progress_json=""
agent_mail_reservations_json=""
resource_lease_plans_json=""
proof_cache_plan_json=""
resident_bundle_report_json=""
no_mock_drill_report_json=""
source_revision=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/proof_economy_replay_trace_normalizer.sh --br-ready-json FILE --br-in-progress-json FILE [OPTIONS]

Normalizes scheduler replay lab inputs into one deterministic proof-economy
trace. Inputs are fixtures only; this script does not query live br, Agent Mail,
rch workers, or execute proof commands.

Required:
  --br-ready-json FILE
  --br-in-progress-json FILE

Optional:
  --agent-mail-reservations-json FILE
  --resource-lease-plans-json FILE
  --proof-cache-plan-json FILE
  --resident-bundle-report-json FILE
  --no-mock-drill-report-json FILE
  --source-revision REV
  --output-dir DIR

Artifacts:
  replay_trace.normalized.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  normalized successfully
  64 invalid or missing required input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --br-ready-json)
      br_ready_json="${2:-}"
      shift 2
      ;;
    --br-in-progress-json)
      br_in_progress_json="${2:-}"
      shift 2
      ;;
    --agent-mail-reservations-json)
      agent_mail_reservations_json="${2:-}"
      shift 2
      ;;
    --resource-lease-plans-json)
      resource_lease_plans_json="${2:-}"
      shift 2
      ;;
    --proof-cache-plan-json)
      proof_cache_plan_json="${2:-}"
      shift 2
      ;;
    --resident-bundle-report-json)
      resident_bundle_report_json="${2:-}"
      shift 2
      ;;
    --no-mock-drill-report-json)
      no_mock_drill_report_json="${2:-}"
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

if [[ -z "$br_ready_json" || -z "$br_in_progress_json" ]]; then
  printf 'proof-economy trace normalizer requires --br-ready-json and --br-in-progress-json\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for proof-economy replay trace normalization\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for proof-economy replay trace normalization\n' >&2
  exit 2
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
trace_path="${run_dir}/replay_trace.normalized.json"
trace_tmp="${trace_path}.tmp"
core_path="${run_dir}/replay_trace.core.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
ready_normalized="${run_dir}/br_ready.normalized.json"
in_progress_normalized="${run_dir}/br_in_progress.normalized.json"
reservations_normalized="${run_dir}/agent_mail_reservations.normalized.json"
leases_normalized="${run_dir}/resource_lease_plans.normalized.json"
proof_cache_normalized="${run_dir}/proof_cache_plan.normalized.json"
resident_bundle_normalized="${run_dir}/resident_bundle_report.normalized.json"
no_mock_drill_normalized="${run_dir}/no_mock_drill_report.normalized.json"
: >"$events_path"

printf './scripts/proof_economy_replay_trace_normalizer.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  jq -nc \
    --arg event "$1" \
    --arg detail "$2" \
    --arg source_revision "$source_revision" \
    '{event: $event, detail: $detail, source_revision: $source_revision}' >>"$events_path"
}

json_input() {
  local path="$1"
  local default_json="$2"
  local output_path="$3"
  local label="$4"
  local required="$5"

  if [[ -z "$path" ]]; then
    if [[ "$required" == "true" ]]; then
      printf 'proof-economy trace normalizer missing %s JSON\n' "$label" >&2
      exit 64
    fi
    printf '%s\n' "$default_json" >"$output_path"
    printf 'missing'
    return 0
  fi
  if [[ ! -f "$path" ]]; then
    printf 'proof-economy trace normalizer missing %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null; then
    printf 'proof-economy trace normalizer invalid %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  jq -c . "$path" >"$output_path"
  printf 'provided'
}

ready_status="$(json_input "$br_ready_json" '[]' "$ready_normalized" 'br ready snapshot' true)"
in_progress_status="$(json_input "$br_in_progress_json" '{"issues":[]}' "$in_progress_normalized" 'br in-progress snapshot' true)"
reservations_status="$(json_input "$agent_mail_reservations_json" '{"reservations":[]}' "$reservations_normalized" 'Agent Mail reservations snapshot' false)"
leases_status="$(json_input "$resource_lease_plans_json" '{"plans":[]}' "$leases_normalized" 'resource lease plans' false)"
proof_cache_status="$(json_input "$proof_cache_plan_json" '{}' "$proof_cache_normalized" 'proof cache plan' false)"
resident_bundle_status="$(json_input "$resident_bundle_report_json" '{}' "$resident_bundle_normalized" 'resident bundle report' false)"
no_mock_status="$(json_input "$no_mock_drill_report_json" '{}' "$no_mock_drill_normalized" 'no-mock drill report' false)"

write_event "inputs_loaded" "loaded fixture snapshots for proof-economy replay trace"

jq -n \
  --arg source_revision "$source_revision" \
  --arg ready_status "$ready_status" \
  --arg in_progress_status "$in_progress_status" \
  --arg reservations_status "$reservations_status" \
  --arg leases_status "$leases_status" \
  --arg proof_cache_status "$proof_cache_status" \
  --arg resident_bundle_status "$resident_bundle_status" \
  --arg no_mock_status "$no_mock_status" \
  --slurpfile ready "$ready_normalized" \
  --slurpfile in_progress "$in_progress_normalized" \
  --slurpfile reservations "$reservations_normalized" \
  --slurpfile leases "$leases_normalized" \
  --slurpfile proof_cache "$proof_cache_normalized" \
  --slurpfile resident_bundle "$resident_bundle_normalized" \
  --slurpfile no_mock "$no_mock_drill_normalized" \
  '
  def arr($doc; $name):
    if ($doc | type) == "array" then $doc else ($doc[$name] // []) end;

  def issue_rows($doc; $fallback_status):
    arr($doc; "issues")
    | map({
        bead_id: (.id // .bead_id // ""),
        title: (.title // ""),
        priority: (.priority // null),
        status: (.status // $fallback_status),
        assignee: (.assignee // null)
      })
    | map(select(.bead_id != ""))
    | sort_by(.status, .bead_id);

  def reservation_rows($doc):
    (
      if ($doc | type) == "array" then $doc
      else ($doc.reservations // $doc.granted // $doc.file_reservations // [])
      end
    )
    | map({
        path_pattern: (.path_pattern // .path // ""),
        agent_id: (.agent_id // .agent_name // .holder // ""),
        bead_id: (.bead_id // (.reason // "" | capture("(bd-[A-Za-z0-9.-]+)")?.string) // ""),
        exclusive: (.exclusive // true)
      })
    | map(select(.path_pattern != ""))
    | sort_by(.path_pattern, .agent_id, .bead_id);

  def lease_rows($doc):
    arr($doc; "plans")
    | map({
        agent_id: (.agent_id // ""),
        bead_id: (.bead_id // ""),
        requested_command: (.requested_command // .command // ""),
        target_dir: (.target_dir // ""),
        lease_decision: (.lease_decision // .decision // "unknown"),
        estimated_cpu_slots: (.estimated_cpu_slots // null),
        memory_class: (.estimated_memory_class // .memory_class // null)
      })
    | map(select(.agent_id != "" or .bead_id != "" or .requested_command != ""))
    | sort_by(.agent_id, .bead_id, .requested_command);

  def artifact_path_rows($doc; $source):
    ($doc.artifact_paths // $doc.child_artifacts // {})
    | to_entries
    | map(select((.value | type) == "string" and (.value | length) > 0))
    | map({
        source: $source,
        artifact_id: .key,
        artifact_path: .value,
        role: .key,
        decision: ($doc.drill_decision // $doc.bundle_decision // $doc.catalog_decision // "observed")
      });

  def proof_cache_rows($doc):
    (
      (($doc.cache_hit_artifacts // []) | map(. + {decision: "cache_hit"}))
      + (($doc.required_refreshes // []) | map(. + {decision: "refresh_required"}))
      + (($doc.invalid_artifacts // []) | map(. + {decision: "invalid"}))
    )
    | map({
        source: "proof_cache_plan",
        artifact_id: (.artifact_id // .proof_id // .receipt_id // .artifact_path // ""),
        artifact_path: (.artifact_path // .path // ""),
        role: (.artifact_role // .role // .receipt_kind // "proof"),
        decision: (.decision // "observed")
      });

  (issue_rows($ready[0]; "ready") + issue_rows($in_progress[0]; "in_progress") | unique_by(.status, .bead_id) | sort_by(.status, .bead_id)) as $beads
  | reservation_rows($reservations[0]) as $reservations_rows
  | lease_rows($leases[0]) as $lease_rows
  | (
      proof_cache_rows($proof_cache[0])
      + artifact_path_rows($resident_bundle[0]; "resident_bundle_report")
      + artifact_path_rows($no_mock[0]; "no_mock_drill_report")
    )
    | map(select(.artifact_path != "" or .artifact_id != ""))
    | unique_by(if (.artifact_path // "") != "" then .artifact_path else .artifact_id end)
    | sort_by(.source, .artifact_path, .artifact_id)
    as $proof_rows
  | (
      [($beads[]?.assignee // empty), ($reservations_rows[]?.agent_id // empty), ($lease_rows[]?.agent_id // empty)]
      | map(select(. != ""))
      | unique
      | sort
      | map({agent_id: ., sources: []})
    ) as $agents
  | {
      source_revision: $source_revision,
      input_statuses: {
        br_ready: $ready_status,
        br_in_progress: $in_progress_status,
        agent_mail_reservations: $reservations_status,
        resource_lease_plans: $leases_status,
        proof_cache_plan: $proof_cache_status,
        resident_bundle_report: $resident_bundle_status,
        no_mock_drill_report: $no_mock_status
      },
      degraded_mode: ($reservations_status == "missing"),
      agents: $agents,
      bead_rows: $beads,
      reservation_rows: $reservations_rows,
      command_rows: $lease_rows,
      proof_rows: $proof_rows,
      findings: (
        if $reservations_status == "missing" then
          [{
            severity: "warning",
            code: "missing_agent_mail_reservations",
            message: "Agent Mail reservation snapshot was not provided; replay trace is degraded and cannot prove file-ownership constraints."
          }]
        else
          []
        end
      ),
      summary: {
        agent_count: ($agents | length),
        bead_count: ($beads | length),
        reservation_count: ($reservations_rows | length),
        command_count: ($lease_rows | length),
        proof_artifact_count: ($proof_rows | length)
      }
    }
  ' >"$core_path"

trace_hash="$(jq -cS . "$core_path" | sha256sum | awk '{print "trace-" substr($1, 1, 16)}')"

jq \
  --arg schema_version "franken-engine.proof-economy-replay-trace.v1" \
  --arg trace_id "$trace_hash" \
  --arg trace_path "$trace_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  '. + {
    schema_version: $schema_version,
    trace_id: $trace_id,
    hash_basis: {
      trace_hash: $trace_id
    },
    artifact_paths: {
      replay_trace_normalized_json: $trace_path,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $report_path
    }
  }' "$core_path" >"$trace_tmp"
mv "$trace_tmp" "$trace_path"

write_event "trace_normalized" "$trace_hash"

{
  printf '# Proof Economy Replay Trace\n\n'
  printf -- '- Trace ID: %s\n' "$(jq -r '.trace_id' "$trace_path")"
  printf -- '- Degraded mode: %s\n' "$(jq -r '.degraded_mode' "$trace_path")"
  printf -- '- Agents: %s\n' "$(jq -r '.summary.agent_count' "$trace_path")"
  printf -- '- Beads: %s\n' "$(jq -r '.summary.bead_count' "$trace_path")"
  printf -- '- Commands: %s\n' "$(jq -r '.summary.command_count' "$trace_path")"
  printf -- '- Proof artifacts: %s\n' "$(jq -r '.summary.proof_artifact_count' "$trace_path")"
} >"$report_path"

printf 'proof_economy_replay_trace=%s\n' "$trace_path"
