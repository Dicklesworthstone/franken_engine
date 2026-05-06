#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_TELEMETRY_SNAPSHOT_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-telemetry-snapshot}"
run_id="${SWARM_TELEMETRY_SNAPSHOT_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_TELEMETRY_SNAPSHOT_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

ready_json=""
in_progress_json=""
validation_plan_json=""
resource_decision_json=""
agent_mail_reservations_json=""
stale_lock_recommendations_json=""
proof_freshness_json=""
admission_drill_report_json=""
predictive_wrapper_report_json=""
archive_lifecycle_report_json=""
proof_economy_drill_report_json=""
stress_suite_manifest_json=""
tail_latency_report_json=""
chaos_verification_report_json=""
swarm_responsiveness_claim_map_json=""
source_revision=""
now_epoch_seconds="$(date -u +%s)"
stale_after_seconds="1800"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_telemetry_snapshot_normalizer.sh --ready-json FILE --in-progress-json FILE --validation-plan-json FILE --resource-decision-json FILE [OPTIONS]

Normalizes existing predictive admission, archive lifecycle, and proof-economy
artifacts into one deterministic swarm capacity snapshot. This script is
fixture-fed only. It does not query live br, Agent Mail, rch, or execute Cargo.

Required:
  --ready-json FILE
  --in-progress-json FILE
  --validation-plan-json FILE
  --resource-decision-json FILE

Optional:
  --agent-mail-reservations-json FILE
  --stale-lock-recommendations-json FILE
  --proof-freshness-json FILE
  --admission-drill-report-json FILE
  --predictive-wrapper-report-json FILE
  --archive-lifecycle-report-json FILE
  --proof-economy-drill-report-json FILE
  --stress-suite-manifest-json FILE
  --tail-latency-report-json FILE
  --chaos-verification-report-json FILE
  --swarm-responsiveness-claim-map-json FILE
  --source-revision REV
  --now-epoch-seconds N
  --stale-after-seconds N
  --output-dir DIR

Artifacts:
  swarm_capacity_snapshot.json
  swarm_slo_input_snapshot.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  snapshot normalized successfully
  42 fail-closed rejection due to missing required fields, stale timestamps,
     contradictory ownership, or non-replayable artifact references
  64 invalid or missing required input path / malformed JSON
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --ready-json)
      ready_json="${2:-}"
      shift 2
      ;;
    --in-progress-json)
      in_progress_json="${2:-}"
      shift 2
      ;;
    --validation-plan-json)
      validation_plan_json="${2:-}"
      shift 2
      ;;
    --resource-decision-json)
      resource_decision_json="${2:-}"
      shift 2
      ;;
    --agent-mail-reservations-json)
      agent_mail_reservations_json="${2:-}"
      shift 2
      ;;
    --stale-lock-recommendations-json)
      stale_lock_recommendations_json="${2:-}"
      shift 2
      ;;
    --proof-freshness-json)
      proof_freshness_json="${2:-}"
      shift 2
      ;;
    --admission-drill-report-json)
      admission_drill_report_json="${2:-}"
      shift 2
      ;;
    --predictive-wrapper-report-json)
      predictive_wrapper_report_json="${2:-}"
      shift 2
      ;;
    --archive-lifecycle-report-json)
      archive_lifecycle_report_json="${2:-}"
      shift 2
      ;;
    --proof-economy-drill-report-json)
      proof_economy_drill_report_json="${2:-}"
      shift 2
      ;;
    --stress-suite-manifest-json)
      stress_suite_manifest_json="${2:-}"
      shift 2
      ;;
    --tail-latency-report-json)
      tail_latency_report_json="${2:-}"
      shift 2
      ;;
    --chaos-verification-report-json)
      chaos_verification_report_json="${2:-}"
      shift 2
      ;;
    --swarm-responsiveness-claim-map-json)
      swarm_responsiveness_claim_map_json="${2:-}"
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
    --stale-after-seconds)
      stale_after_seconds="${2:-}"
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
  [[ "$1" =~ ^[0-9]+$ ]]
}

if [[ -z "$ready_json" || -z "$in_progress_json" || -z "$validation_plan_json" || -z "$resource_decision_json" ]]; then
  printf 'swarm telemetry snapshot normalizer requires ready/in-progress/validation-plan/resource-decision inputs\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm telemetry snapshot normalization\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for swarm telemetry snapshot normalization\n' >&2
  exit 2
fi
if ! is_int "$now_epoch_seconds" || ! is_int "$stale_after_seconds"; then
  printf 'now/stale thresholds must be non-negative integers\n' >&2
  exit 64
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
snapshot_path="${run_dir}/swarm_capacity_snapshot.json"
snapshot_tmp="${snapshot_path}.tmp"
core_path="${run_dir}/swarm_capacity_snapshot.core.json"
slo_snapshot_path="${run_dir}/swarm_slo_input_snapshot.json"
slo_snapshot_tmp="${slo_snapshot_path}.tmp"
slo_core_path="${run_dir}/swarm_slo_input_snapshot.core.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"

ready_normalized="${run_dir}/ready.normalized.json"
in_progress_normalized="${run_dir}/in_progress.normalized.json"
validation_plan_normalized="${run_dir}/validation_plan.normalized.json"
resource_decision_normalized="${run_dir}/resource_decision.normalized.json"
reservations_normalized="${run_dir}/agent_mail_reservations.normalized.json"
stale_lock_normalized="${run_dir}/stale_lock_recommendations.normalized.json"
proof_freshness_normalized="${run_dir}/proof_freshness.normalized.json"
admission_drill_normalized="${run_dir}/admission_drill_report.normalized.json"
predictive_wrapper_normalized="${run_dir}/predictive_wrapper_report.normalized.json"
archive_lifecycle_normalized="${run_dir}/archive_lifecycle_report.normalized.json"
proof_economy_drill_normalized="${run_dir}/proof_economy_drill_report.normalized.json"
stress_suite_manifest_normalized="${run_dir}/stress_suite_manifest.normalized.json"
tail_latency_report_normalized="${run_dir}/tail_latency_report.normalized.json"
chaos_verification_report_normalized="${run_dir}/chaos_verification_report.normalized.json"
swarm_responsiveness_claim_map_normalized="${run_dir}/swarm_responsiveness_claim_map.normalized.json"
missing_required_jsonl="${run_dir}/missing_required.jsonl"
stale_inputs_jsonl="${run_dir}/stale_inputs.jsonl"
contradictions_jsonl="${run_dir}/contradictory_inputs.jsonl"
non_replayable_jsonl="${run_dir}/non_replayable_artifacts.jsonl"
high_core_missing_jsonl="${run_dir}/high_core_missing.jsonl"
high_core_traceability_jsonl="${run_dir}/high_core_traceability.jsonl"

: >"$events_path"
: >"$missing_required_jsonl"
: >"$stale_inputs_jsonl"
: >"$contradictions_jsonl"
: >"$non_replayable_jsonl"
: >"$high_core_missing_jsonl"
: >"$high_core_traceability_jsonl"

printf './scripts/swarm_telemetry_snapshot_normalizer.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-capacity-snapshot.event.v1" \
    --arg event_name "$1" \
    --arg detail "$2" \
    --arg source_revision "$source_revision" \
    '{
      schema_version: $schema_version,
      event_name: $event_name,
      detail: $detail,
      source_revision: $source_revision
    }' >>"$events_path"
}

append_issue() {
  local output_path="$1"
  local kind="$2"
  local source="$3"
  local label="$4"
  local detail="$5"

  jq -nc \
    --arg kind "$kind" \
    --arg source "$source" \
    --arg label "$label" \
    --arg detail "$detail" \
    '{kind: $kind, source: $source, label: $label, detail: $detail}' >>"$output_path"
}

json_input() {
  local path="$1"
  local default_json="$2"
  local output_path="$3"
  local label="$4"
  local required="$5"

  if [[ -z "$path" ]]; then
    if [[ "$required" == "true" ]]; then
      printf 'swarm telemetry snapshot normalizer missing %s JSON\n' "$label" >&2
      exit 64
    fi
    printf '%s\n' "$default_json" >"$output_path"
    printf 'missing'
    return 0
  fi
  if [[ ! -f "$path" ]]; then
    printf 'swarm telemetry snapshot normalizer missing %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null; then
    printf 'swarm telemetry snapshot normalizer invalid %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  jq -c . "$path" >"$output_path"
  printf 'provided'
}

ready_status="$(json_input "$ready_json" '[]' "$ready_normalized" 'ready snapshot' true)"
in_progress_status="$(json_input "$in_progress_json" '{"issues":[]}' "$in_progress_normalized" 'in-progress snapshot' true)"
validation_plan_status="$(json_input "$validation_plan_json" '{}' "$validation_plan_normalized" 'validation plan' true)"
resource_decision_status="$(json_input "$resource_decision_json" '{}' "$resource_decision_normalized" 'resource decision' true)"
reservations_status="$(json_input "$agent_mail_reservations_json" '{"reservations":[]}' "$reservations_normalized" 'Agent Mail reservations' false)"
stale_lock_status="$(json_input "$stale_lock_recommendations_json" '{"stale_lock_recommendations":[],"safe_to_reopen":[],"contact_first":[]}' "$stale_lock_normalized" 'stale lock recommendations' false)"
proof_freshness_status="$(json_input "$proof_freshness_json" '{}' "$proof_freshness_normalized" 'proof freshness' false)"
admission_drill_status="$(json_input "$admission_drill_report_json" '{}' "$admission_drill_normalized" 'swarm admission drill report' false)"
predictive_wrapper_status="$(json_input "$predictive_wrapper_report_json" '{}' "$predictive_wrapper_normalized" 'predictive orchestration wrapper report' false)"
archive_lifecycle_status="$(json_input "$archive_lifecycle_report_json" '{}' "$archive_lifecycle_normalized" 'archive lifecycle report' false)"
proof_economy_drill_status="$(json_input "$proof_economy_drill_report_json" '{}' "$proof_economy_drill_normalized" 'proof economy scheduler replay drill report' false)"
stress_suite_manifest_status="$(json_input "$stress_suite_manifest_json" '{}' "$stress_suite_manifest_normalized" 'stress suite manifest' false)"
tail_latency_report_status="$(json_input "$tail_latency_report_json" '{}' "$tail_latency_report_normalized" 'tail-latency report' false)"
chaos_verification_report_status="$(json_input "$chaos_verification_report_json" '{}' "$chaos_verification_report_normalized" 'chaos verification report' false)"
swarm_responsiveness_claim_map_status="$(json_input "$swarm_responsiveness_claim_map_json" '{}' "$swarm_responsiveness_claim_map_normalized" 'swarm responsiveness claim map' false)"

high_core_requested=false
for status in \
  "$stress_suite_manifest_status" \
  "$tail_latency_report_status" \
  "$chaos_verification_report_status" \
  "$swarm_responsiveness_claim_map_status"; do
  if [[ "$status" == "provided" ]]; then
    high_core_requested=true
    break
  fi
done

write_event "inputs_loaded" "loaded telemetry snapshot inputs"

parse_utc_to_epoch() {
  local utc_value="$1"
  if [[ -z "$utc_value" || "$utc_value" == "null" ]]; then
    printf '0\n'
    return 0
  fi

  python3 - "$utc_value" <<'PY'
import datetime
import sys

raw = sys.argv[1]
for fmt in ("%Y%m%dT%H%M%SZ", "%Y-%m-%dT%H:%M:%SZ"):
    try:
        dt = datetime.datetime.strptime(raw, fmt).replace(tzinfo=datetime.timezone.utc)
        print(int(dt.timestamp()))
        raise SystemExit(0)
    except ValueError:
        pass
print(0)
PY
}

extract_epoch_from_dir_name() {
  local path="$1"
  local base
  base="$(basename "$(dirname "$path")")"
  if [[ "$base" =~ ^([0-9]{8}T[0-9]{6}Z) ]]; then
    parse_utc_to_epoch "${BASH_REMATCH[1]}"
  else
    printf '0\n'
  fi
}

contains_rch_exec() {
  local command_text="$1"
  [[ "$command_text" =~ (^|[[:space:]])rch[[:space:]]+exec[[:space:]]+-- ]]
}

ensure_high_core_input_present() {
  local status="$1"
  local source="$2"
  local detail="$3"
  if [[ "$high_core_requested" == true && "$status" != "provided" ]]; then
    append_issue "$high_core_missing_jsonl" "missing_required_field" "$source" "high_core_required_input" "$detail"
  fi
}

check_high_core_traceability() {
  local source="$1"
  local trace_mode="$2"
  local detail="$3"

  if [[ "$high_core_requested" != true ]]; then
    return 0
  fi

  if [[ "$trace_mode" != "rch_backed" ]]; then
    append_issue "$high_core_traceability_jsonl" "non_rch_traceable_artifact" "$source" "rch_traceability" "$detail"
  fi
}

check_required_fields() {
  local file="$1"
  local expr="$2"
  local source="$3"
  local label="$4"

  if ! jq -e "$expr" "$file" >/dev/null; then
    append_issue "$missing_required_jsonl" "missing_required_field" "$source" "$label" "required field or shape missing"
  fi
}

check_required_fields "$ready_normalized" 'type == "array"' "ready_json" "root_array"
check_required_fields "$in_progress_normalized" '((type == "array") or (type == "object" and ((.issues // []) | type == "array")))' "in_progress_json" "issues_array"
check_required_fields "$validation_plan_normalized" 'has("schema_version") and (.schema_version | type == "string") and has("decision") and (.decision | type == "string") and has("commands") and (.commands | type == "array") and (has("collision_risk") or has("reservation_recommendations"))' "validation_plan_json" "schema_version_decision_commands_collision"
check_required_fields "$resource_decision_normalized" 'has("schema_version") and (.schema_version | type == "string") and has("decision") and (.decision | type == "string") and has("findings") and (.findings | type == "array")' "resource_decision_json" "schema_version_decision_findings"

ensure_high_core_input_present "$stress_suite_manifest_status" "stress_suite_manifest_json" "stress suite manifest is required when high-core SLO normalization is requested"
ensure_high_core_input_present "$tail_latency_report_status" "tail_latency_report_json" "tail-latency report is required when high-core SLO normalization is requested"
ensure_high_core_input_present "$chaos_verification_report_status" "chaos_verification_report_json" "chaos verification report is required when high-core SLO normalization is requested"
ensure_high_core_input_present "$swarm_responsiveness_claim_map_status" "swarm_responsiveness_claim_map_json" "swarm responsiveness claim map is required when high-core SLO normalization is requested"

if [[ "$stress_suite_manifest_status" == "provided" ]]; then
  check_required_fields "$stress_suite_manifest_normalized" 'has("schema_version") and (.schema_version == "franken-engine.stress-concurrency.suite-manifest.v1") and has("generated_at_utc") and (.generated_at_utc | type == "string") and has("commands") and (.commands | type == "array") and has("artifacts") and (.artifacts | type == "object")' "stress_suite_manifest_json" "schema_version_generated_at_commands_artifacts"
fi
if [[ "$tail_latency_report_status" == "provided" ]]; then
  check_required_fields "$tail_latency_report_normalized" 'has("schema_version") and (.schema_version == "franken-engine.tail-latency-control-plane.v1") and has("end_to_end_bounds") and (.end_to_end_bounds | type == "object") and has("guardrails") and (.guardrails | type == "object")' "tail_latency_report_json" "schema_version_bounds_guardrails"
fi
if [[ "$chaos_verification_report_status" == "provided" ]]; then
  check_required_fields "$chaos_verification_report_normalized" 'has("schema_version") and (.schema_version == "franken-engine.rgc-fault-injection-chaos-verification-pack.report.v1") and has("generated_at_utc") and (.generated_at_utc | type == "string") and has("summary") and (.summary | type == "object") and has("evidence_inputs") and (.evidence_inputs | type == "object")' "chaos_verification_report_json" "schema_version_generated_at_summary_inputs"
fi
if [[ "$swarm_responsiveness_claim_map_status" == "provided" ]]; then
  check_required_fields "$swarm_responsiveness_claim_map_normalized" 'has("schema_version") and (.schema_version == "franken-engine.swarm-responsiveness-claim-map.v1") and has("claims") and (.claims | type == "array") and has("operator_verification") and (.operator_verification | type == "array")' "swarm_responsiveness_claim_map_json" "schema_version_claims_operator_verification"
fi

snapshot_epoch_for() {
  local file="$1"

  jq -r '
    if (.snapshot_epoch_seconds? | type) == "number" then
      .snapshot_epoch_seconds
    elif (.captured_epoch_seconds? | type) == "number" then
      .captured_epoch_seconds
    elif (.generated_timestamp_ms? | type) == "number" then
      (.generated_timestamp_ms / 1000 | floor)
    elif (.timestamp_ms? | type) == "number" then
      (.timestamp_ms / 1000 | floor)
    elif (.summary.generated_timestamp_ms? | type) == "number" then
      (.summary.generated_timestamp_ms / 1000 | floor)
    else
      0
    end
  ' "$file"
}

snapshot_epoch_for_high_core() {
  local file="$1"
  local source="$2"
  local epoch

  epoch="$(snapshot_epoch_for "$file")"
  if is_int "$epoch" && (( epoch > 0 )); then
    printf '%s\n' "$epoch"
    return 0
  fi

  case "$source" in
    stress_suite_manifest_json|chaos_verification_report_json)
      epoch="$(jq -r '.generated_at_utc // empty' "$file")"
      parse_utc_to_epoch "$epoch"
      ;;
    tail_latency_report_json)
      extract_epoch_from_dir_name "$tail_latency_report_json"
      ;;
    *)
      printf '0\n'
      ;;
  esac
}

check_staleness() {
  local file="$1"
  local status="$2"
  local source="$3"
  local label="$4"
  local epoch_mode="${5:-standard}"
  local input_epoch age

  if [[ "$status" != "provided" ]]; then
    return 0
  fi
  if [[ "$epoch_mode" == "high_core" ]]; then
    input_epoch="$(snapshot_epoch_for_high_core "$file" "$source")"
  else
    input_epoch="$(snapshot_epoch_for "$file")"
  fi
  if is_int "$input_epoch" && (( input_epoch > 0 )); then
    age=$((now_epoch_seconds - input_epoch))
    if (( age > stale_after_seconds )); then
      append_issue "$stale_inputs_jsonl" "stale_timestamp" "$source" "$label" "snapshot age ${age}s exceeds ${stale_after_seconds}s"
    fi
  fi
}

check_staleness "$reservations_normalized" "$reservations_status" "agent_mail_reservations_json" "snapshot_epoch_seconds"
check_staleness "$predictive_wrapper_normalized" "$predictive_wrapper_status" "predictive_wrapper_report_json" "captured_epoch_seconds"
check_staleness "$archive_lifecycle_normalized" "$archive_lifecycle_status" "archive_lifecycle_report_json" "captured_epoch_seconds"
check_staleness "$proof_economy_drill_normalized" "$proof_economy_drill_status" "proof_economy_drill_report_json" "captured_epoch_seconds"
check_staleness "$stress_suite_manifest_normalized" "$stress_suite_manifest_status" "stress_suite_manifest_json" "generated_at_utc" "high_core"
check_staleness "$tail_latency_report_normalized" "$tail_latency_report_status" "tail_latency_report_json" "artifact_dir_timestamp" "high_core"
check_staleness "$chaos_verification_report_normalized" "$chaos_verification_report_status" "chaos_verification_report_json" "generated_at_utc" "high_core"

if [[ "$reservations_status" == "provided" ]]; then
  jq -nc \
    --slurpfile in_progress "$in_progress_normalized" \
    --slurpfile reservations "$reservations_normalized" '
      def arr($doc; $name):
        if ($doc | type) == "array" then $doc else ($doc[$name] // []) end;
      [
        (arr($in_progress[0]; "issues"))[]? as $issue
        | ($issue.assignee // "") as $assignee
        | select($assignee != "")
        | (arr($reservations[0]; "reservations"))[]?
        | select((.bead_id // "") == ($issue.id // ""))
        | (.agent_name // .agent_id // .agent // .holder // "") as $holder
        | select($holder != "" and $holder != $assignee)
        | {
            kind: "contradictory_active_agent_ownership",
            source: "agent_mail_reservations_json",
            label: ($issue.id // ""),
            detail: ("assignee=" + $assignee + " reservation_holder=" + $holder + " path=" + (.path_pattern // .path // ""))
          }
      ][]' >>"$contradictions_jsonl"
fi

check_report_artifacts() {
  local file="$1"
  local status="$2"
  local source="$3"
  local report_dir artifact_id artifact_path resolved_path

  if [[ "$status" != "provided" ]]; then
    return 0
  fi
  report_dir="$(cd "$(dirname "$file")" && pwd)"
  while IFS=$'\t' read -r artifact_id artifact_path; do
    [[ -n "$artifact_path" ]] || continue
    resolved_path="$artifact_path"
    if [[ "$resolved_path" != /* ]]; then
      resolved_path="$(realpath -m "${report_dir}/${resolved_path}")"
    fi
    if [[ ! -e "$resolved_path" ]]; then
      append_issue "$non_replayable_jsonl" "non_replayable_artifact_reference" "$source" "$artifact_id" "$artifact_path"
    fi
  done < <(
    jq -r '
      [(.artifact_paths? // {}), (.child_artifacts? // {})]
      | map(select(type == "object"))
      | add
      | to_entries[]?
      | select((.value | type) == "string" and (.value | length) > 0)
      | "\(.key)\t\(.value)"
    ' "$file"
  )
}

check_report_artifacts "$admission_drill_report_json" "$admission_drill_status" "admission_drill_report_json"
check_report_artifacts "$predictive_wrapper_report_json" "$predictive_wrapper_status" "predictive_wrapper_report_json"
check_report_artifacts "$archive_lifecycle_report_json" "$archive_lifecycle_status" "archive_lifecycle_report_json"
check_report_artifacts "$proof_economy_drill_report_json" "$proof_economy_drill_status" "proof_economy_drill_report_json"

resolve_artifact_path() {
  local base_dir="$1"
  local candidate="$2"
  if [[ -z "$candidate" || "$candidate" == "null" ]]; then
    printf '\n'
  elif [[ "$candidate" == /* ]]; then
    printf '%s\n' "$candidate"
  else
    realpath -m "${base_dir}/${candidate}"
  fi
}

collect_command_lines() {
  local output_path="$1"
  shift

  : >"$output_path"
  for candidate in "$@"; do
    if [[ -z "$candidate" ]]; then
      continue
    fi
    if [[ -f "$candidate" ]]; then
      cat "$candidate" >>"$output_path"
      printf '\n' >>"$output_path"
      return 0
    fi
  done
  return 1
}

all_commands_are_rch() {
  local file="$1"
  local line
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    if ! contains_rch_exec "$line"; then
      return 1
    fi
  done <"$file"
  return 0
}

extract_repo_script_path() {
  local command_text="$1"
  local token normalized
  for token in $command_text; do
    case "$token" in
      ./scripts/*|scripts/*)
        normalized="${token#./}"
        printf '%s\n' "${root_dir}/${normalized}"
        return 0
        ;;
    esac
  done
  return 1
}

command_is_rch_traceable() {
  local command_text="$1"
  local script_path

  [[ -z "$command_text" ]] && return 0
  if contains_rch_exec "$command_text"; then
    return 0
  fi
  if [[ "$command_text" =~ (^|[[:space:]])cargo([[:space:]]|$) ]]; then
    return 1
  fi
  if ! script_path="$(extract_repo_script_path "$command_text")"; then
    return 0
  fi
  if [[ ! -f "$script_path" ]]; then
    return 1
  fi
  if grep -Eq '(^|[[:space:]])rch[[:space:]]+exec[[:space:]]+--' "$script_path"; then
    return 0
  fi
  if grep -Eq '(^|[[:space:]])cargo([[:space:]]|$)' "$script_path"; then
    return 1
  fi
  return 0
}

all_commands_are_rch_traceable() {
  local file="$1"
  local line
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    if ! command_is_rch_traceable "$line"; then
      return 1
    fi
  done <"$file"
  return 0
}

stress_commands_capture="${run_dir}/stress_suite.commands.txt"
tail_latency_commands_capture="${run_dir}/tail_latency.commands.txt"
chaos_commands_capture="${run_dir}/chaos_verification.commands.txt"
claim_map_commands_capture="${run_dir}/swarm_responsiveness_claim_map.commands.txt"
stress_run_manifest_detail_normalized="${run_dir}/stress_run_manifest_detail.normalized.json"
tail_run_manifest_normalized="${run_dir}/tail_latency_run_manifest.normalized.json"
chaos_run_manifest_normalized="${run_dir}/chaos_run_manifest.normalized.json"

stress_commands_trace_mode="missing"
tail_latency_trace_mode="missing"
chaos_trace_mode="missing"
claim_map_trace_mode="missing"

printf '{}\n' >"$stress_run_manifest_detail_normalized"
printf '{}\n' >"$tail_run_manifest_normalized"
printf '{}\n' >"$chaos_run_manifest_normalized"

if [[ "$stress_suite_manifest_status" == "provided" ]]; then
  stress_manifest_dir="$(cd "$(dirname "$stress_suite_manifest_json")" && pwd)"
  stress_commands_path="$(resolve_artifact_path "$stress_manifest_dir" "commands.txt")"
  stress_run_manifest_path="$(resolve_artifact_path "$stress_manifest_dir" "$(jq -r '.artifacts.stress_manifest // empty' "$stress_suite_manifest_normalized")")"
  if collect_command_lines "$stress_commands_capture" "$stress_commands_path"; then
    if grep -q '.' "$stress_commands_capture" && all_commands_are_rch "$stress_commands_capture"; then
      stress_commands_trace_mode="rch_backed"
    else
      stress_commands_trace_mode="local_or_unknown"
    fi
  fi
  if [[ -n "$stress_run_manifest_path" && -f "$stress_run_manifest_path" ]] && jq empty "$stress_run_manifest_path" >/dev/null 2>&1; then
    jq -c . "$stress_run_manifest_path" >"$stress_run_manifest_detail_normalized"
  else
    append_issue "$non_replayable_jsonl" "non_replayable_artifact_reference" "stress_suite_manifest_json" "artifacts.stress_manifest" "$(jq -r '.artifacts.stress_manifest // "missing"' "$stress_suite_manifest_normalized")"
  fi
  check_high_core_traceability "stress_suite_manifest_json" "$stress_commands_trace_mode" "stress suite commands are not traceable to rch-backed execution"
fi

if [[ "$tail_latency_report_status" == "provided" ]]; then
  tail_report_dir="$(cd "$(dirname "$tail_latency_report_json")" && pwd)"
  tail_commands_path="$(resolve_artifact_path "$tail_report_dir" "commands.txt")"
  tail_run_manifest_path="$(resolve_artifact_path "$tail_report_dir" "run_manifest.json")"
  if collect_command_lines "$tail_latency_commands_capture" "$tail_commands_path"; then
    if grep -q '.' "$tail_latency_commands_capture" && all_commands_are_rch "$tail_latency_commands_capture"; then
      tail_latency_trace_mode="rch_backed"
    else
      tail_latency_trace_mode="local_or_unknown"
    fi
  fi
  if [[ -f "$tail_run_manifest_path" ]] && jq empty "$tail_run_manifest_path" >/dev/null 2>&1; then
    jq -c . "$tail_run_manifest_path" >"$tail_run_manifest_normalized"
  fi
  check_high_core_traceability "tail_latency_report_json" "$tail_latency_trace_mode" "tail-latency artifacts are not traceable to rch-backed execution"
fi

if [[ "$chaos_verification_report_status" == "provided" ]]; then
  chaos_report_dir="$(cd "$(dirname "$chaos_verification_report_json")" && pwd)"
  chaos_commands_path="$(resolve_artifact_path "$chaos_report_dir" "commands.txt")"
  chaos_run_manifest_path="$(resolve_artifact_path "$chaos_report_dir" "run_manifest.json")"
  if collect_command_lines "$chaos_commands_capture" "$chaos_commands_path"; then
    if grep -q '.' "$chaos_commands_capture" && all_commands_are_rch "$chaos_commands_capture"; then
      chaos_trace_mode="rch_backed"
    else
      chaos_trace_mode="local_or_unknown"
    fi
  fi
  if [[ -f "$chaos_run_manifest_path" ]] && jq empty "$chaos_run_manifest_path" >/dev/null 2>&1; then
    jq -c . "$chaos_run_manifest_path" >"$chaos_run_manifest_normalized"
  fi
  check_high_core_traceability "chaos_verification_report_json" "$chaos_trace_mode" "chaos verification artifacts are not traceable to rch-backed execution"
fi

if [[ "$swarm_responsiveness_claim_map_status" == "provided" ]]; then
  jq -r '
    [
      (.operator_verification[]?),
      (.claims[]?.verification_commands[]?)
    ]
    | map(select(type == "string" and length > 0))
    | .[]
  ' "$swarm_responsiveness_claim_map_normalized" >"$claim_map_commands_capture"

  if [[ -s "$claim_map_commands_capture" ]] && all_commands_are_rch_traceable "$claim_map_commands_capture"; then
    claim_map_trace_mode="rch_backed"
  else
    claim_map_trace_mode="local_or_unknown"
  fi
  check_high_core_traceability "swarm_responsiveness_claim_map_json" "$claim_map_trace_mode" "claim-map verification commands must stay rch-backed"
fi

jq -n \
  --arg schema_version "franken-engine.swarm-capacity-snapshot.v1" \
  --arg source_revision "$source_revision" \
  --arg ready_status "$ready_status" \
  --arg in_progress_status "$in_progress_status" \
  --arg validation_plan_status "$validation_plan_status" \
  --arg resource_decision_status "$resource_decision_status" \
  --arg reservations_status "$reservations_status" \
  --arg stale_lock_status "$stale_lock_status" \
  --arg proof_freshness_status "$proof_freshness_status" \
  --arg admission_drill_status "$admission_drill_status" \
  --arg predictive_wrapper_status "$predictive_wrapper_status" \
  --arg archive_lifecycle_status "$archive_lifecycle_status" \
  --arg proof_economy_drill_status "$proof_economy_drill_status" \
  --arg stress_suite_manifest_status "$stress_suite_manifest_status" \
  --arg tail_latency_report_status "$tail_latency_report_status" \
  --arg chaos_verification_report_status "$chaos_verification_report_status" \
  --arg swarm_responsiveness_claim_map_status "$swarm_responsiveness_claim_map_status" \
  --arg stress_commands_trace_mode "$stress_commands_trace_mode" \
  --arg tail_latency_trace_mode "$tail_latency_trace_mode" \
  --arg chaos_trace_mode "$chaos_trace_mode" \
  --arg claim_map_trace_mode "$claim_map_trace_mode" \
  --arg dashboard_contract_path "docs/swarm_predictive_dashboard_contract_v1.json" \
  --arg telemetry_contract_path "docs/swarm_telemetry_snapshot_contract_v1.json" \
  --arg slo_snapshot_path "$slo_snapshot_path" \
  --argjson now_epoch_seconds "$now_epoch_seconds" \
  --argjson stale_after_seconds "$stale_after_seconds" \
  --argjson high_core_requested "$high_core_requested" \
  --arg snapshot_path "$snapshot_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --slurpfile ready "$ready_normalized" \
  --slurpfile in_progress "$in_progress_normalized" \
  --slurpfile validation_plan "$validation_plan_normalized" \
  --slurpfile resource_decision "$resource_decision_normalized" \
  --slurpfile reservations "$reservations_normalized" \
  --slurpfile stale_lock "$stale_lock_normalized" \
  --slurpfile proof_freshness "$proof_freshness_normalized" \
  --slurpfile admission_drill "$admission_drill_normalized" \
  --slurpfile predictive_wrapper "$predictive_wrapper_normalized" \
  --slurpfile archive_lifecycle "$archive_lifecycle_normalized" \
  --slurpfile proof_economy_drill "$proof_economy_drill_normalized" \
  --slurpfile stress_suite_manifest "$stress_suite_manifest_normalized" \
  --slurpfile stress_run_manifest "$stress_run_manifest_detail_normalized" \
  --slurpfile tail_latency_report "$tail_latency_report_normalized" \
  --slurpfile tail_latency_run_manifest "$tail_run_manifest_normalized" \
  --slurpfile chaos_verification_report "$chaos_verification_report_normalized" \
  --slurpfile chaos_run_manifest "$chaos_run_manifest_normalized" \
  --slurpfile swarm_responsiveness_claim_map "$swarm_responsiveness_claim_map_normalized" \
  --slurpfile missing_required "$missing_required_jsonl" \
  --slurpfile stale_inputs "$stale_inputs_jsonl" \
  --slurpfile contradictions "$contradictions_jsonl" \
  --slurpfile non_replayable "$non_replayable_jsonl" \
  --slurpfile high_core_missing "$high_core_missing_jsonl" \
  --slurpfile high_core_traceability "$high_core_traceability_jsonl" \
  '
  def arr($doc; $name):
    if ($doc | type) == "array" then $doc else ($doc[$name] // []) end;
  def issue_rows($doc):
    arr($doc; "issues")
    | map({
        id: (.id // .bead_id // ""),
        title: (.title // ""),
        priority: (.priority // null),
        status: (.status // null),
        assignee: (.assignee // null)
      })
    | map(select(.id != ""));
  def reservations_rows($doc):
    arr($doc; "reservations")
    | map({
        path_pattern: (.path_pattern // .path // ""),
        bead_id: (.bead_id // ""),
        agent: (.agent_name // .agent_id // .agent // .holder // ""),
        exclusive: (.exclusive // true)
      });
  def predicted_rows($doc):
    ($doc.commands // [])
    | map(select(.predicted_cost? != null))
    | map({
        command_id: (.command_id // null),
        display: (.display // null),
        cost_class: (.predicted_cost.cost_class // "unknown"),
        cost_state: (.predicted_cost.state // "unknown"),
        risk_flags: (.risk_flags // [])
      });
  def high_cost_rows($rows):
    $rows
    | map(select(
        (.cost_class == "high")
        or (((.risk_flags // []) | map(select(test("high|unknown|stale|mismatched|contradictory|failed|fallback"))) | length) > 0)
      ));
  def bounded($rows): (($rows // [])[0:8]);
  def issue_rows_for($rows; $source): (($rows // []) | map(select(.source == $source)));
  def issue_count_for($rows; $source): (issue_rows_for($rows; $source) | length);
  def high_core_status($requested; $provided; $missing_rows; $stale_rows; $trace_rows; $source):
    if $requested != true then
      "not_requested"
    elif $provided != "provided" then
      "missing"
    elif issue_count_for($missing_rows; $source) > 0 then
      "missing"
    elif issue_count_for($stale_rows; $source) > 0 then
      "stale"
    elif issue_count_for($trace_rows; $source) > 0 then
      "fail_closed"
    else
      "accepted"
    end;
  def high_core_trace_label($mode):
    if $mode == "rch_backed" then "rch_backed"
    elif $mode == "missing" then "missing"
    else "local_or_unknown"
    end;
  def is_high_core_optional_input($input):
    $input == "stress_suite_manifest_json"
    or $input == "tail_latency_report_json"
    or $input == "chaos_verification_report_json"
    or $input == "swarm_responsiveness_claim_map_json";

  ($ready[0] // []) as $ready_doc
  | ($in_progress[0] // {}) as $in_progress_doc
  | ($validation_plan[0] // {}) as $validation_doc
  | ($resource_decision[0] // {}) as $resource_doc
  | ($reservations[0] // {}) as $reservations_doc
  | ($stale_lock[0] // {}) as $stale_lock_doc
  | ($proof_freshness[0] // {}) as $proof_freshness_doc
  | ($admission_drill[0] // {}) as $admission_doc
  | ($predictive_wrapper[0] // {}) as $predictive_doc
  | ($archive_lifecycle[0] // {}) as $archive_doc
  | ($proof_economy_drill[0] // {}) as $proof_doc
  | ($stress_suite_manifest[0] // {}) as $stress_suite_doc
  | ($stress_run_manifest[0] // {}) as $stress_run_doc
  | ($tail_latency_report[0] // {}) as $tail_report_doc
  | ($tail_latency_run_manifest[0] // {}) as $tail_run_doc
  | ($chaos_verification_report[0] // {}) as $chaos_report_doc
  | ($chaos_run_manifest[0] // {}) as $chaos_run_doc
  | ($swarm_responsiveness_claim_map[0] // {}) as $claim_map_doc
  | (issue_rows($ready_doc)) as $ready_rows
  | (issue_rows($in_progress_doc)) as $in_progress_rows
  | (reservations_rows($reservations_doc)) as $reservation_rows
  | (predicted_rows($validation_doc)) as $predicted_rows
  | (high_cost_rows($predicted_rows)) as $high_cost_rows
  | (
      [
        {input:"ready_json", status:$ready_status, path:"ready.normalized.json", schema_version:"beads.ready-array"},
        {input:"in_progress_json", status:$in_progress_status, path:"in_progress.normalized.json", schema_version:(if ($in_progress_doc.schema_version? // null) == null then "beads.in-progress-array" else $in_progress_doc.schema_version end)},
        {input:"validation_plan_json", status:$validation_plan_status, path:"validation_plan.normalized.json", schema_version:($validation_doc.schema_version // null)},
        {input:"resource_decision_json", status:$resource_decision_status, path:"resource_decision.normalized.json", schema_version:($resource_doc.schema_version // null)},
        {input:"agent_mail_reservations_json", status:$reservations_status, path:"agent_mail_reservations.normalized.json", schema_version:($reservations_doc.schema_version // null)},
        {input:"stale_lock_recommendations_json", status:$stale_lock_status, path:"stale_lock_recommendations.normalized.json", schema_version:($stale_lock_doc.schema_version // null)},
        {input:"proof_freshness_json", status:$proof_freshness_status, path:"proof_freshness.normalized.json", schema_version:($proof_freshness_doc.schema_version // null)},
        {input:"admission_drill_report_json", status:$admission_drill_status, path:"admission_drill_report.normalized.json", schema_version:($admission_doc.schema_version // null)},
        {input:"predictive_wrapper_report_json", status:$predictive_wrapper_status, path:"predictive_wrapper_report.normalized.json", schema_version:($predictive_doc.schema_version // null)},
        {input:"archive_lifecycle_report_json", status:$archive_lifecycle_status, path:"archive_lifecycle_report.normalized.json", schema_version:($archive_doc.schema_version // null)},
        {input:"proof_economy_drill_report_json", status:$proof_economy_drill_status, path:"proof_economy_drill_report.normalized.json", schema_version:($proof_doc.schema_version // null)},
        {input:"stress_suite_manifest_json", status:$stress_suite_manifest_status, path:"stress_suite_manifest.normalized.json", schema_version:($stress_suite_doc.schema_version // null)},
        {input:"tail_latency_report_json", status:$tail_latency_report_status, path:"tail_latency_report.normalized.json", schema_version:($tail_report_doc.schema_version // null)},
        {input:"chaos_verification_report_json", status:$chaos_verification_report_status, path:"chaos_verification_report.normalized.json", schema_version:($chaos_report_doc.schema_version // null)},
        {input:"swarm_responsiveness_claim_map_json", status:$swarm_responsiveness_claim_map_status, path:"swarm_responsiveness_claim_map.normalized.json", schema_version:($claim_map_doc.schema_version // null)}
      ]
    ) as $input_rows
  | ($input_rows | map(select(.status == "provided"))) as $accepted_inputs
  | ($input_rows | map(select(
      .status == "missing"
      and (
        $high_core_requested
        or (is_high_core_optional_input(.input) | not)
      )
    ))) as $missing_inputs
  | ($missing_required // []) as $missing_required_rows
  | ($stale_inputs // []) as $stale_rows
  | ($contradictions // []) as $contradiction_rows
  | ($non_replayable // []) as $non_replayable_rows
  | ($high_core_missing // []) as $high_core_missing_rows
  | ($high_core_traceability // []) as $high_core_traceability_rows
  | (high_core_status($high_core_requested; $stress_suite_manifest_status; $high_core_missing_rows; $stale_rows; $high_core_traceability_rows; "stress_suite_manifest_json")) as $stress_slo_status
  | (high_core_status($high_core_requested; $tail_latency_report_status; $high_core_missing_rows; $stale_rows; $high_core_traceability_rows; "tail_latency_report_json")) as $tail_slo_status
  | (high_core_status($high_core_requested; $chaos_verification_report_status; $high_core_missing_rows; $stale_rows; $high_core_traceability_rows; "chaos_verification_report_json")) as $chaos_slo_status
  | (high_core_status($high_core_requested; $swarm_responsiveness_claim_map_status; $high_core_missing_rows; $stale_rows; $high_core_traceability_rows; "swarm_responsiveness_claim_map_json")) as $claim_map_slo_status
  | ([
      $stress_slo_status,
      $tail_slo_status,
      $chaos_slo_status,
      $claim_map_slo_status
    ] | map(select(. == "accepted")) | length) as $high_core_accepted_count
  | ([
      $stress_slo_status,
      $tail_slo_status,
      $chaos_slo_status,
      $claim_map_slo_status
    ] | map(select(. == "fail_closed" or . == "stale" or . == "missing")) | length) as $high_core_blocked_count
  | ({
      ready_count: ($ready_rows | length),
      in_progress_count: ($in_progress_rows | length),
      active_agent_count: ([($in_progress_rows[]?.assignee), ($reservation_rows[]?.agent)] | map(select(. != null and . != "")) | unique | length),
      high_cost_command_count: ($high_cost_rows | length),
      reservation_count: ($reservation_rows | length),
      safe_to_reopen_count: (($stale_lock_doc.safe_to_reopen // []) | length),
      contact_first_count: (($stale_lock_doc.contact_first // []) | length),
      archive_signal_count: ([($archive_doc.artifact_paths // {}), ($archive_doc.child_artifacts // {})] | map(select(type == "object")) | add | length),
      proof_signal_count: ([($proof_doc.artifact_paths // {}), ($proof_doc.child_artifacts // {})] | map(select(type == "object")) | add | length),
      high_core_requested: $high_core_requested,
      high_core_accepted_count: $high_core_accepted_count,
      high_core_blocked_count: $high_core_blocked_count
    }) as $summary
  | {
      schema_version: $schema_version,
      source_revision: $source_revision,
      generated_epoch_seconds: $now_epoch_seconds,
      stale_after_seconds: $stale_after_seconds,
      decision: (
        if (($missing_required_rows | length)
            + ($stale_rows | length)
            + ($contradiction_rows | length)
            + ($non_replayable_rows | length)
            + (if $high_core_requested then (($high_core_missing_rows | length) + ($high_core_traceability_rows | length)) else 0 end)
           ) > 0
        then "fail_closed"
        else "pass"
        end
      ),
      summary: $summary,
      accepted_inputs: $accepted_inputs,
      missing_inputs: $missing_inputs,
      stale_inputs: $stale_rows,
      contradictory_inputs: $contradiction_rows,
      non_replayable_artifact_refs: $non_replayable_rows,
      missing_required_fields: $missing_required_rows,
      high_core_missing_inputs: $high_core_missing_rows,
      high_core_traceability_failures: $high_core_traceability_rows,
      reuse_audit: {
        consumed_input_count: ($accepted_inputs | length),
        consumed_schemas: ($accepted_inputs | map(.schema_version) | map(select(. != null)) | unique | sort),
        direct_artifact_sources: [
          ($admission_doc.schema_version // empty),
          ($predictive_doc.schema_version // empty),
          ($archive_doc.schema_version // empty),
          ($proof_doc.schema_version // empty),
          ($stress_suite_doc.schema_version // empty),
          ($tail_report_doc.schema_version // empty),
          ($chaos_report_doc.schema_version // empty),
          ($claim_map_doc.schema_version // empty)
        ] | map(select(. != "")) | unique | sort,
        dashboard_contract_extension: {
          contract_json: $dashboard_contract_path,
          telemetry_snapshot_contract_json: $telemetry_contract_path,
          provider: "/dp/frankentui",
          shipped_in_franken_engine: false
        }
      },
      swarm_capacity_snapshot: {
        queue_state: {
          ready_beads: bounded($ready_rows),
          in_progress_beads: bounded($in_progress_rows)
        },
        predictive_cost: {
          collision_risk: ($validation_doc.collision_risk // "unknown"),
          conflicting_agents: ($validation_doc.conflicting_agents // []),
          safe_alternatives: ($validation_doc.safe_alternatives // []),
          reservation_recommendations: ($validation_doc.reservation_recommendations // []),
          commands: bounded($predicted_rows),
          high_risk_commands: bounded($high_cost_rows)
        },
        resource_pressure: {
          decision: ($resource_doc.decision // "unknown"),
          findings: bounded($resource_doc.findings)
        },
        coordination: {
          reservation_rows: bounded($reservation_rows),
          stale_lock_recommendations: bounded($stale_lock_doc.stale_lock_recommendations),
          safe_to_reopen: bounded($stale_lock_doc.safe_to_reopen),
          contact_first: bounded($stale_lock_doc.contact_first)
        },
        archive_lifecycle: {
          schema_version: ($archive_doc.schema_version // null),
          decision: ($archive_doc.drill_decision // $archive_doc.status // null),
          artifact_paths: ($archive_doc.artifact_paths // $archive_doc.child_artifacts // {})
        },
        proof_economy: {
          schema_version: ($proof_doc.schema_version // null),
          decision: ($proof_doc.drill_decision // $proof_doc.status // null),
          artifact_paths: ($proof_doc.artifact_paths // $proof_doc.child_artifacts // {})
        },
        proof_freshness: {
          schema_version: ($proof_freshness_doc.schema_version // null),
          freshness_state: ($proof_freshness_doc.freshness_state // null),
          reusable: ($proof_freshness_doc.reusable // null),
          recommended_next_action: ($proof_freshness_doc.recommended_next_action // null)
        },
        swarm_slo_inputs: {
          requested: $high_core_requested,
          decision: (
            if $high_core_requested != true then
              "not_requested"
            elif $high_core_blocked_count > 0 then
              "fail_closed"
            else
              "pass"
            end
          ),
          stress_concurrency: {
            status: $stress_slo_status,
            traceability: high_core_trace_label($stress_commands_trace_mode),
            generated_at_utc: ($stress_suite_doc.generated_at_utc // null),
            outcome: ($stress_suite_doc.outcome // null),
            scenario_count: ($stress_run_doc.scenario_count // null),
            aggregate_invariant_violations: ($stress_run_doc.aggregate_invariant_violations // null)
          },
          tail_latency_control_plane: {
            status: $tail_slo_status,
            traceability: high_core_trace_label($tail_latency_trace_mode),
            bundle_epoch: ($tail_report_doc.bundle_epoch // null),
            observed_p95_ns: ($tail_report_doc.end_to_end_bounds.observed_p95_ns // null),
            observed_p99_ns: ($tail_report_doc.end_to_end_bounds.observed_p99_ns // null),
            queue_adjusted_p99_ns: ($tail_report_doc.end_to_end_bounds.queue_adjusted_p99_ns // null),
            guardrail_state: ($tail_report_doc.guardrails.state // null),
            violated_stage_count: ($tail_report_doc.guardrails.violated_stage_count // null)
          },
          chaos_verification: {
            status: $chaos_slo_status,
            traceability: high_core_trace_label($chaos_trace_mode),
            generated_at_utc: ($chaos_report_doc.generated_at_utc // null),
            outcome: ($chaos_report_doc.outcome // null),
            vector_count: ($chaos_report_doc.summary.vector_count // null),
            unique_class_count: ($chaos_report_doc.summary.unique_class_count // null)
          },
          responsiveness_claim_map: {
            status: $claim_map_slo_status,
            traceability: high_core_trace_label($claim_map_trace_mode),
            mapped_child_bead_count: (($claim_map_doc.mapped_child_bead_ids // []) | length),
            published_claim_count: (($claim_map_doc.claims // []) | map(select((.claim_status // "") == "published")) | length),
            dashboard_feed_published: any(($claim_map_doc.claims // [])[]?; (.title // "") == "Swarm fleet-health dashboard feed" and (.claim_status // "") == "published"),
            admission_bundle_published: any(($claim_map_doc.claims // [])[]?; (.title // "") == "Admission-control publication bundles" and (.claim_status // "") == "published")
          }
        }
      },
      artifact_paths: {
        swarm_capacity_snapshot_json: $snapshot_path,
        swarm_slo_input_snapshot_json: $slo_snapshot_path,
        events_jsonl: $events_path,
        commands_txt: $commands_path,
        report_md: $report_path
      }
    }
  ' >"$core_path"

snapshot_id="swarm-capacity-snapshot-$(jq -cS 'del(.artifact_paths)' "$core_path" | sha256sum | awk '{print $1}' | cut -c1-16)"
jq --arg snapshot_id "$snapshot_id" '. + {snapshot_id: $snapshot_id}' "$core_path" >"$snapshot_tmp"
mv "$snapshot_tmp" "$snapshot_path"

jq '{
      schema_version: "franken-engine.swarm-slo-input-snapshot.v1",
      source_revision,
      generated_epoch_seconds,
      stale_after_seconds,
      request_state: (if .swarm_capacity_snapshot.swarm_slo_inputs.requested then "requested" else "not_requested" end),
      decision: .swarm_capacity_snapshot.swarm_slo_inputs.decision,
      summary: {
        requested: .swarm_capacity_snapshot.swarm_slo_inputs.requested,
        accepted_count: .summary.high_core_accepted_count,
        blocked_count: .summary.high_core_blocked_count
      },
      missing_inputs: .high_core_missing_inputs,
      stale_inputs: (.stale_inputs | map(select(.source == "stress_suite_manifest_json" or .source == "tail_latency_report_json" or .source == "chaos_verification_report_json"))),
      traceability_failures: .high_core_traceability_failures,
      evidence: .swarm_capacity_snapshot.swarm_slo_inputs,
      parent_snapshot_id: .snapshot_id,
      artifact_paths: {
        swarm_slo_input_snapshot_json: .artifact_paths.swarm_slo_input_snapshot_json,
        source_capacity_snapshot_json: .artifact_paths.swarm_capacity_snapshot_json,
        events_jsonl: .artifact_paths.events_jsonl,
        commands_txt: .artifact_paths.commands_txt,
        report_md: .artifact_paths.report_md
      }
    }' "$snapshot_path" >"$slo_core_path"
slo_snapshot_id="swarm-slo-input-snapshot-$(jq -cS 'del(.artifact_paths)' "$slo_core_path" | sha256sum | awk '{print $1}' | cut -c1-16)"
jq --arg snapshot_id "$slo_snapshot_id" '. + {snapshot_id: $snapshot_id}' "$slo_core_path" >"$slo_snapshot_tmp"
mv "$slo_snapshot_tmp" "$slo_snapshot_path"

write_event "swarm_capacity_snapshot.normalized" "$(jq -r '.decision + " / high_cost_commands=" + (.summary.high_cost_command_count | tostring)' "$snapshot_path")"
write_event "swarm_slo_input_snapshot.normalized" "$(jq -r '.decision + " / blocked_inputs=" + (.summary.blocked_count | tostring)' "$slo_snapshot_path")"

 {
  printf '# Swarm Capacity Snapshot\n\n'
  printf -- "- Decision: \`%s\`\n" "$(jq -r '.decision' "$snapshot_path")"
  printf -- "- Ready beads: \`%s\`\n" "$(jq '.summary.ready_count' "$snapshot_path")"
  printf -- "- In-progress beads: \`%s\`\n" "$(jq '.summary.in_progress_count' "$snapshot_path")"
  printf -- "- High-cost commands: \`%s\`\n" "$(jq '.summary.high_cost_command_count' "$snapshot_path")"
  printf -- "- Accepted inputs: \`%s\`\n" "$(jq '.accepted_inputs | length' "$snapshot_path")"
  printf -- "- Missing inputs: \`%s\`\n" "$(jq '.missing_inputs | length' "$snapshot_path")"
  printf -- "- Stale inputs: \`%s\`\n" "$(jq '.stale_inputs | length' "$snapshot_path")"
  printf -- "- Contradictions: \`%s\`\n" "$(jq '.contradictory_inputs | length' "$snapshot_path")"
  printf -- "- Broken replay refs: \`%s\`\n\n" "$(jq '.non_replayable_artifact_refs | length' "$snapshot_path")"
  printf -- "- High-core SLO request: \`%s\`\n" "$(jq -r '.swarm_capacity_snapshot.swarm_slo_inputs.requested' "$snapshot_path")"
  printf -- "- High-core SLO decision: \`%s\`\n" "$(jq -r '.swarm_capacity_snapshot.swarm_slo_inputs.decision' "$snapshot_path")"
  printf -- "- High-core accepted inputs: \`%s\`\n" "$(jq '.summary.high_core_accepted_count' "$snapshot_path")"
  printf -- "- High-core blocked inputs: \`%s\`\n\n" "$(jq '.summary.high_core_blocked_count' "$snapshot_path")"

  if [[ "$(jq '.missing_required_fields | length' "$snapshot_path")" -ne 0 ]]; then
    printf '## Missing Required Fields\n'
    jq -r '.missing_required_fields[] | "- `" + .source + "` `" + .label + "`: " + .detail' "$snapshot_path"
    printf '\n'
  fi
  if [[ "$(jq '.stale_inputs | length' "$snapshot_path")" -ne 0 ]]; then
    printf '## Stale Inputs\n'
    jq -r '.stale_inputs[] | "- `" + .source + "` `" + .label + "`: " + .detail' "$snapshot_path"
    printf '\n'
  fi
  if [[ "$(jq '.contradictory_inputs | length' "$snapshot_path")" -ne 0 ]]; then
    printf '## Contradictory Ownership\n'
    jq -r '.contradictory_inputs[] | "- `" + .source + "` `" + .label + "`: " + .detail' "$snapshot_path"
    printf '\n'
  fi
  if [[ "$(jq '.non_replayable_artifact_refs | length' "$snapshot_path")" -ne 0 ]]; then
    printf '## Non-Replayable Artifact References\n'
    jq -r '.non_replayable_artifact_refs[] | "- `" + .source + "` `" + .label + "`: missing `" + .detail + "`"' "$snapshot_path"
    printf '\n'
  fi

  if [[ "$(jq '.high_core_traceability_failures | length' "$snapshot_path")" -ne 0 ]]; then
    printf '## High-Core Traceability Failures\n'
    jq -r '.high_core_traceability_failures[] | "- `" + .source + "`: " + .detail' "$snapshot_path"
    printf '\n'
  fi
} >"$report_path"

printf 'swarm_capacity_snapshot_json=%s\n' "$snapshot_path"
printf 'swarm_slo_input_snapshot_json=%s\n' "$slo_snapshot_path"
printf 'swarm_capacity_snapshot_report=%s\n' "$report_path"

if [[ "$(jq -r '.decision' "$snapshot_path")" == "fail_closed" ]]; then
  exit 42
fi
exit 0
