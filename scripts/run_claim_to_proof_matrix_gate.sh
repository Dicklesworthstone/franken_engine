#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
artifact_root="${CLAIM_TO_PROOF_MATRIX_ARTIFACT_ROOT:-artifacts/claim_to_proof_matrix_gate}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
events_path="${run_dir}/events.jsonl"
report_path="${run_dir}/claim_to_proof_gate_report.json"
commands_path="${run_dir}/commands.txt"
matrix_path="${CLAIM_TO_PROOF_MATRIX_PATH:-docs/claim_to_proof_matrix_v1.json}"
human_report_path="docs/CLAIM_TO_PROOF_MATRIX_V1.md"

mkdir -p "$run_dir"

printf './scripts/run_claim_to_proof_matrix_gate.sh %s\n' "$mode" >"$commands_path"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for claim-to-proof matrix validation" >&2
  exit 2
fi

if [[ ! -f "$matrix_path" ]]; then
  echo "missing claim matrix: $matrix_path" >&2
  exit 1
fi

if [[ ! -f "$human_report_path" ]]; then
  echo "missing human-readable claim report: $human_report_path" >&2
  exit 1
fi

jq -e '
  .schema_version == "franken-engine.claim-to-proof-matrix.v1"
  and (.claims | type == "array")
  and (.claims | length > 0)
' "$matrix_path" >/dev/null

state_rank() {
  case "$1" in
    hypothesis) printf '1\n' ;;
    target) printf '2\n' ;;
    observed) printf '3\n' ;;
    *) printf '0\n' ;;
  esac
}

json_string() {
  jq -Rn --arg value "$1" '$value'
}

emit_event() {
  local claim_id="$1"
  local claim_scope="$2"
  local source_path="$3"
  local source_span="$4"
  local allowed_state="$5"
  local actual_wording_state="$6"
  local artifact_path="$7"
  local verification_command="$8"
  local freshness_days="$9"
  local decision="${10}"
  local reason="${11}"
  local owning_bead="${12}"
  local status="${13}"
  local downgrade_text="${14}"

  jq -nc \
    --arg claim_id "$claim_id" \
    --arg claim_scope "$claim_scope" \
    --arg source_path "$source_path" \
    --argjson source_span "$source_span" \
    --arg allowed_state "$allowed_state" \
    --arg actual_wording_state "$actual_wording_state" \
    --arg artifact_path "$artifact_path" \
    --arg verification_command "$verification_command" \
    --arg freshness_days "$freshness_days" \
    --arg decision "$decision" \
    --arg reason "$reason" \
    --arg owning_bead "$owning_bead" \
    --arg status "$status" \
    --arg downgrade_text "$downgrade_text" \
    '{
      claim_id: $claim_id,
      claim_scope: $claim_scope,
      source_path: $source_path,
      source_span: $source_span,
      allowed_state: $allowed_state,
      actual_wording_state: $actual_wording_state,
      artifact_path: (if $artifact_path == "" then null else $artifact_path end),
      verification_command: $verification_command,
      freshness_days: (if $freshness_days == "" then null else ($freshness_days | tonumber) end),
      decision: $decision,
      reason: $reason,
      owning_bead: $owning_bead,
      status: $status,
      downgrade_text: (if $downgrade_text == "" then null else $downgrade_text end)
    }' >>"$events_path"
}

failures=0
claim_count=0
max_observed_freshness_days="$(jq -r '.max_observed_freshness_days // 30' "$matrix_path")"

while IFS= read -r claim; do
  claim_count=$((claim_count + 1))

  claim_id="$(jq -r '.claim_id // ""' <<<"$claim")"
  claim_scope="$(jq -r '.claim_scope // ""' <<<"$claim")"
  source_path="$(jq -r '.source_path // ""' <<<"$claim")"
  start_line="$(jq -r '.source_span.start_line // ""' <<<"$claim")"
  end_line="$(jq -r '.source_span.end_line // ""' <<<"$claim")"
  must_contain="$(jq -r '.source_span.must_contain // ""' <<<"$claim")"
  allowed_state="$(jq -r '.allowed_state // ""' <<<"$claim")"
  actual_wording_state="$(jq -r '.actual_wording_state // ""' <<<"$claim")"
  artifact_path="$(jq -r '.artifact_path // ""' <<<"$claim")"
  verification_command="$(jq -r '.verification_command // ""' <<<"$claim")"
  freshness_days="$(jq -r '.freshness_days // ""' <<<"$claim")"
  decision="$(jq -r '.decision // ""' <<<"$claim")"
  reason="$(jq -r '.reason // ""' <<<"$claim")"
  owning_bead="$(jq -r '.owning_bead // ""' <<<"$claim")"
  downgrade_text="$(jq -r '.downgrade_text // ""' <<<"$claim")"
  source_span="$(jq -c '.source_span' <<<"$claim")"

  status="pass"
  local_reason="$reason"

  if [[ -z "$claim_id" || -z "$claim_scope" || -z "$source_path" || -z "$start_line" || -z "$end_line" || -z "$must_contain" || -z "$allowed_state" || -z "$actual_wording_state" || -z "$decision" || -z "$owning_bead" ]]; then
    status="fail"
    local_reason="missing required claim matrix fields"
  elif [[ ! -f "$source_path" ]]; then
    status="fail"
    local_reason="source_path does not exist"
  elif ! [[ "$start_line" =~ ^[0-9]+$ && "$end_line" =~ ^[0-9]+$ && "$start_line" -le "$end_line" ]]; then
    status="fail"
    local_reason="source_span lines must be numeric and ordered"
  else
    span_text="$(sed -n "${start_line},${end_line}p" "$source_path")"
    if [[ "$span_text" != *"$must_contain"* ]]; then
      status="fail"
      local_reason="source_span no longer contains required text"
    fi
  fi

  allowed_rank="$(state_rank "$allowed_state")"
  actual_rank="$(state_rank "$actual_wording_state")"
  if [[ "$allowed_rank" -eq 0 || "$actual_rank" -eq 0 ]]; then
    status="fail"
    local_reason="invalid claim state"
  elif [[ "$actual_rank" -gt "$allowed_rank" ]]; then
    status="fail"
    local_reason="actual wording state is stronger than allowed state"
  fi

  if [[ "$allowed_state" == "observed" ]]; then
    if [[ -z "$artifact_path" || ! -e "$artifact_path" ]]; then
      status="fail"
      local_reason="observed claim must reference an existing artifact_path"
    elif [[ -z "$verification_command" || "$verification_command" == TBD:* ]]; then
      status="fail"
      local_reason="observed claim must include a concrete verification_command"
    elif ! [[ "$freshness_days" =~ ^[0-9]+$ ]]; then
      status="fail"
      local_reason="observed claim must include numeric freshness_days"
    elif [[ "$freshness_days" -gt "$max_observed_freshness_days" ]]; then
      status="fail"
      local_reason="observed claim freshness exceeds max_observed_freshness_days"
    fi
  else
    if [[ -n "$artifact_path" && ! -e "$artifact_path" ]]; then
      status="fail"
      local_reason="artifact_path is set but does not exist"
    fi
    if [[ -z "$downgrade_text" ]]; then
      status="fail"
      local_reason="non-observed claim must include downgrade_text"
    fi
  fi

  emit_event \
    "$claim_id" \
    "$claim_scope" \
    "$source_path" \
    "$source_span" \
    "$allowed_state" \
    "$actual_wording_state" \
    "$artifact_path" \
    "$verification_command" \
    "$freshness_days" \
    "$decision" \
    "$local_reason" \
    "$owning_bead" \
    "$status" \
    "$downgrade_text"

  if [[ "$status" != "pass" ]]; then
    failures=$((failures + 1))
  fi
done < <(jq -c '.claims[]' "$matrix_path")

jq -n \
  --arg schema_version "franken-engine.claim-to-proof-gate-report.v1" \
  --arg matrix_path "$matrix_path" \
  --arg human_report_path "$human_report_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg mode "$mode" \
  --argjson claim_count "$claim_count" \
  --argjson failures "$failures" \
  --slurpfile events "$events_path" \
  '{
    schema_version: $schema_version,
    matrix_path: $matrix_path,
    human_report_path: $human_report_path,
    events_path: $events_path,
    commands_path: $commands_path,
    mode: $mode,
    claim_count: $claim_count,
    failures: $failures,
    verdict: (if $failures == 0 then "pass" else "fail" end),
    events: $events
  }' >"$report_path"

echo "claim_to_proof_matrix_gate_report=$report_path"
echo "claim_to_proof_matrix_events=$events_path"

if [[ "$failures" -ne 0 ]]; then
  jq -r '.events[] | select(.status != "pass") | "\(.claim_id): \(.reason) -> \(.downgrade_text // "no downgrade text")"' "$report_path" >&2
  exit 1
fi
