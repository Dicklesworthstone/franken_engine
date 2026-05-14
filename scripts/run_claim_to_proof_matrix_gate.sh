#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"
# shellcheck source=scripts/lib/proof_artifact_contract.sh
source "${root_dir}/scripts/lib/proof_artifact_contract.sh"

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

calculate_freshness_days() {
  local generated_utc="$1"
  local current_utc
  current_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  # Convert UTC timestamps to epoch seconds for calculation
  local generated_epoch
  local current_epoch

  # Try parsing standard ISO format first
  if generated_epoch=$(date -d "$generated_utc" +%s 2>/dev/null); then
    :  # Successfully parsed
  # Try parsing compact format like "20260501T101240Z"
  elif [[ "$generated_utc" =~ ^([0-9]{4})([0-9]{2})([0-9]{2})T([0-9]{2})([0-9]{2})([0-9]{2})Z$ ]]; then
    local year="${BASH_REMATCH[1]}"
    local month="${BASH_REMATCH[2]}"
    local day="${BASH_REMATCH[3]}"
    local hour="${BASH_REMATCH[4]}"
    local minute="${BASH_REMATCH[5]}"
    local second="${BASH_REMATCH[6]}"
    local iso_format="${year}-${month}-${day}T${hour}:${minute}:${second}Z"
    generated_epoch=$(date -d "$iso_format" +%s 2>/dev/null)
  fi

  if [[ -n "$generated_epoch" ]] && current_epoch=$(date -d "$current_utc" +%s 2>/dev/null); then
    local diff_seconds=$((current_epoch - generated_epoch))
    local diff_days=$((diff_seconds / 86400))
    printf '%d\n' "$diff_days"
  else
    # Return a high value if timestamp parsing fails (treated as stale)
    printf '999\n'
  fi
}

derive_artifact_freshness() {
  local artifact_path="$1"

  # If artifact_path is a file (not a directory), extract modification time
  if [[ -f "$artifact_path" ]]; then
    local file_mtime
    if file_mtime=$(stat -c %Y "$artifact_path" 2>/dev/null); then
      local current_epoch
      if current_epoch=$(date +%s); then
        local diff_seconds=$((current_epoch - file_mtime))
        local diff_days=$((diff_seconds / 86400))
        printf '%d\n' "$diff_days"
        return 0
      fi
    fi
    # Fallback: treat files as fresh if we can't get mtime
    printf '0\n'
    return 0
  fi

  # For directories, look for manifests with various naming patterns
  local manifest_candidates=()

  if [[ -d "$artifact_path" ]]; then
    # Look for proof-artifact-contract manifests (most recent first)
    while IFS= read -r -d '' manifest_file; do
      manifest_candidates+=("$manifest_file")
    done < <(find "$artifact_path" -name "manifest.json" -printf '%T@ %p\0' | sort -z -nr | cut -z -d' ' -f2-)

    # Look for gate-specific manifests (most recent first)
    while IFS= read -r -d '' manifest_file; do
      manifest_candidates+=("$manifest_file")
    done < <(find "$artifact_path" -name "*_manifest.json" -printf '%T@ %p\0' | sort -z -nr | cut -z -d' ' -f2-)
  fi

  # Try each manifest candidate
  for manifest_path in "${manifest_candidates[@]}"; do
    if [[ -f "$manifest_path" ]]; then
      local generated_utc
      # Try multiple timestamp field patterns
      if generated_utc=$(jq -r '.freshness.generated_utc // .generated_utc // .generated_at_utc // empty' "$manifest_path" 2>/dev/null) &&
         [[ -n "$generated_utc" && "$generated_utc" != "null" ]]; then
        calculate_freshness_days "$generated_utc"
        return 0
      fi
    fi
  done

  # Return high value if no manifest found or no timestamp available
  printf '999\n'
}

artifact_timestamp_epoch() {
  local generated_utc="$1"
  local generated_epoch

  if [[ -z "$generated_utc" || "$generated_utc" == "null" ]]; then
    return 1
  fi

  if generated_epoch=$(date -d "$generated_utc" +%s 2>/dev/null); then
    printf '%s\n' "$generated_epoch"
    return 0
  elif [[ "$generated_utc" =~ ^([0-9]{4})([0-9]{2})([0-9]{2})T([0-9]{2})([0-9]{2})([0-9]{2})Z$ ]]; then
    local year="${BASH_REMATCH[1]}"
    local month="${BASH_REMATCH[2]}"
    local day="${BASH_REMATCH[3]}"
    local hour="${BASH_REMATCH[4]}"
    local minute="${BASH_REMATCH[5]}"
    local second="${BASH_REMATCH[6]}"
    local iso_format="${year}-${month}-${day}T${hour}:${minute}:${second}Z"

    if generated_epoch=$(date -d "$iso_format" +%s 2>/dev/null); then
      printf '%s\n' "$generated_epoch"
      return 0
    fi
  fi

  return 1
}

classify_quality_candidate() {
  local candidate_json="$1"
  local outcome
  local verdict
  local uses_placeholder
  local outcome_reason
  local scenario_set
  local code_revision
  local verification_commands
  local text_blob

  outcome="$(jq -r '.overall_outcome // .outcome // ""' <<<"$candidate_json" | tr '[:upper:]' '[:lower:]')"
  verdict="$(jq -r '.verdict // ""' <<<"$candidate_json" | tr '[:upper:]' '[:lower:]')"
  uses_placeholder="$(jq -r '.uses_placeholder_baselines // false' <<<"$candidate_json")"
  outcome_reason="$(jq -r '.outcome_reason // .reason // ""' <<<"$candidate_json")"
  scenario_set="$(jq -r '.scenario_set // ""' <<<"$candidate_json")"
  code_revision="$(jq -r '.code_revision // ""' <<<"$candidate_json")"
  verification_commands="$(jq -r '[.verification_commands[]?, .verification_command?] | map(select(. != null)) | join(" ")' <<<"$candidate_json")"
  text_blob="$(printf '%s %s %s %s' "$outcome_reason" "$scenario_set" "$code_revision" "$verification_commands" | tr '[:upper:]' '[:lower:]')"

  if [[ "$outcome" == "targeted" ]]; then
    printf 'targeted\n'
  elif [[ -n "$outcome" && "$outcome" != "pass" ]]; then
    printf 'failed\n'
  elif [[ -n "$verdict" && "$verdict" != "pass" ]]; then
    printf 'failed\n'
  elif [[ "$uses_placeholder" == "true" || "$text_blob" == *"placeholder"* ]]; then
    printf 'placeholder\n'
  else
    printf 'ok\n'
  fi
}

detect_simulated_hot_path_evidence() {
  local artifact_path="$1"
  simulated_hot_path_evidence_report_path=""

  local candidates=()
  if [[ -f "$artifact_path" ]]; then
    candidates+=("$artifact_path")
  elif [[ -d "$artifact_path" ]]; then
    while IFS= read -r candidate; do
      candidates+=("$candidate")
    done < <(
      find "$artifact_path" -type f \
        \( -name "*.json" -o -name "*.jsonl" -o -name "*.md" -o -name "*.txt" -o -name "*.log" \) \
        | sort
    )
  fi

  local candidate
  for candidate in "${candidates[@]}"; do
    if grep -Eq 'hot_paths_simulation|MockCertificate' "$candidate"; then
      simulated_hot_path_evidence_report_path="$candidate"
      return 0
    fi
  done

  return 1
}

quality_status_rank() {
  case "$1" in
    ok) printf '0\n' ;;
    placeholder) printf '1\n' ;;
    targeted) printf '2\n' ;;
    failed) printf '3\n' ;;
    *) printf '1\n' ;;
  esac
}

inspect_observed_artifact_quality() {
  local artifact_path="$1"
  artifact_quality_status="ok"
  artifact_quality_reason=""
  artifact_quality_report_path=""

  local candidates=()
  if [[ -f "$artifact_path" && "$artifact_path" == *.json ]]; then
    candidates+=("$artifact_path")
  elif [[ -d "$artifact_path" ]]; then
    while IFS= read -r candidate; do
      candidates+=("$candidate")
    done < <(find "$artifact_path" -type f -name "*.json" | sort)
  fi

  local latest_epoch=-1
  local latest_path=""
  local latest_json=""
  local latest_status="ok"

  for candidate in "${candidates[@]}"; do
    local candidate_json
    if ! candidate_json="$(jq -c 'select(type == "object") | {
      overall_outcome: (.overall_outcome // ""),
      outcome: (.outcome // ""),
      verdict: (.verdict // ""),
      uses_placeholder_baselines: (.uses_placeholder_baselines // false),
      outcome_reason: (.outcome_reason // .reason // ""),
      scenario_set: (.scenario_set // ""),
      code_revision: (.code_revision // ""),
      verification_command: (.verification_command // ""),
      verification_commands: ([.verification_commands[]?] | map(tostring)),
      generated_utc: (.freshness.generated_utc // .generated_utc // .generated_at_utc // "")
    }' "$candidate" 2>/dev/null)"; then
      continue
    fi

    local has_quality_fields
    has_quality_fields="$(jq -r '
      (.overall_outcome != "")
      or (.outcome != "")
      or (.verdict != "")
      or (.uses_placeholder_baselines == true)
      or ((.outcome_reason | ascii_downcase) | contains("placeholder"))
      or ((.scenario_set | ascii_downcase) | contains("placeholder"))
      or ((.code_revision | ascii_downcase) | contains("placeholder"))
      or ((.verification_command | ascii_downcase) | contains("placeholder"))
      or ((.verification_commands | join(" ") | ascii_downcase) | contains("placeholder"))
    ' <<<"$candidate_json")"
    if [[ "$has_quality_fields" != "true" ]]; then
      continue
    fi

    local generated_utc
    local candidate_epoch
    generated_utc="$(jq -r '.generated_utc // ""' <<<"$candidate_json")"
    if ! candidate_epoch="$(artifact_timestamp_epoch "$generated_utc")"; then
      if ! candidate_epoch="$(stat -c %Y "$candidate" 2>/dev/null)"; then
        candidate_epoch=0
      fi
    fi

    local candidate_status
    candidate_status="$(classify_quality_candidate "$candidate_json")"
    local candidate_rank
    local latest_rank
    candidate_rank="$(quality_status_rank "$candidate_status")"
    latest_rank="$(quality_status_rank "$latest_status")"

    if [[ "$candidate_epoch" -gt "$latest_epoch" ||
          ( "$candidate_epoch" -eq "$latest_epoch" && "$candidate_rank" -gt "$latest_rank" ) ]]; then
      latest_epoch="$candidate_epoch"
      latest_path="$candidate"
      latest_json="$candidate_json"
      latest_status="$candidate_status"
    fi
  done

  if [[ -z "$latest_path" || "$latest_status" == "ok" ]]; then
    return 0
  fi

  artifact_quality_status="$latest_status"
  artifact_quality_report_path="$latest_path"

  local outcome
  local verdict
  local uses_placeholder
  local outcome_reason
  outcome="$(jq -r '.overall_outcome // .outcome // ""' <<<"$latest_json")"
  verdict="$(jq -r '.verdict // ""' <<<"$latest_json")"
  uses_placeholder="$(jq -r '.uses_placeholder_baselines // false' <<<"$latest_json")"
  outcome_reason="$(jq -r '.outcome_reason // ""' <<<"$latest_json")"

  artifact_quality_reason="observed claim artifact is not promotable: artifact_quality_status=${artifact_quality_status}, overall_outcome=${outcome:-none}, verdict=${verdict:-none}, uses_placeholder_baselines=${uses_placeholder}, report=${artifact_quality_report_path}"
  if [[ -n "$outcome_reason" ]]; then
    artifact_quality_reason="${artifact_quality_reason}, outcome_reason=${outcome_reason}"
  fi
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
  local actual_freshness_days="${15}"
  local freshness_status="${16}"
  local artifact_quality_status="${17}"
  local artifact_quality_reason="${18}"
  local artifact_quality_report_path="${19}"

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
    --arg actual_freshness_days "$actual_freshness_days" \
    --arg freshness_status "$freshness_status" \
    --arg artifact_quality_status "$artifact_quality_status" \
    --arg artifact_quality_reason "$artifact_quality_reason" \
    --arg artifact_quality_report_path "$artifact_quality_report_path" \
    '{
      schema_version: "'"$PROOF_ARTIFACT_EVENT_SCHEMA_VERSION"'",
      event_name: "claim_to_proof_matrix.claim_checked",
      severity: (if $status == "pass" then "info"
                 elif $freshness_status == "stale" then "warning"
                 else "error" end),
      step_id: $claim_id,
      command_id: "claim-to-proof-matrix",
      claim_id: $claim_id,
      claim_scope: $claim_scope,
      source_path: $source_path,
      source_span: $source_span,
      allowed_state: $allowed_state,
      actual_wording_state: $actual_wording_state,
      artifact_path: (if $artifact_path == "" then null else $artifact_path end),
      verification_command: $verification_command,
      freshness_days: (if $freshness_days == "" then null else ($freshness_days | tonumber) end),
      actual_freshness_days: (if $actual_freshness_days == "" then null else ($actual_freshness_days | tonumber) end),
      freshness_status: (if $freshness_status == "" then null else $freshness_status end),
      artifact_quality_status: (if $artifact_quality_status == "" then null else $artifact_quality_status end),
      artifact_quality_reason: (if $artifact_quality_reason == "" then null else $artifact_quality_reason end),
      artifact_quality_report_path: (if $artifact_quality_report_path == "" then null else $artifact_quality_report_path end),
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
stale_threshold_days="$(jq -r '.stale_threshold_days // .max_observed_freshness_days // 30' "$matrix_path")"

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

  actual_freshness_days=""
  freshness_status="ok"
  artifact_quality_status="ok"
  artifact_quality_reason=""
  artifact_quality_report_path=""

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
    else
      # Calculate actual freshness from artifact manifest timestamp
      actual_freshness_days="$(derive_artifact_freshness "$artifact_path")"

      if [[ "$actual_freshness_days" -gt "$stale_threshold_days" ]]; then
        freshness_status="stale"

        # Downgrade decision for stale proofs
        if [[ "$decision" == "allow_observed" ]]; then
          decision="downgrade_stale_proof"
          local_reason="proof artifact is stale (${actual_freshness_days} days > ${stale_threshold_days} threshold); downgraded to provisional"

          # Update downgrade_text to reflect provisional status
          if [[ -n "$downgrade_text" ]]; then
            downgrade_text="PROVISIONAL: $downgrade_text (proof stale: ${actual_freshness_days}d)"
          else
            downgrade_text="PROVISIONAL: proof artifact is stale (${actual_freshness_days} days old)"
          fi

          # Emit warning to stderr
          printf "WARNING: %s: Proof artifact is stale (%d days > %d threshold) - downgraded to provisional\n" \
            "$claim_id" "$actual_freshness_days" "$stale_threshold_days" >&2
        fi
      elif [[ "$actual_freshness_days" == "999" ]]; then
        freshness_status="unknown"
        printf "WARNING: %s: Cannot determine proof freshness from artifact manifest - assuming fresh\n" \
          "$claim_id" >&2
      fi

      if [[ "$claim_scope" == "performance" && "$status" == "pass" ]]; then
        inspect_observed_artifact_quality "$artifact_path"
        if [[ "$artifact_quality_status" != "ok" ]]; then
          status="fail"
          local_reason="$artifact_quality_reason"
        elif detect_simulated_hot_path_evidence "$artifact_path"; then
          status="fail"
          artifact_quality_status="simulated_hot_path"
          artifact_quality_report_path="$simulated_hot_path_evidence_report_path"
          artifact_quality_reason="observed performance claim artifact cites simulated hot-path evidence: ${simulated_hot_path_evidence_report_path}; hot_paths_simulation and MockCertificate are fixture-only markers, not observed real-runtime proof"
          local_reason="$artifact_quality_reason"
        fi
      fi
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
    "$downgrade_text" \
    "$actual_freshness_days" \
    "$freshness_status" \
    "$artifact_quality_status" \
    "$artifact_quality_reason" \
    "$artifact_quality_report_path"

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

claim_ids_csv="$(jq -r '.claims[].claim_id' "$matrix_path" | paste -sd, -)"
verdict="$(jq -r '.verdict' "$report_path")"
proof_contract_write_standard_bundle \
  "$run_dir" \
  "claim_to_proof_matrix_gate" \
  "$verdict" \
  "./scripts/run_claim_to_proof_matrix_gate.sh ${mode}" \
  "$report_path" \
  "$events_path" \
  "$commands_path" \
  "bd-1qkrc,bd-1k59y" \
  "$claim_ids_csv" \
  "$failures"

echo "claim_to_proof_matrix_gate_report=$report_path"
echo "claim_to_proof_matrix_events=$events_path"
echo "claim_to_proof_matrix_manifest=${run_dir}/manifest.json"
echo "claim_to_proof_matrix_contract_report=${run_dir}/report.json"

# Report stale proofs as warnings (non-failing)
stale_count="$(jq '[.events[] | select(.freshness_status == "stale")] | length' "$report_path")"
if [[ "$stale_count" -gt 0 ]]; then
  echo "WARNING: Found $stale_count claims with stale proof artifacts:" >&2
  jq -r '.events[] | select(.freshness_status == "stale") | "\(.claim_id): proof is \(.actual_freshness_days) days old (max: \(.freshness_days // "unknown"))"' "$report_path" >&2
fi

if [[ "$failures" -ne 0 ]]; then
  jq -r '.events[] | select(.status != "pass") | "\(.claim_id): \(.reason) -> \(.downgrade_text // "no downgrade text")"' "$report_path" >&2
  exit 1
fi
