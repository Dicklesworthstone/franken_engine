#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_path=""
expected_source_revision="${PROOF_FRESHNESS_EXPECTED_SOURCE_REVISION:-}"
expected_schema_version="${PROOF_FRESHNESS_EXPECTED_SCHEMA_VERSION:-}"
now_ms="${PROOF_FRESHNESS_NOW_MS:-}"
artifact_root="${PROOF_FRESHNESS_DECAY_ARTIFACT_ROOT:-artifacts/proof_freshness_decay_gate}"
run_id="${PROOF_FRESHNESS_DECAY_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${PROOF_FRESHNESS_DECAY_RUN_DIR:-${artifact_root}/${run_id}}"
superseding_artifact=""
changed_paths=()

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/proof_freshness_decay_gate.sh --artifact FILE [OPTIONS]

Classifies whether a proof artifact is reusable for the current source state.
The gate does not execute the proof command; it only evaluates existing evidence.

Options:
  --artifact FILE                 Proof artifact or manifest JSON to classify.
  --expected-source-revision REV  Source revision required for reuse.
  --expected-schema-version VER   Required artifact schema_version.
  --changed-path PATH             Changed path since the proof was generated. Repeatable.
  --now-ms EPOCH_MS               Override current time for deterministic tests.
  --superseding-artifact FILE     Newer artifact that supersedes this one.
  --output-dir DIR                Artifact output directory.
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --artifact)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      artifact_path="$2"
      shift 2
      ;;
    --expected-source-revision)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      expected_source_revision="$2"
      shift 2
      ;;
    --expected-schema-version)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      expected_schema_version="$2"
      shift 2
      ;;
    --changed-path)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      changed_paths+=("${2#./}")
      shift 2
      ;;
    --now-ms)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      now_ms="$2"
      shift 2
      ;;
    --superseding-artifact)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      superseding_artifact="$2"
      shift 2
      ;;
    --output-dir)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      run_dir="$2"
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

if [[ -z "$artifact_path" ]]; then
  usage
  exit 64
fi

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for proof freshness classification\n' >&2
  exit 2
fi

if [[ -z "$expected_source_revision" ]]; then
  expected_source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

if [[ -z "$now_ms" ]]; then
  now_ms="$(($(date -u +%s) * 1000))"
fi

if ! [[ "$now_ms" =~ ^[0-9]+$ ]]; then
  printf 'now-ms must be numeric epoch milliseconds\n' >&2
  exit 64
fi

mkdir -p "$run_dir"
report_path="${run_dir}/proof_freshness_report.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
summary_path="${run_dir}/report.md"
: >"$events_path"

json_array_from_lines() {
  jq -R 'select(length > 0)' | jq -s .
}

changed_paths_json="$(
  printf '%s\n' "${changed_paths[@]:-}" | json_array_from_lines
)"

write_event() {
  local event="$1"
  local detail="$2"

  jq -nc \
    --arg event "$event" \
    --arg detail "$detail" \
    --arg artifact_path "$artifact_path" \
    --arg expected_source_revision "$expected_source_revision" \
    '{event: $event, detail: $detail, artifact_path: $artifact_path, expected_source_revision: $expected_source_revision}' >>"$events_path"
}

iso_to_epoch_ms() {
  local iso="$1"
  local epoch

  if [[ -z "$iso" || "$iso" == "null" ]]; then
    return 1
  fi

  if epoch="$(date -u -d "$iso" +%s 2>/dev/null)"; then
    printf '%s000\n' "$epoch"
    return 0
  fi

  if [[ "$iso" =~ ^([0-9]{4})([0-9]{2})([0-9]{2})T([0-9]{2})([0-9]{2})([0-9]{2})Z$ ]]; then
    local expanded="${BASH_REMATCH[1]}-${BASH_REMATCH[2]}-${BASH_REMATCH[3]}T${BASH_REMATCH[4]}:${BASH_REMATCH[5]}:${BASH_REMATCH[6]}Z"
    if epoch="$(date -u -d "$expanded" +%s 2>/dev/null)"; then
      printf '%s000\n' "$epoch"
      return 0
    fi
  fi

  return 1
}

repo_relative_path() {
  local path="$1"
  if [[ "$path" = /* ]]; then
    case "$path" in
      "$root_dir"/*) printf '%s' "${path#"$root_dir"/}" ;;
      "$root_dir") printf '.' ;;
      *) printf '%s' "$path" ;;
    esac
  else
    printf '%s' "${path#./}"
  fi
}

paths_overlap() {
  local left="${1#./}"
  local right="${2#./}"

  [[ -n "$left" && -n "$right" ]] || return 1
  [[ "$left" == "$right" || "$left" == "$right"/* || "$right" == "$left"/* ]]
}

first_changed_overlap() {
  local covered_json="$1"
  local covered path

  while IFS= read -r covered; do
    for path in "${changed_paths[@]:-}"; do
      if paths_overlap "$covered" "$path"; then
        printf '%s -> %s\n' "$path" "$covered"
        return 0
      fi
    done
  done < <(jq -r '.[]' <<<"$covered_json")

  return 1
}

write_commands() {
  {
    printf './scripts/proof_freshness_decay_gate.sh --artifact %q' "$artifact_path"
    printf ' --expected-source-revision %q' "$expected_source_revision"
    [[ -n "$expected_schema_version" ]] && printf ' --expected-schema-version %q' "$expected_schema_version"
    [[ -n "$superseding_artifact" ]] && printf ' --superseding-artifact %q' "$superseding_artifact"
    printf ' --now-ms %q' "$now_ms"
    for path in "${changed_paths[@]:-}"; do
      printf ' --changed-path %q' "$path"
    done
    printf '\n'
  } >"$commands_path"
}

write_commands
write_event "classification_started" "loaded proof freshness gate inputs"

schema_version=""
proof_artifact_id=""
source_revision=""
generated_timestamp_ms=""
freshness_deadline_ms=""
artifact_status=""
artifact_status_lc=""
covered_paths_json="[]"
declared_superseded_by=""
artifact_parse_error=""

if [[ -f "$artifact_path" ]]; then
  if ! artifact_json="$(jq -c 'select(type == "object")' "$artifact_path" 2>/dev/null)"; then
    artifact_parse_error="artifact JSON could not be parsed"
    write_event "artifact_parse_failed" "$artifact_parse_error"
  elif [[ -z "$artifact_json" ]]; then
    artifact_parse_error="artifact JSON is not an object"
    write_event "artifact_parse_failed" "$artifact_parse_error"
  else
    schema_version="$(jq -r '.schema_version // ""' <<<"$artifact_json")"
    proof_artifact_id="$(jq -r '.proof_artifact_id // .artifact_id // .bundle_id // ""' <<<"$artifact_json")"
    source_revision="$(jq -r '.source_revision // .freshness.source_revision // ""' <<<"$artifact_json")"
    artifact_status="$(jq -r '.status // .verdict // .gate_status // ""' <<<"$artifact_json")"
    artifact_status_lc="$(printf '%s' "$artifact_status" | tr '[:upper:]' '[:lower:]')"
    declared_superseded_by="$(jq -r '.superseded_by // .supersession.superseded_by // ""' <<<"$artifact_json")"
    covered_paths_json="$(jq -c '[
        .covered_paths[]?,
        .changed_paths[]?,
        .source_paths[]?,
        .artifact_paths.covered_paths[]?,
        .freshness.covered_paths[]?
      ] | map(tostring | sub("^./"; "")) | unique' <<<"$artifact_json")"

    generated_timestamp_ms="$(jq -r '.generated_timestamp_ms // .generated_ms // .freshness.generated_timestamp_ms // ""' <<<"$artifact_json")"
    freshness_deadline_ms="$(jq -r '.freshness_deadline_ms // .freshness.deadline_ms // ""' <<<"$artifact_json")"

    if [[ -z "$generated_timestamp_ms" || "$generated_timestamp_ms" == "null" ]]; then
      generated_utc="$(jq -r '.generated_utc // .generated_at // .freshness.generated_utc // ""' <<<"$artifact_json")"
      generated_timestamp_ms="$(iso_to_epoch_ms "$generated_utc" 2>/dev/null || true)"
    fi

    if [[ -z "$freshness_deadline_ms" || "$freshness_deadline_ms" == "null" ]]; then
      freshness_policy_ms="$(jq -r '.freshness_policy_ms // .freshness.policy_ms // ""' <<<"$artifact_json")"
      max_freshness_days="$(jq -r '.max_freshness_days // .freshness.max_freshness_days // ""' <<<"$artifact_json")"
      if [[ "$generated_timestamp_ms" =~ ^[0-9]+$ && "$freshness_policy_ms" =~ ^[0-9]+$ ]]; then
        freshness_deadline_ms="$((generated_timestamp_ms + freshness_policy_ms))"
      elif [[ "$generated_timestamp_ms" =~ ^[0-9]+$ && "$max_freshness_days" =~ ^[0-9]+$ ]]; then
        freshness_deadline_ms="$((generated_timestamp_ms + (max_freshness_days * 86400000)))"
      fi
    fi
  fi
else
  write_event "artifact_missing" "artifact path does not exist"
fi

state="fresh"
reusable=true
reason="proof artifact is reusable for the requested source state"
recommended_next_action="Reuse the proof artifact and record this freshness receipt with the operator evidence."
overlap_detail=""
superseded_by="$declared_superseded_by"

if [[ -n "$superseding_artifact" ]]; then
  superseded_by="$(repo_relative_path "$superseding_artifact")"
fi

if [[ ! -f "$artifact_path" ]]; then
  state="incomplete"
  reusable=false
  reason="artifact file is missing"
  recommended_next_action="Rerun the proof with rch exec and preserve the emitted manifest before reusing this claim."
elif [[ -n "$artifact_parse_error" ]]; then
  state="incomplete"
  reusable=false
  reason="$artifact_parse_error"
  recommended_next_action="Treat the artifact as unusable; regenerate it with a valid proof-evidence manifest."
elif [[ -z "$schema_version" || -z "$proof_artifact_id" || -z "$source_revision" ||
        ! "$generated_timestamp_ms" =~ ^[0-9]+$ || ! "$freshness_deadline_ms" =~ ^[0-9]+$ ]]; then
  state="incomplete"
  reusable=false
  reason="artifact is missing required schema, id, source revision, generated timestamp, or freshness deadline fields"
  recommended_next_action="Treat the artifact as unusable; regenerate it with a proof-evidence manifest that records source revision and freshness policy."
elif [[ -n "$artifact_status_lc" &&
        "$artifact_status_lc" != "pass" &&
        "$artifact_status_lc" != "passed" &&
        "$artifact_status_lc" != "ok" &&
        "$artifact_status_lc" != "success" ]]; then
  state="mismatched"
  reusable=false
  reason="artifact status is not a passing proof"
  recommended_next_action="Do not reuse failed proof output; rerun the proof and classify the new artifact."
elif [[ -n "$superseded_by" && "$superseded_by" != "null" ]]; then
  state="superseded"
  reusable=false
  reason="artifact declares newer evidence supersedes it"
  recommended_next_action="Use the superseding artifact or rerun the proof against the current source revision."
elif [[ -n "$expected_schema_version" && "$schema_version" != "$expected_schema_version" ]]; then
  state="mismatched"
  reusable=false
  reason="artifact schema_version does not match the required schema"
  recommended_next_action="Regenerate the artifact with the expected schema before reusing it."
elif [[ "$source_revision" != "$expected_source_revision" ]]; then
  state="stale_by_source_revision"
  reusable=false
  reason="artifact source_revision does not match the requested source revision"
  recommended_next_action="Rerun the proof with rch exec for the current source revision."
elif overlap_detail="$(first_changed_overlap "$covered_paths_json")"; then
  state="stale_by_changed_path"
  reusable=false
  reason="changed path overlaps a path covered by the proof artifact: ${overlap_detail}"
  recommended_next_action="Rerun the proof because covered source changed after the artifact was generated."
elif [[ "$now_ms" -gt "$freshness_deadline_ms" ]]; then
  state="stale_by_time"
  reusable=false
  reason="current time exceeds the artifact freshness deadline"
  recommended_next_action="Refresh the proof artifact before publishing or relying on the claim."
fi

if [[ "$reusable" != true ]]; then
  write_event "classified_not_reusable" "$state"
else
  write_event "classified_reusable" "$state"
fi

# shellcheck disable=SC2094
jq -n \
  --arg schema_version "franken-engine.proof-freshness-decay-report.v1" \
  --arg artifact_path "$(repo_relative_path "$artifact_path")" \
  --arg proof_artifact_id "$proof_artifact_id" \
  --arg artifact_schema_version "$schema_version" \
  --arg expected_schema_version "$expected_schema_version" \
  --arg source_revision "$source_revision" \
  --arg expected_source_revision "$expected_source_revision" \
  --arg state "$state" \
  --arg artifact_status "$artifact_status" \
  --arg reason "$reason" \
  --arg recommended_next_action "$recommended_next_action" \
  --arg superseded_by "$superseded_by" \
  --argjson reusable "$reusable" \
  --argjson now_ms "$now_ms" \
  --arg generated_timestamp_ms "${generated_timestamp_ms:-null}" \
  --arg freshness_deadline_ms "${freshness_deadline_ms:-null}" \
  --argjson covered_paths "$covered_paths_json" \
  --argjson changed_paths "$changed_paths_json" \
  --arg report_path "$report_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg summary_path "$summary_path" \
  '{
    schema_version: $schema_version,
    artifact_path: $artifact_path,
    proof_artifact_id: (if $proof_artifact_id == "" then null else $proof_artifact_id end),
    artifact_schema_version: (if $artifact_schema_version == "" then null else $artifact_schema_version end),
    expected_schema_version: (if $expected_schema_version == "" then null else $expected_schema_version end),
    source_revision: (if $source_revision == "" then null else $source_revision end),
    expected_source_revision: $expected_source_revision,
    artifact_status: (if $artifact_status == "" then null else $artifact_status end),
    freshness_state: $state,
    reusable: $reusable,
    reason: $reason,
    recommended_next_action: $recommended_next_action,
    generated_timestamp_ms: (if $generated_timestamp_ms == "null" or $generated_timestamp_ms == "" then null else ($generated_timestamp_ms | tonumber) end),
    freshness_deadline_ms: (if $freshness_deadline_ms == "null" or $freshness_deadline_ms == "" then null else ($freshness_deadline_ms | tonumber) end),
    now_ms: $now_ms,
    covered_paths: $covered_paths,
    changed_paths: $changed_paths,
    superseded_by: (if $superseded_by == "" or $superseded_by == "null" then null else $superseded_by end),
    artifact_paths: {
      proof_freshness_report_json: $report_path,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $summary_path
    }
  }' >"$report_path"

{
  printf '# Proof Freshness Decay Report\n\n'
  printf -- "- State: \`%s\`\n" "$state"
  printf -- "- Reusable: \`%s\`\n" "$reusable"
  printf -- "- Reason: %s\n" "$reason"
  printf -- "- Recommended next action: %s\n" "$recommended_next_action"
  [[ -n "$proof_artifact_id" ]] && printf -- "- Artifact id: \`%s\`\n" "$proof_artifact_id"
  [[ -n "$source_revision" ]] && printf -- "- Source revision: \`%s\`\n" "$source_revision"
  printf -- "- Expected source revision: \`%s\`\n" "$expected_source_revision"
} >"$summary_path"

printf 'proof_freshness_report=%s\n' "$report_path"
printf 'proof_freshness_summary=%s\n' "$summary_path"

if [[ "$reusable" == true ]]; then
  exit 0
fi
exit 42
