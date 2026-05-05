#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
proof_index_json=""
expected_source_revision="${PROOF_REUSE_CACHE_EXPECTED_SOURCE_REVISION:-}"
artifact_root="${PROOF_REUSE_CACHE_ARTIFACT_ROOT:-artifacts/proof_reuse_cache_planner}"
run_id="${PROOF_REUSE_CACHE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${PROOF_REUSE_CACHE_RUN_DIR:-${artifact_root}/${run_id}}"
declare -a changed_paths=()
declare -a freshness_reports=()

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/proof_reuse_cache_planner.sh --proof-index-json FILE [OPTIONS]

Plans which proof artifacts may be reused versus refreshed for the current
source state. The planner is classifier-only: it does not execute proof
commands.

Options:
  --proof-index-json FILE       Proof evidence query report JSON.
  --freshness-report FILE       Proof freshness decay report JSON. Repeatable.
  --expected-source-revision REV
                                Source revision required for reuse.
  --changed-path PATH           Changed path since the proof was generated. Repeatable.
  --output-dir DIR              Artifact output directory.
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --proof-index-json)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      proof_index_json="$2"
      shift 2
      ;;
    --freshness-report)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      freshness_reports+=("$2")
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
    --changed-path)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      changed_paths+=("$2")
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

if [[ -z "$proof_index_json" ]]; then
  usage
  exit 64
fi

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for proof reuse cache planning\n' >&2
  exit 2
fi

if [[ -z "$expected_source_revision" ]]; then
  expected_source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
plan_path="${run_dir}/proof_cache_plan.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
summary_path="${run_dir}/report.md"
index_rows_path="${run_dir}/proof_index_rows.json"
freshness_reports_jsonl="${run_dir}/freshness_reports.jsonl"
freshness_reports_path="${run_dir}/freshness_reports.json"
cache_hits_jsonl="${run_dir}/cache_hits.jsonl"
refreshes_jsonl="${run_dir}/required_refreshes.jsonl"
invalid_jsonl="${run_dir}/invalid_artifacts.jsonl"
invalidated_paths_jsonl="${run_dir}/invalidated_paths.jsonl"
: >"$events_path"
: >"$freshness_reports_jsonl"
: >"$cache_hits_jsonl"
: >"$refreshes_jsonl"
: >"$invalid_jsonl"
: >"$invalidated_paths_jsonl"
printf '[]\n' >"$index_rows_path"
printf '[]\n' >"$freshness_reports_path"

repo_relative_path() {
  local path="$1"
  if [[ "$path" = /* ]]; then
    case "$path" in
      "$root_dir"/*) printf '%s\n' "${path#"$root_dir"/}" ;;
      "$root_dir") printf '.\n' ;;
      *) printf '%s\n' "$path" ;;
    esac
  else
    printf '%s\n' "${path#./}"
  fi
}

json_array_from_lines() {
  jq -R 'select(length > 0)' | jq -s .
}

write_event() {
  local event="$1"
  local detail="$2"

  jq -nc \
    --arg event "$event" \
    --arg detail "$detail" \
    --arg proof_index_path "$(repo_relative_path "$proof_index_json")" \
    '{event: $event, detail: $detail, proof_index_path: $proof_index_path}' >>"$events_path"
}

append_json() {
  local path="$1"
  local json="$2"
  printf '%s\n' "$json" >>"$path"
}

is_heavy_cargo_command() {
  local command="$1"
  [[ "$command" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]
}

is_rch_wrapped() {
  local command="$1"
  [[ "$command" == *"rch exec -- env"* && "$command" == *"CARGO_TARGET_DIR="* ]]
}

paths_overlap() {
  local left="${1#./}"
  local right="${2#./}"

  [[ -n "$left" && -n "$right" ]] || return 1
  [[ "$left" == "$right" || "$left" == "$right"/* || "$right" == "$left"/* ]]
}

changed_paths_json="$(
  printf '%s\n' "${changed_paths[@]:-}" | while IFS= read -r raw_path; do
    [[ -n "$raw_path" ]] || continue
    repo_relative_path "$raw_path"
  done | json_array_from_lines
)"

{
  printf './scripts/proof_reuse_cache_planner.sh --proof-index-json %q' "$proof_index_json"
  printf ' --expected-source-revision %q' "$expected_source_revision"
  for path in "${changed_paths[@]:-}"; do
    printf ' --changed-path %q' "$path"
  done
  for report in "${freshness_reports[@]:-}"; do
    printf ' --freshness-report %q' "$report"
  done
  printf '\n'
} >"$commands_path"

write_event "planner_started" "loaded proof reuse cache planner inputs"

index_parse_error=""
if [[ ! -f "$proof_index_json" ]]; then
  index_parse_error="proof evidence query report is missing"
  write_event "proof_index_missing" "$index_parse_error"
elif ! jq -e '.schema_version == "franken-engine.proof-evidence-query.v1" and (.rows | type == "array")' \
  "$proof_index_json" >/dev/null 2>&1; then
  index_parse_error="proof evidence query report must use franken-engine.proof-evidence-query.v1 with rows[]"
  write_event "proof_index_invalid" "$index_parse_error"
else
  jq '
    .rows
    | map(
        .metadata_json as $metadata_raw
        | {
            bead_id: (.bead_id // ""),
            source_revision: (.source_revision // ""),
            artifact_id: (.artifact_id // ""),
            artifact_path: ((.artifact_path // "") | sub("^\\./"; "")),
            artifact_role: (.artifact_role // ""),
            receipt_kind: (.receipt_kind // ""),
            gate_status: ((.gate_status // "") | ascii_downcase),
            freshness_deadline_ms: (.freshness_deadline_ms // null),
            metadata_valid: (
              if $metadata_raw == null or $metadata_raw == "" then
                true
              else
                (($metadata_raw | fromjson?) != null)
              end
            ),
            metadata: (
              if $metadata_raw == null or $metadata_raw == "" then
                {}
              else
                (($metadata_raw | fromjson?) // {})
              end
            )
          }
      )
  ' "$proof_index_json" >"$index_rows_path"
fi

if [[ "${#freshness_reports[@]}" -eq 0 ]]; then
  write_event "freshness_reports_missing" "no proof freshness reports were supplied"
fi

for report_path in "${freshness_reports[@]:-}"; do
  normalized_report_path="$(repo_relative_path "$report_path")"
  if [[ ! -f "$report_path" ]]; then
    append_json "$freshness_reports_jsonl" "$(jq -nc \
      --arg report_path "$normalized_report_path" \
      --arg parse_error "freshness report is missing" \
      '{report_path: $report_path, parse_error: $parse_error}')"
    continue
  fi

  if ! jq -e '.schema_version == "franken-engine.proof-freshness-decay-report.v1" and type == "object"' \
    "$report_path" >/dev/null 2>&1; then
    append_json "$freshness_reports_jsonl" "$(jq -nc \
      --arg report_path "$normalized_report_path" \
      --arg parse_error "freshness report must use franken-engine.proof-freshness-decay-report.v1" \
      '{report_path: $report_path, parse_error: $parse_error}')"
    continue
  fi

  jq -nc \
    --arg report_path "$normalized_report_path" \
    --argjson report "$(jq -c . "$report_path")" '
      {
        report_path: $report_path,
        parse_error: null,
        proof_artifact_id: ($report.proof_artifact_id // ""),
        artifact_path: (($report.artifact_path // "") | sub("^\\./"; "")),
        source_revision: ($report.source_revision // ""),
        expected_source_revision: ($report.expected_source_revision // ""),
        freshness_state: ($report.freshness_state // ""),
        reusable: (if ($report.reusable | type) == "boolean" then $report.reusable else false end),
        reason: ($report.reason // ""),
        recommended_next_action: ($report.recommended_next_action // ""),
        covered_paths: (($report.covered_paths // []) | map(tostring | sub("^\\./"; "")) | unique),
        artifact_schema_version: ($report.artifact_schema_version // ""),
        freshness_deadline_ms: ($report.freshness_deadline_ms // null)
      }
    ' >>"$freshness_reports_jsonl"
done

jq -s '.' "$freshness_reports_jsonl" >"$freshness_reports_path"

total_index_rows="$(jq 'length' "$index_rows_path")"

if [[ -z "$index_parse_error" ]]; then
  while IFS= read -r row; do
    [[ -n "$row" ]] || continue

    artifact_id="$(jq -r '.artifact_id' <<<"$row")"
    artifact_path="$(jq -r '.artifact_path' <<<"$row")"
    bead_id="$(jq -r '.bead_id' <<<"$row")"
    source_revision="$(jq -r '.source_revision' <<<"$row")"
    artifact_role="$(jq -r '.artifact_role' <<<"$row")"
    receipt_kind="$(jq -r '.receipt_kind' <<<"$row")"
    gate_status="$(jq -r '.gate_status' <<<"$row")"
    metadata_valid="$(jq -r '.metadata_valid' <<<"$row")"

    if [[ -z "$artifact_id" || -z "$artifact_path" || -z "$source_revision" || "$metadata_valid" != "true" ]]; then
      append_json "$invalid_jsonl" "$(jq -nc \
        --arg artifact_id "$artifact_id" \
        --arg artifact_path "$artifact_path" \
        --arg bead_id "$bead_id" \
        --arg artifact_role "$artifact_role" \
        --arg receipt_kind "$receipt_kind" \
        --arg reason "proof index row is missing artifact identity, source revision, or valid metadata_json" \
        '{artifact_id: $artifact_id, artifact_path: $artifact_path, bead_id: $bead_id, artifact_role: $artifact_role, receipt_kind: $receipt_kind, reason: $reason}')"
      continue
    fi

    case "$gate_status" in
      pass|passed|ok|success)
        ;;
      *)
        append_json "$invalid_jsonl" "$(jq -nc \
          --arg artifact_id "$artifact_id" \
          --arg artifact_path "$artifact_path" \
          --arg bead_id "$bead_id" \
          --arg artifact_role "$artifact_role" \
          --arg receipt_kind "$receipt_kind" \
          --arg reason "proof index row gate_status is not passing" \
          '{artifact_id: $artifact_id, artifact_path: $artifact_path, bead_id: $bead_id, artifact_role: $artifact_role, receipt_kind: $receipt_kind, reason: $reason}')"
        continue
        ;;
    esac

    matched_report="$(jq -c \
      --arg artifact_id "$artifact_id" \
      --arg artifact_path "$artifact_path" \
      '[.[] | select((.proof_artifact_id != "" and .proof_artifact_id == $artifact_id) or (.artifact_path != "" and .artifact_path == $artifact_path))][0] // null' \
      "$freshness_reports_path")"

    if [[ "$matched_report" == "null" ]]; then
      append_json "$invalid_jsonl" "$(jq -nc \
        --arg artifact_id "$artifact_id" \
        --arg artifact_path "$artifact_path" \
        --arg bead_id "$bead_id" \
        --arg artifact_role "$artifact_role" \
        --arg receipt_kind "$receipt_kind" \
        --arg reason "matching freshness report is missing" \
        '{artifact_id: $artifact_id, artifact_path: $artifact_path, bead_id: $bead_id, artifact_role: $artifact_role, receipt_kind: $receipt_kind, reason: $reason}')"
      continue
    fi

    parse_error="$(jq -r '.parse_error // ""' <<<"$matched_report")"
    if [[ -n "$parse_error" ]]; then
      append_json "$invalid_jsonl" "$(jq -nc \
        --arg artifact_id "$artifact_id" \
        --arg artifact_path "$artifact_path" \
        --arg bead_id "$bead_id" \
        --arg artifact_role "$artifact_role" \
        --arg receipt_kind "$receipt_kind" \
        --arg reason "$parse_error" \
        '{artifact_id: $artifact_id, artifact_path: $artifact_path, bead_id: $bead_id, artifact_role: $artifact_role, receipt_kind: $receipt_kind, reason: $reason}')"
      continue
    fi

    freshness_state="$(jq -r '.freshness_state' <<<"$matched_report")"
    freshness_reusable="$(jq -r '.reusable' <<<"$matched_report")"
    freshness_reason="$(jq -r '.reason' <<<"$matched_report")"
    freshness_source_revision="$(jq -r '.source_revision' <<<"$matched_report")"
    freshness_expected_source_revision="$(jq -r '.expected_source_revision' <<<"$matched_report")"
    covered_paths_json="$(jq -c \
      --argjson freshness_paths "$(jq -c '.covered_paths' <<<"$matched_report")" \
      --argjson row_metadata "$(jq -c '.metadata' <<<"$row")" '
        ($row_metadata.covered_paths // []) as $metadata_covered
        | ($row_metadata.changed_paths // []) as $metadata_changed
        | ($freshness_paths + $metadata_covered + $metadata_changed)
        | map(tostring | sub("^\\./"; ""))
        | unique
      ' <<<"null")"
    refresh_command="$(jq -r '.metadata.refresh_command // .metadata.refresh_commands[0] // .metadata.commands[0] // ""' <<<"$row")"

    if [[ -z "$freshness_state" || -z "$freshness_source_revision" || "$(jq 'length' <<<"$covered_paths_json")" -eq 0 ]]; then
      append_json "$invalid_jsonl" "$(jq -nc \
        --arg artifact_id "$artifact_id" \
        --arg artifact_path "$artifact_path" \
        --arg bead_id "$bead_id" \
        --arg artifact_role "$artifact_role" \
        --arg receipt_kind "$receipt_kind" \
        --arg reason "freshness report is missing source revision, freshness_state, or covered_paths" \
        '{artifact_id: $artifact_id, artifact_path: $artifact_path, bead_id: $bead_id, artifact_role: $artifact_role, receipt_kind: $receipt_kind, reason: $reason}')"
      continue
    fi

    invalidated_paths=()
    while IFS= read -r covered_path; do
      [[ -n "$covered_path" ]] || continue
      for changed_path in "${changed_paths[@]:-}"; do
        normalized_changed="$(repo_relative_path "$changed_path")"
        if paths_overlap "$covered_path" "$normalized_changed"; then
          invalidated_paths+=("$normalized_changed")
        fi
      done
    done < <(jq -r '.[]' <<<"$covered_paths_json")

    if [[ "${#invalidated_paths[@]}" -ne 0 ]]; then
      mapfile -t invalidated_paths < <(printf '%s\n' "${invalidated_paths[@]}" | LC_ALL=C sort -u)
      while IFS= read -r path; do
        [[ -n "$path" ]] || continue
        printf '%s\n' "$path" >>"$invalidated_paths_jsonl"
      done < <(printf '%s\n' "${invalidated_paths[@]}")
    fi
    invalidated_paths_json="$(printf '%s\n' "${invalidated_paths[@]:-}" | json_array_from_lines)"

    classification="hit"
    classification_reason="fresh proof artifact may be reused"
    if [[ "$source_revision" != "$expected_source_revision" ||
          "$freshness_source_revision" != "$expected_source_revision" ||
          ( -n "$freshness_expected_source_revision" && "$freshness_expected_source_revision" != "$expected_source_revision" ) ]]; then
      classification="refresh"
      classification_reason="artifact source revision does not match the requested revision"
    elif [[ "${#invalidated_paths[@]}" -ne 0 ]]; then
      classification="refresh"
      classification_reason="changed paths invalidate the proof artifact coverage set"
    elif [[ "$freshness_state" == "fresh" && "$freshness_reusable" == "true" ]]; then
      classification="hit"
      classification_reason="freshness report allows reuse"
    elif [[ "$freshness_state" == "stale_by_time" ||
            "$freshness_state" == "stale_by_source_revision" ||
            "$freshness_state" == "stale_by_changed_path" ||
            "$freshness_state" == "superseded" ]]; then
      classification="refresh"
      classification_reason="${freshness_reason:-proof freshness report requires refresh}"
    else
      classification="invalid"
      classification_reason="${freshness_reason:-freshness report does not allow safe reuse}"
    fi

    if [[ "$classification" == "refresh" ]]; then
      if [[ -z "$refresh_command" ]]; then
        classification="invalid"
        classification_reason="proof refresh is required but metadata_json does not provide a refresh command"
      elif is_heavy_cargo_command "$refresh_command" && ! is_rch_wrapped "$refresh_command"; then
        classification="invalid"
        classification_reason="heavy proof refresh command is not wrapped with rch exec -- env CARGO_TARGET_DIR=..."
      fi
    fi

    if [[ "$classification" == "hit" ]]; then
      append_json "$cache_hits_jsonl" "$(jq -nc \
        --arg artifact_id "$artifact_id" \
        --arg artifact_path "$artifact_path" \
        --arg bead_id "$bead_id" \
        --arg artifact_role "$artifact_role" \
        --arg receipt_kind "$receipt_kind" \
        --arg source_revision "$source_revision" \
        --arg freshness_state "$freshness_state" \
        --arg reason "$classification_reason" \
        --argjson covered_paths "$covered_paths_json" \
        '{artifact_id: $artifact_id, artifact_path: $artifact_path, bead_id: $bead_id, artifact_role: $artifact_role, receipt_kind: $receipt_kind, source_revision: $source_revision, freshness_state: $freshness_state, reason: $reason, covered_paths: $covered_paths}')"
    elif [[ "$classification" == "refresh" ]]; then
      append_json "$refreshes_jsonl" "$(jq -nc \
        --arg artifact_id "$artifact_id" \
        --arg artifact_path "$artifact_path" \
        --arg bead_id "$bead_id" \
        --arg artifact_role "$artifact_role" \
        --arg receipt_kind "$receipt_kind" \
        --arg source_revision "$source_revision" \
        --arg freshness_state "$freshness_state" \
        --arg refresh_command "$refresh_command" \
        --arg reason "$classification_reason" \
        --argjson covered_paths "$covered_paths_json" \
        --argjson invalidated_paths "$invalidated_paths_json" \
        '{artifact_id: $artifact_id, artifact_path: $artifact_path, bead_id: $bead_id, artifact_role: $artifact_role, receipt_kind: $receipt_kind, source_revision: $source_revision, freshness_state: $freshness_state, refresh_command: $refresh_command, reason: $reason, covered_paths: $covered_paths, invalidated_paths: $invalidated_paths}')"
    else
      append_json "$invalid_jsonl" "$(jq -nc \
        --arg artifact_id "$artifact_id" \
        --arg artifact_path "$artifact_path" \
        --arg bead_id "$bead_id" \
        --arg artifact_role "$artifact_role" \
        --arg receipt_kind "$receipt_kind" \
        --arg reason "$classification_reason" \
        '{artifact_id: $artifact_id, artifact_path: $artifact_path, bead_id: $bead_id, artifact_role: $artifact_role, receipt_kind: $receipt_kind, reason: $reason}')"
    fi
  done < <(jq -c '.[]' "$index_rows_path")
fi

cache_hits_json="$(jq -s 'sort_by(.artifact_path, .artifact_id)' "$cache_hits_jsonl")"
refreshes_json="$(jq -s 'sort_by(.artifact_path, .artifact_id)' "$refreshes_jsonl")"
invalid_json="$(jq -s 'sort_by(.artifact_path, .artifact_id)' "$invalid_jsonl")"
invalidated_paths_json="$(json_array_from_lines <"$invalidated_paths_jsonl")"
refresh_commands_json="$(jq '[.[].refresh_command] | map(select(length > 0)) | unique | sort' <<<"$refreshes_json")"

cache_hit_count="$(jq 'length' <<<"$cache_hits_json")"
refresh_count="$(jq 'length' <<<"$refreshes_json")"
invalid_count="$(jq 'length' <<<"$invalid_json")"

proof_cache_decision="cache_hit"
exit_code=0
planner_reason="all requested proof artifacts are safely reusable"
if [[ -n "$index_parse_error" || "${#freshness_reports[@]}" -eq 0 || "$total_index_rows" -eq 0 || "$invalid_count" -ne 0 ]]; then
  proof_cache_decision="fail_closed"
  exit_code=42
  planner_reason="${index_parse_error:-proof reuse cache planner is missing required freshness evidence or encountered invalid artifacts}"
elif [[ "$refresh_count" -ne 0 && "$cache_hit_count" -ne 0 ]]; then
  proof_cache_decision="partial_refresh"
  planner_reason="some proof artifacts may be reused while others require refresh"
elif [[ "$refresh_count" -ne 0 ]]; then
  proof_cache_decision="refresh_required"
  planner_reason="all matching proof artifacts require refresh before reuse"
fi

write_event "planner_classified" "$proof_cache_decision"

jq -n \
  --arg schema_version "franken-engine.proof-reuse-cache-plan.v1" \
  --arg proof_index_path "$(repo_relative_path "$proof_index_json")" \
  --arg expected_source_revision "$expected_source_revision" \
  --arg proof_cache_decision "$proof_cache_decision" \
  --arg reason "$planner_reason" \
  --arg index_parse_error "$index_parse_error" \
  --arg plan_path "$plan_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg summary_path "$summary_path" \
  --argjson changed_paths "$changed_paths_json" \
  --argjson cache_hits "$cache_hits_json" \
  --argjson refreshes "$refreshes_json" \
  --argjson invalid_artifacts "$invalid_json" \
  --argjson invalidated_paths "$invalidated_paths_json" \
  --argjson refresh_commands "$refresh_commands_json" \
  --argjson freshness_reports "$(jq -c 'map(.report_path)' "$freshness_reports_path")" \
  '{
    schema_version: $schema_version,
    proof_index_path: $proof_index_path,
    expected_source_revision: $expected_source_revision,
    changed_paths: $changed_paths,
    proof_cache_decision: $proof_cache_decision,
    reason: $reason,
    cache_hit_artifacts: $cache_hits,
    required_refreshes: $refreshes,
    invalid_artifacts: $invalid_artifacts,
    invalidated_paths: $invalidated_paths,
    refresh_commands: $refresh_commands,
    freshness_reports: $freshness_reports,
    summary: {
      cache_hit_count: ($cache_hits | length),
      refresh_count: ($refreshes | length),
      invalid_count: ($invalid_artifacts | length)
    },
    errors: (if $index_parse_error == "" then [] else [$index_parse_error] end),
    artifact_paths: {
      proof_cache_plan_json: $plan_path,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $summary_path
    }
  }' >"$plan_path"

{
  printf '# Proof Reuse Cache Planner\n\n'
  printf -- "- Decision: \`%s\`\n" "$proof_cache_decision"
  printf -- "- Reason: %s\n" "$planner_reason"
  printf -- "- Expected source revision: \`%s\`\n" "$expected_source_revision"
  printf -- "- Cache hits: \`%s\`\n" "$cache_hit_count"
  printf -- "- Required refreshes: \`%s\`\n" "$refresh_count"
  printf -- "- Invalid artifacts: \`%s\`\n" "$invalid_count"
  if [[ "${#changed_paths[@]}" -ne 0 ]]; then
    printf '\n## Changed Paths\n\n'
    jq -r '.changed_paths[] | "- `" + . + "`"' "$plan_path"
  fi
  if [[ "$cache_hit_count" -ne 0 ]]; then
    printf '\n## Cache Hits\n\n'
    jq -r '.cache_hit_artifacts[] | "- `" + .artifact_id + "` from `" + .artifact_path + "`: " + .reason' "$plan_path"
  fi
  if [[ "$refresh_count" -ne 0 ]]; then
    printf '\n## Required Refreshes\n\n'
    jq -r '.required_refreshes[] | "- `" + .artifact_id + "` from `" + .artifact_path + "`: " + .reason + "\n  refresh: `" + .refresh_command + "`"' "$plan_path"
  fi
  if [[ "$invalid_count" -ne 0 ]]; then
    printf '\n## Fail-Closed Reasons\n\n'
    jq -r '.invalid_artifacts[] | "- `" + (.artifact_id // "unknown") + "` from `" + (.artifact_path // "unknown") + "`: " + .reason' "$plan_path"
  fi
} >"$summary_path"

printf 'proof_reuse_cache_plan=%s\n' "$plan_path"
printf 'proof_reuse_cache_summary=%s\n' "$summary_path"

exit "$exit_code"
