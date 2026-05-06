#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${STAGED_OWNERSHIP_GUARD_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-staged-ownership-guard}"
run_id="${STAGED_OWNERSHIP_GUARD_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${STAGED_OWNERSHIP_GUARD_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

agent_id=""
bead_id=""
reservation_snapshot_json=""
staged_name_status_json=""
beads_diff_json=""
declare -a allowed_paths=()

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/staged_ownership_contamination_guard.sh --agent-id ID --bead-id ID [OPTIONS]

Compares staged paths against an explicit bead write set and Agent Mail
reservation snapshot. The guard never mutates the index.

Required:
  --agent-id ID
  --bead-id ID

Options:
  --output-dir DIR
  --allowed-path PATH_OR_GLOB       Allowed bead write path. Repeatable.
  --reservation-snapshot-json FILE  Agent Mail reservation fixture.
  --staged-name-status-json FILE    Fixture array of {status,path} rows.
  --beads-diff-json FILE            Fixture with touched_bead_ids for .beads.

If --staged-name-status-json is omitted, the guard reads:
  git diff --cached --name-only

If --beads-diff-json is omitted, scoped bead evidence for .beads/issues.jsonl
is extracted from:
  git diff --cached -U0 -- .beads/issues.jsonl

Writes staged_ownership_report.json, events.jsonl, commands.txt, and report.md.
Exit codes: 0 pass/pass_degraded, 42 contamination.
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
    --output-dir)
      run_dir="${2:-}"
      shift 2
      ;;
    --allowed-path)
      allowed_paths+=("${2:-}")
      shift 2
      ;;
    --reservation-snapshot-json)
      reservation_snapshot_json="${2:-}"
      shift 2
      ;;
    --staged-name-status-json)
      staged_name_status_json="${2:-}"
      shift 2
      ;;
    --beads-diff-json)
      beads_diff_json="${2:-}"
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

if [[ -z "$agent_id" || -z "$bead_id" ]]; then
  printf 'staged ownership guard requires --agent-id and --bead-id\n' >&2
  usage
  exit 64
fi

mkdir -p "$run_dir"
report_json="${run_dir}/staged_ownership_report.json"
report_tmp="${report_json}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_md="${run_dir}/report.md"
staged_rows_json="${run_dir}/staged_rows.json"
allowed_paths_json="${run_dir}/allowed_paths.json"
reservation_rows_json="${run_dir}/reservation_rows.json"
touched_beads_json="${run_dir}/touched_beads.json"
decisions_jsonl="${run_dir}/decisions.jsonl"
offenders_jsonl="${run_dir}/offending_paths.jsonl"
findings_jsonl="${run_dir}/findings.jsonl"
: >"$events_path"
: >"$decisions_jsonl"
: >"$offenders_jsonl"
: >"$findings_jsonl"

printf './scripts/staged_ownership_contamination_guard.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

repo_relative_path() {
  local path="$1"
  if [[ "$path" = /* ]]; then
    realpath --relative-to="$root_dir" "$path"
  else
    printf '%s\n' "${path#./}"
  fi
}

write_allowed_paths() {
  if [[ "${#allowed_paths[@]}" -eq 0 ]]; then
    printf '[]\n' >"$allowed_paths_json"
    return 0
  fi
  {
    local path
    for path in "${allowed_paths[@]}"; do
      repo_relative_path "$path"
    done
  } | jq -R . | jq -s 'map(select(length > 0)) | unique' >"$allowed_paths_json"
}

load_staged_rows() {
  if [[ -n "$staged_name_status_json" ]]; then
    if [[ ! -f "$staged_name_status_json" ]]; then
      printf 'missing staged name-status fixture: %s\n' "$staged_name_status_json" >&2
      exit 64
    fi
    if ! jq empty "$staged_name_status_json" >/dev/null; then
      printf 'invalid staged name-status JSON: %s\n' "$staged_name_status_json" >&2
      exit 64
    fi
    jq '
      map({
        status: (.status // "unknown"),
        path: (.path // .new_path // .file // "")
      })
      | map(select(.path != ""))
      | sort_by(.path)
    ' "$staged_name_status_json" >"$staged_rows_json"
    return 0
  fi

  git -C "$root_dir" diff --cached --name-only -- . |
    jq -R '{status:"staged", path:.}' |
    jq -s 'sort_by(.path)' >"$staged_rows_json"
}

load_reservations() {
  if [[ -z "$reservation_snapshot_json" ]]; then
    printf '[]\n' >"$reservation_rows_json"
    printf 'missing'
    return 0
  fi
  if [[ ! -f "$reservation_snapshot_json" ]]; then
    printf 'missing reservation snapshot fixture: %s\n' "$reservation_snapshot_json" >&2
    exit 64
  fi
  if ! jq empty "$reservation_snapshot_json" >/dev/null; then
    printf 'invalid reservation snapshot JSON: %s\n' "$reservation_snapshot_json" >&2
    exit 64
  fi
  jq '
    [
      .. | objects
      | select((.path_pattern? // .path? // "") != "")
      | {
          path_pattern: (.path_pattern // .path),
          agent_id: (.agent_id // .agent_name // .holder // ""),
          bead_id: (.bead_id // ""),
          exclusive: (.exclusive // true)
        }
    ]
  ' "$reservation_snapshot_json" >"$reservation_rows_json"
  printf 'provided'
}

extract_bead_ids_from_git_diff() {
  git -C "$root_dir" diff --cached -U0 -- .beads/issues.jsonl 2>/dev/null |
    sed -nE 's/^[+-].*"id":"(bd-[A-Za-z0-9.-]+)".*/\1/p' |
    sort -u |
    jq -R . |
    jq -s 'unique'
}

load_touched_beads() {
  if [[ -n "$beads_diff_json" ]]; then
    if [[ ! -f "$beads_diff_json" ]]; then
      printf 'missing beads diff fixture: %s\n' "$beads_diff_json" >&2
      exit 64
    fi
    if ! jq empty "$beads_diff_json" >/dev/null; then
      printf 'invalid beads diff JSON: %s\n' "$beads_diff_json" >&2
      exit 64
    fi
    jq '(.touched_bead_ids // .bead_ids // []) | unique' "$beads_diff_json" >"$touched_beads_json"
    return 0
  fi
  extract_bead_ids_from_git_diff >"$touched_beads_json"
}

path_matches_pattern() {
  local path="$1"
  local pattern="$2"
  # shellcheck disable=SC2254
  case "$path" in
    $pattern) return 0 ;;
    *) return 1 ;;
  esac
}

allowed_by_explicit_path() {
  local path="$1"
  local pattern
  while IFS= read -r pattern; do
    [[ -n "$pattern" ]] || continue
    if path_matches_pattern "$path" "$pattern"; then
      return 0
    fi
  done < <(jq -r '.[]' "$allowed_paths_json")
  return 1
}

reservation_owner_for_path() {
  local path="$1"
  local row pattern holder holder_bead
  while IFS= read -r row; do
    pattern="$(jq -r '.path_pattern' <<<"$row")"
    holder="$(jq -r '.agent_id' <<<"$row")"
    holder_bead="$(jq -r '.bead_id' <<<"$row")"
    if path_matches_pattern "$path" "$pattern"; then
      printf '%s\t%s\t%s\n' "$pattern" "$holder" "$holder_bead"
      return 0
    fi
  done < <(jq -c '.[]' "$reservation_rows_json")
  return 1
}

emit_decision() {
  local path="$1"
  local status="$2"
  local decision="$3"
  local reason="$4"
  local owner="${5:-}"
  local owner_bead="${6:-}"
  local pattern="${7:-}"

  jq -nc \
    --arg path "$path" \
    --arg status "$status" \
    --arg decision "$decision" \
    --arg reason "$reason" \
    --arg owner "$owner" \
    --arg owner_bead "$owner_bead" \
    --arg pattern "$pattern" \
    '{
      path: $path,
      status: $status,
      decision: $decision,
      reason: $reason,
      expected_owner: $owner,
      expected_bead: $owner_bead,
      matched_pattern: $pattern
    }' >>"$decisions_jsonl"
}

emit_offender() {
  local path="$1"
  local reason="$2"
  local owner="${3:-}"
  local owner_bead="${4:-}"
  local remediation="unstage the path or move it into the current bead write set after acquiring a matching Agent Mail reservation"

  jq -nc \
    --arg path "$path" \
    --arg reason "$reason" \
    --arg expected_agent_id "$agent_id" \
    --arg expected_bead_id "$bead_id" \
    --arg actual_reservation_holder "$owner" \
    --arg actual_reservation_bead "$owner_bead" \
    --arg remediation "$remediation" \
    '{
      path: $path,
      reason: $reason,
      expected_agent_id: $expected_agent_id,
      expected_bead_id: $expected_bead_id,
      actual_reservation_holder: $actual_reservation_holder,
      actual_reservation_bead: $actual_reservation_bead,
      remediation: $remediation
    }' \
    >>"$offenders_jsonl"
}

emit_finding() {
  local severity="$1"
  local code="$2"
  local message="$3"

  jq -nc \
    --arg severity "$severity" \
    --arg code "$code" \
    --arg message "$message" \
    '{severity: $severity, code: $code, message: $message}' >>"$findings_jsonl"
}

write_allowed_paths
load_staged_rows
reservation_status="$(load_reservations)"
load_touched_beads

if [[ "$reservation_status" == "missing" ]]; then
  emit_finding "warning" "missing_reservation_snapshot" \
    "Agent Mail reservation snapshot missing; guard can only trust explicit allowed paths and scoped .beads evidence."
fi

while IFS= read -r row; do
  path="$(jq -r '.path' <<<"$row")"
  status="$(jq -r '.status' <<<"$row")"

  if [[ "$path" == ".beads/issues.jsonl" ]]; then
    touched_count="$(jq 'length' "$touched_beads_json")"
    unrelated_count="$(jq --arg bead "$bead_id" '[.[] | select(. != $bead)] | length' "$touched_beads_json")"
    if [[ "$touched_count" == "0" ]]; then
      emit_decision "$path" "$status" "fail_closed" "missing scoped bead-line evidence"
      emit_offender "$path" "missing scoped bead-line evidence"
    elif [[ "$unrelated_count" != "0" ]]; then
      emit_decision "$path" "$status" "fail_closed" "shared .beads export touches unrelated bead ids"
      emit_offender "$path" "shared .beads export touches unrelated bead ids"
    else
      emit_decision "$path" "$status" "allow" "shared .beads export scoped to current bead"
    fi
    continue
  fi

  if allowed_by_explicit_path "$path"; then
    emit_decision "$path" "$status" "allow" "path is in explicit bead write set"
    continue
  fi

  if owner_line="$(reservation_owner_for_path "$path")"; then
    IFS=$'\t' read -r pattern holder holder_bead <<<"$owner_line"
    if [[ "$holder" == "$agent_id" || "$holder_bead" == "$bead_id" ]]; then
      emit_decision "$path" "$status" "allow" "path is covered by current agent/bead reservation" "$holder" "$holder_bead" "$pattern"
    else
      emit_decision "$path" "$status" "fail_closed" "path is reserved by another owner" "$holder" "$holder_bead" "$pattern"
      emit_offender "$path" "path is reserved by another owner" "$holder" "$holder_bead"
    fi
    continue
  fi

  emit_decision "$path" "$status" "fail_closed" "path is outside allowed write set and reservations"
  emit_offender "$path" "path is outside allowed write set and reservations"
done < <(jq -c '.[]' "$staged_rows_json")

offender_count="$(jq -s 'length' "$offenders_jsonl")"
staged_count="$(jq 'length' "$staged_rows_json")"
decision="pass"
exit_code=0
if [[ "$offender_count" != "0" ]]; then
  decision="fail_closed"
  exit_code=42
  emit_finding "error" "staged_ownership_contamination" "Staged paths include files outside the current bead or reservation set."
elif [[ "$reservation_status" == "missing" ]]; then
  decision="pass_degraded"
fi

jq -n \
  --arg schema_version "franken-engine.staged-ownership-report.v1" \
  --arg agent_id "$agent_id" \
  --arg bead_id "$bead_id" \
  --arg decision "$decision" \
  --arg reservation_status "$reservation_status" \
  --argjson staged_count "$staged_count" \
  --argjson offender_count "$offender_count" \
  --slurpfile staged "$staged_rows_json" \
  --slurpfile allowed "$allowed_paths_json" \
  --slurpfile reservations "$reservation_rows_json" \
  --slurpfile touched "$touched_beads_json" \
  --argjson decisions "$(jq -s '.' "$decisions_jsonl")" \
  --argjson offenders "$(jq -s '.' "$offenders_jsonl")" \
  --argjson findings "$(jq -s '.' "$findings_jsonl")" \
  --arg report_json "$report_json" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_md "$report_md" \
  '{
    schema_version: $schema_version,
    agent_id: $agent_id,
    bead_id: $bead_id,
    decision: $decision,
    reservation_snapshot_status: $reservation_status,
    expected_owner: {
      agent_id: $agent_id,
      bead_id: $bead_id
    },
    staged_path_count: $staged_count,
    offender_count: $offender_count,
    staged_paths: $staged[0],
    allowed_paths: $allowed[0],
    reservation_rows: $reservations[0],
    scoped_beads_issue_ids: $touched[0],
    path_decisions: $decisions,
    offending_paths: $offenders,
    findings: $findings,
    artifact_paths: {
      staged_ownership_report_json: $report_json,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $report_md
    }
  }' >"$report_tmp"
mv "$report_tmp" "$report_json"

jq -nc \
  --arg schema_version "franken-engine.staged-ownership-event.v1" \
  --arg event_name "staged_ownership_contamination_guard.decision" \
  --arg agent_id "$agent_id" \
  --arg bead_id "$bead_id" \
  --arg decision "$decision" \
  --argjson offender_count "$offender_count" \
  '{
    schema_version: $schema_version,
    event_name: $event_name,
    agent_id: $agent_id,
    bead_id: $bead_id,
    decision: $decision,
    offender_count: $offender_count
  }' >>"$events_path"

{
  printf '# Staged Ownership Report\n\n'
  printf "%s\n" "- Agent: \`${agent_id}\`"
  printf "%s\n" "- Bead: \`${bead_id}\`"
  printf "%s\n" "- Decision: \`${decision}\`"
  printf "%s\n" "- Staged paths: \`${staged_count}\`"
  printf "%s\n" "- Offending paths: \`${offender_count}\`"
} >"$report_md"

exit "$exit_code"
