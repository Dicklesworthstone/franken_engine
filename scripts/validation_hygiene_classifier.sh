#!/usr/bin/env bash
# shellcheck disable=SC2016
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo_root="$root_dir"
artifact_root="${VALIDATION_HYGIENE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-validation-hygiene}"
run_id="${VALIDATION_HYGIENE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${VALIDATION_HYGIENE_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${VALIDATION_HYGIENE_SOURCE_REVISION:-}"
bead_id="bd-validation-hygiene"
case_id="manual"
command_text=""
transcript_file=""
exit_code="0"
status_file=""
diff_file=""
untracked_file=""
ignored_file=""
original_args=("$@")
declare -a scoped_paths=()

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/validation_hygiene_classifier.sh [OPTIONS]

Classify dirty shared-worktree validation blockers without deleting, moving,
formatting, staging, or rewriting files.

Options:
  --scope PATH             Scoped file path; may be repeated.
  --command TEXT           Original validation command text.
  --transcript FILE        Captured stdout/stderr transcript for the command.
  --exit-code CODE         Exit code from the validation command.
  --bead-id ID             Bead id for the report.
  --case-id ID             Deterministic case id for tests/reports.
  --repo-root DIR          Git repo root to inspect. Defaults to this repo.
  --source-revision REV    Source revision recorded in artifacts.
  --output-dir DIR         Artifact directory.

Fixture injection, used by deterministic smoke tests:
  --status-file FILE       Pre-captured git status --porcelain=v1 output.
  --diff-file FILE         Pre-captured git diff --name-only output.
  --untracked-file FILE    Pre-captured git ls-files --others output.
  --ignored-file FILE      Pre-captured ignored-artifact list.

Artifacts:
  hygiene_report.json
  events.jsonl
  commands.txt
  report.md
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --scope)
      scoped_paths+=("${2:-}")
      shift 2
      ;;
    --command)
      command_text="${2:-}"
      shift 2
      ;;
    --transcript)
      transcript_file="${2:-}"
      shift 2
      ;;
    --exit-code)
      exit_code="${2:-}"
      shift 2
      ;;
    --bead-id)
      bead_id="${2:-}"
      shift 2
      ;;
    --case-id)
      case_id="${2:-}"
      shift 2
      ;;
    --repo-root)
      repo_root="${2:-}"
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
    --status-file)
      status_file="${2:-}"
      shift 2
      ;;
    --diff-file)
      diff_file="${2:-}"
      shift 2
      ;;
    --untracked-file)
      untracked_file="${2:-}"
      shift 2
      ;;
    --ignored-file)
      ignored_file="${2:-}"
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
  printf 'jq is required for validation hygiene classification\n' >&2
  exit 2
fi

if [[ ! "$exit_code" =~ ^[0-9]+$ ]]; then
  printf 'exit code must be numeric: %s\n' "$exit_code" >&2
  exit 64
fi

repo_root="$(cd "$repo_root" && pwd)"
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$repo_root" rev-parse --short HEAD 2>/dev/null || printf unknown)"
fi

normalize_path() {
  local path="$1"
  if [[ "$path" = /* ]]; then
    realpath --relative-to="$repo_root" "$path" 2>/dev/null || printf '%s\n' "$path"
  else
    path="${path#./}"
    printf '%s\n' "$path"
  fi
}

path_in_array() {
  local needle="$1"
  shift || true
  local item
  for item in "$@"; do
    if [[ "$item" == "$needle" ]]; then
      return 0
    fi
  done
  return 1
}

safe_write_json_object() {
  local output="$1"
  shift
  jq -nc "$@" >>"$output"
}

classify_untracked() {
  local path="$1"
  local base
  base="$(basename "$path")"
  case "$base" in
    *_probe.rs|*_diag.rs|*_debug.rs|*_irdump.rs|*.patch|*.txt|*.actual|*.snap.new|*.tmp)
      printf 'untracked_ephemeral_candidate|untracked filename matches probe/scratch/generated heuristic\n'
      return
      ;;
  esac
  if [[ "$path" == crates/franken-engine/tests/* &&
        ( "$path" == *probe* || "$path" == *diag* || "$path" == *scratch* || "$path" == *dump* ) ]]; then
    printf 'untracked_ephemeral_candidate|untracked test path contains probe/diag/scratch/dump\n'
    return
  fi
  case "$path" in
    src/*.rs|crates/*/src/*.rs|tests/*.rs|crates/*/tests/*.rs|examples/*.rs|crates/*/examples/*.rs|*.toml|*.json|*.md|scripts/*.sh)
      printf 'untracked_source_candidate|untracked durable source-shaped file without ephemeral heuristic\n'
      return
      ;;
  esac
  printf 'untracked_ephemeral_candidate|untracked file outside durable source patterns\n'
}

parse_porcelain_path() {
  local line="$1"
  local path="${line:3}"
  if [[ "$path" == *" -> "* ]]; then
    path="${path##* -> }"
  fi
  path="${path%\"}"
  path="${path#\"}"
  normalize_path "$path"
}

mkdir -p "$run_dir"
report_json="${run_dir}/hygiene_report.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_md="${run_dir}/report.md"
status_snapshot="${run_dir}/git_status_porcelain.txt"
diff_snapshot="${run_dir}/git_diff_name_only.txt"
untracked_snapshot="${run_dir}/git_untracked.txt"
ignored_snapshot="${run_dir}/git_ignored.txt"
scoped_jsonl="${run_dir}/scoped_files.jsonl"
tracked_jsonl="${run_dir}/tracked_unrelated_dirty.jsonl"
untracked_ephemeral_jsonl="${run_dir}/untracked_ephemeral_candidates.jsonl"
untracked_source_jsonl="${run_dir}/untracked_source_candidates.jsonl"
ignored_jsonl="${run_dir}/ignored_artifacts.jsonl"
external_jsonl="${run_dir}/external_environment_blockers.jsonl"
first_blocker_json="${run_dir}/first_blocker.json"

for artifact_path in \
  "$report_json" \
  "$events_path" \
  "$commands_path" \
  "$report_md" \
  "$status_snapshot" \
  "$diff_snapshot" \
  "$untracked_snapshot" \
  "$ignored_snapshot" \
  "$scoped_jsonl" \
  "$tracked_jsonl" \
  "$untracked_ephemeral_jsonl" \
  "$untracked_source_jsonl" \
  "$ignored_jsonl" \
  "$external_jsonl" \
  "$first_blocker_json"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

: >"$events_path"
: >"$scoped_jsonl"
: >"$tracked_jsonl"
: >"$untracked_ephemeral_jsonl"
: >"$untracked_source_jsonl"
: >"$ignored_jsonl"
: >"$external_jsonl"

printf './scripts/validation_hygiene_classifier.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"
printf 'original_validation_command=%s\n' "$command_text" >>"$commands_path"

write_event() {
  local event="$1"
  local outcome="$2"
  local detail="$3"
  jq -nc \
    --arg schema_version "franken-engine.validation-hygiene-classifier.event.v1" \
    --arg component "validation_hygiene_classifier" \
    --arg event "$event" \
    --arg outcome "$outcome" \
    --arg detail "$detail" \
    --arg case_id "$case_id" \
    --arg bead_id "$bead_id" \
    '{schema_version:$schema_version,component:$component,event:$event,outcome:$outcome,detail:$detail,case_id:$case_id,bead_id:$bead_id}' >>"$events_path"
}

copy_or_run() {
  local fixture="$1"
  local output="$2"
  shift 2
  if [[ -n "$fixture" ]]; then
    if [[ ! -f "$fixture" ]]; then
      printf 'fixture file not found: %s\n' "$fixture" >&2
      exit 64
    fi
    sed -n '1,$p' "$fixture" >"$output"
  else
    "$@" >"$output" 2>/dev/null || true
  fi
}

write_event "classifier.started" "ok" "$case_id"
copy_or_run "$status_file" "$status_snapshot" git -C "$repo_root" status --porcelain=v1 --untracked-files=all
copy_or_run "$diff_file" "$diff_snapshot" git -C "$repo_root" diff --name-only
copy_or_run "$untracked_file" "$untracked_snapshot" git -C "$repo_root" ls-files --others --exclude-standard
copy_or_run "$ignored_file" "$ignored_snapshot" git -C "$repo_root" ls-files --others -i --exclude-standard

declare -a normalized_scopes=()
for scoped_path in "${scoped_paths[@]}"; do
  normalized_scopes+=("$(normalize_path "$scoped_path")")
done

declare -a tracked_dirty=()
declare -a untracked_paths=()
declare -a ignored_paths=()
declare -a candidate_records=()

while IFS= read -r line || [[ -n "$line" ]]; do
  [[ -z "$line" ]] && continue
  status_code="${line:0:2}"
  parsed_path="$(parse_porcelain_path "$line")"
  case "$status_code" in
    '??')
      if ! path_in_array "$parsed_path" "${untracked_paths[@]}"; then
        untracked_paths+=("$parsed_path")
      fi
      ;;
    '!!')
      if ! path_in_array "$parsed_path" "${ignored_paths[@]}"; then
        ignored_paths+=("$parsed_path")
      fi
      ;;
    *)
      if ! path_in_array "$parsed_path" "${tracked_dirty[@]}"; then
        tracked_dirty+=("$parsed_path")
      fi
      ;;
  esac
done <"$status_snapshot"

while IFS= read -r path || [[ -n "$path" ]]; do
  [[ -z "$path" ]] && continue
  parsed_path="$(normalize_path "$path")"
  if ! path_in_array "$parsed_path" "${tracked_dirty[@]}"; then
    tracked_dirty+=("$parsed_path")
  fi
done <"$diff_snapshot"

while IFS= read -r path || [[ -n "$path" ]]; do
  [[ -z "$path" ]] && continue
  parsed_path="$(normalize_path "$path")"
  if ! path_in_array "$parsed_path" "${untracked_paths[@]}"; then
    untracked_paths+=("$parsed_path")
  fi
done <"$untracked_snapshot"

while IFS= read -r path || [[ -n "$path" ]]; do
  [[ -z "$path" ]] && continue
  parsed_path="$(normalize_path "$path")"
  if ! path_in_array "$parsed_path" "${ignored_paths[@]}"; then
    ignored_paths+=("$parsed_path")
  fi
done <"$ignored_snapshot"

for scoped_path in "${normalized_scopes[@]}"; do
  git_state="clean_or_unknown"
  if path_in_array "$scoped_path" "${tracked_dirty[@]}"; then
    git_state="tracked_dirty"
  elif path_in_array "$scoped_path" "${untracked_paths[@]}"; then
    git_state="untracked"
  elif path_in_array "$scoped_path" "${ignored_paths[@]}"; then
    git_state="ignored"
  fi
  safe_write_json_object "$scoped_jsonl" \
    --arg path "$scoped_path" \
    --arg git_state "$git_state" \
    '{path:$path,role:"scoped",git_state:$git_state,reserved:null,status:"pending_command_result"}'
  candidate_records+=("scoped_file|$scoped_path")
done

for path in "${tracked_dirty[@]}"; do
  if path_in_array "$path" "${normalized_scopes[@]}"; then
    continue
  fi
  safe_write_json_object "$tracked_jsonl" \
    --arg path "$path" \
    '{path:$path,classification_reason:"tracked modified file outside scoped_files",observed_by_command:null}'
  candidate_records+=("tracked_unrelated_dirty|$path")
done

for path in "${untracked_paths[@]}"; do
  if path_in_array "$path" "${normalized_scopes[@]}"; then
    continue
  fi
  classification_pair="$(classify_untracked "$path")"
  classification="${classification_pair%%|*}"
  reason="${classification_pair#*|}"
  if [[ "$classification" == "untracked_source_candidate" ]]; then
    safe_write_json_object "$untracked_source_jsonl" \
      --arg path "$path" \
      --arg reason "$reason" \
      '{path:$path,classification_reason:$reason,observed_by_command:null}'
  else
    safe_write_json_object "$untracked_ephemeral_jsonl" \
      --arg path "$path" \
      --arg reason "$reason" \
      '{path:$path,classification_reason:$reason,observed_by_command:null}'
  fi
  candidate_records+=("${classification}|$path")
done

for path in "${ignored_paths[@]}"; do
  if path_in_array "$path" "${normalized_scopes[@]}"; then
    continue
  fi
  safe_write_json_object "$ignored_jsonl" \
    --arg path "$path" \
    '{path:$path,classification_reason:"git ignored artifact outside scoped_files",observed_by_command:null}'
  candidate_records+=("ignored_artifact|$path")
done

transcript_text=""
if [[ -n "$transcript_file" ]]; then
  if [[ ! -f "$transcript_file" ]]; then
    printf 'transcript file not found: %s\n' "$transcript_file" >&2
    exit 64
  fi
  transcript_text="$(sed -n '1,$p' "$transcript_file")"
fi

first_class=""
first_path=""
first_summary=""
if [[ -n "$transcript_text" ]]; then
  while IFS= read -r line || [[ -n "$line" ]]; do
    lower="${line,,}"
    for record in "${candidate_records[@]}"; do
      candidate_class="${record%%|*}"
      candidate_path="${record#*|}"
      if [[ -n "$candidate_path" && "$line" == *"$candidate_path"* ]]; then
        first_class="$candidate_class"
        first_path="$candidate_path"
        first_summary="$line"
        break 2
      fi
    done
    if [[ "$lower" == *"bus error"* ||
          "$lower" == *"enospc"* ||
          "$lower" == *"no space left"* ||
          "$lower" == *"linker"* ||
          "$lower" == *"license-file"* ||
          ( "$lower" == *"manifest"* && "$lower" == *"parse"* ) ]]; then
      first_class="external_environment_blocker"
      first_path=""
      first_summary="$line"
      safe_write_json_object "$external_jsonl" \
        --arg summary "$line" \
        '{class:"external_environment_blocker",summary:$summary}'
      break
    fi
  done <<<"$transcript_text"
fi

if [[ -n "$first_class" ]]; then
  jq -n \
    --arg class "$first_class" \
    --arg path "$first_path" \
    --arg summary "$first_summary" \
    '{class:$class,path:(if $path == "" then null else $path end),summary:$summary}' >"$first_blocker_json"
else
  printf 'null\n' >"$first_blocker_json"
fi

outcome_status="pass"
scoped_files_clean="true"
package_or_workspace_gate_clean="true"
tool_exit_code=0
if [[ "$exit_code" -ne 0 ]]; then
  package_or_workspace_gate_clean="false"
  case "$first_class" in
    scoped_file)
      outcome_status="fail_scoped_files"
      scoped_files_clean="false"
      tool_exit_code=42
      ;;
    tracked_unrelated_dirty|untracked_ephemeral_candidate|untracked_source_candidate|ignored_artifact)
      outcome_status="blocked_by_unrelated_context"
      ;;
    external_environment_blocker)
      outcome_status="blocked_by_environment"
      ;;
    *)
      outcome_status="inconclusive"
      scoped_files_clean="false"
      tool_exit_code=42
      ;;
  esac
fi

scoped_json="$(jq -s '.' "$scoped_jsonl")"
tracked_json="$(jq -s '.' "$tracked_jsonl")"
untracked_ephemeral_json="$(jq -s '.' "$untracked_ephemeral_jsonl")"
untracked_source_json="$(jq -s '.' "$untracked_source_jsonl")"
ignored_json="$(jq -s '.' "$ignored_jsonl")"
external_json="$(jq -s '.' "$external_jsonl")"
first_blocker="$(cat "$first_blocker_json")"
scope_json="$(printf '%s\n' "${normalized_scopes[@]}" | jq -R . | jq -s 'map(select(length > 0))')"

jq -n \
  --arg schema_version "franken-engine.validation-hygiene-report.v1" \
  --arg report_id "vh-${run_id}-${bead_id}" \
  --arg bead_id "$bead_id" \
  --arg case_id "$case_id" \
  --arg source_revision "$source_revision" \
  --arg repo_root "$repo_root" \
  --arg command_text "$command_text" \
  --argjson exit_code "$exit_code" \
  --arg outcome_status "$outcome_status" \
  --arg scoped_files_clean "$scoped_files_clean" \
  --arg package_or_workspace_gate_clean "$package_or_workspace_gate_clean" \
  --argjson first_blocker "$first_blocker" \
  --argjson scope_paths "$scope_json" \
  --argjson scoped_files "$scoped_json" \
  --argjson tracked_unrelated_dirty "$tracked_json" \
  --argjson untracked_ephemeral_candidates "$untracked_ephemeral_json" \
  --argjson untracked_source_candidates "$untracked_source_json" \
  --argjson ignored_artifacts "$ignored_json" \
  --argjson external_environment_blockers "$external_json" \
  --arg status_snapshot "$status_snapshot" \
  --arg diff_snapshot "$diff_snapshot" \
  --arg untracked_snapshot "$untracked_snapshot" \
  --arg ignored_snapshot "$ignored_snapshot" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_md "$report_md" \
  '{
    schema_version: $schema_version,
    report_id: $report_id,
    bead_id: $bead_id,
    case_id: $case_id,
    source_revision: $source_revision,
    repo_root: $repo_root,
    command: {
      raw: $command_text,
      exit_code: $exit_code,
      preserves_original_command: true
    },
    outcome: {
      status: $outcome_status,
      scoped_files_clean: ($scoped_files_clean == "true"),
      package_or_workspace_gate_clean: ($package_or_workspace_gate_clean == "true"),
      first_blocker: $first_blocker
    },
    scope_paths: $scope_paths,
    scoped_files: $scoped_files,
    tracked_unrelated_dirty: $tracked_unrelated_dirty,
    untracked_ephemeral_candidates: $untracked_ephemeral_candidates,
    untracked_source_candidates: $untracked_source_candidates,
    ignored_artifacts: $ignored_artifacts,
    external_environment_blockers: $external_environment_blockers,
    reservation_snapshot: {
      agent: null,
      exclusive_paths: [],
      missing_expected_reservations: []
    },
    rch_context: {
      used: ($command_text | test("(^| )rch exec( |$)")),
      sync_scope: "not_inspected_by_classifier",
      retrieval_status: "not_inspected_by_classifier",
      worker_blocker: (if $outcome_status == "blocked_by_environment" then $first_blocker else null end)
    },
    no_delete_guarantee: {
      performed_deletions: false,
      performed_reverts: false,
      performed_moves: false,
      performed_unrelated_formatting: false,
      performed_unrelated_staging: false
    },
    non_mutation_attestation: {
      runs_cargo: false,
      runs_rch: false,
      mutates_git_index: false,
      deletes_files: false,
      moves_files: false,
      formats_files: false
    },
    artifact_paths: {
      hygiene_report_json: "'"$report_json"'",
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $report_md,
      git_status_porcelain: $status_snapshot,
      git_diff_name_only: $diff_snapshot,
      git_untracked: $untracked_snapshot,
      git_ignored: $ignored_snapshot
    }
  }' >"$report_json"

write_event "classifier.completed" "$outcome_status" "$case_id"

{
  printf '# Validation Hygiene Classifier\n\n'
  printf -- '- bead_id: `%s`\n' "$bead_id"
  printf -- '- case_id: `%s`\n' "$case_id"
  printf -- '- outcome: `%s`\n' "$outcome_status"
  printf -- '- scoped_files_clean: `%s`\n' "$scoped_files_clean"
  printf -- '- package_or_workspace_gate_clean: `%s`\n' "$package_or_workspace_gate_clean"
  if [[ -n "$first_class" ]]; then
    printf -- '- first_blocker: `%s`' "$first_class"
    if [[ -n "$first_path" ]]; then
      printf ' `%s`' "$first_path"
    fi
    printf ' - %s\n' "$first_summary"
  else
    printf -- '- first_blocker: `null`\n'
  fi
  printf -- '- no_delete_guarantee: `true`\n'
} >"$report_md"

exit "$tool_exit_code"
