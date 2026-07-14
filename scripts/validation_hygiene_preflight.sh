#!/usr/bin/env bash
# shellcheck disable=SC2016,SC2094
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo_root="$root_dir"
artifact_root="${VALIDATION_HYGIENE_PREFLIGHT_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-validation-hygiene-preflight}"
run_id="${VALIDATION_HYGIENE_PREFLIGHT_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${VALIDATION_HYGIENE_PREFLIGHT_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${VALIDATION_HYGIENE_PREFLIGHT_SOURCE_REVISION:-}"
bead_id="bd-validation-hygiene-preflight"
case_id="manual"
agent_name="${AGENT_NAME:-unknown}"
reservation_json=""
output_format="${VALIDATION_HYGIENE_PREFLIGHT_FORMAT:-text}"
original_args=("$@")
declare -a scoped_paths=()

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/validation_hygiene_preflight.sh [OPTIONS]

Emit a read-only preflight report for scoped bead validation in a dirty shared
worktree. The preflight never runs Cargo, rch, formatting, staging, deletion, or
cleanup commands.

Options:
  --scope PATH             Scoped file path; may be repeated.
  --reservation-json FILE  Optional Agent Mail reservation snapshot to embed.
  --agent NAME             Agent name; defaults to AGENT_NAME or unknown.
  --bead-id ID             Bead id for the report.
  --case-id ID             Deterministic case id for tests/reports.
  --repo-root DIR          Git repo root to inspect. Defaults to this repo.
  --source-revision REV    Source revision recorded in artifacts.
  --output-dir DIR         Artifact directory.
  --format MODE            stdout mode: text, json, or none. Defaults to text.

Artifacts:
  preflight_report.json
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
    --reservation-json)
      reservation_json="${2:-}"
      shift 2
      ;;
    --agent)
      agent_name="${2:-}"
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
    --format)
      output_format="${2:-}"
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
  printf 'jq is required for validation hygiene preflight\n' >&2
  exit 2
fi

case "$output_format" in
  text|json|none)
    ;;
  *)
    printf 'unknown output format: %s\n' "$output_format" >&2
    usage
    exit 64
    ;;
esac

repo_root="$(cd "$repo_root" && pwd)"
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$repo_root" rev-parse --short HEAD 2>/dev/null || printf unknown)"
fi

normalize_path() {
  local path="$1"
  if [[ "$path" = /* ]]; then
    realpath --relative-to="$repo_root" "$path" 2>/dev/null || printf '%s\n' "$path"
  else
    printf '%s\n' "${path#./}"
  fi
}

path_in_array() {
  local needle="$1"
  shift || true
  local item
  for item in "$@"; do
    [[ "$item" == "$needle" ]] && return 0
  done
  return 1
}

json_array() {
  if [[ "$#" -eq 0 ]]; then
    printf '[]\n'
    return
  fi
  printf '%s\n' "$@" | jq -R . | jq -s .
}

append_object() {
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
preflight_report="${run_dir}/preflight_report.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_md="${run_dir}/report.md"
tracked_jsonl="${run_dir}/tracked_dirty.jsonl"
untracked_jsonl="${run_dir}/untracked_files.jsonl"
scope_jsonl="${run_dir}/scoped_files.jsonl"
risks_jsonl="${run_dir}/risks.jsonl"
suggestions_jsonl="${run_dir}/validation_suggestions.jsonl"

for artifact_path in \
  "$preflight_report" \
  "$events_path" \
  "$commands_path" \
  "$report_md" \
  "$tracked_jsonl" \
  "$untracked_jsonl" \
  "$scope_jsonl" \
  "$risks_jsonl" \
  "$suggestions_jsonl"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

: >"$events_path"
: >"$tracked_jsonl"
: >"$untracked_jsonl"
: >"$scope_jsonl"
: >"$risks_jsonl"
: >"$suggestions_jsonl"

printf './scripts/validation_hygiene_preflight.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  local event="$1"
  local outcome="$2"
  local detail="$3"
  jq -nc \
    --arg schema_version "franken-engine.validation-hygiene-preflight.event.v1" \
    --arg component "validation_hygiene_preflight" \
    --arg event "$event" \
    --arg outcome "$outcome" \
    --arg detail "$detail" \
    --arg case_id "$case_id" \
    --arg bead_id "$bead_id" \
    '{schema_version:$schema_version,component:$component,event:$event,outcome:$outcome,detail:$detail,case_id:$case_id,bead_id:$bead_id}' >>"$events_path"
}

write_event "preflight.started" "ok" "$case_id"
branch="$(git -C "$repo_root" rev-parse --abbrev-ref HEAD 2>/dev/null || printf unknown)"
head_sha="$(git -C "$repo_root" rev-parse --short HEAD 2>/dev/null || printf unknown)"

declare -a normalized_scopes=()
declare -a tracked_dirty=()
declare -a untracked_paths=()

for scoped_path in "${scoped_paths[@]}"; do
  normalized_scopes+=("$(normalize_path "$scoped_path")")
done

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
      ;;
    *)
      if ! path_in_array "$parsed_path" "${tracked_dirty[@]}"; then
        tracked_dirty+=("$parsed_path")
      fi
      ;;
  esac
done < <(git -C "$repo_root" status --porcelain=v1 --untracked-files=all)

for scoped_path in "${normalized_scopes[@]}"; do
  git_state="clean_or_unknown"
  if path_in_array "$scoped_path" "${tracked_dirty[@]}"; then
    git_state="tracked_dirty"
    append_object "$risks_jsonl" \
      --arg risk_type "in_scope_dirty" \
      --arg path "$scoped_path" \
      --arg severity "review" \
      '{risk_type:$risk_type,path:$path,severity:$severity,summary:"scoped file is dirty and must be validated before closeout"}'
  elif path_in_array "$scoped_path" "${untracked_paths[@]}"; then
    git_state="untracked"
    append_object "$risks_jsonl" \
      --arg risk_type "in_scope_untracked" \
      --arg path "$scoped_path" \
      --arg severity "review" \
      '{risk_type:$risk_type,path:$path,severity:$severity,summary:"scoped file is untracked and must be intentionally staged before commit"}'
  fi
  append_object "$scope_jsonl" \
    --arg path "$scoped_path" \
    --arg git_state "$git_state" \
    '{path:$path,git_state:$git_state}'
done

for path in "${tracked_dirty[@]}"; do
  if path_in_array "$path" "${normalized_scopes[@]}"; then
    continue
  fi
  append_object "$tracked_jsonl" \
    --arg path "$path" \
    '{path:$path,classification:"tracked_unrelated_dirty",summary:"tracked dirty file outside scoped paths"}'
  append_object "$risks_jsonl" \
    --arg risk_type "tracked_unrelated_dirty" \
    --arg path "$path" \
    --arg severity "blocks_full_gate_claims" \
    '{risk_type:$risk_type,path:$path,severity:$severity,summary:"unrelated tracked dirty file may contaminate package/workspace validation"}'
done

for path in "${untracked_paths[@]}"; do
  if path_in_array "$path" "${normalized_scopes[@]}"; then
    continue
  fi
  classification_pair="$(classify_untracked "$path")"
  classification="${classification_pair%%|*}"
  reason="${classification_pair#*|}"
  append_object "$untracked_jsonl" \
    --arg path "$path" \
    --arg classification "$classification" \
    --arg reason "$reason" \
    '{path:$path,classification:$classification,classification_reason:$reason}'
  append_object "$risks_jsonl" \
    --arg risk_type "$classification" \
    --arg path "$path" \
    --arg severity "blocks_full_gate_claims" \
    '{risk_type:$risk_type,path:$path,severity:$severity,summary:"untracked file may contaminate package/workspace validation if discovered by the command"}'
done

scope_text="$(printf '%q ' "${normalized_scopes[@]}")"
scope_text="${scope_text% }"
if [[ "${#normalized_scopes[@]}" -gt 0 ]]; then
  append_object "$suggestions_jsonl" \
    --arg command "git diff --check -- ${scope_text}" \
    --arg claim_scope "scoped_whitespace_only" \
    '{command:$command,claim_scope:$claim_scope,full_gate_claim:false,requires_rch:false}'
fi

declare -a shell_scopes=()
declare -a rust_scopes=()
declare -a docs_scopes=()
for scoped_path in "${normalized_scopes[@]}"; do
  case "$scoped_path" in
    *.sh)
      shell_scopes+=("$scoped_path")
      ;;
    *.rs)
      rust_scopes+=("$scoped_path")
      ;;
    *.md|*.json|*.toml)
      docs_scopes+=("$scoped_path")
      ;;
  esac
done

if [[ "${#shell_scopes[@]}" -gt 0 ]]; then
  shell_text="$(printf '%q ' "${shell_scopes[@]}")"
  shell_text="${shell_text% }"
  append_object "$suggestions_jsonl" \
    --arg command "bash -n ${shell_text}" \
    --arg claim_scope "scoped_shell_syntax" \
    '{command:$command,claim_scope:$claim_scope,full_gate_claim:false,requires_rch:false}'
  append_object "$suggestions_jsonl" \
    --arg command "shellcheck -x ${shell_text}" \
    --arg claim_scope "scoped_shell_lint" \
    '{command:$command,claim_scope:$claim_scope,full_gate_claim:false,requires_rch:false,optional_when_missing_tool:true}'
fi

if [[ "${#rust_scopes[@]}" -gt 0 ]]; then
  append_object "$suggestions_jsonl" \
    --arg command "env -u CARGO_ENCODED_RUSTFLAGS rch exec -- env -u CARGO_ENCODED_RUSTFLAGS CARGO_INCREMENTAL=0 RUSTFLAGS='-C linker=cc -Clinker-features=-lld' cargo test -p frankenengine-engine <focused-target-for-scoped-files>" \
    --arg claim_scope "focused_rust_validation" \
    '{command:$command,claim_scope:$claim_scope,full_gate_claim:false,requires_rch:true,requires_operator_target_selection:true}'
fi

if [[ "${#docs_scopes[@]}" -gt 0 && "${#shell_scopes[@]}" -eq 0 && "${#rust_scopes[@]}" -eq 0 ]]; then
  append_object "$suggestions_jsonl" \
    --arg command "No Cargo/rch required for docs-only scoped validation unless the bead changes generated docs contracts." \
    --arg claim_scope "docs_only" \
    '{command:$command,claim_scope:$claim_scope,full_gate_claim:false,requires_rch:false}'
fi

reservation_snapshot='null'
if [[ -n "$reservation_json" ]]; then
  if [[ ! -f "$reservation_json" ]]; then
    printf 'reservation JSON not found: %s\n' "$reservation_json" >&2
    exit 64
  fi
  reservation_snapshot="$(jq '.' "$reservation_json")"
fi

tracked_json="$(jq -s '.' "$tracked_jsonl")"
untracked_json="$(jq -s '.' "$untracked_jsonl")"
scope_json="$(jq -s '.' "$scope_jsonl")"
risks_json="$(jq -s '.' "$risks_jsonl")"
suggestions_json="$(jq -s '.' "$suggestions_jsonl")"
scope_paths_json="$(json_array "${normalized_scopes[@]}")"

jq -n \
  --arg schema_version "franken-engine.validation-hygiene-preflight.v1" \
  --arg report_id "vhp-${run_id}-${bead_id}" \
  --arg bead_id "$bead_id" \
  --arg case_id "$case_id" \
  --arg agent_name "$agent_name" \
  --arg source_revision "$source_revision" \
  --arg repo_root "$repo_root" \
  --arg branch "$branch" \
  --arg head_sha "$head_sha" \
  --argjson scope_paths "$scope_paths_json" \
  --argjson scoped_files "$scope_json" \
  --argjson tracked_dirty "$tracked_json" \
  --argjson untracked_files "$untracked_json" \
  --argjson risks "$risks_json" \
  --argjson suggestions "$suggestions_json" \
  --argjson reservation_snapshot "$reservation_snapshot" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_md "$report_md" \
  --arg preflight_report_json "$preflight_report" \
  --arg output_format "$output_format" \
  '{
    schema_version: $schema_version,
    report_id: $report_id,
    bead_id: $bead_id,
    case_id: $case_id,
    agent_name: $agent_name,
    source_revision: $source_revision,
    repo: {
      root: $repo_root,
      branch: $branch,
      head: $head_sha
    },
    scope_paths: $scope_paths,
    scoped_files: $scoped_files,
    dirty_context: {
      tracked_dirty: $tracked_dirty,
      untracked_files: $untracked_files
    },
    risks: $risks,
    reservation_snapshot: $reservation_snapshot,
    validation_suggestions: $suggestions,
    output_format: $output_format,
    claim_limits: {
      scoped_validation_may_close_scoped_bead: true,
      scoped_validation_proves_full_workspace_gate: false,
      full_gate_blockers_must_remain_visible: true
    },
    no_delete_no_revert_disclaimer: "Do not delete, revert, move, format, stage, or commit unrelated dirty/untracked files to make validation pass.",
    non_mutation_attestation: {
      runs_cargo: false,
      runs_rch: false,
      mutates_git_index: false,
      deletes_files: false,
      moves_files: false,
      formats_files: false
    },
    artifact_paths: {
      preflight_report_json: $preflight_report_json,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $report_md
    }
  }' >"$preflight_report"

write_event "preflight.completed" "ok" "$case_id"

{
  printf '# Validation Hygiene Preflight\n\n'
  printf -- '- bead_id: `%s`\n' "$bead_id"
  printf -- '- case_id: `%s`\n' "$case_id"
  printf -- '- agent: `%s`\n' "$agent_name"
  printf -- '- branch: `%s`\n' "$branch"
  printf -- '- head: `%s`\n' "$head_sha"
  printf -- '- risks: `%s`\n' "$(jq -s 'length' "$risks_jsonl")"
  printf '\n'
  printf 'Do not delete, revert, move, format, stage, or commit unrelated dirty/untracked files to make validation pass.\n'
} >"$report_md"

case "$output_format" in
  text)
    cat "$report_md"
    ;;
  json)
    cat "$preflight_report"
    ;;
  none)
    ;;
esac

exit 0
