#!/usr/bin/env bash
# shellcheck disable=SC2016
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo_root="$root_dir"
classifier_path="${root_dir}/scripts/validation_hygiene_classifier.sh"
artifact_root="${VALIDATION_HYGIENE_WRAPPER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-validation-hygiene-wrapper}"
run_id="${VALIDATION_HYGIENE_WRAPPER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${VALIDATION_HYGIENE_WRAPPER_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${VALIDATION_HYGIENE_WRAPPER_SOURCE_REVISION:-}"
bead_id="bd-validation-hygiene-wrapper"
case_id="manual"
command_text=""
json_out=""
original_args=("$@")
declare -a scoped_paths=()
declare -a command_argv=()

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/validation_hygiene_wrapper.sh [OPTIONS] [-- COMMAND [ARG...]]

Run a validation command, capture stdout/stderr/exit evidence, classify the
result with validation_hygiene_classifier.sh, and exit with the original command
status.

Options:
  --scope PATH             Scoped file path; may be repeated.
  --command TEXT           Command text executed through bash -lc.
  --json-out PATH|-        Write wrapper_report.json to PATH, or stdout with '-'.
  --bead-id ID             Bead id for the report.
  --case-id ID             Deterministic case id for tests/reports.
  --repo-root DIR          Git repo root to inspect and command working dir.
  --source-revision REV    Source revision recorded in artifacts.
  --output-dir DIR         Artifact directory.

Prefer argv mode after '--' for exact argument preservation. Cargo/build/test
commands must already use the rch command shape required by AGENTS.md; this
wrapper records the command and does not rewrite it.

Artifacts:
  wrapper_report.json
  stdout.txt
  stderr.txt
  transcript.txt
  events.jsonl
  commands.txt
  report.md
  classifier/hygiene_report.json
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
    --json-out)
      json_out="${2:-}"
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
    --)
      shift
      command_argv=("$@")
      break
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
  printf 'jq is required for validation hygiene wrapper\n' >&2
  exit 2
fi
if [[ ! -x "$classifier_path" ]]; then
  printf 'classifier script is not executable: %s\n' "$classifier_path" >&2
  exit 2
fi
if [[ -n "$command_text" && "${#command_argv[@]}" -gt 0 ]]; then
  printf 'use either --command TEXT or argv after --, not both\n' >&2
  exit 64
fi
if [[ -z "$command_text" && "${#command_argv[@]}" -eq 0 ]]; then
  printf 'missing command; provide --command TEXT or argv after --\n' >&2
  usage
  exit 64
fi

repo_root="$(cd "$repo_root" && pwd)"
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$repo_root" rev-parse --short HEAD 2>/dev/null || printf unknown)"
fi

shell_quote_array() {
  local quoted=()
  local item
  for item in "$@"; do
    quoted+=("$(printf '%q' "$item")")
  done
  local IFS=' '
  printf '%s' "${quoted[*]}"
}

array_to_json() {
  if [[ "$#" -eq 0 ]]; then
    printf '[]\n'
    return
  fi
  printf '%s\n' "$@" | jq -R . | jq -s .
}

if [[ "${#command_argv[@]}" -gt 0 ]]; then
  command_mode="argv"
  command_text="$(shell_quote_array "${command_argv[@]}")"
else
  command_mode="shell"
  command_argv=("bash" "-lc" "$command_text")
fi

mkdir -p "$run_dir"
wrapper_report="${run_dir}/wrapper_report.json"
stdout_path="${run_dir}/stdout.txt"
stderr_path="${run_dir}/stderr.txt"
transcript_path="${run_dir}/transcript.txt"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_md="${run_dir}/report.md"
classifier_dir="${run_dir}/classifier"
classifier_report="${classifier_dir}/hygiene_report.json"

for artifact_path in \
  "$wrapper_report" \
  "$stdout_path" \
  "$stderr_path" \
  "$transcript_path" \
  "$events_path" \
  "$commands_path" \
  "$report_md"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done
if [[ -e "$classifier_dir" ]]; then
  printf 'refusing to overwrite existing classifier artifact dir: %s\n' "$classifier_dir" >&2
  exit 73
fi
mkdir -p "$classifier_dir"

: >"$events_path"
printf './scripts/validation_hygiene_wrapper.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"
printf 'wrapped_command=%s\n' "$command_text" >>"$commands_path"

write_event() {
  local event="$1"
  local outcome="$2"
  local detail="$3"
  jq -nc \
    --arg schema_version "franken-engine.validation-hygiene-wrapper.event.v1" \
    --arg component "validation_hygiene_wrapper" \
    --arg event "$event" \
    --arg outcome "$outcome" \
    --arg detail "$detail" \
    --arg case_id "$case_id" \
    --arg bead_id "$bead_id" \
    '{schema_version:$schema_version,component:$component,event:$event,outcome:$outcome,detail:$detail,case_id:$case_id,bead_id:$bead_id}' >>"$events_path"
}

write_event "wrapper.started" "ok" "$case_id"
start_ns="$(date +%s%N)"
set +e
if [[ "$command_mode" == "shell" ]]; then
  (cd "$repo_root" && bash -lc "$command_text") >"$stdout_path" 2>"$stderr_path"
else
  (cd "$repo_root" && "${command_argv[@]}") >"$stdout_path" 2>"$stderr_path"
fi
command_exit=$?
set -e
end_ns="$(date +%s%N)"
elapsed_ms="$(( (end_ns - start_ns) / 1000000 ))"

{
  printf 'STDOUT\n'
  sed -n '1,$p' "$stdout_path"
  printf '\nSTDERR\n'
  sed -n '1,$p' "$stderr_path"
} >"$transcript_path"

first_failure_line="$(
  awk 'NF { print; exit }' "$stderr_path"
  if [[ ! -s "$stderr_path" ]]; then
    awk 'NF { print; exit }' "$stdout_path"
  fi
)"

classifier_args=(
  --repo-root "$repo_root"
  --case-id "$case_id"
  --bead-id "$bead_id"
  --command "$command_text"
  --transcript "$transcript_path"
  --exit-code "$command_exit"
  --source-revision "$source_revision"
  --output-dir "$classifier_dir"
)
for scoped_path in "${scoped_paths[@]}"; do
  classifier_args+=(--scope "$scoped_path")
done

set +e
"$classifier_path" "${classifier_args[@]}" >/dev/null 2>&1
classifier_exit=$?
set -e
if [[ ! -f "$classifier_report" ]]; then
  printf 'classifier did not emit report: %s\n' "$classifier_report" >&2
  exit 2
fi

write_event "wrapped_command.completed" "$command_exit" "$first_failure_line"
write_event "classifier.completed" "$classifier_exit" "$classifier_report"

command_argv_json="$(array_to_json "${command_argv[@]}")"
scope_json="$(printf '%s\n' "${scoped_paths[@]}" | jq -R . | jq -s 'map(select(length > 0))')"
classifier_report_json="$(cat "$classifier_report")"

jq -n \
  --arg schema_version "franken-engine.validation-hygiene-wrapper-report.v1" \
  --arg report_id "vhw-${run_id}-${bead_id}" \
  --arg bead_id "$bead_id" \
  --arg case_id "$case_id" \
  --arg source_revision "$source_revision" \
  --arg repo_root "$repo_root" \
  --arg command_mode "$command_mode" \
  --arg command_text "$command_text" \
  --argjson command_argv "$command_argv_json" \
  --argjson command_exit "$command_exit" \
  --argjson classifier_exit "$classifier_exit" \
  --argjson elapsed_ms "$elapsed_ms" \
  --arg first_failure_line "$first_failure_line" \
  --argjson scope_paths "$scope_json" \
  --argjson classifier_report "$classifier_report_json" \
  --arg stdout_path "$stdout_path" \
  --arg stderr_path "$stderr_path" \
  --arg transcript_path "$transcript_path" \
  --arg classifier_report_path "$classifier_report" \
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
      mode: $command_mode,
      text: $command_text,
      argv: $command_argv,
      exit_code: $command_exit,
      elapsed_ms: $elapsed_ms,
      first_failure_line: (if $first_failure_line == "" then null else $first_failure_line end),
      preserves_original_command: true,
      wrapper_exit_code: $command_exit
    },
    scope_paths: $scope_paths,
    classifier_exit_code: $classifier_exit,
    classifier_report: $classifier_report,
    no_masking_attestation: {
      exits_with_original_command_status: true,
      original_command_exit_code: $command_exit,
      wrapper_exit_code: $command_exit
    },
    non_mutation_attestation: {
      rewrites_command: false,
      deletes_files: false,
      moves_files: false,
      formats_unrelated_files: false,
      stages_files: false
    },
    artifact_paths: {
      wrapper_report_json: "'"$wrapper_report"'",
      stdout_txt: $stdout_path,
      stderr_txt: $stderr_path,
      transcript_txt: $transcript_path,
      classifier_report_json: $classifier_report_path,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $report_md
    }
  }' >"$wrapper_report"

{
  printf '# Validation Hygiene Wrapper\n\n'
  printf -- '- bead_id: `%s`\n' "$bead_id"
  printf -- '- case_id: `%s`\n' "$case_id"
  printf -- '- command_exit: `%s`\n' "$command_exit"
  printf -- '- classifier_exit: `%s`\n' "$classifier_exit"
  printf -- '- elapsed_ms: `%s`\n' "$elapsed_ms"
  printf -- '- classifier_outcome: `%s`\n' "$(jq -r '.outcome.status' "$classifier_report")"
  if [[ -n "$first_failure_line" ]]; then
    printf -- '- first_failure_line: %s\n' "$first_failure_line"
  fi
  printf -- '- wrapper_exit_code: `%s`\n' "$command_exit"
} >"$report_md"

if [[ -n "$json_out" ]]; then
  if [[ "$json_out" == "-" ]]; then
    sed -n '1,$p' "$wrapper_report"
  else
    if [[ -e "$json_out" ]]; then
      printf 'refusing to overwrite --json-out path: %s\n' "$json_out" >&2
      exit 73
    fi
    jq '.' "$wrapper_report" >"$json_out"
  fi
fi

write_event "wrapper.completed" "$command_exit" "$case_id"
exit "$command_exit"
