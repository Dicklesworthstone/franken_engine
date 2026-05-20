#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

readonly capability_count=13
readonly root_readme="$root_dir/README.md"
readonly examples_readme="$root_dir/examples/README.md"

declare -a failures=()
declare -A root_demo_by_capability=()
declare -A root_command_by_capability=()
declare -A examples_demo_by_capability=()
declare -A examples_command_by_capability=()

record_failure() {
  failures+=("$1")
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s\n' "$value"
}

first_inline_code_or_trimmed() {
  local value
  value="$(trim "$1")"

  if [[ "$value" == *\`* ]]; then
    value="${value#*\`}"
    value="${value%%\`*}"
  fi

  trim "$value"
}

looks_like_stale_placeholder() {
  local value
  value="$(trim "$1")"
  value="${value,,}"

  [[ "$value" == *"no dedicated example"* ]] ||
    [[ "$value" == *"not currently shipped"* ]] ||
    [[ "$value" == *"not shipped"* ]] ||
    [[ "$value" == *"coming soon"* ]] ||
    [[ "$value" == *"todo"* ]] ||
    [[ "$value" == "-" ]] ||
    [[ "$value" == "--" ]]
}

extract_capability_rows() {
  local markdown_file="$1"

  awk -F'|' '
    /^\|[[:space:]]*#[[:space:]]*\|[[:space:]]*Capability[[:space:]]*\|/ {
      in_table = 1
      next
    }

    in_table && /^\|[[:space:]-]+\|/ {
      next
    }

    in_table && /^\|[[:space:]]*[0-9]+[[:space:]]*\|/ {
      number = $2
      capability = $3
      demo = $4
      command = $5

      gsub(/^[[:space:]]+|[[:space:]]+$/, "", number)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", capability)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", demo)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", command)

      print number "\t" capability "\t" demo "\t" command
      next
    }

    in_table && $0 !~ /^\|/ {
      exit
    }
  ' "$markdown_file"
}

load_table() {
  local label="$1"
  local markdown_file="$2"
  local demo_map_name="$3"
  local command_map_name="$4"
  # shellcheck disable=SC2178
  local -n demo_map="$demo_map_name"
  # shellcheck disable=SC2178
  local -n command_map="$command_map_name"
  local count=0

  if [[ ! -f "$markdown_file" ]]; then
    record_failure "$label table file is missing: $markdown_file"
    return
  fi

  while IFS=$'\t' read -r number capability raw_demo raw_command; do
    count=$((count + 1))

    if ! [[ "$number" =~ ^[0-9]+$ ]]; then
      record_failure "$label row has non-numeric capability id: $number"
      continue
    fi

    if ((number < 1 || number > capability_count)); then
      record_failure "$label row $number is outside expected 1..$capability_count range"
      continue
    fi

    if [[ -n "${demo_map[$number]+set}" ]]; then
      record_failure "$label has duplicate row for capability $number"
      continue
    fi

    if looks_like_stale_placeholder "$raw_demo"; then
      record_failure "$label capability $number has stale demo placeholder: $raw_demo"
    fi

    if looks_like_stale_placeholder "$raw_command"; then
      record_failure "$label capability $number has stale command placeholder: $raw_command"
    fi

    if looks_like_stale_placeholder "$capability"; then
      record_failure "$label capability $number has stale capability text: $capability"
    fi

    demo_map["$number"]="$(first_inline_code_or_trimmed "$raw_demo")"
    command_map["$number"]="$(first_inline_code_or_trimmed "$raw_command")"
  done < <(extract_capability_rows "$markdown_file")

  if ((count != capability_count)); then
    record_failure "$label table has $count rows; expected $capability_count"
  fi
}

validate_document_set() {
  local label="$1"
  local demo_map_name="$2"
  local command_map_name="$3"
  # shellcheck disable=SC2178
  local -n demo_map="$demo_map_name"
  # shellcheck disable=SC2178
  local -n command_map="$command_map_name"

  for number in $(seq 1 "$capability_count"); do
    if [[ -z "${demo_map[$number]+set}" ]]; then
      record_failure "$label is missing capability $number"
      continue
    fi

    local demo="${demo_map[$number]}"
    local command="${command_map[$number]}"

    if [[ -z "$demo" ]]; then
      record_failure "$label capability $number has an empty demo directory"
      continue
    fi

    if [[ ! -d "$root_dir/examples/$demo" ]]; then
      record_failure "$label capability $number references missing demo directory: examples/$demo"
    fi

    if [[ -z "$command" ]]; then
      record_failure "$label capability $number has an empty command"
      continue
    fi

    if [[ "$command" != ./* ]]; then
      record_failure "$label capability $number command is not repo-relative: $command"
      continue
    fi

    if [[ "$command" != ./examples/"$demo"/* ]]; then
      record_failure "$label capability $number command '$command' is not under examples/$demo/"
    fi

    local command_path="$root_dir/${command#./}"
    if [[ ! -f "$command_path" ]]; then
      record_failure "$label capability $number command file is missing: $command"
    elif [[ "$command" == *.sh && ! -x "$command_path" ]]; then
      record_failure "$label capability $number shell command is not executable: $command"
    fi
  done
}

validate_cross_document_consistency() {
  for number in $(seq 1 "$capability_count"); do
    if [[ -z "${root_demo_by_capability[$number]+set}" ]] ||
      [[ -z "${examples_demo_by_capability[$number]+set}" ]]; then
      continue
    fi

    if [[ "${root_demo_by_capability[$number]}" != "${examples_demo_by_capability[$number]}" ]]; then
      record_failure "capability $number demo mismatch: README.md has '${root_demo_by_capability[$number]}', examples/README.md has '${examples_demo_by_capability[$number]}'"
    fi

    if [[ "${root_command_by_capability[$number]}" != "${examples_command_by_capability[$number]}" ]]; then
      record_failure "capability $number command mismatch: README.md has '${root_command_by_capability[$number]}', examples/README.md has '${examples_command_by_capability[$number]}'"
    fi
  done
}

load_table "README.md" "$root_readme" root_demo_by_capability root_command_by_capability
load_table "examples/README.md" "$examples_readme" examples_demo_by_capability examples_command_by_capability

validate_document_set "README.md" root_demo_by_capability root_command_by_capability
validate_document_set "examples/README.md" examples_demo_by_capability examples_command_by_capability
validate_cross_document_consistency

if ((${#failures[@]} > 0)); then
  printf 'Impossible-by-default demo index gate failed:\n' >&2
  for failure in "${failures[@]}"; do
    printf ' - %s\n' "$failure" >&2
  done
  exit 1
fi

printf 'Impossible-by-default demo index gate passed: %d capabilities wired\n' "$capability_count"
