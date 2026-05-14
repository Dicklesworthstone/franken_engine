#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'USAGE'
usage: scripts/check_shell_hygiene.sh [--strict] [--verbose] [--max-findings <n>]
                                      [--report-jsonl <path>] [--root <repo>] [path ...]

Runs shell-only hygiene checks over operator/e2e scripts:
  - bash -n syntax validation
  - shellcheck diagnostics

Default mode is advisory: findings are reported but the command exits 0 so the
current legacy script surface can be inventoried without blocking unrelated
work. Use --strict for CI-style failure, especially with explicit paths.

No Cargo commands are executed by this checker.
USAGE
}

strict=false
verbose=false
max_findings=80
report_jsonl=""
scan_roots=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --strict)
      strict=true
      shift
      ;;
    --verbose)
      verbose=true
      shift
      ;;
    --max-findings)
      if [[ $# -lt 2 ]]; then
        echo "--max-findings requires a count" >&2
        exit 2
      fi
      max_findings="$2"
      shift 2
      ;;
    --report-jsonl)
      if [[ $# -lt 2 ]]; then
        echo "--report-jsonl requires a path" >&2
        exit 2
      fi
      report_jsonl="$2"
      shift 2
      ;;
    --root)
      if [[ $# -lt 2 ]]; then
        echo "--root requires a path" >&2
        exit 2
      fi
      repo_root="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      scan_roots+=("$1")
      shift
      ;;
  esac
done

if [[ ${#scan_roots[@]} -eq 0 ]]; then
  scan_roots=("scripts" "examples")
fi

if [[ -n "$report_jsonl" ]]; then
  mkdir -p "$(dirname "$report_jsonl")"
  : >"$report_jsonl"
fi

find_shell_scripts() {
  local path
  for path in "${scan_roots[@]}"; do
    if [[ -f "${repo_root}/${path}" ]]; then
      printf '%s\n' "${repo_root}/${path}"
    elif [[ -d "${repo_root}/${path}" ]]; then
      find "${repo_root}/${path}" \
        \( -name .git -o -name target -o -name node_modules -o -name .venv \) -prune -o \
        -type f -name '*.sh' -print | sort
    elif [[ -f "$path" ]]; then
      printf '%s\n' "$path"
    elif [[ -d "$path" ]]; then
      find "$path" \
        \( -name .git -o -name target -o -name node_modules -o -name .venv \) -prune -o \
        -type f -name '*.sh' -print | sort
    else
      echo "scan path not found: $path" >&2
      exit 2
    fi
  done
}

rel_path_for() {
  local path="$1"
  if [[ "$path" == "${repo_root}/"* ]]; then
    printf '%s\n' "${path#"${repo_root}/"}"
  else
    printf '%s\n' "$path"
  fi
}

findings=0
checked=0

write_report_record() {
  local tool="$1"
  local path="$2"
  local line="$3"
  local message="$4"

  [[ -n "$report_jsonl" ]] || return 0

  jq -cn \
    --arg tool "$tool" \
    --arg path "$path" \
    --arg line "$line" \
    --arg message "$message" \
    '{tool: $tool, path: $path, line: ($line | tonumber? // null), message: $message}' \
    >>"$report_jsonl"
}

record_finding() {
  local tool="$1"
  local path="$2"
  local line="$3"
  local message="$4"

  findings=$((findings + 1))
  write_report_record "$tool" "$path" "$line" "$message"

  if "$verbose" || [[ "$findings" -le "$max_findings" ]]; then
    if [[ -n "$line" ]]; then
      printf '%s:%s: %s: %s\n' "$path" "$line" "$tool" "$message" >&2
    else
      printf '%s: %s: %s\n' "$path" "$tool" "$message" >&2
    fi
  fi
}

record_bash_syntax_findings() {
  local script_path="$1"
  local rel_path="$2"
  local output exit_code diagnostic

  set +e
  output="$(bash -n "$script_path" 2>&1)"
  exit_code=$?
  set -e

  if [[ "$exit_code" -eq 0 ]]; then
    return 0
  fi

  if [[ -z "$output" ]]; then
    record_finding "bash-n" "$rel_path" "" "syntax validation failed with exit code ${exit_code}"
    return 0
  fi

  while IFS= read -r diagnostic; do
    [[ -n "$diagnostic" ]] || continue
    record_finding "bash-n" "$rel_path" "" "$diagnostic"
  done <<<"$output"
}

record_shellcheck_findings() {
  local script_path="$1"
  local rel_path="$2"
  local output exit_code diagnostic line message

  if ! command -v shellcheck >/dev/null 2>&1; then
    record_finding "shellcheck" "$rel_path" "" "shellcheck is not installed"
    return 0
  fi

  set +e
  output="$(shellcheck -f gcc "$script_path" 2>&1)"
  exit_code=$?
  set -e

  if [[ "$exit_code" -eq 0 ]]; then
    return 0
  fi

  if [[ -z "$output" ]]; then
    record_finding "shellcheck" "$rel_path" "" "shellcheck failed with exit code ${exit_code}"
    return 0
  fi

  while IFS= read -r diagnostic; do
    [[ -n "$diagnostic" ]] || continue
    if [[ "$diagnostic" =~ :([0-9]+):[0-9]+:[[:space:]](.*)$ ]]; then
      line="${BASH_REMATCH[1]}"
      message="${BASH_REMATCH[2]}"
      record_finding "shellcheck" "$rel_path" "$line" "$message"
    else
      record_finding "shellcheck" "$rel_path" "" "$diagnostic"
    fi
  done <<<"$output"
}

while IFS= read -r script_path; do
  [[ -f "$script_path" ]] || continue
  checked=$((checked + 1))
  rel_path="$(rel_path_for "$script_path")"
  record_bash_syntax_findings "$script_path" "$rel_path"
  record_shellcheck_findings "$script_path" "$rel_path"
done < <(find_shell_scripts)

if [[ "$findings" -ne 0 ]]; then
  if ! "$verbose" && [[ "$findings" -gt "$max_findings" ]]; then
    echo "shell hygiene report: omitted $((findings - max_findings)) additional finding(s); rerun with --verbose for full output" >&2
  fi

  if [[ -n "$report_jsonl" ]]; then
    echo "shell hygiene report jsonl: ${report_jsonl}" >&2
  fi

  if "$strict"; then
    echo "shell hygiene check failed: ${findings} finding(s) across ${checked} script(s)" >&2
    exit 1
  fi

  echo "shell hygiene advisory: ${findings} finding(s) across ${checked} script(s); rerun with --strict and explicit paths to fail" >&2
  exit 0
fi

if [[ -n "$report_jsonl" ]]; then
  echo "shell hygiene report jsonl: ${report_jsonl}"
fi
echo "shell hygiene check passed: ${checked} script(s)"
