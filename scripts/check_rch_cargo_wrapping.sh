#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'USAGE'
usage: scripts/check_rch_cargo_wrapping.sh [--strict] [--verbose] [--max-findings <n>] [--root <repo>] [path ...]

Scans shell scripts for executable Cargo commands that are not routed through an
rch wrapper. This is a text-only conformance check; it does not run Cargo.

Default mode reports a capped finding sample and exits successfully so legacy
script debt can be surveyed without blocking unrelated work. Use --strict for
CI-style failure, and --verbose to print every finding.

Allowed patterns:
  - commands inside an rch exec continuation block
  - lines invoking helper wrappers such as run_rch
  - comments, echoes, printf fixtures, grep/rg/jq assertions, and here-doc bodies
  - lines annotated with: rch-cargo-allow
USAGE
}

strict=false
verbose=false
max_findings=50
explicit_scan=false
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
      explicit_scan=true
      scan_roots+=("$1")
      shift
      ;;
  esac
done

if [[ ${#scan_roots[@]} -eq 0 ]]; then
  scan_roots=("scripts" "examples")
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

find_candidate_shell_scripts() {
  find_shell_scripts | xargs -r grep -lE 'cargo[[:space:]]+(check|test|clippy|fmt|build|run)' || true
}

find_candidate_cargo_lines() {
  find_shell_scripts | xargs -r grep -nE 'cargo[[:space:]]+(check|test|clippy|fmt|build|run)' || true
}

is_ignorable_line() {
  local line="$1"
  [[ "$line" =~ ^[[:space:]]*$ ]] && return 0
  [[ "$line" =~ ^[[:space:]]*# ]] && return 0
  [[ "$line" == *"rch-cargo-allow"* ]] && return 0
  [[ "$line" =~ ^[[:space:]]*(echo|printf|grep|rg|jq|sed|awk|cat)[[:space:]] ]] && return 0
  [[ "$line" == *"forbidden"* && "$line" == *"cargo "* ]] && return 0
  [[ "$line" == *"fixture"* && "$line" == *"cargo "* ]] && return 0
  [[ "$line" == *"expected"* && "$line" == *"cargo "* ]] && return 0
  [[ "$line" == *"command:"* && "$line" == *"cargo "* ]] && return 0
  return 1
}

starts_heredoc() {
  local line="$1"
  if [[ "$line" =~ \<\<[\'\"]?([A-Za-z_][A-Za-z0-9_]*)[\'\"]? ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
    return 0
  fi
  return 1
}

starts_rch_continuation() {
  local line="$1"
  [[ "$line" == *"rch exec"* ]] && return 0
  [[ "$line" == *'RCH_BIN'* && "$line" == *" exec"* ]] && return 0
  # shellcheck disable=SC2016 # Literal fixture/pattern match, not expansion.
  [[ "$line" == *'${RCH_BIN}'* && "$line" == *" exec"* ]] && return 0
  # shellcheck disable=SC2016 # Literal fixture/pattern match, not expansion.
  [[ "$line" == *'"$RCH_BIN" exec'* ]] && return 0
  return 1
}

contains_wrapped_cargo() {
  local line="$1"
  [[ "$line" == *"run_rch cargo "* ]] && return 0
  [[ "$line" == *"run_rch_cargo"* ]] && return 0
  [[ "$line" == *"remote batch via rch"* ]] && return 0
  return 1
}

contains_cargo_command() {
  local line="$1"
  local normalized="$line"
  normalized="${normalized//;/ }"
  normalized="${normalized//\(/ }"
  normalized="${normalized//\)/ }"
  normalized="${normalized//&/ }"
  normalized="${normalized//\|/ }"

  case " ${normalized} " in
    *" cargo check "*) # rch-cargo-allow: checker pattern, not executable Cargo
      return 0
      ;;
    *" cargo test "*) # rch-cargo-allow: checker pattern, not executable Cargo
      return 0
      ;;
    *" cargo clippy "*) # rch-cargo-allow: checker pattern, not executable Cargo
      return 0
      ;;
    *" cargo fmt "*) # rch-cargo-allow: checker pattern, not executable Cargo
      return 0
      ;;
    *" cargo build "*) # rch-cargo-allow: checker pattern, not executable Cargo
      return 0
      ;;
    *" cargo run "*) # rch-cargo-allow: checker pattern, not executable Cargo
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

violations=0

record_violation() {
  local rel_path="$1"
  local line_no="$2"
  violations=$((violations + 1))

  if "$verbose" || [[ "$violations" -le "$max_findings" ]]; then
    printf '%s:%s: bare Cargo command must be routed through rch exec or marked as a fixture\n' \
      "$rel_path" "$line_no" >&2
  fi
}

report_violation_summary() {
  if [[ "$violations" -ne 0 ]]; then
    if ! "$verbose" && [[ "$violations" -gt "$max_findings" ]]; then
      echo "rch cargo wrapping report: omitted $((violations - max_findings)) additional finding(s); rerun with --verbose for full output" >&2
    fi

    if "$strict"; then
      echo "rch cargo wrapping check failed: ${violations} violation(s)" >&2
      exit 1
    fi

    echo "rch cargo wrapping report: ${violations} violation(s); rerun with --strict and explicit paths to fail" >&2
    exit 0
  fi

  echo "rch cargo wrapping check passed"
  exit 0
}

if ! "$explicit_scan"; then
  while IFS= read -r match; do
    script_path="${match%%:*}"
    rest="${match#*:}"
    line_no="${rest%%:*}"
    line="${rest#*:}"

    is_ignorable_line "$line" && continue
    contains_wrapped_cargo "$line" && continue
    starts_rch_continuation "$line" && continue

    rel_path="${script_path#"${repo_root}"/}"
    record_violation "$rel_path" "$line_no"
  done < <(find_candidate_cargo_lines)

  report_violation_summary
fi

while IFS= read -r script_path; do
  [[ -f "$script_path" ]] || continue

  line_no=0
  heredoc_end=""
  in_rch_block=false
  while IFS= read -r line || [[ -n "$line" ]]; do
    line_no=$((line_no + 1))

    if [[ -n "$heredoc_end" ]]; then
      if [[ "$line" == "$heredoc_end" ]]; then
        heredoc_end=""
      fi
      continue
    fi

    if "$in_rch_block"; then
      [[ "$line" =~ \\[[:space:]]*$ ]] || in_rch_block=false
      continue
    fi

    if heredoc_marker="$(starts_heredoc "$line")"; then
      heredoc_end="$heredoc_marker"
      continue
    fi

    if starts_rch_continuation "$line"; then
      [[ "$line" =~ \\[[:space:]]*$ ]] && in_rch_block=true
      continue
    fi

    is_ignorable_line "$line" && continue
    contains_wrapped_cargo "$line" && continue

    if contains_cargo_command "$line"; then
      rel_path="${script_path#"${repo_root}"/}"
      record_violation "$rel_path" "$line_no"
    fi
  done < "$script_path"
done < <(find_candidate_shell_scripts)

report_violation_summary
