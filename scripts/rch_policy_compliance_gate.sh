#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${RCH_POLICY_COMPLIANCE_ARTIFACT_ROOT:-artifacts/rch_policy_compliance_gate}"
run_id="${RCH_POLICY_COMPLIANCE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${RCH_POLICY_COMPLIANCE_RUN_DIR:-${artifact_root}/${run_id}}"
scope_file=""
declare -a requested_paths=()

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/rch_policy_compliance_gate.sh [--output-dir DIR] [--scope-file FILE] [PATH ...]

Scans shell scripts and operator docs for heavy Cargo commands that are not
routed through:

  rch exec -- env CARGO_TARGET_DIR=... cargo <heavy-subcommand>

Violations are emitted to diagnostics.json and report.md. The gate exits 42 when
violations are found.

Same-line or immediately preceding-line waivers are allowed only in this form:

  # rch-policy-waive: <violation_kind> reason=<specific reason>

Violation kinds:
  bare_cargo
  missing_target_dir
  local_fallback_not_rejected
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --output-dir)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      run_dir="$2"
      shift 2
      ;;
    --scope-file)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      scope_file="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      while [[ "$#" -gt 0 ]]; do
        requested_paths+=("$1")
        shift
      done
      ;;
    -*)
      printf 'unknown option: %s\n' "$1" >&2
      usage
      exit 64
      ;;
    *)
      requested_paths+=("$1")
      shift
      ;;
  esac
done

mkdir -p "$run_dir"
diagnostics_path="${run_dir}/diagnostics.json"
report_path="${run_dir}/report.md"
commands_path="${run_dir}/commands.txt"
violations_jsonl="${run_dir}/violations.jsonl"
waivers_jsonl="${run_dir}/waivers.jsonl"
: >"$violations_jsonl"
: >"$waivers_jsonl"

printf './scripts/rch_policy_compliance_gate.sh' >"$commands_path"
if [[ -n "$scope_file" ]]; then
  printf ' --scope-file %q' "$scope_file" >>"$commands_path"
fi
for path in "${requested_paths[@]}"; do
  printf ' %q' "$path" >>"$commands_path"
done
printf '\n' >>"$commands_path"

repo_relative_path() {
  local path="$1"
  local rel_path
  if [[ "$path" = /* ]]; then
    rel_path="$(realpath --relative-to="$root_dir" "$path")"
    if [[ "$rel_path" == ../* ]]; then
      realpath "$path"
    else
      printf '%s\n' "$rel_path"
    fi
  else
    printf '%s\n' "${path#./}"
  fi
}

default_scope() {
  git -C "$root_dir" ls-files \
    'README.md' \
    'docs/*.md' \
    'docs/*.json' \
    'scripts/*.sh' \
    'scripts/e2e/*.sh' |
    grep -Ev '(^scripts/rch_policy_compliance_gate\.sh$|^scripts/e2e/rch_policy_compliance_gate_smoke\.sh$)'
}

collect_scope() {
  if [[ -n "$scope_file" ]]; then
    if [[ ! -f "$scope_file" ]]; then
      printf 'scope file not found: %s\n' "$scope_file" >&2
      exit 64
    fi
    sed '/^[[:space:]]*$/d' "$scope_file"
    return
  fi

  if [[ "${#requested_paths[@]}" -gt 0 ]]; then
    printf '%s\n' "${requested_paths[@]}"
    return
  fi

  default_scope
}

waiver_reason() {
  local kind="$1"
  local current_line="$2"
  local previous_line="$3"
  local candidate=""
  local marker="rch-policy-waive: ${kind} reason="

  if [[ "$current_line" == *"$marker"* ]]; then
    candidate="$current_line"
  elif [[ "$previous_line" == *"$marker"* ]]; then
    candidate="$previous_line"
  else
    return 1
  fi

  candidate="${candidate#*"$marker"}"
  candidate="${candidate%%#*}"
  candidate="${candidate%"${candidate##*[![:space:]]}"}"
  candidate="${candidate#"${candidate%%[![:space:]]*}"}"
  if [[ "${#candidate}" -lt 8 ]]; then
    return 1
  fi
  printf '%s\n' "$candidate"
}

emit_waiver() {
  local file="$1"
  local line_no="$2"
  local kind="$3"
  local reason="$4"

  jq -nc \
    --arg file "$file" \
    --argjson line "$line_no" \
    --arg kind "$kind" \
    --arg reason "$reason" \
    '{file: $file, line: $line, kind: $kind, reason: $reason}' >>"$waivers_jsonl"
}

emit_violation() {
  local file="$1"
  local line_no="$2"
  local kind="$3"
  local command="$4"
  local remediation="$5"

  jq -nc \
    --arg file "$file" \
    --argjson line "$line_no" \
    --arg kind "$kind" \
    --arg command "$command" \
    --arg remediation "$remediation" \
    '{file: $file, line: $line, kind: $kind, command: $command, remediation: $remediation}' >>"$violations_jsonl"
}

record_or_waive() {
  local file="$1"
  local line_no="$2"
  local kind="$3"
  local line="$4"
  local previous_line="$5"
  local remediation="$6"
  local reason

  if reason="$(waiver_reason "$kind" "$line" "$previous_line")"; then
    emit_waiver "$file" "$line_no" "$kind" "$reason"
    return
  fi

  emit_violation "$file" "$line_no" "$kind" "$line" "$remediation"
}

function_body() {
  local function_name="$1"
  local path="$2"

  awk -v fn="$function_name" '
    function brace_delta(line, tmp, opens, closes) {
      tmp = line
      opens = gsub(/\{/, "{", tmp)
      tmp = line
      closes = gsub(/\}/, "}", tmp)
      return opens - closes
    }
    {
      if (!in_body && ($0 ~ "^[[:space:]]*" fn "[[:space:]]*\\(\\)[[:space:]]*\\{" || $0 ~ "^[[:space:]]*function[[:space:]]+" fn "[[:space:]]*\\{")) {
        in_body = 1
      }
      if (in_body) {
        print
        depth += brace_delta($0)
        if (depth <= 0 && $0 ~ /\}/) {
          exit
        }
      }
    }
  ' "$path"
}

trusted_rch_wrappers() {
  local path="$1"
  local candidate body wrapper
  local -a direct_candidates=(
    run_rch
    run_rch_cargo
    rch_cargo
    run_remote_cargo
    cargo_via_rch
  )
  local -a passthrough_candidates=(
    run_step
    run_rch_step
    run_remote_step
    run_cargo_step
  )
  local -a trusted=()

  for candidate in "${direct_candidates[@]}"; do
    body="$(function_body "$candidate" "$path")"
    [[ -n "$body" ]] || continue
    [[ "$body" == *"exec -- env"* ]] || continue
    [[ "$body" == *"CARGO_TARGET_DIR="* ]] || continue
    if [[ "$body" == *"\"\$@\""* || "$body" == *" \$@"* ]]; then
      trusted+=("$candidate")
    fi
  done

  for candidate in "${passthrough_candidates[@]}"; do
    body="$(function_body "$candidate" "$path")"
    [[ -n "$body" ]] || continue
    for wrapper in "${trusted[@]}"; do
      if [[ "$body" == *"${wrapper} \"\$@\""* || "$body" == *"${wrapper} \$@"* ]]; then
        trusted+=("$candidate")
        break
      fi
    done
  done

  printf '%s\n' "${trusted[@]}" | sort -u
}

line_starts_with_wrapper() {
  local line="$1"
  shift
  local wrapper

  for wrapper in "$@"; do
    if [[ "$line" =~ ^[[:space:]]*${wrapper}([[:space:]]|$) ]]; then
      return 0
    fi
  done
  return 1
}

trusted_wrapper_cargo_context() {
  local line="$1"
  local previous_line="$2"
  shift 2

  line_starts_with_wrapper "$line" "$@" && return 0
  if [[ "$previous_line" =~ \\[[:space:]]*$ ]] && line_starts_with_wrapper "$previous_line" "$@"; then
    return 0
  fi

  return 1
}

local_fallback_rejected_line() {
  local line="$1"

  if [[ "$line" =~ (reject|refus|fail|scan|detect|marker|exit[[:space:]]+[1242]|return[[:space:]]+1) ]]; then
    return 0
  fi
  if [[ "$line" =~ (no[[:space:]]+local[[:space:]-]*fallback|without[[:space:]]+local[[:space:]-]*fallback|must[[:space:]]+not[[:space:]]+fall[[:space:]]+back|never[[:space:]]+fall[[:space:]]+back) ]]; then
    return 0
  fi

  return 1
}

scan_file() {
  local path="$1"
  local rel_path scan_path line_no line previous_line previous_previous_line cargo_context
  local -a trusted_wrappers=()

  rel_path="$(repo_relative_path "$path")"
  if [[ "$rel_path" = /* ]]; then
    scan_path="$rel_path"
  else
    scan_path="${root_dir}/${rel_path}"
  fi

  if [[ ! -f "$scan_path" ]]; then
    emit_violation "$rel_path" 0 "missing_file" "$rel_path" "Remove the stale path from the scope or restore the referenced file."
    return
  fi

  mapfile -t trusted_wrappers < <(trusted_rch_wrappers "$scan_path")

  line_no=0
  previous_line=""
  previous_previous_line=""
  while IFS= read -r line || [[ -n "$line" ]]; do
    line_no=$((line_no + 1))
    cargo_context="${previous_previous_line} ${previous_line} ${line}"

    if [[ "$line" =~ (^|[[:space:];|&])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
      if [[ "${#trusted_wrappers[@]}" -gt 0 ]] && trusted_wrapper_cargo_context "$line" "$previous_line" "${trusted_wrappers[@]}"; then
        previous_previous_line="$previous_line"
        previous_line="$line"
        continue
      fi

      if [[ "$cargo_context" == *"rch exec -- env"* && "$cargo_context" == *"CARGO_TARGET_DIR="* ]]; then
        previous_previous_line="$previous_line"
        previous_line="$line"
        continue
      fi

      if [[ "$cargo_context" == *"rch exec --"* ]]; then
        record_or_waive \
          "$rel_path" \
          "$line_no" \
          "missing_target_dir" \
          "$line" \
          "$previous_line" \
          "Route heavy Cargo through 'rch exec -- env CARGO_TARGET_DIR=... cargo ...'."
      else
        record_or_waive \
          "$rel_path" \
          "$line_no" \
          "bare_cargo" \
          "$line" \
          "$previous_line" \
          "Route heavy Cargo through rch with an explicit off-repo CARGO_TARGET_DIR, or add a narrow waiver for a lightweight example."
      fi
    fi

    if [[ "$line" =~ (falling[[:space:]]+back[[:space:]]+to[[:space:]]+local|local[[:space:]-]*fallback|running[[:space:]]+locally) ]]; then
      if local_fallback_rejected_line "$line"; then
        previous_line="$line"
        continue
      fi
      record_or_waive \
        "$rel_path" \
        "$line_no" \
        "local_fallback_not_rejected" \
        "$line" \
        "$previous_line" \
        "Treat rch local fallback as a gate failure for heavy commands."
    fi

    previous_previous_line="$previous_line"
    previous_line="$line"
  done <"$scan_path"
}

mapfile -t scope_paths < <(collect_scope | sed '/^[[:space:]]*$/d' | sort -u)

for path in "${scope_paths[@]}"; do
  scan_file "$path"
done

violation_count="$(jq -s 'length' "$violations_jsonl")"
waiver_count="$(jq -s 'length' "$waivers_jsonl")"
status="pass"
exit_code=0
if [[ "$violation_count" -ne 0 ]]; then
  status="fail"
  exit_code=42
fi

# shellcheck disable=SC2094
jq -n \
  --arg schema_version "franken-engine.rch-policy-compliance-gate.v1" \
  --arg status "$status" \
  --arg diagnostics_path "$diagnostics_path" \
  --arg report_path "$report_path" \
  --slurpfile violations "$violations_jsonl" \
  --slurpfile waivers "$waivers_jsonl" \
  --argjson checked_files "$(printf '%s\n' "${scope_paths[@]}" | jq -R . | jq -s .)" \
  --argjson violation_count "$violation_count" \
  --argjson waiver_count "$waiver_count" \
  '{
    schema_version: $schema_version,
    status: $status,
    checked_files: $checked_files,
    checked_file_count: ($checked_files | length),
    violation_count: $violation_count,
    waiver_count: $waiver_count,
    violations: $violations,
    waivers: $waivers,
    remediation: [
      "Use rch exec -- env CARGO_TARGET_DIR=... cargo ... for heavy build/check/test/clippy/bench/run commands.",
      "Reject rch local fallback markers instead of continuing locally.",
      "Use rch-policy-waive comments only for lightweight examples, and include a specific reason."
    ],
    artifact_paths: {
      diagnostics_json: $diagnostics_path,
      report_md: $report_path
    }
  }' >"$diagnostics_path"

{
  printf '# RCH Policy Compliance Gate\n\n'
  printf -- "- Status: \`%s\`\n" "$status"
  printf -- "- Checked files: \`%s\`\n" "${#scope_paths[@]}"
  printf -- "- Violations: \`%s\`\n" "$violation_count"
  printf -- "- Waivers: \`%s\`\n\n" "$waiver_count"
  if [[ "$violation_count" -eq 0 ]]; then
    printf 'No rch policy violations were found.\n'
  else
    printf '## Violations\n\n'
    jq -r '.violations[] | "- `\(.kind)` at `\(.file):\(.line)`: \(.remediation)"' "$diagnostics_path"
  fi
} >"$report_path"

printf 'rch_policy_compliance_diagnostics=%s\n' "$diagnostics_path"
printf 'rch_policy_compliance_report=%s\n' "$report_path"

exit "$exit_code"
