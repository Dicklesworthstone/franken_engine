#!/usr/bin/env bash
# Third-party scripted verifier for repro.lock bundles (bd-cixqu.14.2).
#
# Consumes a repro.lock, extracts its deterministic replay commands, and
# reruns them in a pinned environment. Direct cargo commands are wrapped with
# rch; gate scripts that already own their rch usage are executed as scripts.

set -euo pipefail

export TZ=UTC
export LC_ALL=C
export LANG=C
export LANGUAGE=C

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ROOT_DIR
cd "${ROOT_DIR}"

readonly REPORT_SCHEMA_VERSION="franken-engine.third-party-repro-lock-verifier-report.v1"
readonly COMPONENT="third_party_repro_lock_verifier"
readonly DEFAULT_REPORT_ROOT="artifacts/third_party_repro_lock_verifier"

lock_path=""
report_path=""
plan_only=0

usage() {
  cat >&2 <<'EOF'
Usage:
  scripts/third_party_repro_lock_verifier.sh --lock <path> [--report <path>] [--plan-only]

Options:
  --lock <path>     Path to repro.lock.
  --report <path>   Optional JSON report path. Defaults under artifacts/.
  --plan-only       Validate and emit the derived replay plan without execution.

Exit codes:
  0  verification passed or plan emitted
  1  replay command failed or lock is invalid
  2  CLI/environment error
EOF
}

json_string_array() {
  jq -Rn '[inputs]' <<<"$1"
}

write_report() {
  local verdict="$1"
  local exit_code="$2"
  local failed_command="$3"
  local commands_json="$4"
  local source_commit="$5"
  local schema_version="$6"
  local determinism_ok="$7"
  local command_count="$8"
  local executed_count="$9"
  local generated_at
  generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  local report_json
  report_json="$(jq -n \
    --arg schema "${REPORT_SCHEMA_VERSION}" \
    --arg component "${COMPONENT}" \
    --arg lock_path "${lock_path}" \
    --arg source_commit "${source_commit}" \
    --arg lock_schema_version "${schema_version}" \
    --arg generated_at_utc "${generated_at}" \
    --arg verdict "${verdict}" \
    --arg failed_command "${failed_command}" \
    --argjson exit_code "${exit_code}" \
    --argjson determinism_ok "${determinism_ok}" \
    --argjson command_count "${command_count}" \
    --argjson executed_count "${executed_count}" \
    --argjson commands "${commands_json}" \
    '{
      schema_version: $schema,
      component: $component,
      generated_at_utc: $generated_at_utc,
      lock_path: $lock_path,
      lock_schema_version: $lock_schema_version,
      source_commit: $source_commit,
      verdict: $verdict,
      exit_code: $exit_code,
      deterministic_policy_ok: $determinism_ok,
      command_count: $command_count,
      executed_count: $executed_count,
      failed_command: (if $failed_command == "" then null else $failed_command end),
      commands: $commands,
      execution_policy: {
        cargo_commands: "wrapped with rch exec and CARGO_INCREMENTAL=0",
        script_commands: "executed with deterministic environment; scripts must own any cargo/rch calls",
        rustflags: "-C linker=cc"
      }
    }')"

  if [[ -n "${report_path}" ]]; then
    mkdir -p "$(dirname "${report_path}")"
    printf '%s\n' "${report_json}" >"${report_path}"
  fi
  printf '%s\n' "${report_json}"
}

requires_rch_for_cargo() {
  local command_text="$1"
  local cargo_regex='(^|[[:space:];(&])cargo[[:space:]]'
  [[ "${command_text}" =~ ${cargo_regex} ]] \
    && [[ "${command_text}" != *"rch exec"* ]]
}

run_locked_command() {
  local command_text="$1"
  if requires_rch_for_cargo "${command_text}"; then
    rch exec -- env CARGO_INCREMENTAL=0 RUSTFLAGS="-C linker=cc" bash -lc "${command_text}"
  else
    env CARGO_INCREMENTAL=0 RUSTFLAGS="-C linker=cc" bash -lc "${command_text}"
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --lock)
      lock_path="${2:-}"
      shift 2
      ;;
    --report)
      report_path="${2:-}"
      shift 2
      ;;
    --plan-only)
      plan_only=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "${lock_path}" ]]; then
  usage
  echo "--lock is required" >&2
  exit 2
fi

if [[ ! -f "${lock_path}" ]]; then
  echo "repro.lock not found: ${lock_path}" >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required" >&2
  exit 2
fi

if [[ -z "${report_path}" ]]; then
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  report_path="${DEFAULT_REPORT_ROOT}/${timestamp}/verification_report.json"
fi

if ! jq empty "${lock_path}" >/dev/null 2>&1; then
  commands_json="[]"
  write_report "fail" 1 "" "${commands_json}" "" "" false 0 0 >/dev/null
  echo "invalid JSON repro.lock: ${lock_path}" >&2
  exit 1
fi

schema_version="$(jq -r '.schema_version // ""' "${lock_path}")"
source_commit="$(jq -r '.source_commit // ""' "${lock_path}")"
determinism_ok="$(jq -r '
  if (.determinism | type) != "object" then
    false
  elif (.determinism.allow_network? == false
        and .determinism.allow_wall_clock? == false
        and .determinism.allow_randomness? == false
        and (.determinism.max_clock_skew_seconds? // 0) == 0) then
    true
  elif (.determinism.mode? == "strict"
        and (.determinism.reproducible_builds? // true) == true) then
    true
  else
    false
  end
' "${lock_path}")"

commands_json="$(jq '
  def string_array(value):
    if (value | type) == "array" then
      [value[] | select(type == "string" and length > 0)]
    else
      []
    end;
  (
    string_array(.replay.command_sequence)
    + string_array(.commands)
    + (if (.commands | type) == "object" and (.commands.verification | type) == "string"
       then [.commands.verification] else [] end)
    + (if (.verification.command | type) == "string"
       then [.verification.command] else [] end)
  )
  | reduce .[] as $cmd ([]; if index($cmd) then . else . + [$cmd] end)
' "${lock_path}")"

command_count="$(jq 'length' <<<"${commands_json}")"

if [[ "${schema_version}" != *"repro"* || "${schema_version}" != *"lock"* ]]; then
  write_report "fail" 1 "" "${commands_json}" "${source_commit}" "${schema_version}" "${determinism_ok}" "${command_count}" 0 >/dev/null
  echo "schema_version is not a repro.lock schema: ${schema_version}" >&2
  exit 1
fi

if [[ "${determinism_ok}" != "true" ]]; then
  write_report "fail" 1 "" "${commands_json}" "${source_commit}" "${schema_version}" false "${command_count}" 0 >/dev/null
  echo "determinism policy is not fail-closed in ${lock_path}" >&2
  exit 1
fi

if [[ "${command_count}" -eq 0 ]]; then
  write_report "fail" 1 "" "${commands_json}" "${source_commit}" "${schema_version}" "${determinism_ok}" 0 0 >/dev/null
  echo "no replay command found in ${lock_path}" >&2
  exit 1
fi

if [[ "${plan_only}" -eq 1 ]]; then
  write_report "planned" 0 "" "${commands_json}" "${source_commit}" "${schema_version}" "${determinism_ok}" "${command_count}" 0
  exit 0
fi

executed_count=0
failed_command=""
while IFS= read -r command_text; do
  if [[ -z "${command_text}" ]]; then
    continue
  fi
  if ! run_locked_command "${command_text}"; then
    failed_command="${command_text}"
    write_report "fail" 1 "${failed_command}" "${commands_json}" "${source_commit}" "${schema_version}" "${determinism_ok}" "${command_count}" "${executed_count}" >/dev/null
    echo "replay command failed: ${command_text}" >&2
    exit 1
  fi
  executed_count=$((executed_count + 1))
done < <(jq -r '.[]' <<<"${commands_json}")

write_report "pass" 0 "" "${commands_json}" "${source_commit}" "${schema_version}" "${determinism_ok}" "${command_count}" "${executed_count}"
