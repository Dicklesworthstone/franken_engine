#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
component="phase_a_exit_gate"
bead_id="bd-1csl"
artifact_root="${PHASE_A_GATE_ARTIFACT_ROOT:-artifacts/phase_a_exit_gate}"
skip_subgates="${PHASE_A_GATE_SKIP_SUBGATES:-0}"
run_subgates_when_blocked="${PHASE_A_GATE_RUN_SUBGATES_WHEN_BLOCKED:-0}"

trace_prefix="trace-phase-a-gate"
decision_prefix="decision-phase-a-gate"
policy_id="policy-phase-a-exit-gate-v1"

timestamp="$(date -u +%Y%m%dT%H%M%S%NZ)"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
logs_dir="${run_dir}/logs"

trace_id="${trace_prefix}-${timestamp}"
decision_id="${decision_prefix}-${timestamp}"

mkdir -p "$logs_dir"

dependency_ids=(
  "bd-ntq"
  "bd-3vk"
  "bd-383"
  "bd-1pi9"
  "bd-1b70"
  "bd-3rjg"
  "bd-1gfn"
  "bd-2mds"
)

declare -a commands_run=()
declare -a command_logs=()
declare -a unmet_dependencies=()
declare -a dependency_snapshots=()
failed_command=""
failed_log_path=""
manifest_written=false

test262_manifest_path=""
parser_oracle_manifest_path=""

json_escape() {
  local input="$1"
  input="${input//\\/\\\\}"
  input="${input//\"/\\\"}"
  input="${input//$'\n'/\\n}"
  printf '%s' "$input"
}

run_step() {
  local command_text="$1"
  shift
  local step_index="${#commands_run[@]}"
  local log_path="${logs_dir}/step_$(printf '%02d' "$step_index").log"
  commands_run+=("$command_text")
  command_logs+=("$log_path")

  echo "==> $command_text"
  if "$@" > >(tee "$log_path") 2>&1; then
    return 0
  fi

  failed_command="$command_text"
  failed_log_path="$log_path"
  return 1
}

capture_subgate_artifacts() {
  local log_path="$1"
  local key="$2"
  local pattern="$3"
  local value

  value="$(rg -o "$pattern" "$log_path" | tail -n 1 | sed "s/.*: //")"
  if [[ -z "$value" ]]; then
    return 0
  fi

  if [[ "$key" == "test262" ]]; then
    test262_manifest_path="$value"
  elif [[ "$key" == "parser_oracle" ]]; then
    parser_oracle_manifest_path="$value"
  fi
}

check_dependencies() {
  local dep status title dependency_index_path dependency_json
  local -a list_args=()

  unmet_dependencies=()
  dependency_snapshots=()

  for dep in "${dependency_ids[@]}"; do
    list_args+=(--id "$dep")
  done

  dependency_index_path="${logs_dir}/dependency_statuses.json"
  if ! br list --all --limit 0 --json "${list_args[@]}" >"$dependency_index_path" 2>/dev/null; then
    for dep in "${dependency_ids[@]}"; do
      unmet_dependencies+=("${dep}=unknown")
      dependency_snapshots+=("${dep}|unknown|lookup_failed")
    done
    return 0
  fi

  for dep in "${dependency_ids[@]}"; do
    dependency_json="$(jq -c --arg dep "$dep" 'map(select(.id == $dep)) | .[0] // empty' "$dependency_index_path")"
    if [[ -z "$dependency_json" ]]; then
      status="unknown"
      title="lookup_failed"
      unmet_dependencies+=("${dep}=unknown")
    else
      status="$(jq -r '.status // "unknown"' <<<"$dependency_json")"
      title="$(jq -r '.title // ""' <<<"$dependency_json")"
      if [[ "$status" != "closed" ]]; then
        unmet_dependencies+=("${dep}=${status}")
      fi
    fi
    dependency_snapshots+=("${dep}|${status}|${title}")
  done
}

run_subgates_for_mode() {
  if [[ "$skip_subgates" == "1" ]]; then
    echo "PHASE_A_GATE_SKIP_SUBGATES=1 -> skipping sub-gate command execution"
    return 0
  fi

  case "$mode" in
    check)
      run_step "./scripts/run_test262_es2020_gate.sh check" ./scripts/run_test262_es2020_gate.sh check
      capture_subgate_artifacts "${command_logs[$(( ${#command_logs[@]} - 1 ))]}" "test262" "test262 gate run manifest: .*"

      run_step "./scripts/run_parser_oracle_gate.sh check" ./scripts/run_parser_oracle_gate.sh check
      capture_subgate_artifacts "${command_logs[$(( ${#command_logs[@]} - 1 ))]}" "parser_oracle" "parser oracle gate manifest: .*"
      ;;
    test)
      run_step "./scripts/run_test262_es2020_gate.sh test" ./scripts/run_test262_es2020_gate.sh test
      capture_subgate_artifacts "${command_logs[$(( ${#command_logs[@]} - 1 ))]}" "test262" "test262 gate run manifest: .*"

      run_step "./scripts/run_parser_oracle_gate.sh test" ./scripts/run_parser_oracle_gate.sh test
      capture_subgate_artifacts "${command_logs[$(( ${#command_logs[@]} - 1 ))]}" "parser_oracle" "parser oracle gate manifest: .*"
      ;;
    clippy)
      run_step "./scripts/run_test262_es2020_gate.sh clippy" ./scripts/run_test262_es2020_gate.sh clippy
      capture_subgate_artifacts "${command_logs[$(( ${#command_logs[@]} - 1 ))]}" "test262" "test262 gate run manifest: .*"

      run_step "./scripts/run_parser_oracle_gate.sh clippy" ./scripts/run_parser_oracle_gate.sh clippy
      capture_subgate_artifacts "${command_logs[$(( ${#command_logs[@]} - 1 ))]}" "parser_oracle" "parser oracle gate manifest: .*"
      ;;
    ci)
      run_step "./scripts/run_test262_es2020_gate.sh ci" ./scripts/run_test262_es2020_gate.sh ci
      capture_subgate_artifacts "${command_logs[$(( ${#command_logs[@]} - 1 ))]}" "test262" "test262 gate run manifest: .*"

      run_step "./scripts/run_parser_oracle_gate.sh ci" ./scripts/run_parser_oracle_gate.sh ci
      capture_subgate_artifacts "${command_logs[$(( ${#command_logs[@]} - 1 ))]}" "parser_oracle" "parser oracle gate manifest: .*"
      ;;
    *)
      echo "usage: $0 [check|test|clippy|ci]" >&2
      return 2
      ;;
  esac
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome error_code_json failed_log_json idx comma dep_idx dep_count dep comma_dep

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 && "${#unmet_dependencies[@]}" -eq 0 ]]; then
    outcome="pass"
    error_code_json="null"
  else
    outcome="fail"
    error_code_json='"FE-PHASE-A-GATE-1001"'
  fi

  if [[ -n "$failed_log_path" ]]; then
    failed_log_json="\"$(json_escape "$failed_log_path")\""
  else
    failed_log_json="null"
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  cat >"$events_path" <<JSONL
{"trace_id":"${trace_id}","decision_id":"${decision_id}","policy_id":"${policy_id}","component":"${component}","event":"phase_a_gate_completed","outcome":"${outcome}","error_code":${error_code_json}}
JSONL

  {
    echo "{";
    echo '  "schema_version": "franken-engine.phase-a-exit-gate.run-manifest.v1",';
    echo "  \"component\": \"${component}\",";
    echo "  \"bead_id\": \"${bead_id}\",";
    echo "  \"mode\": \"${mode}\",";
    echo "  \"skip_subgates\": ${skip_subgates},";
    echo "  \"run_subgates_when_blocked\": ${run_subgates_when_blocked},";
    echo "  \"trace_id\": \"${trace_id}\",";
    echo "  \"decision_id\": \"${decision_id}\",";
    echo "  \"policy_id\": \"${policy_id}\",";
    echo "  \"generated_at_utc\": \"${timestamp}\",";
    echo "  \"toolchain\": \"${toolchain}\",";
    echo "  \"outcome\": \"${outcome}\",";
    if [[ -n "$failed_command" ]]; then
      echo "  \"failed_command\": \"$(json_escape "$failed_command")\",";
    fi
    echo "  \"failed_log\": ${failed_log_json},";
    echo '  "dependency_statuses": [';
    dep_count="${#dependency_snapshots[@]}"
    for dep_idx in "${!dependency_snapshots[@]}"; do
      dep="${dependency_snapshots[$dep_idx]}"
      IFS='|' read -r dep_id dep_status dep_title <<<"$dep"
      comma_dep=","
      if [[ "$dep_idx" == "$((dep_count - 1))" ]]; then
        comma_dep=""
      fi
      echo "    {\"id\":\"$(json_escape "$dep_id")\",\"status\":\"$(json_escape "$dep_status")\",\"title\":\"$(json_escape "$dep_title")\"}${comma_dep}"
    done
    echo '  ],';
    echo '  "unmet_dependencies": [';
    for idx in "${!unmet_dependencies[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#unmet_dependencies[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(json_escape "${unmet_dependencies[$idx]}")\"${comma}"
    done
    echo '  ],';
    echo '  "subgate_artifacts": {';
    if [[ -n "$test262_manifest_path" ]]; then
      echo "    \"test262_manifest\": \"$(json_escape "$test262_manifest_path")\",";
    else
      echo '    "test262_manifest": null,';
    fi
    if [[ -n "$parser_oracle_manifest_path" ]]; then
      echo "    \"parser_oracle_manifest\": \"$(json_escape "$parser_oracle_manifest_path")\"";
    else
      echo '    "parser_oracle_manifest": null';
    fi
    echo '  },';
    echo '  "commands": [';
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(json_escape "${commands_run[$idx]}")\"${comma}"
    done
    echo '  ],';
    echo '  "command_logs": [';
    for idx in "${!command_logs[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#command_logs[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(json_escape "${command_logs[$idx]}")\"${comma}"
    done
    echo '  ],';
    echo '  "operator_verification": [';
    echo "    \"cat $(json_escape "$manifest_path")\",";
    echo "    \"cat $(json_escape "$events_path")\",";
    echo "    \"cat $(json_escape "$commands_path")\",";
    echo "    \"PHASE_A_GATE_SKIP_SUBGATES=1 ./scripts/run_phase_a_exit_gate.sh check\",";
    echo "    \"PHASE_A_GATE_RUN_SUBGATES_WHEN_BLOCKED=1 ./scripts/run_phase_a_exit_gate.sh check\",";
    echo "    \"./scripts/run_phase_a_exit_gate.sh ci\"";
    echo '  ]';
    echo "}";
  } >"$manifest_path"

  echo "phase-a gate run manifest: ${manifest_path}"
  echo "phase-a gate events: ${events_path}"
}

main() {
  check_dependencies
  if [[ "${#unmet_dependencies[@]}" -gt 0 && "$run_subgates_when_blocked" != "1" ]]; then
    echo "Phase-A gate blocked by unresolved dependencies (sub-gates skipped; set PHASE_A_GATE_RUN_SUBGATES_WHEN_BLOCKED=1 to force evidence collection):" >&2
    printf '  - %s\n' "${unmet_dependencies[@]}" >&2
    return 1
  fi

  run_subgates_for_mode

  check_dependencies
  if [[ "${#unmet_dependencies[@]}" -gt 0 ]]; then
    echo "Phase-A gate blocked by unresolved dependencies:" >&2
    printf '  - %s\n' "${unmet_dependencies[@]}" >&2
    return 1
  fi

  return 0
}

trap 'write_manifest $?' EXIT
main
