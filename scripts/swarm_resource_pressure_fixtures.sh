#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
governor="${root_dir}/scripts/swarm_resource_governor.sh"
planner="${root_dir}/scripts/swarm_validation_planner.sh"
artifact_root="${SWARM_RESOURCE_PRESSURE_FIXTURE_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-resource-pressure-fixtures}"
run_id="${SWARM_RESOURCE_PRESSURE_FIXTURE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_RESOURCE_PRESSURE_FIXTURE_RUN_DIR:-${artifact_root}/${run_id}}"
bead_id="${SWARM_RESOURCE_PRESSURE_FIXTURE_BEAD_ID:-bd-aq8nn}"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_resource_pressure_fixtures.sh [--output-dir DIR] [--bead-id ID]

Builds deterministic fixture inputs for the swarm resource governor and
validation planner. It does not spawn real CPU, memory, disk, rch, or Agent Mail
pressure. It writes fixtures.json, commands.txt, and report.md.
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
    --bead-id)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      bead_id="$2"
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

mkdir -p "$run_dir"
fixtures_path="${run_dir}/fixtures.json"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
cases_jsonl="${run_dir}/cases.jsonl"
: >"$commands_path"
: >"$cases_jsonl"

sha256_file() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$path" | awk '{print $1}'
  else
    openssl dgst -sha256 "$path" | awk '{print $NF}'
  fi
}

append_command() {
  printf '%s\n' "$1" >>"$commands_path"
}

emit_case() {
  local case_id="$1"
  local component="$2"
  local expected_decision="$3"
  local observed_decision="$4"
  local expected_exit="$5"
  local observed_exit="$6"
  local artifact_path="$7"
  local finding_count="$8"
  local status="pass"

  if [[ "$expected_decision" != "$observed_decision" || "$expected_exit" -ne "$observed_exit" ]]; then
    status="fail"
  fi

  jq -nc \
    --arg case_id "$case_id" \
    --arg component "$component" \
    --arg expected_decision "$expected_decision" \
    --arg observed_decision "$observed_decision" \
    --arg artifact_path "$artifact_path" \
    --arg status "$status" \
    --argjson expected_exit "$expected_exit" \
    --argjson observed_exit "$observed_exit" \
    --argjson finding_count "$finding_count" \
    '{
      case_id: $case_id,
      component: $component,
      expected_decision: $expected_decision,
      observed_decision: $observed_decision,
      expected_exit: $expected_exit,
      observed_exit: $observed_exit,
      finding_count: $finding_count,
      artifact_path: $artifact_path,
      status: $status
    }' >>"$cases_jsonl"
}

base_governor_args=(
  --active-compile-count 1
  --disk-available-bytes 2147483648
  --target-dir /tmp/rch_target_franken_engine_swarm_pressure
  --target-dir-writable true
  --memory-available-bytes 2147483648
  --rch-present true
  --rch-status ok
  --rch-fallback-detected false
  --command-exit-code 0
  --command-failure-kind none
  --ownership-state none
  --dirty-state clean
)

run_governor_case() {
  local case_id="$1"
  local expected_decision="$2"
  local expected_exit="$3"
  shift 3
  local case_dir="${run_dir}/${case_id}"
  local output exit_code observed_decision finding_count decision_path

  mkdir -p "$case_dir"
  append_command "./scripts/swarm_resource_governor.sh --bead-id ${bead_id} --output-dir ${case_dir} ${*}"
  set +e
  output="$("$governor" --bead-id "$bead_id" --output-dir "$case_dir" "$@" 2>&1)"
  exit_code=$?
  set -e

  decision_path="${case_dir}/decision.json"
  if [[ ! -f "$decision_path" ]]; then
    printf '%s\n' "$output" >&2
    observed_decision="missing_artifact"
    finding_count=0
  else
    observed_decision="$(jq -r '.decision' "$decision_path")"
    finding_count="$(jq '.findings | length' "$decision_path")"
  fi
  emit_case "$case_id" "swarm_resource_governor" "$expected_decision" "$observed_decision" "$expected_exit" "$exit_code" "$decision_path" "$finding_count"
}

run_planner_case() {
  local case_id="$1"
  local expected_decision="$2"
  local expected_exit="$3"
  shift 3
  local case_dir="${run_dir}/${case_id}"
  local output exit_code observed_decision finding_count plan_path broad_check_present

  mkdir -p "$case_dir"
  append_command "./scripts/swarm_validation_planner.sh --bead-id ${bead_id} --source-revision smoke-rev --output-dir ${case_dir} ${*}"
  set +e
  output="$(SWARM_VALIDATION_PLANNER_GIT_STATUS_OVERRIDE='' "$planner" --bead-id "$bead_id" --source-revision smoke-rev --output-dir "$case_dir" "$@" 2>&1)"
  exit_code=$?
  set -e

  plan_path="${case_dir}/plan.json"
  if [[ ! -f "$plan_path" ]]; then
    printf '%s\n' "$output" >&2
    observed_decision="missing_artifact"
    finding_count=0
  else
    observed_decision="$(jq -r '.decision' "$plan_path")"
    finding_count="$(jq '(.omitted_commands | length) + (.warnings | length)' "$plan_path")"
    broad_check_present="false"
    if grep -Fq 'cargo check --all-targets' "${case_dir}/commands.txt"; then
      broad_check_present="true"
    fi
    jq --argjson broad_check_present "$broad_check_present" \
      '.fixture_assertions = {broad_check_present: $broad_check_present}' \
      "$plan_path" >"${plan_path}.tmp"
    mv "${plan_path}.tmp" "$plan_path"
  fi
  emit_case "$case_id" "swarm_validation_planner" "$expected_decision" "$observed_decision" "$expected_exit" "$exit_code" "$plan_path" "$finding_count"
}

cpu_args=("${base_governor_args[@]}")
cpu_args[1]=5
run_governor_case "governor_cpu_pressure" "defer" 75 "${cpu_args[@]}"

memory_args=("${base_governor_args[@]}")
memory_args[9]=64
run_governor_case "governor_memory_pressure" "defer" 75 "${memory_args[@]}"

disk_args=("${base_governor_args[@]}")
disk_args[3]=64
run_governor_case "governor_disk_pressure" "fail_closed" 42 "${disk_args[@]}"

target_args=("${base_governor_args[@]}")
target_args[7]=false
run_governor_case "governor_unwritable_target" "fail_closed" 42 "${target_args[@]}"

missing_rch_args=("${base_governor_args[@]}")
missing_rch_args[11]=false
missing_rch_args[13]=missing
run_governor_case "governor_missing_rch" "fail_closed" 42 "${missing_rch_args[@]}"

fallback_args=("${base_governor_args[@]}")
fallback_args[15]=true
run_governor_case "governor_fallback_to_local" "fail_closed" 42 "${fallback_args[@]}"

mail_args=("${base_governor_args[@]}")
mail_args[21]=unknown
run_governor_case "governor_agent_mail_unavailable" "fail_closed" 42 "${mail_args[@]}"

reserved_args=("${base_governor_args[@]}")
reserved_args[21]=overlap
run_governor_case "governor_reserved_overlap" "defer" 75 "${reserved_args[@]}"

stale_proof_args=("${base_governor_args[@]}")
stale_proof_args[17]=7
stale_proof_args[19]=build_failure
run_governor_case "governor_stale_proof_evidence" "fail_closed" 42 "${stale_proof_args[@]}"

run_planner_case "planner_unknown_path_mapping" "fail_closed" 42 --changed-path unknown/path.rs
run_planner_case "planner_script_only" "admit" 0 --changed-path scripts/swarm_resource_governor.sh
run_planner_case "planner_package_fallback" "admit_narrow" 0 --changed-path crates/franken-engine/src/proof_artifact.rs

case_count="$(jq -s 'length' "$cases_jsonl")"
failure_count="$(jq -s '[.[] | select(.status != "pass")] | length' "$cases_jsonl")"
commands_sha256="$(sha256_file "$commands_path")"

jq -n \
  --arg schema_version "franken-engine.swarm-resource-pressure-fixtures.v1" \
  --arg bead_id "$bead_id" \
  --arg commands_path "$commands_path" \
  --arg commands_sha256 "$commands_sha256" \
  --arg report_path "$report_path" \
  --argjson case_count "$case_count" \
  --argjson failure_count "$failure_count" \
  --slurpfile cases "$cases_jsonl" \
  '{
    schema_version: $schema_version,
    bead_id: $bead_id,
    status: (if $failure_count == 0 then "pass" else "fail" end),
    case_count: $case_count,
    failure_count: $failure_count,
    cases: ($cases | sort_by(.case_id)),
    artifact_paths: {
      commands_txt: $commands_path,
      report_md: $report_path
    },
    generated_artifacts: [
      {path: $commands_path, sha256: $commands_sha256, role: "fixture_command_transcript"}
    ]
  }' >"$fixtures_path"

{
  printf '# Swarm Resource Pressure Fixtures\n\n'
  printf -- "- Cases: \`%s\`\n" "$case_count"
  printf -- "- Failures: \`%s\`\n\n" "$failure_count"
  jq -r '.cases[] | "- `" + .case_id + "`: expected `" + .expected_decision + "`, observed `" + .observed_decision + "`, status `" + .status + "`"' "$fixtures_path"
} >"$report_path"

printf 'swarm_resource_pressure_fixtures=%s\n' "$fixtures_path"
printf 'swarm_resource_pressure_report=%s\n' "$report_path"

if [[ "$failure_count" -ne 0 ]]; then
  exit 42
fi
