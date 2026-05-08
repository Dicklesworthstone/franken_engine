#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_root="${SWARM_BENCHMARK_RUNBOOK_TRUTH_GATE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-benchmark-runbook-truth-gate}"
run_id="${SWARM_BENCHMARK_RUNBOOK_TRUTH_GATE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_BENCHMARK_RUNBOOK_TRUTH_GATE_RUN_DIR:-${artifact_root}/${run_id}}"
bead_id="${SWARM_BENCHMARK_RUNBOOK_TRUTH_GATE_BEAD_ID:-bd-k2prt}"
source_revision="${SWARM_BENCHMARK_RUNBOOK_TRUTH_GATE_SOURCE_REVISION:-}"
mode="${1:-help}"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_benchmark_runbook_truth_gate.sh [MODE]

Validate that benchmark surfaces follow truth contracts and do not perform
forbidden mutations or operations outside their advisory scope.

Modes:
  check      Validate gate structure and required files
  selftest   Run lightweight truth validation
  ci         Full truth gate validation
  help       Show this help

Truth gate rejects claims that benchmark surfaces:
  - Execute Cargo/RCH themselves
  - Mutate beads or reservations
  - Change queue policy
  - Replace operator status reports
  - Perform live mutations outside advisory scope

Validation checks:
  - Mutation policy compliance in producer scripts
  - Advisory-only operation verification
  - Forbidden operation detection
  - Contract compliance validation

Artifacts:
  swarm_benchmark_runbook_truth_validation_report.json
  mutation_policy_verification.json
  validation_commands_results.json
  events.jsonl
  commands.txt

Exit codes:
  0  truth gate passed
  42 truth gate rejection (forbidden operation detected)
  64 invalid argument or malformed contract
EOF
}

log_event() {
  local event_type="$1"
  local message="$2"
  local timestamp
  timestamp="$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
  echo "{\"timestamp\":\"$timestamp\",\"event_type\":\"$event_type\",\"message\":\"$message\",\"bead_id\":\"$bead_id\"}" >> "$run_dir/events.jsonl"
}

check_script_mutations() {
  local script_path="$1"
  local script_name
  script_name="$(basename "$script_path")"
  local violations=()

  log_event "mutation_check_start" "Checking $script_name for forbidden mutations"

  # Check for forbidden Cargo/RCH execution
  if grep -q "cargo " "$script_path" 2>/dev/null || grep -q "\brch\b" "$script_path" 2>/dev/null; then
    if ! grep -q "advisory_only.*true\|proof_only.*true" "$script_path" 2>/dev/null; then
      violations+=("executes_cargo_or_rch")
    fi
  fi

  # Check for bead mutations
  if grep -qE "\bbr\s+(update|close|claim)" "$script_path" 2>/dev/null; then
    violations+=("mutates_beads")
  fi

  # Check for reservation changes
  if grep -qE "reservation.*release\|release.*reservation" "$script_path" 2>/dev/null; then
    violations+=("mutates_reservations")
  fi

  # Check for queue policy changes
  if grep -qE "queue.*policy\|policy.*change" "$script_path" 2>/dev/null; then
    violations+=("changes_queue_policy")
  fi

  # Check for operator status replacement
  if grep -q "swarm_operator_status_report" "$script_path" 2>/dev/null; then
    if grep -qE "replace\|override\|substitute" "$script_path" 2>/dev/null; then
      violations+=("replaces_operator_status")
    fi
  fi

  if [[ ${#violations[@]} -gt 0 ]]; then
    log_event "mutation_violations" "$script_name: ${violations[*]}"
    echo "{\"script\":\"$script_name\",\"violations\":[$(printf '"%s",' "${violations[@]}" | sed 's/,$//')]}"
    return 1
  else
    log_event "mutation_clean" "$script_name: no violations found"
    echo "{\"script\":\"$script_name\",\"violations\":[]}"
    return 0
  fi
}

validate_mutation_policy() {
  log_event "mutation_policy_check_start" "Validating producer script mutation policies"

  local producer_scripts=(
    "scripts/swarm_benchmark_workload_catalog_normalizer.sh"
    "scripts/swarm_benchmark_bundle_replay_normalizer.sh"
    "scripts/swarm_benchmark_responsiveness_scorer.sh"
    "scripts/swarm_operator_status_report.sh"
  )

  local violations_found=false
  echo "{" > "$run_dir/mutation_policy_verification.json"
  echo "  \"validation_timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)\"," >> "$run_dir/mutation_policy_verification.json"
  echo "  \"scripts\": [" >> "$run_dir/mutation_policy_verification.json"

  local first_script=true
  for script in "${producer_scripts[@]}"; do
    if [[ "$first_script" == "false" ]]; then
      echo "," >> "$run_dir/mutation_policy_verification.json"
    fi
    first_script=false

    if [[ -f "$root_dir/$script" ]]; then
      local result
      if result=$(check_script_mutations "$root_dir/$script"); then
        echo "    $result" >> "$run_dir/mutation_policy_verification.json"
      else
        echo "    $result" >> "$run_dir/mutation_policy_verification.json"
        violations_found=true
      fi
    else
      echo "    {\"script\":\"$(basename "$script")\",\"status\":\"missing\"}" >> "$run_dir/mutation_policy_verification.json"
      log_event "script_missing" "$script not found"
      violations_found=true
    fi
  done

  echo "" >> "$run_dir/mutation_policy_verification.json"
  echo "  ]," >> "$run_dir/mutation_policy_verification.json"
  echo "  \"violations_found\": $violations_found" >> "$run_dir/mutation_policy_verification.json"
  echo "}" >> "$run_dir/mutation_policy_verification.json"

  if [[ "$violations_found" == "true" ]]; then
    log_event "mutation_policy_failure" "Mutation policy violations detected"
    return 1
  else
    log_event "mutation_policy_success" "All scripts comply with mutation policy"
    return 0
  fi
}

run_validation_commands() {
  log_event "validation_commands_start" "Running contract validation commands"

  local validation_commands=(
    "jq empty docs/swarm_benchmark_runbook_truth_contract_v1.json"
    "bash -n scripts/e2e/swarm_benchmark_no_mock_drill.sh"
    "bash -n scripts/e2e/swarm_benchmark_runbook_truth_gate.sh"
    "shellcheck -x scripts/e2e/swarm_benchmark_no_mock_drill.sh || true"
    "shellcheck -x scripts/e2e/swarm_benchmark_runbook_truth_gate.sh || true"
  )

  echo "{" > "$run_dir/validation_commands_results.json"
  echo "  \"validation_timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)\"," >> "$run_dir/validation_commands_results.json"
  echo "  \"commands\": [" >> "$run_dir/validation_commands_results.json"

  local first_command=true
  local any_failed=false

  for cmd in "${validation_commands[@]}"; do
    if [[ "$first_command" == "false" ]]; then
      echo "," >> "$run_dir/validation_commands_results.json"
    fi
    first_command=false

    log_event "validation_command" "Running: $cmd"

    local exit_code=0
    if cd "$root_dir" && eval "$cmd" >/dev/null 2>&1; then
      echo "    {\"command\": \"$cmd\", \"exit_code\": 0, \"status\": \"pass\"}" >> "$run_dir/validation_commands_results.json"
    else
      exit_code=$?
      any_failed=true
      echo "    {\"command\": \"$cmd\", \"exit_code\": $exit_code, \"status\": \"fail\"}" >> "$run_dir/validation_commands_results.json"
    fi
  done

  echo "" >> "$run_dir/validation_commands_results.json"
  echo "  ]," >> "$run_dir/validation_commands_results.json"
  echo "  \"any_failed\": $any_failed" >> "$run_dir/validation_commands_results.json"
  echo "}" >> "$run_dir/validation_commands_results.json"

  if [[ "$any_failed" == "true" ]]; then
    log_event "validation_commands_failure" "Some validation commands failed"
    return 1
  else
    log_event "validation_commands_success" "All validation commands passed"
    return 0
  fi
}

check_mode() {
  echo "Checking swarm benchmark runbook truth gate structure..."

  # Check required files exist
  local required_files=(
    "docs/swarm_benchmark_runbook_truth_contract_v1.json"
    "docs/SWARM_BENCH_OPERATOR_RUNBOOK.md"
    "scripts/e2e/swarm_benchmark_no_mock_drill.sh"
    "scripts/e2e/swarm_benchmark_runbook_truth_gate.sh"
  )

  for file in "${required_files[@]}"; do
    if [[ ! -f "$root_dir/$file" ]]; then
      echo >&2 "ERROR: Required file missing: $file"
      exit 64
    fi
  done

  # Validate contract JSON
  if ! jq empty "$root_dir/docs/swarm_benchmark_runbook_truth_contract_v1.json" >/dev/null 2>&1; then
    echo >&2 "ERROR: Invalid contract JSON: docs/swarm_benchmark_runbook_truth_contract_v1.json"
    exit 64
  fi

  echo "Check passed: truth gate structure validated"
  exit 0
}

selftest_mode() {
  echo "Running swarm benchmark runbook truth gate selftest..."

  mkdir -p "$run_dir"
  echo "{\"command\":\"./scripts/e2e/swarm_benchmark_runbook_truth_gate.sh\",\"args\":[\"selftest\"],\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)\"}" > "$run_dir/commands.txt"

  # Initialize events log
  echo > "$run_dir/events.jsonl"

  log_event "truth_gate_selftest_start" "swarm_benchmark_runbook_truth_gate"

  # Run lightweight validation
  validate_mutation_policy

  # Generate selftest report
  echo "{\"gate_mode\":\"selftest\",\"mutation_policy_checked\":true,\"status\":\"pass\",\"bead_id\":\"$bead_id\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)\"}" > "$run_dir/swarm_benchmark_runbook_truth_validation_report.json"

  log_event "truth_gate_selftest_complete" "Selftest validation passed"

  echo "Selftest passed: truth gate validation completed"
  exit 0
}

ci_mode() {
  echo "Running swarm benchmark runbook truth gate (CI mode)..."

  mkdir -p "$run_dir"
  echo "{\"command\":\"./scripts/e2e/swarm_benchmark_runbook_truth_gate.sh\",\"args\":[\"ci\"],\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)\"}" > "$run_dir/commands.txt"

  # Initialize events log
  echo > "$run_dir/events.jsonl"

  log_event "truth_gate_start" "swarm_benchmark_runbook_truth_gate"

  local validation_failures=()

  # Run full validation suite
  if ! validate_mutation_policy; then
    validation_failures+=("mutation_policy")
  fi

  if ! run_validation_commands; then
    validation_failures+=("validation_commands")
  fi

  # Check for truth gate rejections
  if [[ ${#validation_failures[@]} -gt 0 ]]; then
    echo "{\"gate_mode\":\"ci\",\"status\":\"rejected\",\"failures\":[$(printf '"%s",' "${validation_failures[@]}" | sed 's/,$//')]," > "$run_dir/swarm_benchmark_runbook_truth_validation_report.json"
    echo "\"bead_id\":\"$bead_id\",\"source_revision\":\"$source_revision\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)\"}" >> "$run_dir/swarm_benchmark_runbook_truth_validation_report.json"

    log_event "truth_gate_rejection" "Truth gate rejected: ${validation_failures[*]}"

    echo >&2 "Truth gate REJECTED: ${validation_failures[*]}"
    exit 42
  fi

  # Generate success report
  echo "{\"gate_mode\":\"ci\",\"status\":\"pass\",\"mutation_policy_verified\":true,\"validation_commands_verified\":true," > "$run_dir/swarm_benchmark_runbook_truth_validation_report.json"
  echo "\"bead_id\":\"$bead_id\",\"source_revision\":\"$source_revision\",\"run_dir\":\"$run_dir\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)\"}" >> "$run_dir/swarm_benchmark_runbook_truth_validation_report.json"

  log_event "truth_gate_complete" "All truth validations passed"

  echo "CI truth gate passed: all validations successful"
  exit 0
}

case "$mode" in
  check)
    check_mode
    ;;
  selftest)
    selftest_mode
    ;;
  ci)
    ci_mode
    ;;
  help|--help|-h)
    usage
    exit 0
    ;;
  *)
    echo >&2 "ERROR: Invalid mode: $mode"
    usage
    exit 64
    ;;
esac