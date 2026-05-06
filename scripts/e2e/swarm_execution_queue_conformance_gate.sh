#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture_dir="${root_dir}/scripts/testdata/swarm_execution_queue"
golden_dir="${fixture_dir}/goldens"
docs_path="${root_dir}/docs/SWARM_EXECUTION_QUEUE_CONFORMANCE.md"
contract_path="${root_dir}/docs/swarm_execution_queue_conformance_contract_v1.json"
input_contract_path="${root_dir}/docs/swarm_execution_queue_input_contract_v1.json"
runner_contract_path="${root_dir}/docs/swarm_execution_queue_runner_contract_v1.json"
runner_bin="${FRANKEN_SWARM_EXECUTION_QUEUE_BIN:-}"

cases=(
  "healthy:healthy_input.json:healthy_runner_golden.json:pass"
  "stale_owner:stale_owner_input.json:stale_owner_runner_golden.json:degraded"
  "proof_brownout:proof_brownout_input.json:proof_brownout_runner_golden.json:degraded"
  "blocked_parent:blocked_parent_input.json:blocked_parent_runner_golden.json:pass"
  "cyclic_input:cyclic_input.json:cyclic_input_runner_golden.json:fail_closed"
)

failures=0

record_pass() {
  printf 'PASS swarm-execution-queue-conformance %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-execution-queue-conformance %s\n' "$1" >&2
  failures=$((failures + 1))
}

relative_path() {
  local path="$1"
  printf '%s\n' "${path#"$root_dir"/}"
}

check_path_exists() {
  local relative="$1"
  if [[ -z "$relative" || "$relative" == "null" ]]; then
    record_failure "referenced path is empty"
  elif [[ ! -e "${root_dir}/${relative}" ]]; then
    record_failure "missing referenced path ${relative}"
  else
    record_pass "referenced path exists ${relative}"
  fi
}

text_has_forbidden_mutation_claim() {
  local path="$1"
  grep -Eiq 'automatic reopen is allowed|automatically reopens|runs br update|will run br update|br update .*--status|release_file_reservations|will release reservations|sends Agent Mail automatically|mutates remote workers|live worker mutation is performed' "$path"
}

check_no_mutation_claims() {
  local path="$1"
  if text_has_forbidden_mutation_claim "$path"; then
    record_failure "$(relative_path "$path") contains live-mutation wording"
  else
    record_pass "$(relative_path "$path") has advisory-only wording"
  fi
}

check_no_bare_heavy_cargo() {
  local path="$1"
  local command
  while IFS= read -r command; do
    if [[ "$command" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
      if [[ "$command" != *"rch exec --"* || "$command" != *"CARGO_TARGET_DIR="* ]]; then
        record_failure "$(relative_path "$path") has bare heavy Cargo command: ${command}"
      fi
    fi
  done < <(jq -r '.. | strings' "$path" 2>/dev/null || sed -n '1,240p' "$path")
}

fixture_shape_ok() {
  local path="$1"
  local expected="$2"
  jq -e --arg expected "$expected" '
    def millionths: type == "number" and . >= 0 and . <= 1000000;
    .schema_version == "franken-engine.swarm-execution-queue-input.v1"
    and (.fixture_id | type == "string" and length > 0)
    and (.tasks | type == "array" and length > 0)
    and (.expected_output_assertions.decision == $expected)
    and (.expected_output_assertions.top_queue | type == "array")
    and (.expected_output_assertions.conservative_mode | type == "boolean")
    and (.expected_output_assertions.bottleneck_ids | type == "array")
    and all(.tasks[]; (
      (.task_id | type == "string" and length > 0)
      and (.title | type == "string" and length > 0)
      and (.depends_on | type == "array")
      and (.dependents | type == "array")
      and (.open_blocker_count | type == "number")
      and (.owner_freshness.state | type == "string" and length > 0)
      and (.reservation_pressure.state | type == "string" and length > 0)
      and (.reservation_pressure.active_reservation_count | type == "number")
      and (.proof_transport.state | type == "string" and length > 0)
      and (.proof_transport.local_fallback_detected == false)
      and (.scores.impact_millionths | millionths)
      and (.scores.confidence_millionths | millionths)
      and (.scores.reuse_millionths | millionths)
      and (.scores.effort_millionths | millionths)
      and (.scores.friction_millionths | millionths)
      and (.fallback_trigger | type == "string" and length > 0)
      and (.first_action | type == "string" and length > 0)
    ))
    and (
      if $expected == "fail_closed" then
        .expected_output_assertions.expected_exit_code == 42
        and (.expected_output_assertions.fail_closed_reason_contains | type == "string" and length > 0)
        and (.expected_output_assertions.top_queue | length) == 0
      else
        (.expected_output_assertions.top_queue | length) > 0
      end
    )
  ' "$path" >/dev/null
}

golden_shape_ok() {
  local golden_path="$1"
  local fixture_path="$2"
  local expected="$3"
  jq -e --slurpfile fixture "$fixture_path" --arg expected "$expected" --arg fixture_path "$fixture_path" '
    def hex64: type == "string" and test("^[0-9a-f]{64}$");
    $fixture[0] as $fixture_doc |
    .schema_version == "franken-engine.swarm-execution-queue-conformance-golden.v1"
    and .fixture_id == $fixture_doc.fixture_id
    and .normalized_input_path == ("scripts/testdata/swarm_execution_queue/" + ($fixture_path | split("/") | last))
    and .expected_decision == $fixture_doc.expected_output_assertions.decision
    and .runner_invocation.binary == "franken_swarm_execution_queue"
    and .runner_invocation.queue_depth == 8
    and .runner_invocation.epoch == 7
    and .runner_invocation.timestamp_ns == 777
    and (
      if $expected == "fail_closed" then
        .expected_exit_code == 42
        and .failure.fail_closed_rule == "dependency cycles fail closed"
        and (.failure.stderr_contains | contains($fixture_doc.expected_output_assertions.fail_closed_reason_contains))
      else
        .expected_exit_code == 0
        and (.runner as $runner |
          $runner.artifact_schema_version == "franken-engine.swarm-execution-queue-artifact.v1"
          and $runner.risk_budget_schema_version == "franken-engine.swarm-execution-risk-budget-receipt.v1"
          and $runner.bottleneck_schema_version == "franken-engine.swarm-execution-bottleneck-report.v1"
          and ($runner.artifact_hash_hex | hex64)
          and ($runner.normalized_input_hash_hex | hex64)
          and ($runner.queue_depth as $queue_depth | ($queue_depth | type == "number") and $queue_depth > 0 and $queue_depth <= .runner_invocation.queue_depth and $queue_depth <= 64)
          and (($runner.queue | type) == "array" and ($runner.queue | length) == $runner.queue_depth)
          and ([$runner.queue[].rank] == [range(1; ($runner.queue | length) + 1)])
          and ([$runner.queue[].task_id] == $runner.top_queue)
          and $runner.top_queue == $fixture_doc.expected_output_assertions.top_queue
          and $runner.conservative_mode == $fixture_doc.expected_output_assertions.conservative_mode
          and $runner.bottleneck_ids == $fixture_doc.expected_output_assertions.bottleneck_ids
          and ($runner.critical_bottleneck_count | type == "number" and . >= 0)
          and all($runner.queue[]; (
            (.task_id | type == "string" and length > 0)
            and (.wave | type == "string" and length > 0)
            and (.first_action | type == "string" and length > 0)
            and (.fallback_trigger | type == "string" and length > 0)
            and (.open_blocker_count | type == "number")
            and (.ev_millionths | type == "number")
          ))
        )
      end
    )
  ' "$golden_path" >/dev/null
}

contract_shape_ok() {
  local path="$1"
  jq -e '
    .schema_version == "franken-engine.swarm-execution-queue-conformance-contract.v1"
    and .bead_id == "bd-zllzm"
    and .parent_bead_id == "bd-g347f"
    and (.depends_on | index("bd-pthn9") != null)
    and .docs == "docs/SWARM_EXECUTION_QUEUE_CONFORMANCE.md"
    and .gate_script == "scripts/e2e/swarm_execution_queue_conformance_gate.sh"
    and .golden_schema_version == "franken-engine.swarm-execution-queue-conformance-golden.v1"
    and (.fixture_goldens | length) == 5
    and all(.fixture_goldens[]; (.normalized_input_path | length) > 0 and (.golden_path | length) > 0)
    and all(.requirements_matrix[]; .level == "MUST" and .status == "covered" and (.covered_by | length) > 0)
    and any(.requirements_matrix[]; .requirement_id == "REQ-FAIL-CLOSED-CYCLE")
    and .live_runner_replay.optional == true
    and .live_runner_replay.env_var == "FRANKEN_SWARM_EXECUTION_QUEUE_BIN"
    and .mutation_policy.mutates_br == false
    and .mutation_policy.reassigns_beads == false
    and .mutation_policy.releases_reservations == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.mutates_remote_workers == false
  ' "$path" >/dev/null
}

validate_fixture() {
  local fixture_path="$1"
  local expected="$2"
  jq empty "$fixture_path"
  if fixture_shape_ok "$fixture_path" "$expected"; then
    record_pass "$(relative_path "$fixture_path") fixture shape"
  else
    record_failure "$(relative_path "$fixture_path") fixture shape mismatch"
  fi
}

validate_golden() {
  local golden_path="$1"
  local fixture_path="$2"
  local expected="$3"
  jq empty "$golden_path"
  if golden_shape_ok "$golden_path" "$fixture_path" "$expected"; then
    record_pass "$(relative_path "$golden_path") golden shape"
  else
    record_failure "$(relative_path "$golden_path") golden shape mismatch"
  fi
}

validate_contract() {
  jq empty "$contract_path" "$input_contract_path" "$runner_contract_path"
  if contract_shape_ok "$contract_path"; then
    record_pass "top-level conformance contract"
  else
    record_failure "top-level conformance contract mismatch"
  fi

  while IFS= read -r referenced_path; do
    check_path_exists "$referenced_path"
  done < <(jq -r '.docs, .gate_script, .input_contract, .runner_contract, .fixture_goldens[].normalized_input_path, .fixture_goldens[].golden_path' "$contract_path")

  check_no_mutation_claims "$docs_path"
  check_no_mutation_claims "$contract_path"
  check_no_bare_heavy_cargo "$docs_path"
  check_no_bare_heavy_cargo "$contract_path"
}

validate_docs() {
  grep -q 'SWARM-CTRL-XII' "$docs_path"
  grep -q 'advisory-only' "$docs_path"
  grep -q 'cyclic_input.json' "$docs_path"
  grep -q 'goldens' "$docs_path"
  record_pass "docs mention contract scope and goldens"
}

compare_live_success() {
  local fixture_id="$1"
  local fixture_path="$2"
  local golden_path="$3"
  local output_dir="$4"

  "$runner_bin" \
    --normalized-input-json "$fixture_path" \
    --output-dir "$output_dir" \
    --queue-depth 8 \
    --epoch 7 \
    --timestamp-ns 777 >/dev/null

  local actual_queue expected_queue
  actual_queue="$(jq -c '[.queue_artifact.queue[] | {rank,task_id,wave,open_blocker_count,ev_millionths,first_action,fallback_trigger}]' "${output_dir}/execution_queue_artifact.json")"
  expected_queue="$(jq -c '.runner.queue' "$golden_path")"
  if [[ "$actual_queue" != "$expected_queue" ]]; then
    record_failure "${fixture_id} live runner queue diverged from golden"
    return
  fi

  local actual_artifact_hash expected_artifact_hash
  actual_artifact_hash="$(jq -r '.artifact_hash_hex' "${output_dir}/execution_queue_artifact.json")"
  expected_artifact_hash="$(jq -r '.runner.artifact_hash_hex' "$golden_path")"
  if [[ "$actual_artifact_hash" != "$expected_artifact_hash" ]]; then
    record_failure "${fixture_id} live runner artifact hash diverged from golden"
    return
  fi

  local actual_conservative expected_conservative
  actual_conservative="$(jq -r '.conservative_mode' "${output_dir}/risk_budget_receipt.json")"
  expected_conservative="$(jq -r '.runner.conservative_mode' "$golden_path")"
  if [[ "$actual_conservative" != "$expected_conservative" ]]; then
    record_failure "${fixture_id} live runner conservative mode diverged from golden"
    return
  fi

  local actual_bottlenecks expected_bottlenecks
  actual_bottlenecks="$(jq -c '[.bottlenecks[]?.task_id]' "${output_dir}/bottleneck_report.json")"
  expected_bottlenecks="$(jq -c '.runner.bottleneck_ids' "$golden_path")"
  if [[ "$actual_bottlenecks" != "$expected_bottlenecks" ]]; then
    record_failure "${fixture_id} live runner bottlenecks diverged from golden"
    return
  fi

  record_pass "${fixture_id} live runner replay"
}

compare_live_failure() {
  local fixture_id="$1"
  local fixture_path="$2"
  local golden_path="$3"
  local output_dir="$4"
  local expected_code expected_stderr code

  expected_code="$(jq -r '.expected_exit_code' "$golden_path")"
  expected_stderr="$(jq -r '.failure.stderr_contains' "$golden_path")"
  set +e
  "$runner_bin" \
    --normalized-input-json "$fixture_path" \
    --output-dir "$output_dir" \
    --queue-depth 8 \
    --epoch 7 \
    --timestamp-ns 777 >"${output_dir}/stdout.txt" 2>"${output_dir}/stderr.txt"
  code=$?
  set -e

  if [[ "$code" -ne "$expected_code" ]]; then
    record_failure "${fixture_id} live runner expected exit ${expected_code}, got ${code}"
    return
  fi
  if ! grep -Fq "$expected_stderr" "${output_dir}/stderr.txt"; then
    record_failure "${fixture_id} live runner stderr did not quote ${expected_stderr}"
    return
  fi
  record_pass "${fixture_id} live fail-closed replay"
}

run_live_runner_replay() {
  if [[ -z "$runner_bin" ]]; then
    record_pass "live runner replay not requested; checked-in goldens validated"
    return
  fi
  if [[ ! -x "$runner_bin" ]]; then
    record_failure "FRANKEN_SWARM_EXECUTION_QUEUE_BIN is not executable: ${runner_bin}"
    return
  fi

  local tmp_parent tmp_root case_spec fixture_id fixture_name golden_name expected fixture_path golden_path output_dir
  tmp_parent="${SWARM_EXECUTION_QUEUE_CONFORMANCE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/swarm-execution-queue-conformance-live.XXXXXX")"

  for case_spec in "${cases[@]}"; do
    IFS=: read -r fixture_id fixture_name golden_name expected <<<"$case_spec"
    fixture_path="${fixture_dir}/${fixture_name}"
    golden_path="${golden_dir}/${golden_name}"
    output_dir="${tmp_root}/${fixture_id}"
    mkdir -p "$output_dir"
    if [[ "$expected" == "fail_closed" ]]; then
      compare_live_failure "$fixture_id" "$fixture_path" "$golden_path" "$output_dir"
    else
      compare_live_success "$fixture_id" "$fixture_path" "$golden_path" "$output_dir"
    fi
  done

  printf 'swarm_execution_queue_conformance_live_artifacts=%s\n' "$tmp_root"
}

run_rch_policy_gate() {
  local scope_file output_dir
  scope_file="$(mktemp "${TMPDIR:-/tmp}/swarm-execution-queue-conformance-scope.XXXXXX")"
  output_dir="${SWARM_EXECUTION_QUEUE_CONFORMANCE_RCH_POLICY_ROOT:-${TMPDIR:-/tmp}/swarm-execution-queue-conformance-rch-policy}"
  {
    printf '%s\n' "scripts/e2e/swarm_execution_queue_conformance_gate.sh"
    printf '%s\n' "docs/SWARM_EXECUTION_QUEUE_CONFORMANCE.md"
    printf '%s\n' "docs/swarm_execution_queue_conformance_contract_v1.json"
    printf '%s\n' "scripts/testdata/swarm_execution_queue/cyclic_input.json"
    printf '%s\n' "scripts/testdata/swarm_execution_queue/goldens/healthy_runner_golden.json"
    printf '%s\n' "scripts/testdata/swarm_execution_queue/goldens/stale_owner_runner_golden.json"
    printf '%s\n' "scripts/testdata/swarm_execution_queue/goldens/proof_brownout_runner_golden.json"
    printf '%s\n' "scripts/testdata/swarm_execution_queue/goldens/blocked_parent_runner_golden.json"
    printf '%s\n' "scripts/testdata/swarm_execution_queue/goldens/cyclic_input_runner_golden.json"
  } >"$scope_file"

  "${root_dir}/scripts/rch_policy_compliance_gate.sh" \
    --output-dir "$output_dir" \
    --scope-file "$scope_file" >/dev/null
  record_pass "rch policy scoped gate"
}

run_check() {
  local case_spec fixture_id fixture_name golden_name expected fixture_path golden_path

  bash -n "${BASH_SOURCE[0]}"
  validate_docs
  validate_contract

  for case_spec in "${cases[@]}"; do
    IFS=: read -r fixture_id fixture_name golden_name expected <<<"$case_spec"
    fixture_path="${fixture_dir}/${fixture_name}"
    golden_path="${golden_dir}/${golden_name}"
    validate_fixture "$fixture_path" "$expected"
    validate_golden "$golden_path" "$fixture_path" "$expected"
  done

  run_live_runner_replay
  run_rch_policy_gate

  if [[ "$failures" -ne 0 ]]; then
    return 1
  fi
}

run_selftest() {
  local tmp_parent tmp_root bad_fixture bad_golden bad_contract bad_doc
  tmp_parent="${SWARM_EXECUTION_QUEUE_CONFORMANCE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/swarm-execution-queue-conformance.XXXXXX")"

  run_check

  bad_fixture="${tmp_root}/bad_fixture.json"
  jq '.tasks[0].first_action = ""' "${fixture_dir}/healthy_input.json" >"$bad_fixture"
  if fixture_shape_ok "$bad_fixture" "pass"; then
    record_failure "bad fixture without first_action should fail"
  else
    record_pass "bad fixture without first_action fails"
  fi

  bad_golden="${tmp_root}/bad_golden.json"
  jq '.runner.top_queue = ["bd-wrong"]' "${golden_dir}/healthy_runner_golden.json" >"$bad_golden"
  if golden_shape_ok "$bad_golden" "${fixture_dir}/healthy_input.json" "pass"; then
    record_failure "bad golden queue order should fail"
  else
    record_pass "bad golden queue order fails"
  fi

  bad_contract="${tmp_root}/bad_contract.json"
  jq '.fixture_goldens = []' "$contract_path" >"$bad_contract"
  if contract_shape_ok "$bad_contract"; then
    record_failure "bad contract without fixture goldens should fail"
  else
    record_pass "bad contract without fixture goldens fails"
  fi

  bad_doc="${tmp_root}/bad_doc.md"
  printf 'This gate automatically reopens beads with br update --status open.\n' >"$bad_doc"
  if text_has_forbidden_mutation_claim "$bad_doc"; then
    record_pass "bad mutation wording fails"
  else
    record_failure "bad mutation wording should fail"
  fi

  if [[ "$failures" -ne 0 ]]; then
    return 1
  fi
  printf 'swarm_execution_queue_conformance_artifacts=%s\n' "$tmp_root"
}

case "${1:-check}" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  *)
    record_failure "unknown mode: ${1:-}"
    exit 64
    ;;
esac
