#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
planner="${root_dir}/scripts/build_storm_qos_batch_planner.sh"
docs_path="${root_dir}/docs/BUILD_STORM_QOS_BATCH_PLANNER.md"
golden_dir="${BUILD_STORM_QOS_BATCH_PLANNER_GOLDEN_DIR:-${root_dir}/scripts/testdata/goldens}"

record_pass() {
  printf 'PASS build-storm-qos-batch-planner %s\n' "$1"
}

record_failure() {
  printf 'FAIL build-storm-qos-batch-planner %s\n' "$1" >&2
}

write_workers() {
  local path="$1"
  local idle_count="$2"

  if [[ "$idle_count" == "0" ]]; then
    jq -n '{workers:[
      {worker_id:"worker-a", status:"busy", cpu_slots_available:0, memory_class:"large"},
      {worker_id:"worker-b", status:"busy", cpu_slots_available:0, memory_class:"large"}
    ]}' >"$path"
    return 0
  fi

  jq -n --argjson idle_count "$idle_count" '
    {workers: [range(0; $idle_count) as $idx | {
      worker_id: ("worker-" + ($idx | tostring)),
      status: "idle",
      cpu_slots_available: 8,
      memory_class: "large"
    }]}
  ' >"$path"
}

write_empty_aux() {
  local fixture_dir="$1"

  jq -n '{plans:[]}' >"${fixture_dir}/leases.json"
  jq -n '{history:[]}' >"${fixture_dir}/costs.json"
}

run_case() {
  local case_name="$1"
  local expected_decision="$2"
  local expected_exit="$3"
  local output_dir="$4"
  local tmp_root="$5"
  shift 5
  local output
  local exit_code

  set +e
  output="$("$planner" --output-dir "$output_dir" "$@" 2>&1)"
  exit_code=$?
  set -e

  if [[ "$exit_code" -ne "$expected_exit" ]]; then
    record_failure "${case_name} exit ${exit_code}, expected ${expected_exit}"
    printf '%s\n' "$output" >&2
    return 1
  fi

  jq -e --arg expected_decision "$expected_decision" '
    .schema_version == "franken-engine.build-storm-batch-plan.v1"
    and (.batch_id | test("^batch-[0-9a-f]{16}$"))
    and (.stable_output_hash | test("^[0-9a-f]{64}$"))
    and .batch_decision == $expected_decision
    and (.fairness_reason | length > 0)
    and (.max_parallel_heavy | type == "number")
    and (.retry_after_seconds | type == "number")
    and (.admitted_commands | type == "array")
    and (.deferred_commands | type == "array")
    and (.artifact_paths.build_storm_batch_plan_json | length > 0)
    and (.artifact_paths.events_jsonl | length > 0)
    and (.artifact_paths.commands_txt | length > 0)
    and (.artifact_paths.report_md | length > 0)
  ' "${output_dir}/build_storm_batch_plan.json" >/dev/null
  test -s "${output_dir}/events.jsonl"
  test -s "${output_dir}/commands.txt"
  test -s "${output_dir}/report.md"
  assert_case_golden "$case_name" "${output_dir}/build_storm_batch_plan.json" "$tmp_root"
  record_pass "${case_name} decided ${expected_decision}"
}

assert_admitted_ids() {
  local plan="$1"
  shift
  local expected
  expected="$(printf '%s\n' "$@" | jq -R . | jq -s 'sort')"
  jq -e --argjson expected "$expected" '
    [.admitted_commands[].request_id] | sort == $expected
  ' "$plan" >/dev/null
}

assert_deferred_reason() {
  local plan="$1"
  local request_id="$2"
  local reason_fragment="$3"

  jq -e --arg request_id "$request_id" --arg reason_fragment "$reason_fragment" '
    any(.deferred_commands[]?;
      .request_id == $request_id
      and (.fairness_reason | contains($reason_fragment))
    )
  ' "$plan" >/dev/null
}

golden_case_names() {
  printf '%s\n' \
    balanced-two-agent-admission \
    balanced-two-agent-repeat \
    one-noisy-agent-throttled \
    p1-proof-refresh-preempts-p3-broad-check \
    all-workers-busy \
    stale-proof-refresh-short-retry
}

canonicalize_plan() {
  local plan="$1"
  local tmp_root="$2"

  jq --arg tmp_root "$tmp_root" '
    def scrub:
      if type == "string" then
        gsub($tmp_root; "[SMOKE_ROOT]")
        | gsub("/tmp/rch_target_"; "[RCH_TARGET]/")
        | gsub("/tmp/[A-Za-z0-9._-]+"; "[TMP_PATH]")
        | gsub("/data/tmp/[A-Za-z0-9._-]+"; "[DATA_TMP_PATH]")
      elif type == "array" then
        map(scrub)
      elif type == "object" then
        with_entries(.value |= scrub)
      else
        .
      end;
    scrub
  ' "$plan"
}

assert_case_golden() {
  local case_name="$1"
  local plan="$2"
  local tmp_root="$3"
  local golden_path="${golden_dir}/build_storm_qos_batch_planner_${case_name}.golden"

  if [[ "${UPDATE_GOLDENS:-0}" == "1" ]]; then
    mkdir -p "$golden_dir"
    canonicalize_plan "$plan" "$tmp_root" >"$golden_path"
    return 0
  fi

  if [[ ! -f "$golden_path" ]]; then
    record_failure "${case_name} missing golden"
    return 1
  fi

  if ! diff -u "$golden_path" <(canonicalize_plan "$plan" "$tmp_root"); then
    record_failure "${case_name} golden drift"
    return 1
  fi
}

goldens_shape_ok() {
  local case_name golden_path

  if [[ "${UPDATE_GOLDENS:-0}" == "1" ]]; then
    return 0
  fi

  while IFS= read -r case_name; do
    golden_path="${golden_dir}/build_storm_qos_batch_planner_${case_name}.golden"
    if [[ ! -f "$golden_path" ]]; then
      record_failure "${case_name} missing checked-in golden"
      return 1
    fi
    jq empty "$golden_path" >/dev/null || {
      record_failure "${case_name} invalid golden json"
      return 1
    }
  done < <(golden_case_names)
}

run_check() {
  local scope_file

  bash -n "$planner"
  bash -n "${BASH_SOURCE[0]}"
  test -f "$docs_path"
  record_pass "bash syntax and docs exist"

  scope_file="$(mktemp "${TMPDIR:-/tmp}/build-storm-qos-rch-scope.XXXXXX")"
  printf '%s\n' \
    "scripts/build_storm_qos_batch_planner.sh" \
    "scripts/e2e/build_storm_qos_batch_planner_smoke.sh" \
    "docs/BUILD_STORM_QOS_BATCH_PLANNER.md" >"$scope_file"
  "${root_dir}/scripts/rch_policy_compliance_gate.sh" \
    --output-dir "${TMPDIR:-/tmp}/build-storm-qos-rch-policy" \
    --scope-file "$scope_file" >/dev/null
  record_pass "rch policy compliance"
  goldens_shape_ok
}

run_selftest() {
  local tmp_parent tmp_root fixture_dir target_dir hash_one hash_two batch_one batch_two

  run_check
  tmp_parent="${BUILD_STORM_QOS_BATCH_PLANNER_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/build-storm-qos-batch-planner.XXXXXX")"
  fixture_dir="${tmp_root}/fixtures"
  target_dir="/tmp/rch_target_franken_engine_build_storm"
  mkdir -p "$fixture_dir"
  write_empty_aux "$fixture_dir"

  write_workers "${fixture_dir}/workers-two.json" 2
  jq -n --arg target_dir "$target_dir" '{requests:[
    {request_id:"alpha-proof", agent_id:"ScarletOwl", bead_id:"bd-alpha", bead_priority:1, proof_refresh:true, heavy:true, command:("rch exec -- env CARGO_TARGET_DIR=" + $target_dir + "/alpha cargo test -p frankenengine-engine --test alpha_proof"), submitted_order:1},
    {request_id:"beta-proof", agent_id:"CyanOak", bead_id:"bd-beta", bead_priority:1, proof_refresh:true, heavy:true, command:("rch exec -- env CARGO_TARGET_DIR=" + $target_dir + "/beta cargo test -p frankenengine-engine --test beta_proof"), submitted_order:2}
  ]}' >"${fixture_dir}/balanced.json"
  run_case "balanced-two-agent-admission" "planned" 0 "${tmp_root}/balanced-one" \
    "$tmp_root" \
    --pending-requests-json "${fixture_dir}/balanced.json" \
    --resource-lease-plans-json "${fixture_dir}/leases.json" \
    --proof-cost-history-json "${fixture_dir}/costs.json" \
    --rch-workers-json "${fixture_dir}/workers-two.json" \
    --max-parallel-heavy 2
  assert_admitted_ids "${tmp_root}/balanced-one/build_storm_batch_plan.json" alpha-proof beta-proof
  run_case "balanced-two-agent-repeat" "planned" 0 "${tmp_root}/balanced-two" \
    "$tmp_root" \
    --pending-requests-json "${fixture_dir}/balanced.json" \
    --resource-lease-plans-json "${fixture_dir}/leases.json" \
    --proof-cost-history-json "${fixture_dir}/costs.json" \
    --rch-workers-json "${fixture_dir}/workers-two.json" \
    --max-parallel-heavy 2
  hash_one="$(jq -r '.stable_output_hash' "${tmp_root}/balanced-one/build_storm_batch_plan.json")"
  hash_two="$(jq -r '.stable_output_hash' "${tmp_root}/balanced-two/build_storm_batch_plan.json")"
  batch_one="$(jq -r '.batch_id' "${tmp_root}/balanced-one/build_storm_batch_plan.json")"
  batch_two="$(jq -r '.batch_id' "${tmp_root}/balanced-two/build_storm_batch_plan.json")"
  test "$hash_one" = "$hash_two"
  test "$batch_one" = "$batch_two"
  record_pass "deterministic stable output hash"

  jq -n --arg target_dir "$target_dir" '{requests:[
    {request_id:"noisy-a", agent_id:"NoisyAgent", bead_id:"bd-noisy-a", bead_priority:1, proof_refresh:true, heavy:true, command:("rch exec -- env CARGO_TARGET_DIR=" + $target_dir + "/noisy-a cargo test -p frankenengine-engine --test noisy_a"), submitted_order:1},
    {request_id:"noisy-b", agent_id:"NoisyAgent", bead_id:"bd-noisy-b", bead_priority:1, proof_refresh:true, heavy:true, command:("rch exec -- env CARGO_TARGET_DIR=" + $target_dir + "/noisy-b cargo test -p frankenengine-engine --test noisy_b"), submitted_order:2},
    {request_id:"quiet-a", agent_id:"QuietAgent", bead_id:"bd-quiet-a", bead_priority:1, proof_refresh:true, heavy:true, command:("rch exec -- env CARGO_TARGET_DIR=" + $target_dir + "/quiet-a cargo test -p frankenengine-engine --test quiet_a"), submitted_order:3}
  ]}' >"${fixture_dir}/noisy.json"
  run_case "one-noisy-agent-throttled" "planned" 0 "${tmp_root}/noisy-agent" \
    "$tmp_root" \
    --pending-requests-json "${fixture_dir}/noisy.json" \
    --resource-lease-plans-json "${fixture_dir}/leases.json" \
    --proof-cost-history-json "${fixture_dir}/costs.json" \
    --rch-workers-json "${fixture_dir}/workers-two.json" \
    --max-parallel-heavy 2 \
    --max-per-agent-heavy 1
  assert_admitted_ids "${tmp_root}/noisy-agent/build_storm_batch_plan.json" noisy-a quiet-a
  assert_deferred_reason "${tmp_root}/noisy-agent/build_storm_batch_plan.json" noisy-b "agent fairness throttle"

  write_workers "${fixture_dir}/workers-one.json" 1
  jq -n --arg target_dir "$target_dir" '{requests:[
    {request_id:"p1-proof-refresh", agent_id:"ScarletOwl", bead_id:"bd-p1", bead_priority:1, proof_refresh:true, fail_closed_proof_refresh:true, heavy:true, command:("rch exec -- env CARGO_TARGET_DIR=" + $target_dir + "/p1 cargo test -p frankenengine-engine --test focused_fail_closed_proof"), submitted_order:2},
    {request_id:"p3-broad-check", agent_id:"CyanOak", bead_id:"bd-p3", bead_priority:3, broad_check:true, heavy:true, command:("rch exec -- env CARGO_TARGET_DIR=" + $target_dir + "/p3 cargo check --all-targets"), submitted_order:1}
  ]}' >"${fixture_dir}/preempt.json"
  run_case "p1-proof-refresh-preempts-p3-broad-check" "planned" 0 "${tmp_root}/preempt" \
    "$tmp_root" \
    --pending-requests-json "${fixture_dir}/preempt.json" \
    --resource-lease-plans-json "${fixture_dir}/leases.json" \
    --proof-cost-history-json "${fixture_dir}/costs.json" \
    --rch-workers-json "${fixture_dir}/workers-one.json" \
    --max-parallel-heavy 1
  assert_admitted_ids "${tmp_root}/preempt/build_storm_batch_plan.json" p1-proof-refresh
  assert_deferred_reason "${tmp_root}/preempt/build_storm_batch_plan.json" p3-broad-check "batch heavy capacity reached"

  write_workers "${fixture_dir}/workers-busy.json" 0
  run_case "all-workers-busy" "all_deferred" 75 "${tmp_root}/all-workers-busy" \
    "$tmp_root" \
    --pending-requests-json "${fixture_dir}/balanced.json" \
    --resource-lease-plans-json "${fixture_dir}/leases.json" \
    --proof-cost-history-json "${fixture_dir}/costs.json" \
    --rch-workers-json "${fixture_dir}/workers-busy.json" \
    --max-parallel-heavy 2
  assert_deferred_reason "${tmp_root}/all-workers-busy/build_storm_batch_plan.json" alpha-proof "all rch workers busy"

  jq -n --arg target_dir "$target_dir" '{requests:[
    {request_id:"p0-refresh", agent_id:"ScarletOwl", bead_id:"bd-p0", bead_priority:0, proof_refresh:true, fail_closed_proof_refresh:true, heavy:true, command:("rch exec -- env CARGO_TARGET_DIR=" + $target_dir + "/p0 cargo test -p frankenengine-engine --test p0_refresh"), submitted_order:1},
    {request_id:"stale-refresh", agent_id:"CyanOak", bead_id:"bd-stale", bead_priority:1, proof_refresh:true, stale_proof_refresh:true, heavy:true, command:("rch exec -- env CARGO_TARGET_DIR=" + $target_dir + "/stale cargo test -p frankenengine-engine --test stale_refresh"), submitted_order:2}
  ]}' >"${fixture_dir}/stale.json"
  run_case "stale-proof-refresh-short-retry" "planned" 0 "${tmp_root}/stale-retry" \
    "$tmp_root" \
    --pending-requests-json "${fixture_dir}/stale.json" \
    --resource-lease-plans-json "${fixture_dir}/leases.json" \
    --proof-cost-history-json "${fixture_dir}/costs.json" \
    --rch-workers-json "${fixture_dir}/workers-one.json" \
    --max-parallel-heavy 1 \
    --stale-retry-after-seconds 45
  assert_admitted_ids "${tmp_root}/stale-retry/build_storm_batch_plan.json" p0-refresh
  jq -e '.retry_after_seconds == 45' "${tmp_root}/stale-retry/build_storm_batch_plan.json" >/dev/null
  assert_deferred_reason "${tmp_root}/stale-retry/build_storm_batch_plan.json" stale-refresh "batch heavy capacity reached"

  printf 'build_storm_qos_batch_planner_smoke_artifacts=%s\n' "$tmp_root"
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
