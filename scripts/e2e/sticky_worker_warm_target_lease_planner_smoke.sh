#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
planner="${root_dir}/scripts/sticky_worker_warm_target_lease_planner.sh"
docs_path="${root_dir}/docs/STICKY_WORKER_WARM_TARGET_LEASE_PLANNER.md"

record_pass() {
  printf 'PASS sticky-worker-warm-target %s\n' "$1"
}

record_failure() {
  printf 'FAIL sticky-worker-warm-target %s\n' "$1" >&2
}

write_manifest() {
  local path="$1"
  local target_dir="$2"

  jq -n \
    --arg target_dir "$target_dir" '
    {
      schema_version: "franken-engine.remote-proof-suite-manifest.v1",
      suite_id: "semantic-dark-matter-pipeline",
      phases: [
        {
          phase: "check",
          command_id: "check-1",
          bead_id: "bd-lviqm",
          requested_command: ("rch exec -- env CARGO_TARGET_DIR=" + $target_dir + " cargo check -p frankenengine-engine --test semantic_dark_matter_engine_integration")
        },
        {
          phase: "test",
          command_id: "test-1",
          bead_id: "bd-lviqm",
          requested_command: ("rch exec -- env CARGO_TARGET_DIR=" + $target_dir + " cargo test -p frankenengine-engine --test semantic_dark_matter_engine_integration -- --nocapture")
        },
        {
          phase: "clippy",
          command_id: "clippy-1",
          bead_id: "bd-lviqm",
          requested_command: ("rch exec -- env CARGO_TARGET_DIR=" + $target_dir + " cargo clippy -p frankenengine-engine --test semantic_dark_matter_engine_integration -- -D warnings")
        }
      ]
    }
  ' >"$path"
}

write_sticky_state() {
  local path="$1"
  local worker_id="$2"
  local target_dir="$3"

  jq -n \
    --arg worker_id "$worker_id" \
    --arg target_dir "$target_dir" '
    {
      schema_version: "franken-engine.sticky-worker-state.v1",
      suite_id: "semantic-dark-matter-pipeline",
      preferred_worker_id: $worker_id,
      warm_target_dir: $target_dir,
      last_successful_phase: "test"
    }
  ' >"$path"
}

write_workers() {
  local path="$1"
  local sticky_status="$2"
  # rch-policy-waive: local_fallback_not_rejected reason=fixture parameter names describe worker availability only, not executable local fallback handling
  local fallback_status="$3"

  jq -n \
    --arg sticky_status "$sticky_status" \
    --arg fallback_status "$fallback_status" '
    {
      workers: [
        {
          worker_id: "vmi1156319",
          status: $sticky_status,
          cpu_slots_available: 8,
          target_dir_root: "/tmp"
        },
        {
          worker_id: "vmi1167313",
          status: $fallback_status,
          cpu_slots_available: 8,
          target_dir_root: "/tmp"
        }
      ]
    }
  ' >"$path"
}

run_check() {
  local scope_file

  bash -n "$planner"
  bash -n "${BASH_SOURCE[0]}"
  grep -q 'franken-engine.sticky-worker-warm-target-lease-plan.v1' "$docs_path"
  grep -q 'rch exec -- env CARGO_TARGET_DIR=' "$docs_path"
  record_pass "bash syntax and docs contract"

  scope_file="$(mktemp "${TMPDIR:-/tmp}/sticky-worker-warm-target-scope.XXXXXX")"
  printf '%s\n' \
    "scripts/sticky_worker_warm_target_lease_planner.sh" \
    "scripts/e2e/sticky_worker_warm_target_lease_planner_smoke.sh" \
    "docs/STICKY_WORKER_WARM_TARGET_LEASE_PLANNER.md" >"$scope_file"
  "${root_dir}/scripts/rch_policy_compliance_gate.sh" \
    --output-dir "${TMPDIR:-/tmp}/sticky-worker-warm-target-rch-policy" \
    --scope-file "$scope_file" >/dev/null
  record_pass "rch policy compliance"
}

run_case() {
  local case_name="$1"
  local expected_exit="$2"
  local output_dir="$3"
  shift 3

  local output actual_exit
  set +e
  output="$("$planner" --output-dir "$output_dir" "$@" 2>&1)"
  actual_exit=$?
  set -e

  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    record_failure "${case_name} exit ${actual_exit}, expected ${expected_exit}"
    printf '%s\n' "$output" >&2
    return 1
  fi

  test -s "${output_dir}/sticky_worker_warm_target_plan.json"
  test -s "${output_dir}/sticky_worker_warm_target_summary.md"
  test -s "${output_dir}/commands.txt"
  test -s "${output_dir}/events.jsonl"
  record_pass "$case_name"
}

run_selftest() {
  local tmp_parent tmp_root fixture_dir target_dir
  local sticky_dir fallback_dir conflict_dir fail_closed_dir

  run_check
  tmp_parent="${STICKY_WORKER_WARM_TARGET_LEASE_PLANNER_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/sticky-worker-warm-target.XXXXXX")"
  fixture_dir="${tmp_root}/fixtures"
  mkdir -p "$fixture_dir"
  target_dir="/tmp/rch_target_franken_engine_bd_lviqm_sticky"

  write_manifest "${fixture_dir}/suite_manifest.json" "$target_dir"
  write_sticky_state "${fixture_dir}/sticky_state.json" "vmi1156319" "$target_dir"

  write_workers "${fixture_dir}/workers-sticky.json" "idle" "idle"
  sticky_dir="${tmp_root}/sticky"
  run_case "same-worker-reuse" 0 "$sticky_dir" \
    --agent-id CyanOak \
    --bead-id bd-lviqm \
    --suite-manifest-json "${fixture_dir}/suite_manifest.json" \
    --sticky-worker-state-json "${fixture_dir}/sticky_state.json" \
    --rch-workers-json "${fixture_dir}/workers-sticky.json"
  jq -e '
    .plan_decision == "admit_sticky"
    and .assigned_worker_id == "vmi1156319"
    and .assigned_target_dir == "/tmp/rch_target_franken_engine_bd_lviqm_sticky"
    and (.phase_plans | length == 3)
    and (all(.phase_plans[]; .assigned_worker_id == "vmi1156319"))
    and (all(.phase_plans[]; .assigned_target_dir == "/tmp/rch_target_franken_engine_bd_lviqm_sticky"))
    and ([.phase_plans[].command_class] | sort == ["check","clippy","test"])
    and (.hash_basis.input_hash | length == 64)
    and (.hash_basis.plan_hash | length == 64)
  ' "${sticky_dir}/sticky_worker_warm_target_plan.json" >/dev/null
  record_pass "same-worker reuse assertions"

  write_workers "${fixture_dir}/workers-fallback.json" "busy" "idle"
  fallback_dir="${tmp_root}/fallback"
  run_case "worker-unavailable-fallback" 0 "$fallback_dir" \
    --agent-id CyanOak \
    --bead-id bd-lviqm \
    --suite-manifest-json "${fixture_dir}/suite_manifest.json" \
    --sticky-worker-state-json "${fixture_dir}/sticky_state.json" \
    --rch-workers-json "${fixture_dir}/workers-fallback.json"
  jq -e '
    .plan_decision == "admit_fallback_worker"
    and .assigned_worker_id == "vmi1167313"
    and (.assigned_target_dir | contains("vmi1167313"))
    and (.phase_plans | length == 3)
    and (all(.phase_plans[]; .assigned_worker_id == "vmi1167313"))
  ' "${fallback_dir}/sticky_worker_warm_target_plan.json" >/dev/null
  record_pass "worker unavailable fallback assertions"

  jq -n \
    --arg target_dir "$target_dir" '
    {
      reservations: [
        {
          target_dir: $target_dir,
          agent_id: "ScarletOwl",
          bead_id: "bd-other",
          exclusive: true
        }
      ]
    }
  ' >"${fixture_dir}/target-conflict.json"
  write_workers "${fixture_dir}/workers-conflict.json" "idle" "idle"
  conflict_dir="${tmp_root}/conflict"
  run_case "conflicting-target-dir-holder" 75 "$conflict_dir" \
    --agent-id CyanOak \
    --bead-id bd-lviqm \
    --suite-manifest-json "${fixture_dir}/suite_manifest.json" \
    --sticky-worker-state-json "${fixture_dir}/sticky_state.json" \
    --rch-workers-json "${fixture_dir}/workers-conflict.json" \
    --reservation-snapshot-json "${fixture_dir}/target-conflict.json"
  jq -e '
    .plan_decision == "defer_conflicting_target_dir"
    and .assigned_worker_id == null
    and .assigned_target_dir == null
    and (.safe_alternatives | length >= 2)
  ' "${conflict_dir}/sticky_worker_warm_target_plan.json" >/dev/null
  record_pass "conflicting target-dir holder assertions"

  jq -n '
    {
      markers: [
        {
          suite_id: "semantic-dark-matter-pipeline",
          command_id: "test-1",
          detected: true,
          marker: "[RCH] local"
        }
      ]
    }
  ' >"${fixture_dir}/fallback-markers.json"
  fail_closed_dir="${tmp_root}/fail-closed"
  run_case "rejected-local-fallback-marker" 42 "$fail_closed_dir" \
    --agent-id CyanOak \
    --bead-id bd-lviqm \
    --suite-manifest-json "${fixture_dir}/suite_manifest.json" \
    --sticky-worker-state-json "${fixture_dir}/sticky_state.json" \
    --rch-workers-json "${fixture_dir}/workers-sticky.json" \
    --local-fallback-markers-json "${fixture_dir}/fallback-markers.json"
  jq -e '
    .plan_decision == "fail_closed"
    and .local_fallback_marker_count == 1
    and .phase_plans == []
  ' "${fail_closed_dir}/sticky_worker_warm_target_plan.json" >/dev/null
  record_pass "rejected local-fallback marker assertions"

  printf 'sticky_worker_warm_target_lease_planner_smoke_artifacts=%s\n' "$tmp_root"
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
