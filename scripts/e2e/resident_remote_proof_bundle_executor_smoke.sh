#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
executor="${root_dir}/scripts/resident_remote_proof_bundle_executor.sh"
docs_path="${root_dir}/docs/RESIDENT_REMOTE_PROOF_BUNDLE_EXECUTOR.md"
contract_path="${root_dir}/docs/resident_remote_proof_bundle_contract_v1.json"

record_pass() {
  printf 'PASS resident-remote-proof-bundle %s\n' "$1"
}

record_failure() {
  printf 'FAIL resident-remote-proof-bundle %s\n' "$1" >&2
}

write_manifest() {
  local path="$1"
  local worker_id="$2"
  local target_dir="$3"

  jq -n \
    --arg worker_id "$worker_id" \
    --arg target_dir "$target_dir" '
    {
      schema_version: "franken-engine.resident-remote-proof-phase-manifest.v1",
      bundle_id: "semantic-dark-matter-resident-proof",
      expected_worker_id: $worker_id,
      expected_target_dir: $target_dir,
      phases: [
        {
          phase: "check",
          command_id: "check-1",
          requested_command: ("rch exec -- env CARGO_TARGET_DIR=" + $target_dir + " cargo check -p frankenengine-engine --test semantic_dark_matter_engine_integration"),
          required_artifacts: ["run_manifest.json", "events.jsonl", "commands.txt"]
        },
        {
          phase: "test",
          command_id: "test-1",
          requested_command: ("rch exec -- env CARGO_TARGET_DIR=" + $target_dir + " cargo test -p frankenengine-engine --test semantic_dark_matter_engine_integration -- --nocapture"),
          required_artifacts: ["run_manifest.json", "events.jsonl", "commands.txt"]
        },
        {
          phase: "clippy",
          command_id: "clippy-1",
          requested_command: ("rch exec -- env CARGO_TARGET_DIR=" + $target_dir + " cargo clippy -p frankenengine-engine --test semantic_dark_matter_engine_integration -- -D warnings"),
          required_artifacts: ["run_manifest.json", "events.jsonl", "commands.txt"]
        }
      ]
    }
  ' >"$path"
}

write_success_receipts() {
  local path="$1"
  local worker_id="$2"
  local target_dir="$3"

  jq -n \
    --arg worker_id "$worker_id" \
    --arg target_dir "$target_dir" '
    {
      schema_version: "franken-engine.resident-remote-proof-phase-receipts.v1",
      receipts: [
        {
          phase: "check",
          command_id: "check-1",
          worker_id: $worker_id,
          target_dir: $target_dir,
          exit_code: 0,
          completion_marker: "present",
          stdout: ("[RCH] remote " + $worker_id + "\nREMOTE_PROOF_PHASE_COMPLETE check"),
          stderr: ""
        },
        {
          phase: "test",
          command_id: "test-1",
          worker_id: $worker_id,
          target_dir: $target_dir,
          exit_code: 0,
          completion_marker: "present",
          stdout: ("[RCH] remote " + $worker_id + "\nREMOTE_PROOF_PHASE_COMPLETE test"),
          stderr: ""
        },
        {
          phase: "clippy",
          command_id: "clippy-1",
          worker_id: $worker_id,
          target_dir: $target_dir,
          exit_code: 0,
          completion_marker: "present",
          stdout: ("[RCH] remote " + $worker_id + "\nREMOTE_PROOF_PHASE_COMPLETE clippy"),
          stderr: ""
        }
      ]
    }
  ' >"$path"
}

run_check() {
  local scope_file

  bash -n "$executor"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$contract_path"
  grep -q 'franken-engine.resident-remote-proof-bundle.v1' "$docs_path"
  grep -q 'rch exec -- env CARGO_TARGET_DIR=' "$docs_path"
  record_pass "bash syntax and docs contract"

  scope_file="$(mktemp "${TMPDIR:-/tmp}/resident-remote-proof-bundle-scope.XXXXXX")"
  printf '%s\n' \
    "scripts/resident_remote_proof_bundle_executor.sh" \
    "scripts/e2e/resident_remote_proof_bundle_executor_smoke.sh" \
    "docs/RESIDENT_REMOTE_PROOF_BUNDLE_EXECUTOR.md" \
    "docs/resident_remote_proof_bundle_contract_v1.json" >"$scope_file"
  "${root_dir}/scripts/rch_policy_compliance_gate.sh" \
    --output-dir "${TMPDIR:-/tmp}/resident-remote-proof-bundle-rch-policy" \
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
  output="$("$executor" --output-dir "$output_dir" "$@" 2>&1)"
  actual_exit=$?
  set -e

  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    record_failure "${case_name} exit ${actual_exit}, expected ${expected_exit}"
    printf '%s\n' "$output" >&2
    return 1
  fi

  test -s "${output_dir}/bundle_report.json"
  test -s "${output_dir}/run_manifest.json"
  test -s "${output_dir}/commands.txt"
  test -s "${output_dir}/events.jsonl"
  test -s "${output_dir}/summary.md"
  test -s "${output_dir}/phase_logs/check-1.stdout.log"
  record_pass "$case_name"
}

run_selftest() {
  local tmp_parent tmp_root fixture_dir target_dir worker_id
  local success_dir drift_dir target_drift_dir fallback_dir

  run_check
  tmp_parent="${RESIDENT_REMOTE_PROOF_BUNDLE_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/resident-remote-proof-bundle.XXXXXX")"
  fixture_dir="${tmp_root}/fixtures"
  mkdir -p "$fixture_dir"
  worker_id="vmi1156319"
  target_dir="/tmp/rch_target_franken_engine_bd_doi34_bundle"

  write_manifest "${fixture_dir}/phase_manifest.json" "$worker_id" "$target_dir"
  write_success_receipts "${fixture_dir}/receipts-success.json" "$worker_id" "$target_dir"

  success_dir="${tmp_root}/success"
  run_case "same-worker-same-target-success" 0 "$success_dir" \
    --agent-id ScarletOwl \
    --bead-id bd-doi34 \
    --phase-manifest-json "${fixture_dir}/phase_manifest.json" \
    --phase-receipts-json "${fixture_dir}/receipts-success.json"
  jq -e \
    --arg worker_id "$worker_id" \
    --arg target_dir "$target_dir" '
    .bundle_decision == "pass"
    and .expected_worker_id == $worker_id
    and .expected_target_dir == $target_dir
    and (.phase_results | length == 3)
    and (all(.phase_results[]; .worker_id == $worker_id))
    and (all(.phase_results[]; .target_dir == $target_dir))
    and ([.phase_results[].command_class] | sort == ["check","clippy","test"])
    and (.hash_basis.input_hash | length == 64)
    and (.hash_basis.bundle_hash | length == 64)
  ' "${success_dir}/bundle_report.json" >/dev/null
  record_pass "same-worker same-target success assertions"

  jq \
    '.receipts[2].worker_id = "vmi1167313"' \
    "${fixture_dir}/receipts-success.json" >"${fixture_dir}/receipts-worker-drift.json"
  drift_dir="${tmp_root}/worker-drift"
  run_case "worker-drift-fail-closed" 42 "$drift_dir" \
    --agent-id ScarletOwl \
    --bead-id bd-doi34 \
    --phase-manifest-json "${fixture_dir}/phase_manifest.json" \
    --phase-receipts-json "${fixture_dir}/receipts-worker-drift.json"
  jq -e '
    .bundle_decision == "fail_closed"
    and .reason == "phase receipts show worker identity drift"
    and (.worker_drift_receipts | length == 1)
  ' "${drift_dir}/bundle_report.json" >/dev/null
  record_pass "worker drift fail-closed assertions"

  jq \
    '.receipts[1].target_dir = "/tmp/rch_target_franken_engine_other_bundle"' \
    "${fixture_dir}/receipts-success.json" >"${fixture_dir}/receipts-target-drift.json"
  target_drift_dir="${tmp_root}/target-drift"
  run_case "target-dir-drift-fail-closed" 42 "$target_drift_dir" \
    --agent-id ScarletOwl \
    --bead-id bd-doi34 \
    --phase-manifest-json "${fixture_dir}/phase_manifest.json" \
    --phase-receipts-json "${fixture_dir}/receipts-target-drift.json"
  jq -e '
    .bundle_decision == "fail_closed"
    and .reason == "phase receipts show CARGO_TARGET_DIR drift"
    and (.target_dir_drift_receipts | length == 1)
  ' "${target_drift_dir}/bundle_report.json" >/dev/null
  record_pass "target-dir drift fail-closed assertions"

  jq \
    '.receipts[0].stderr = "[RCH] local fallback marker: running locally"' \
    "${fixture_dir}/receipts-success.json" >"${fixture_dir}/receipts-rch-fallback-marker.json"
  fallback_dir="${tmp_root}/fallback-marker"
  run_case "local-fallback-fail-closed" 42 "$fallback_dir" \
    --agent-id ScarletOwl \
    --bead-id bd-doi34 \
    --phase-manifest-json "${fixture_dir}/phase_manifest.json" \
    --phase-receipts-json "${fixture_dir}/receipts-rch-fallback-marker.json"
  jq -e '
    .bundle_decision == "fail_closed"
    and .reason == "rch local fallback marker detected in phase output"
    and (.local_fallback_marker_receipts | length == 1)
  ' "${fallback_dir}/bundle_report.json" >/dev/null
  record_pass "local fallback fail-closed assertions"

  printf 'resident_remote_proof_bundle_executor_smoke_artifacts=%s\n' "$tmp_root"
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
