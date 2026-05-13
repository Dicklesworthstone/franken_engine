#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
runner_script="${root_dir}/scripts/rch_all_target_cargo_proof_shard_runner.sh"
tmp_root="${TMPDIR:-/tmp}/franken-engine-rch-shard-runner-smoke-$(date -u +%Y%m%dT%H%M%SZ)-$$"
fake_bin="${tmp_root}/bin"
mkdir -p "$fake_bin"

record_pass() {
  printf 'PASS rch-all-target-cargo-proof-shard-runner %s\n' "$1"
}

record_failure() {
  printf 'FAIL rch-all-target-cargo-proof-shard-runner %s\n' "$1" >&2
  printf 'smoke artifacts: %s\n' "$tmp_root" >&2
  exit 1
}

cat >"${fake_bin}/rch" <<'FAKE_RCH'
#!/usr/bin/env bash
if [[ "${1:-}" == "diagnose" ]]; then
  selected="${FAKE_RCH_DIAGNOSE_WORKER:-vmi-good}"
  cat <<JSON
{
  "api_version": "1.0",
  "command": "diagnose",
  "success": true,
  "data": {
    "worker_selection": {
      "worker": { "id": "${selected}" },
      "reason": "success"
    }
  }
}
JSON
  exit "${FAKE_RCH_DIAGNOSE_STATUS:-0}"
fi

if [[ "${1:-}" == "--json" && "${2:-}" == "status" ]]; then
  cat <<'JSON'
{
  "api_version": "1.0",
  "command": "status",
  "success": true,
  "data": {
    "daemon": {
      "workers": [
        {
          "id": "vmi-good",
          "status": "healthy",
          "used_slots": 0,
          "total_slots": 8,
          "pressure_state": "healthy",
          "pressure_reason_code": "pressure_healthy",
          "pressure_policy_rule": "all_pressure_rules_within_threshold",
          "pressure_disk_free_gb": 200,
          "pressure_disk_free_ratio": 0.5,
          "pressure_memory_pressure": 0,
          "pressure_telemetry_fresh": true
        },
        {
          "id": "vmi-other",
          "status": "healthy",
          "used_slots": 0,
          "total_slots": 8,
          "pressure_state": "healthy",
          "pressure_reason_code": "pressure_healthy",
          "pressure_policy_rule": "all_pressure_rules_within_threshold",
          "pressure_disk_free_gb": 180,
          "pressure_disk_free_ratio": 0.4,
          "pressure_memory_pressure": 0,
          "pressure_telemetry_fresh": true
        },
        {
          "id": "vmi-critical",
          "status": "healthy",
          "used_slots": 0,
          "total_slots": 8,
          "pressure_state": "critical",
          "pressure_reason_code": "disk_ratio_below_critical",
          "pressure_policy_rule": "disk_free_ratio<=critical_free_ratio",
          "pressure_disk_free_gb": 1,
          "pressure_disk_free_ratio": 0.01,
          "pressure_memory_pressure": 0,
          "pressure_telemetry_fresh": true
        }
      ]
    }
  }
}
JSON
  exit "${FAKE_RCH_STATUS_STATUS:-0}"
fi

if [[ "${1:-}" == "exec" ]]; then
  if [[ -n "${FAKE_RCH_EXEC_MARKER:-}" ]]; then
    printf 'exec\n' >>"${FAKE_RCH_EXEC_MARKER}"
  fi
  worker="${FAKE_RCH_EXEC_WORKER:-vmi-good}"
  printf 'Remote build #123456789 on %s\n' "$worker"
  printf 'Selected worker: %s at 192.0.2.10 (rust)\n' "$worker"
  if [[ "${FAKE_RCH_LOCAL_FALLBACK:-0}" == "1" ]]; then
    printf '[RCH] local (forced smoke fixture)\n'
    exit 0
  fi
  printf '   Compiling frankenengine-engine v0.1.0 (/data/projects/franken_engine/crates/franken-engine)\n'
  if [[ "${FAKE_RCH_NO_TEST_EXECUTION:-0}" != "1" ]]; then
    printf '    Finished `test` profile [unoptimized + debuginfo] target(s) in 1.00s\n'
    printf '     Running unittests src/lib.rs\n\n'
    printf 'running 1 test\n'
    printf 'test fake::test_executes ... ok\n\n'
    printf 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n'
  fi
  exit "${FAKE_RCH_EXEC_STATUS:-0}"
fi

printf 'unexpected fake rch invocation: %s\n' "$*" >&2
exit 99
FAKE_RCH
chmod +x "${fake_bin}/rch"

manifest_path="${tmp_root}/manifest.json"
cat >"$manifest_path" <<'MANIFEST'
{
  "schema_version": "franken-engine.all-target-cargo-proof-shard-manifest.v1",
  "decision": "pass",
  "shards": [
    {
      "shard_id": "cargo-proof-lib_test_fake",
      "lane": "lib_test",
      "package": "frankenengine-engine",
      "target_name": null,
      "target_kind": "lib",
      "command": "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_fake CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p frankenengine-engine --lib fake::test_executes -- --nocapture",
      "target_dir": "/tmp/rch_target_fake",
      "expected_artifacts": ["lib-test.log"],
      "rch_policy": {
        "direct_rch_exec": true,
        "requires_cargo_target_dir": true,
        "rejects_local_fallback": true,
        "requires_worker_selection_preflight": true,
        "requires_worker_pressure_snapshot": true,
        "rejects_critical_worker_pressure": true,
        "executes_now": false
      },
      "preflight": {
        "diagnose_command": "rch diagnose --json -- env CARGO_TARGET_DIR=/tmp/rch_target_fake CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p frankenengine-engine --lib fake::test_executes -- --nocapture",
        "worker_status_command": "rch --json status --workers --jobs",
        "selected_worker_json_path": ".data.worker_selection.worker.id",
        "worker_status_json_path": ".data.daemon.workers[]",
        "fail_closed_pressure_states": ["critical"],
        "fail_closed_pressure_reason_pattern": "critical",
        "required_artifacts": ["worker-diagnose.json", "worker-pressure-status.json", "cargo-output.log"]
      }
    }
  ]
}
MANIFEST

runner() {
  PATH="${fake_bin}:${PATH}" "$runner_script" --manifest "$manifest_path" --shard-id cargo-proof-lib_test_fake "$@"
}

preflight_dir="${tmp_root}/preflight"
FAKE_RCH_EXEC_MARKER="${tmp_root}/preflight-exec.marker" \
  runner --output-dir "$preflight_dir" >/dev/null
jq -e '.decision == "pass" and .reason == "preflight_only" and .selected_worker == "vmi-good"' \
  "${preflight_dir}/result.json" >/dev/null || record_failure "preflight result"
[[ ! -f "${tmp_root}/preflight-exec.marker" ]] || record_failure "preflight unexpectedly executed shard"
record_pass "preflight_only"

execute_dir="${tmp_root}/execute"
FAKE_RCH_EXEC_MARKER="${tmp_root}/execute-exec.marker" \
  runner --output-dir "$execute_dir" --execute --timeout-seconds 30 >/dev/null
jq -e '.decision == "pass" and .reason == "remote_execution_passed" and .execution_worker == "vmi-good" and .rch_build_id == "123456789"' \
  "${execute_dir}/result.json" >/dev/null || record_failure "execute result"
grep -q 'running 1 test' "${execute_dir}/cargo-output.log" || record_failure "execute test output"
grep -q '^remote_keepalive_seconds=0$' "${execute_dir}/commands.txt" || record_failure "default remote keepalive disabled"
if grep -q '^executed_command=' "${execute_dir}/commands.txt"; then
  record_failure "default keepalive unexpectedly wrapped command"
fi
record_pass "execute_success"

keepalive_enabled_dir="${tmp_root}/keepalive-enabled"
runner --output-dir "$keepalive_enabled_dir" --execute --timeout-seconds 30 --remote-keepalive-seconds 60 >/dev/null
jq -e '.decision == "pass" and .reason == "remote_execution_passed" and .execution_worker == "vmi-good"' \
  "${keepalive_enabled_dir}/result.json" >/dev/null || record_failure "keepalive enabled result"
grep -q '^remote_keepalive_seconds=60$' "${keepalive_enabled_dir}/commands.txt" || record_failure "enabled remote keepalive recorded"
grep -Eq '^executed_command=.*RUSTC_WRAPPER=.*rch_all_target_cargo_proof_shard_runner[.]sh.* cargo test' \
  "${keepalive_enabled_dir}/commands.txt" || record_failure "instrumented execute command recorded"
record_pass "remote_keepalive_enable"

keepalive_disabled_dir="${tmp_root}/keepalive-disabled"
runner --output-dir "$keepalive_disabled_dir" --execute --timeout-seconds 30 --remote-keepalive-seconds 0 >/dev/null
jq -e '.decision == "pass" and .reason == "remote_execution_passed" and .execution_worker == "vmi-good"' \
  "${keepalive_disabled_dir}/result.json" >/dev/null || record_failure "keepalive disabled result"
grep -q '^remote_keepalive_seconds=0$' "${keepalive_disabled_dir}/commands.txt" || record_failure "disabled remote keepalive recorded"
if grep -q '^executed_command=' "${keepalive_disabled_dir}/commands.txt"; then
  record_failure "disabled keepalive unexpectedly wrapped command"
fi
record_pass "remote_keepalive_disable"

critical_dir="${tmp_root}/critical"
set +e
FAKE_RCH_DIAGNOSE_WORKER=vmi-critical \
FAKE_RCH_EXEC_MARKER="${tmp_root}/critical-exec.marker" \
  runner --output-dir "$critical_dir" --execute --timeout-seconds 30 >/dev/null 2>"${critical_dir}.stderr"
critical_status=$?
set -e
[[ "$critical_status" -eq 42 ]] || record_failure "critical pressure exit ${critical_status}"
jq -e '.decision == "fail_closed" and .reason == "worker_pressure_preflight_critical"' \
  "${critical_dir}/result.json" >/dev/null || record_failure "critical pressure result"
[[ ! -f "${tmp_root}/critical-exec.marker" ]] || record_failure "critical preflight unexpectedly executed shard"
record_pass "critical_pressure_fail_closed"

drift_dir="${tmp_root}/drift"
set +e
FAKE_RCH_EXEC_WORKER=vmi-other \
  runner --output-dir "$drift_dir" --execute --timeout-seconds 30 >/dev/null 2>"${drift_dir}.stderr"
drift_status=$?
set -e
[[ "$drift_status" -eq 68 ]] || record_failure "worker drift exit ${drift_status}"
jq -e '.decision == "fail_closed" and .reason == "execution_worker_drift" and .selected_worker == "vmi-good" and .execution_worker == "vmi-other"' \
  "${drift_dir}/result.json" >/dev/null || record_failure "worker drift result"
record_pass "worker_drift_fail_closed"

fallback_dir="${tmp_root}/fallback"
set +e
FAKE_RCH_LOCAL_FALLBACK=1 \
  runner --output-dir "$fallback_dir" --execute --timeout-seconds 30 >/dev/null 2>"${fallback_dir}.stderr"
fallback_status=$?
set -e
[[ "$fallback_status" -eq 67 ]] || record_failure "local fallback exit ${fallback_status}"
jq -e '.decision == "fail_closed" and .reason == "rch_local_fallback_detected"' \
  "${fallback_dir}/result.json" >/dev/null || record_failure "local fallback result"
record_pass "local_fallback_fail_closed"

no_test_dir="${tmp_root}/no-test"
set +e
FAKE_RCH_NO_TEST_EXECUTION=1 \
  runner --output-dir "$no_test_dir" --execute --timeout-seconds 30 >/dev/null 2>"${no_test_dir}.stderr"
no_test_status=$?
set -e
[[ "$no_test_status" -eq 69 ]] || record_failure "missing test execution exit ${no_test_status}"
jq -e '.decision == "fail_closed" and .reason == "test_execution_not_observed"' \
  "${no_test_dir}/result.json" >/dev/null || record_failure "missing test execution result"
record_pass "missing_test_execution_fail_closed"

remote_failure_dir="${tmp_root}/remote-failure"
set +e
FAKE_RCH_EXEC_STATUS=101 \
  runner --output-dir "$remote_failure_dir" --execute --timeout-seconds 30 >/dev/null 2>"${remote_failure_dir}.stderr"
remote_failure_status=$?
set -e
[[ "$remote_failure_status" -eq 101 ]] || record_failure "remote failure exit ${remote_failure_status}"
jq -e '.decision == "remote_failure" and .reason == "remote_command_failed" and .exit_code == 101' \
  "${remote_failure_dir}/result.json" >/dev/null || record_failure "remote failure result"
record_pass "remote_failure_propagates"

terminated_dir="${tmp_root}/terminated"
set +e
FAKE_RCH_EXEC_STATUS=15 \
  runner --output-dir "$terminated_dir" --execute --timeout-seconds 30 >/dev/null 2>"${terminated_dir}.stderr"
terminated_status=$?
set -e
[[ "$terminated_status" -eq 15 ]] || record_failure "terminated exit ${terminated_status}"
jq -e '.decision == "remote_failure" and .reason == "remote_command_terminated" and .exit_code == 15 and .rch_build_id == "123456789"' \
  "${terminated_dir}/result.json" >/dev/null || record_failure "terminated result"
record_pass "remote_command_terminated_classified"

printf 'rch all-target cargo proof shard runner smoke passed\n'
printf 'smoke artifacts: %s\n' "$tmp_root"
