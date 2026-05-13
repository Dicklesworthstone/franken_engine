#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
tmp_root="${TMPDIR:-/tmp}/franken-engine-lib-unit-smoke-gate-${timestamp}-$$"
good_dir="${tmp_root}/good"
bad_dir="${tmp_root}/bad"
exec_dir="${tmp_root}/exec"
failure_dir="${tmp_root}/failure"
mkdir -p "$good_dir" "$bad_dir" "$exec_dir" "$failure_dir"

cat >"${good_dir}/cargo-output.log" <<'GOOD_LOG'
Selected worker: vmi-good at 192.0.2.10 (rust)
INFO rch::transfer: Syncing /data/projects/franken_engine/crates/franken-engine-test-support -> /data/projects/franken_engine/crates/franken-engine-test-support on worker
   Compiling frankenengine-extension-host v0.1.0 (/data/projects/franken_engine/crates/franken-extension-host)
   Compiling frankenengine-engine v0.1.0 (/data/projects/franken_engine/crates/franken-engine)
GOOD_LOG

cat >"${bad_dir}/cargo-output.log" <<'BAD_LOG'
Selected worker: vmi-bad at 192.0.2.11 (rust)
   Compiling frankenengine-test-support v0.1.0 (/data/projects/franken_engine/crates/franken-engine-test-support)
BAD_LOG

cat >"${exec_dir}/cargo-output.log" <<'EXEC_LOG'
Selected worker: vmi-good at 192.0.2.10 (rust)
   Compiling frankenengine-engine v0.1.0 (/data/projects/franken_engine/crates/franken-engine)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 1.00s
     Running unittests src/lib.rs

running 1 test
test recovery_artifact::tests::verify_uses_constant_time_signature_comparison ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 101 filtered out; finished in 0.00s
EXEC_LOG

cat >"${bad_dir}/no-execution.log" <<'NO_EXEC_LOG'
Selected worker: vmi-good at 192.0.2.10 (rust)
   Compiling frankenengine-engine v0.1.0 (/data/projects/franken_engine/crates/franken-engine)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 1.00s
NO_EXEC_LOG

cat >"${good_dir}/wrapped.sh" <<'GOOD_SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
RCH_BIN="${RCH_BIN:-rch}"
"$RCH_BIN" exec -- env \
  "RUSTUP_TOOLCHAIN=nightly" \
  "CARGO_TARGET_DIR=/tmp/rch_target_good" \
  cargo test -p frankenengine-engine --lib some::unit::test --no-run
GOOD_SCRIPT

cat >"${bad_dir}/bare.sh" <<'BAD_SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
cargo test -p frankenengine-engine --lib some::unit::test --no-run
BAD_SCRIPT

cat >"${failure_dir}/fake-rch" <<'FAKE_RCH'
#!/usr/bin/env bash
echo "fake rch failure"
exit 42
FAKE_RCH
chmod +x "${failure_dir}/fake-rch"

cat >"${failure_dir}/fake-rch-diagnose" <<'FAKE_RCH_DIAGNOSE'
#!/usr/bin/env bash
if [[ "${1:-}" == "diagnose" ]]; then
  if [[ -n "${FAKE_RCH_ENV_LOG:-}" ]]; then
    printf '%s\n' "${RCH_WORKERS:-}" >"${FAKE_RCH_ENV_LOG}"
  fi
  cat <<'JSON'
{
  "api_version": "1.0",
  "command": "diagnose",
  "success": true,
  "data": {
    "worker_selection": {
      "worker": {
        "id": "vmi-other"
      },
      "reason": "success"
    }
  }
}
JSON
  exit 0
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
          "used_slots": 4,
          "total_slots": 8,
          "pressure_state": "healthy",
          "pressure_reason_code": "pressure_healthy"
        },
        {
          "id": "vmi-other",
          "status": "healthy",
          "used_slots": 0,
          "total_slots": 8,
          "pressure_state": "healthy",
          "pressure_reason_code": "pressure_healthy"
        }
      ]
    }
  }
}
JSON
  exit 0
fi
echo "unexpected fake rch invocation: $*" >&2
exit 99
FAKE_RCH_DIAGNOSE
chmod +x "${failure_dir}/fake-rch-diagnose"

cat >"${failure_dir}/native-route-advisory.json" <<'NATIVE_ROUTE_ADVISORY'
{
  "schema_version": "franken-engine.native-dependency-route-planner.output.v1",
  "decision": "pass",
  "truth_state": "confirmed",
  "compatible_worker_ids": ["vmi-good"],
  "reason_codes": ["compatible_worker_available", "hdf5_present"]
}
NATIVE_ROUTE_ADVISORY

"${repo_root}/scripts/rch_engine_lib_unit_smoke_gate.sh" --scan-log "${good_dir}/cargo-output.log" >/dev/null
"${repo_root}/scripts/rch_engine_lib_unit_smoke_gate.sh" --check-script "${good_dir}/wrapped.sh" >/dev/null
FRANKEN_ENGINE_LIB_UNIT_EXPECTED_WORKER=vmi-good \
  "${repo_root}/scripts/rch_engine_lib_unit_smoke_gate.sh" --scan-log "${good_dir}/cargo-output.log" >/dev/null

if ! "${repo_root}/scripts/rch_engine_lib_unit_smoke_gate.sh" --print-command | grep -q 'rch exec -- env'; then
  echo "expected printed command to use rch exec -- env" >&2
  echo "smoke artifacts: ${tmp_root}" >&2
  exit 1
fi

if ! "${repo_root}/scripts/rch_engine_lib_unit_smoke_gate.sh" --print-execute-command | grep -q -- '-- --nocapture'; then
  echo "expected printed execute command to run the filtered test" >&2
  echo "smoke artifacts: ${tmp_root}" >&2
  exit 1
fi

if FRANKEN_ENGINE_LIB_UNIT_EXPECTED_WORKER=vmi-other \
  "${repo_root}/scripts/rch_engine_lib_unit_smoke_gate.sh" --scan-log "${good_dir}/cargo-output.log" >"${tmp_root}/bad-worker.stdout" 2>"${tmp_root}/bad-worker.stderr"; then
  echo "expected wrong selected worker fixture to fail" >&2
  echo "smoke artifacts: ${tmp_root}" >&2
  exit 1
fi

if ! grep -q 'unexpected_worker_selected' "${tmp_root}/bad-worker.stdout"; then
  echo "expected wrong selected worker diagnostic not found" >&2
  echo "smoke artifacts: ${tmp_root}" >&2
  exit 1
fi

if "${repo_root}/scripts/rch_engine_lib_unit_smoke_gate.sh" --scan-log "${bad_dir}/cargo-output.log" >"${tmp_root}/bad-log.stdout" 2>"${tmp_root}/bad-log.stderr"; then
  echo "expected forbidden support dependency fixture to fail" >&2
  echo "smoke artifacts: ${tmp_root}" >&2
  exit 1
fi

if ! grep -q 'forbidden_support_dependency' "${tmp_root}/bad-log.stdout"; then
  echo "expected support dependency diagnostic not found" >&2
  echo "smoke artifacts: ${tmp_root}" >&2
  exit 1
fi

if "${repo_root}/scripts/rch_engine_lib_unit_smoke_gate.sh" --check-script "${bad_dir}/bare.sh" >"${tmp_root}/bad-script.stdout" 2>"${tmp_root}/bad-script.stderr"; then
  echo "expected bare cargo fixture to fail" >&2
  echo "smoke artifacts: ${tmp_root}" >&2
  exit 1
fi

if ! grep -q 'bare Cargo command must be routed through rch exec' "${tmp_root}/bad-script.stderr"; then
  echo "expected bare cargo diagnostic not found" >&2
  echo "smoke artifacts: ${tmp_root}" >&2
  exit 1
fi

if ! "${repo_root}/scripts/rch_engine_lib_unit_smoke_gate.sh" --scan-execution-log "${exec_dir}/cargo-output.log" >/dev/null; then
  echo "expected execution fixture to pass" >&2
  echo "smoke artifacts: ${tmp_root}" >&2
  exit 1
fi

if "${repo_root}/scripts/rch_engine_lib_unit_smoke_gate.sh" --scan-execution-log "${bad_dir}/no-execution.log" >"${tmp_root}/bad-exec.stdout" 2>"${tmp_root}/bad-exec.stderr"; then
  echo "expected no-execution fixture to fail" >&2
  echo "smoke artifacts: ${tmp_root}" >&2
  exit 1
fi

if ! grep -q 'test_execution_not_observed' "${tmp_root}/bad-exec.stdout"; then
  echo "expected no-execution diagnostic not found" >&2
  echo "smoke artifacts: ${tmp_root}" >&2
  exit 1
fi

if RCH_BIN="${failure_dir}/fake-rch-diagnose" \
  FRANKEN_ENGINE_LIB_UNIT_EXPECTED_WORKER=vmi-good \
  FRANKEN_ENGINE_LIB_UNIT_SMOKE_ARTIFACT_ROOT="${failure_dir}/preflight-artifacts" \
  "${repo_root}/scripts/rch_engine_lib_unit_smoke_gate.sh" run >"${failure_dir}/preflight-fail.stdout" 2>"${failure_dir}/preflight-fail.stderr"; then
  echo "expected diagnose worker mismatch to fail before compile" >&2
  echo "smoke artifacts: ${tmp_root}" >&2
  exit 1
fi

if ! grep -q 'expected_worker_preflight_mismatch' "${failure_dir}/preflight-fail.stdout"; then
  echo "expected diagnose worker mismatch diagnostic not found" >&2
  echo "smoke artifacts: ${tmp_root}" >&2
  exit 1
fi

if RCH_BIN="${failure_dir}/fake-rch-diagnose" \
  FRANKEN_ENGINE_LIB_UNIT_NATIVE_ROUTE_ADVISORY_JSON="${failure_dir}/native-route-advisory.json" \
  FRANKEN_ENGINE_LIB_UNIT_SMOKE_ARTIFACT_ROOT="${failure_dir}/native-route-artifacts" \
  "${repo_root}/scripts/rch_engine_lib_unit_smoke_gate.sh" run >"${failure_dir}/native-route-fail.stdout" 2>"${failure_dir}/native-route-fail.stderr"; then
  echo "expected native-route worker mismatch to fail before compile" >&2
  echo "smoke artifacts: ${tmp_root}" >&2
  exit 1
fi

if ! grep -q 'native_route_preflight_incompatible_worker' "${failure_dir}/native-route-fail.stdout"; then
  echo "expected native-route worker diagnostic not found" >&2
  echo "smoke artifacts: ${tmp_root}" >&2
  exit 1
fi
if ! grep -q 'compatible_context=vmi-good:status=healthy,slots=4/8,pressure=healthy,reason=pressure_healthy' "${failure_dir}/native-route-fail.stdout"; then
  echo "expected native-route compatible worker status context not found" >&2
  echo "smoke artifacts: ${tmp_root}" >&2
  exit 1
fi

if RCH_BIN="${failure_dir}/fake-rch-diagnose" \
  FAKE_RCH_ENV_LOG="${failure_dir}/native-route-env.log" \
  FRANKEN_ENGINE_LIB_UNIT_NATIVE_ROUTE_ADVISORY_JSON="${failure_dir}/native-route-advisory.json" \
  FRANKEN_ENGINE_LIB_UNIT_SMOKE_ARTIFACT_ROOT="${failure_dir}/native-route-env-artifacts" \
  "${repo_root}/scripts/rch_engine_lib_unit_smoke_gate.sh" run >"${failure_dir}/native-route-env-fail.stdout" 2>"${failure_dir}/native-route-env-fail.stderr"; then
  echo "expected native-route env fixture to fail on fake selected worker" >&2
  echo "smoke artifacts: ${tmp_root}" >&2
  exit 1
fi

if [[ "$(cat "${failure_dir}/native-route-env.log")" != "vmi-good" ]]; then
  echo "expected native-route compatible workers to be passed as RCH_WORKERS" >&2
  echo "smoke artifacts: ${tmp_root}" >&2
  exit 1
fi

set +e
RCH_BIN="${failure_dir}/fake-rch" \
FRANKEN_ENGINE_LIB_UNIT_SMOKE_ARTIFACT_ROOT="${failure_dir}/artifacts" \
"${repo_root}/scripts/rch_engine_lib_unit_smoke_gate.sh" run >"${failure_dir}/run-fail.stdout" 2>"${failure_dir}/run-fail.stderr"
fake_status=$?
set -e

if [[ "$fake_status" -ne 42 ]]; then
  echo "expected failed rch exit status to propagate, got ${fake_status}" >&2
  echo "smoke artifacts: ${tmp_root}" >&2
  exit 1
fi

if ! grep -q 'result=fail exit_code=42' "${failure_dir}/run-fail.stdout"; then
  echo "expected failed rch diagnostic not found" >&2
  echo "smoke artifacts: ${tmp_root}" >&2
  exit 1
fi

echo "rch engine lib-unit smoke gate smoke passed"
echo "smoke artifacts: ${tmp_root}"
