#!/usr/bin/env bash
# Smoke coverage for the bd-cixqu.14.2 repro.lock verifier environment.

set -euo pipefail

export TZ=UTC
export LC_ALL=C
export LANG=C
export LANGUAGE=C

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ROOT_DIR
cd "${ROOT_DIR}"

readonly VERIFIER="${ROOT_DIR}/scripts/third_party_repro_lock_verifier.sh"
WORK_DIR="$(mktemp -d)"
readonly WORK_DIR

failures=0

pass() { printf 'PASS third-party-repro-lock %s\n' "$1"; }
fail() {
  printf 'FAIL third-party-repro-lock %s\n' "$1" >&2
  failures=$((failures + 1))
}

write_lock_with_replay_sequence() {
  local path="$1"
  local marker="$2"
  jq -n \
    --arg marker "${marker}" \
    '{
      schema_version: "franken-engine.repro-lock.v1",
      schema_hash: "sha256:test",
      generated_at_utc: "2026-05-23T00:00:00Z",
      lock_id: "lock-smoke",
      manifest_id: "manifest-smoke",
      source_commit: "fixture-commit",
      determinism: {
        allow_network: false,
        allow_wall_clock: false,
        allow_randomness: false,
        max_clock_skew_seconds: 0
      },
      commands: ["printf replay-ok > " + $marker],
      inputs: [],
      expected_outputs: [],
      replay: {
        trace_id: "trace-smoke",
        replay_pointer: "replay://smoke"
      },
      verification: {
        command: "printf verifier-ok",
        expected_verdict: "pass"
      }
    }' >"${path}"
}

write_backfilled_shape_lock() {
  local path="$1"
  jq -n '{
    schema_version: "frankenengine.reproducibility.lock.v1",
    schema_hash: "sha256:test",
    generated_at_utc: "2026-05-23T00:00:00.000000+00:00",
    lock_id: "lock-backfilled-smoke",
    manifest_id: "manifest-backfilled-smoke",
    source_commit: "fixture-commit",
    determinism: {
      environment_isolation: "containerized",
      mode: "strict",
      reproducible_builds: true,
      seed_control: "fixed"
    },
    commands: {
      cleanup: "cargo clean",
      environment_setup: "export CARGO_INCREMENTAL=0",
      verification: "./scripts/run_fake_gate.sh ci"
    },
    expected_outputs: {
      deterministic_trace: true,
      evidence_generated: true,
      exit_code: 0,
      verification_success: true
    },
    inputs: {},
    replay: {
      command_sequence: ["./scripts/run_fake_gate.sh ci"],
      environment_vars: {
        CARGO_INCREMENTAL: "0",
        RUSTFLAGS: "-C linker=cc"
      },
      working_directory: "/data/projects/franken_engine"
    },
    verification: {
      freshness_check: "required",
      hash_algorithm: "sha256",
      replay_validation: "automated",
      signature_required: false
    }
  }' >"${path}"
}

assert_plan_report() {
  local report="$1"
  local command="$2"
  if jq -e \
    --arg command "${command}" \
    '.schema_version == "franken-engine.third-party-repro-lock-verifier-report.v1"
     and .component == "third_party_repro_lock_verifier"
     and .verdict == "planned"
     and .deterministic_policy_ok == true
     and .commands[0] == $command' \
    "${report}" >/dev/null; then
    pass "plan report records deterministic replay command"
  else
    fail "plan report missing expected replay command"
  fi
}

plan_mode_accepts_template_shape() {
  local lock="${WORK_DIR}/template-shape.repro.lock"
  local marker="${WORK_DIR}/template-marker.txt"
  local report="${WORK_DIR}/template-report.json"
  write_lock_with_replay_sequence "${lock}" "${marker}"
  if "${VERIFIER}" --lock "${lock}" --report "${report}" --plan-only >/dev/null; then
    assert_plan_report "${report}" "printf replay-ok > ${marker}"
  else
    fail "plan mode should accept template-shaped repro.lock"
  fi
}

plan_mode_accepts_backfilled_shape() {
  local lock="${WORK_DIR}/backfilled.repro.lock"
  local report="${WORK_DIR}/backfilled-report.json"
  write_backfilled_shape_lock "${lock}"
  if "${VERIFIER}" --lock "${lock}" --report "${report}" --plan-only >/dev/null; then
    assert_plan_report "${report}" "./scripts/run_fake_gate.sh ci"
  else
    fail "plan mode should accept backfilled runbook repro.lock shape"
  fi
}

verify_mode_executes_non_cargo_replay_command() {
  local lock="${WORK_DIR}/execute.repro.lock"
  local marker="${WORK_DIR}/execute-marker.txt"
  local report="${WORK_DIR}/execute-report.json"
  write_lock_with_replay_sequence "${lock}" "${marker}"
  if "${VERIFIER}" --lock "${lock}" --report "${report}" >/dev/null \
      && [[ -f "${marker}" ]] \
      && jq -e '.verdict == "pass" and .executed_count == 2' "${report}" >/dev/null; then
    pass "verify mode executes locked non-cargo commands"
  else
    fail "verify mode should execute locked non-cargo commands"
  fi
}

missing_command_fails_closed() {
  local lock="${WORK_DIR}/missing-command.repro.lock"
  local report="${WORK_DIR}/missing-command-report.json"
  jq -n '{
    schema_version: "franken-engine.repro-lock.v1",
    source_commit: "fixture-commit",
    determinism: {
      allow_network: false,
      allow_wall_clock: false,
      allow_randomness: false,
      max_clock_skew_seconds: 0
    }
  }' >"${lock}"

  set +e
  "${VERIFIER}" --lock "${lock}" --report "${report}" --plan-only >/dev/null 2>&1
  local status=$?
  set -e
  if [[ "${status}" -eq 1 ]] && jq -e '.verdict == "fail" and .command_count == 0' "${report}" >/dev/null; then
    pass "missing command fails closed"
  else
    fail "missing command should fail closed with report"
  fi
}

plan_mode_accepts_template_shape
plan_mode_accepts_backfilled_shape
verify_mode_executes_non_cargo_replay_command
missing_command_fails_closed

if [[ "${failures}" -ne 0 ]]; then
  exit 1
fi
