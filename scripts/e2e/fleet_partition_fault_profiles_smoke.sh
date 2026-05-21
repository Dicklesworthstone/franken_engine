#!/usr/bin/env bash
# fleet_partition_fault_profiles_smoke.sh (bd-cixqu.2.4)
#
# Smoke test for the partition-profile selection lane added to the
# bd-cixqu.2.2 SLO gate. Asserts that:
#
#   1. shell syntax + shellcheck clean.
#   2. The profiles JSON declares the 7 base profiles plus the 2 new
#      bd-cixqu.2.4 chaos vectors (repeated_short_partitions,
#      message_loss_without_partition).
#   3. Default ci mode (no PROFILE override) uses the SLO contract's
#      primary profile and verdict=pass.
#   4. FLEET_CONVERGENCE_SLO_PROFILE=permanent_split produces
#      verdict=convergence-impossible.
#   5. FLEET_CONVERGENCE_SLO_PROFILE=split_brain produces
#      verdict=convergence-impossible.
#   6. FLEET_CONVERGENCE_SLO_PROFILE=repeated_short_partitions
#      produces verdict=pass and records the chaos_vector.
#   7. FLEET_CONVERGENCE_SLO_PROFILE=message_loss_without_partition
#      produces verdict=pass and records the chaos_vector.
#   8. An unknown profile name fails closed (gate exit != 0).

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${PROJECT_DIR}"

readonly GATE="${PROJECT_DIR}/scripts/run_rgc_fleet_convergence_slo_gate.sh"
readonly PROFILES="${PROJECT_DIR}/docs/fleet_partition_fault_profiles_v1.json"

failures=0
pass() { printf 'PASS fleet-partition-fault-profiles %s\n' "$1"; }
fail() { printf 'FAIL fleet-partition-fault-profiles %s\n' "$1" >&2; failures=$((failures + 1)); }

usage() {
  cat >&2 <<'EOF'
Usage: scripts/e2e/fleet_partition_fault_profiles_smoke.sh [check|run]
EOF
}

assert_syntax() {
  bash -n "${GATE}"
  bash -n "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x -e SC2016,SC2155 "${GATE}" "${BASH_SOURCE[0]}" >/dev/null 2>&1 \
      || fail "shellcheck reported issues"
  fi
  pass "shell syntax + shellcheck clean"
}

assert_profile_set() {
  if ! jq -e '
        (.profiles | has("normal"))
        and (.profiles | has("degraded"))
        and (.profiles | has("healing"))
        and (.profiles | has("majority_partition"))
        and (.profiles | has("minority_partition"))
        and (.profiles | has("permanent_split"))
        and (.profiles | has("split_brain"))
        and (.profiles | has("repeated_short_partitions"))
        and (.profiles | has("message_loss_without_partition"))
      ' "${PROFILES}" >/dev/null; then
    fail "profiles JSON missing one of the 9 expected profiles"
    return
  fi
  pass "profiles JSON declares all 9 expected profiles (7 base + 2 chaos vectors)"
}

run_with_profile() {
  local profile="$1"
  local tmp
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/fleet-partition-smoke.XXXXXX")"
  set +e
  if [[ -n "${profile}" ]]; then
    FLEET_CONVERGENCE_SLO_PROFILE="${profile}" "${GATE}" ci "${tmp}" \
      >/dev/null 2>&1
  else
    "${GATE}" ci "${tmp}" >/dev/null 2>&1
  fi
  rc=$?
  set -e
  printf '%s\n%d\n' "${tmp}" "${rc}"
}

assert_default_pass() {
  local result rc
  result=$(run_with_profile "")
  local dir; dir="$(printf '%s\n' "${result}" | head -1)"
  rc="$(printf '%s\n' "${result}" | tail -1)"
  if [[ "${rc}" -ne 0 ]]; then
    fail "default ci exit ${rc} (expected 0)"
    return
  fi
  local verdict; verdict="$(jq -r '.verdict' "${dir}/run_manifest.json")"
  if [[ "${verdict}" != "pass" ]]; then
    fail "default verdict=${verdict} (expected pass)"
    return
  fi
  pass "default profile verdict=pass"
}

assert_impossible() {
  local profile="$1"
  local result rc
  result=$(run_with_profile "${profile}")
  local dir; dir="$(printf '%s\n' "${result}" | head -1)"
  rc="$(printf '%s\n' "${result}" | tail -1)"
  if [[ "${rc}" -ne 0 ]]; then
    fail "${profile}: ci exit ${rc} (expected 0)"
    return
  fi
  local verdict; verdict="$(jq -r '.verdict' "${dir}/run_manifest.json")"
  if [[ "${verdict}" != "convergence-impossible" ]]; then
    fail "${profile}: verdict=${verdict} (expected convergence-impossible)"
    return
  fi
  pass "${profile} verdict=convergence-impossible"
}

assert_chaos() {
  local profile="$1"
  local expected_vector="$2"
  local result rc
  result=$(run_with_profile "${profile}")
  local dir; dir="$(printf '%s\n' "${result}" | head -1)"
  rc="$(printf '%s\n' "${result}" | tail -1)"
  if [[ "${rc}" -ne 0 ]]; then
    fail "${profile}: ci exit ${rc} (expected 0)"
    return
  fi
  if ! jq -e --arg v "${expected_vector}" \
        '.verdict == "pass" and .partition_profile_chaos_vector == $v' \
        "${dir}/run_manifest.json" >/dev/null; then
    local got
    got="$(jq -r '"verdict=" + .verdict + " chaos_vector=" + .partition_profile_chaos_vector' "${dir}/run_manifest.json")"
    fail "${profile}: ${got} (expected verdict=pass + chaos_vector=${expected_vector})"
    return
  fi
  pass "${profile} verdict=pass + chaos_vector=${expected_vector}"
}

assert_unknown_profile_fails() {
  local result rc
  result=$(run_with_profile "this_profile_does_not_exist")
  rc="$(printf '%s\n' "${result}" | tail -1)"
  if [[ "${rc}" -eq 0 ]]; then
    fail "unknown profile must fail closed (got exit 0)"
    return
  fi
  pass "unknown profile fails closed (exit ${rc})"
}

case "${1:-check}" in
  check)
    assert_syntax
    assert_profile_set
    ;;
  run)
    assert_syntax
    assert_profile_set
    assert_default_pass
    assert_impossible "permanent_split"
    assert_impossible "split_brain"
    assert_chaos "repeated_short_partitions" "intermittent_partition_cycle"
    assert_chaos "message_loss_without_partition" "uniform_random_message_loss"
    assert_unknown_profile_fails
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage
    fail "unknown mode: ${1:-}"
    exit 64
    ;;
esac

if [[ "${failures}" -ne 0 ]]; then
  exit 1
fi
