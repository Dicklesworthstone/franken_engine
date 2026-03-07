#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

export TZ=UTC
export LC_ALL=C
export LANG=C
export LANGUAGE=C

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
cargo_build_jobs="${CARGO_BUILD_JOBS:-1}"
artifact_root="${RGC_CLAIM_ENTITLEMENT_ARTIFACT_ROOT:-artifacts/rgc_claim_entitlement_algebra}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
target_namespace="${mode}_$$"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_rgc_claim_entitlement_algebra_${target_namespace}}"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
claim_atom_catalog_path="${run_dir}/claim_atom_catalog.json"
evidence_morphism_catalog_path="${run_dir}/evidence_morphism_catalog.json"
side_constraint_lattice_path="${run_dir}/side_constraint_lattice.json"
disqualifier_rules_path="${run_dir}/disqualifier_rules.json"
claim_entitlement_report_path="${run_dir}/claim_entitlement_report.json"
missing_evidence_cutsets_path="${run_dir}/missing_evidence_cutsets.json"
impossibility_certificates_path="${run_dir}/impossibility_certificates.json"
claim_counterexample_ledger_path="${run_dir}/claim_counterexample_ledger.json"
contract_json="docs/rgc_claim_entitlement_algebra_v1.json"
scenario_fixture="${RGC_CLAIM_ENTITLEMENT_SCENARIO_FIXTURE:-crates/franken-engine/tests/fixtures/claim_entitlement_scenarios_v1.json}"
component="rgc_claim_entitlement_algebra"
policy_id="policy-rgc-claim-entitlement-algebra-v1"
scenario_id="rgc-017-foundation"
trace_id="trace-rgc-claim-entitlement-${timestamp}"
decision_id="decision-rgc-claim-entitlement-${timestamp}"
replay_command="./scripts/e2e/rgc_claim_entitlement_algebra_replay.sh ${mode}"

usage() {
  echo "usage: $0 [check|test|clippy|ci]" >&2
}

case "${mode}" in
  check|test|clippy|ci) ;;
  -h|--help)
    usage
    exit 0
    ;;
  *)
    usage
    exit 2
    ;;
esac

mkdir -p "${run_dir}"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for claim entitlement algebra heavy commands" >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for claim entitlement artifact extraction" >&2
  exit 2
fi

if [[ ! -f "${contract_json}" ]]; then
  echo "missing contract json: ${contract_json}" >&2
  exit 2
fi

if [[ ! -f "${scenario_fixture}" ]]; then
  echo "missing scenario fixture: ${scenario_fixture}" >&2
  exit 2
fi

run_rch() {
  rch exec -- env \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "CARGO_BUILD_JOBS=${cargo_build_jobs}" \
    "RGC_CLAIM_ENTITLEMENT_ARTIFACT_DIR=${run_dir}" \
    "RGC_CLAIM_ENTITLEMENT_SCENARIO_FIXTURE=${scenario_fixture}" \
    "$@"
}

declare -a commands_run=()
failed_command=""

run_step() {
  local command_text="$1"
  local log_path status
  shift

  commands_run+=("${command_text}")
  echo "==> ${command_text}"
  log_path="$(mktemp)"

  set +e
  run_rch "$@" > >(tee "${log_path}") 2>&1
  status=$?
  set -e

  if grep -Eiq 'falling back to local|fallback to local|local fallback|running locally' "${log_path}"; then
    rm -f "${log_path}"
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi

  rm -f "${log_path}"
  if [[ "${status}" -ne 0 ]]; then
    failed_command="${command_text}"
    return 1
  fi
}

assert_report_artifacts() {
  local artifact_path

  for artifact_path in \
    "${claim_entitlement_report_path}" \
    "${missing_evidence_cutsets_path}" \
    "${impossibility_certificates_path}" \
    "${claim_counterexample_ledger_path}"; do
    if [[ ! -f "${artifact_path}" ]]; then
      echo "missing expected artifact: ${artifact_path}" >&2
      failed_command="artifact materialization (${artifact_path})"
      return 1
    fi
  done
}

run_mode() {
  case "${mode}" in
    check)
      run_step "cargo check -p frankenengine-engine --test claim_entitlement" \
        cargo check -p frankenengine-engine --test claim_entitlement
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test claim_entitlement" \
        cargo test -p frankenengine-engine --test claim_entitlement
      assert_report_artifacts
      ;;
    clippy)
      run_step "cargo clippy -p frankenengine-engine --test claim_entitlement -- -D warnings" \
        cargo clippy -p frankenengine-engine --test claim_entitlement -- -D warnings
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --test claim_entitlement" \
        cargo check -p frankenengine-engine --test claim_entitlement
      run_step "cargo test -p frankenengine-engine --test claim_entitlement" \
        cargo test -p frankenengine-engine --test claim_entitlement
      assert_report_artifacts
      run_step "cargo clippy -p frankenengine-engine --test claim_entitlement -- -D warnings" \
        cargo clippy -p frankenengine-engine --test claim_entitlement -- -D warnings
      ;;
  esac
}

write_artifacts() {
  jq '.claim_atom_catalog' "${contract_json}" > "${claim_atom_catalog_path}"
  jq '.evidence_morphism_catalog' "${contract_json}" > "${evidence_morphism_catalog_path}"
  jq '.side_constraint_lattice' "${contract_json}" > "${side_constraint_lattice_path}"
  jq '.disqualifier_rules' "${contract_json}" > "${disqualifier_rules_path}"
  printf '%s\n' "${commands_run[@]}" > "${commands_path}"
}

write_manifest() {
  local outcome="$1"
  local error_code_json="$2"
  local git_commit dirty_worktree commands_json failed_command_json

  write_artifacts

  if [[ -z "$(git status --short --untracked-files=normal 2>/dev/null)" ]]; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi
  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  commands_json="$(printf '%s\n' "${commands_run[@]}" | jq -R . | jq -s .)"
  if [[ -n "${failed_command}" ]]; then
    failed_command_json="$(printf '%s' "${failed_command}" | jq -R .)"
  else
    failed_command_json="null"
  fi

  printf '%s\n' \
    "{\"schema_version\":\"franken-engine.rgc-claim-entitlement-algebra.log-event.v1\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"${component}\",\"event\":\"gate_completed\",\"scenario_id\":\"${scenario_id}\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}" \
    > "${events_path}"

  cat > "${manifest_path}" <<EOF
{
  "schema_version": "franken-engine.rgc-claim-entitlement-algebra.run-manifest.v1",
  "bead_id": "bd-1lsy.1.7",
  "component": "${component}",
  "policy_id": "${policy_id}",
  "mode": "${mode}",
  "scenario_id": "${scenario_id}",
  "scenario_fixture": "${scenario_fixture}",
  "trace_id": "${trace_id}",
  "decision_id": "${decision_id}",
  "toolchain": "${toolchain}",
  "cargo_build_jobs": ${cargo_build_jobs},
  "cargo_target_dir": "${target_dir}",
  "contract_json": "${contract_json}",
  "replay_command": "${replay_command}",
  "commands": ${commands_json},
  "required_artifacts": [
    "claim_atom_catalog.json",
    "evidence_morphism_catalog.json",
    "side_constraint_lattice.json",
    "disqualifier_rules.json",
    "claim_entitlement_report.json",
    "missing_evidence_cutsets.json",
    "impossibility_certificates.json",
    "claim_counterexample_ledger.json",
    "run_manifest.json",
    "events.jsonl",
    "commands.txt"
  ],
  "git_commit": "${git_commit}",
  "dirty_worktree": ${dirty_worktree},
  "failed_command": ${failed_command_json}
}
EOF
}

if run_mode; then
  write_manifest "pass" "null"
  exit 0
else
  write_manifest "fail" '"FE-RGC-017-0001"'
  exit 1
fi
