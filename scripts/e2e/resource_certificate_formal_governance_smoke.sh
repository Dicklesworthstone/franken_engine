#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${root_dir}"
source "${root_dir}/scripts/lib/proof_artifact_contract.sh"

artifact_root="${RESOURCE_CERTIFICATE_FORMAL_GOVERNANCE_ARTIFACT_ROOT:-${root_dir}/artifacts/resource_certificate_formal_governance_smoke}"
run_id="${RESOURCE_CERTIFICATE_FORMAL_GOVERNANCE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${RESOURCE_CERTIFICATE_FORMAL_GOVERNANCE_RUN_DIR:-${artifact_root}/${run_id}}"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
source_report_path="${run_dir}/source_report.json"

export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/franken_engine_resource_certificate_formal_governance_${USER:-agent}}"

mkdir -p "${run_dir}"
: >"${events_path}"
: >"${commands_path}"

failure_count=0

record_event() {
  local event_name="$1"
  local step_id="$2"
  local command_id="$3"
  local artifact_path="$4"
  local exit_code="$5"
  local duration_ms="$6"
  local decision="$7"
  local remediation="$8"
  local artifact_rel
  local artifact_sha

  artifact_rel="$(proof_contract_repo_relative_path "${artifact_path}")"
  artifact_sha="$(proof_contract_sha256_file "${artifact_path}")"

  jq -nc \
    --arg schema_version "${PROOF_ARTIFACT_EVENT_SCHEMA_VERSION}" \
    --arg event_name "${event_name}" \
    --arg severity "info" \
    --arg step_id "${step_id}" \
    --arg command_id "${command_id}" \
    --arg artifact_path "${artifact_rel}" \
    --arg artifact_sha256 "${artifact_sha}" \
    --argjson exit_code "${exit_code}" \
    --argjson duration_ms "${duration_ms}" \
    --arg decision "${decision}" \
    --arg remediation "${remediation}" \
    '{
      schema_version: $schema_version,
      event_name: $event_name,
      severity: $severity,
      step_id: $step_id,
      command_id: $command_id,
      artifact_path: $artifact_path,
      artifact_sha256: $artifact_sha256,
      exit_code: $exit_code,
      duration_ms: $duration_ms,
      decision: $decision,
      remediation: (if $remediation == "" then null else $remediation end)
    }' >>"${events_path}"
}

run_step() {
  local step_id="$1"
  local command_id="$2"
  shift 2
  local log_path="${run_dir}/${step_id}.log"
  local start_ms
  local end_ms
  local duration_ms
  local exit_code

  printf '%q ' "$@" >>"${commands_path}"
  printf '\n' >>"${commands_path}"

  echo "resource_certificate_formal_governance: running ${step_id}"
  start_ms="$(date +%s%3N)"
  set +e
  "$@" >"${log_path}" 2>&1
  exit_code=$?
  set -e
  end_ms="$(date +%s%3N)"
  duration_ms=$((end_ms - start_ms))

  if [[ "${exit_code}" -eq 0 ]]; then
    echo "resource_certificate_formal_governance: ${step_id} passed (${duration_ms}ms)"
    record_event \
      "resource_certificate_formal_governance.${step_id}" \
      "${step_id}" \
      "${command_id}" \
      "${log_path}" \
      "${exit_code}" \
      "${duration_ms}" \
      "passed" \
      ""
  else
    echo "resource_certificate_formal_governance: ${step_id} failed (${duration_ms}ms); see ${log_path}" >&2
    failure_count=$((failure_count + 1))
    record_event \
      "resource_certificate_formal_governance.${step_id}" \
      "${step_id}" \
      "${command_id}" \
      "${log_path}" \
      "${exit_code}" \
      "${duration_ms}" \
      "failed" \
      "Fix the deterministic bound-proof invariant or keep resource-certificate validity claims non-formal."
  fi
}

run_step \
  "unit-formal-policy" \
  "cargo-test-unit-formal-policy" \
  cargo test -p frankenengine-engine --lib formal_policy -- --nocapture

run_step \
  "integration-formal-policy" \
  "cargo-test-integration-formal-policy" \
  cargo test -p frankenengine-engine --test resource_certificate_governance_integration formal_policy -- --nocapture

run_step \
  "enrichment-formal-policy" \
  "cargo-test-enrichment-formal-policy" \
  cargo test -p frankenengine-engine --test resource_certificate_governance_enrichment_integration formal_policy -- --nocapture

status="pass"
if [[ "${failure_count}" -ne 0 ]]; then
  status="fail"
fi

jq -n \
  --arg schema_version "franken-engine.resource-certificate-formal-governance-smoke.v1" \
  --arg status "${status}" \
  --arg module "crates/franken-engine/src/resource_certificate_governance.rs" \
  --arg target_dir "${CARGO_TARGET_DIR}" \
  --argjson failure_count "${failure_count}" \
  '{
    schema_version: $schema_version,
    status: $status,
    failure_count: $failure_count,
    checked_module: $module,
    cargo_target_dir: $target_dir,
    checked_properties: [
      "sample-count and observability thresholds remain heuristic-only evidence",
      "formal policy requires deterministic resource-bound proofs",
      "missing deterministic proofs block formal certificate approval",
      "invalid deterministic upper bounds block formal certificate approval",
      "valid deterministic proofs establish measured_usage <= bound <= certified_budget"
    ]
  }' >"${source_report_path}"

proof_contract_write_standard_bundle \
  "${run_dir}" \
  "resource_certificate_formal_governance_smoke" \
  "${status}" \
  "./scripts/e2e/resource_certificate_formal_governance_smoke.sh" \
  "${source_report_path}" \
  "${events_path}" \
  "${commands_path}" \
  "bd-3249t" \
  "FE-RESOURCE-CERT-FORMAL-GOVERNANCE" \
  "${failure_count}"

echo "resource_certificate_formal_governance_manifest=${run_dir}/manifest.json"

if [[ "${failure_count}" -ne 0 ]]; then
  exit 1
fi
