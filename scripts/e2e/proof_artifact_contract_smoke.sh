#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${root_dir}/scripts/lib/proof_artifact_contract.sh"

artifact_root="${PROOF_ARTIFACT_CONTRACT_SMOKE_ARTIFACT_ROOT:-${root_dir}/artifacts/proof_artifact_contract_smoke}"
run_id="${PROOF_ARTIFACT_CONTRACT_SMOKE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${PROOF_ARTIFACT_CONTRACT_SMOKE_RUN_DIR:-${artifact_root}/${run_id}}"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
source_report_path="${run_dir}/source_report.json"

mkdir -p "${run_dir}"
printf 'API_TOKEN=<redacted> ./scripts/e2e/proof_artifact_contract_smoke.sh\n' >"${commands_path}"

jq -n \
  --arg schema_version "franken-engine.proof-artifact-contract-smoke-source.v1" \
  --arg status "pass" \
  '{schema_version: $schema_version, status: $status, checked: ["manifest", "commands", "events", "report", "redaction_policy"]}' \
  >"${source_report_path}"

source_report_sha256="$(proof_contract_sha256_file "${source_report_path}")"
source_report_rel="$(proof_contract_repo_relative_path "${source_report_path}")"
jq -nc \
  --arg schema_version "${PROOF_ARTIFACT_EVENT_SCHEMA_VERSION}" \
  --arg event_name "proof_artifact_contract.bundle_written" \
  --arg severity "info" \
  --arg step_id "write-standard-bundle" \
  --arg command_id "proof-contract-smoke" \
  --arg artifact_path "${source_report_rel}" \
  --arg artifact_sha256 "${source_report_sha256}" \
  '{
    schema_version: $schema_version,
    event_name: $event_name,
    severity: $severity,
    step_id: $step_id,
    command_id: $command_id,
    artifact_path: $artifact_path,
    artifact_sha256: $artifact_sha256,
    exit_code: 0,
    duration_ms: 0,
    decision: "passed",
    remediation: null
  }' >"${events_path}"

proof_contract_write_standard_bundle \
  "${run_dir}" \
  "proof_artifact_contract_smoke" \
  "pass" \
  "API_TOKEN=secret-token ./scripts/e2e/proof_artifact_contract_smoke.sh" \
  "${source_report_path}" \
  "${events_path}" \
  "${commands_path}" \
  "bd-1k59y" \
  "PROOF-ARTIFACT-CONTRACT" \
  "0"

manifest_rel="$(proof_contract_repo_relative_path "${run_dir}/manifest.json")"
jq -e \
  --arg schema "${PROOF_ARTIFACT_MANIFEST_SCHEMA_VERSION}" \
  --arg manifest_rel "${manifest_rel}" \
  '.schema_version == $schema
   and .status == "pass"
   and .artifact_paths.manifest_json == $manifest_rel
   and (.commands | length == 1)
   and (.generated_artifacts | map(.role) | index("command_transcript") != null)
   and (.generated_artifacts | map(.role) | index("structured_events") != null)
   and (.generated_artifacts | map(.role) | index("source_machine_report") != null)' \
  "${run_dir}/manifest.json" >/dev/null

jq -e \
  --arg schema "${PROOF_ARTIFACT_REPORT_SCHEMA_VERSION}" \
  '.schema_version == $schema and .status == "pass" and .failure_count == 0' \
  "${run_dir}/report.json" >/dev/null

jq -e \
  --arg schema "${PROOF_ARTIFACT_REDACTION_POLICY_SCHEMA_VERSION}" \
  '.schema_version == $schema and .replacement == "<redacted>"' \
  "${run_dir}/redaction_policy.json" >/dev/null

if grep -R "secret-token" "${run_dir}/manifest.json" "${run_dir}/report.json" "${run_dir}/report.md" >/dev/null; then
  echo "proof contract redaction failed: secret token leaked into standard reports" >&2
  exit 1
fi

grep -R "<redacted>" "${run_dir}/manifest.json" "${run_dir}/report.json" "${run_dir}/report.md" >/dev/null

if proof_contract_assert_required_artifacts "${run_dir}/missing" "${events_path}" "${commands_path}"; then
  echo "proof contract missing-artifact assertion unexpectedly passed" >&2
  exit 1
fi

echo "proof_artifact_contract_manifest=${run_dir}/manifest.json"
