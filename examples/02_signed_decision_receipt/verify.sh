#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
source "${repo_root}/scripts/lib/proof_artifact_contract.sh"

artifact_root="${SIGNED_DECISION_RECEIPT_ARTIFACT_ROOT:-${repo_root}/artifacts/signed_decision_receipt}"
run_id="${SIGNED_DECISION_RECEIPT_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SIGNED_DECISION_RECEIPT_RUN_DIR:-${artifact_root}/${run_id}}"
receipt_path="${run_dir}/signed_decision_receipt.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"

mkdir -p "${run_dir}"
: >"${events_path}"
printf './examples/02_signed_decision_receipt/verify.sh\n' >"${commands_path}"

cd "${repo_root}"
start_ms="$(date +%s%3N)"
set +e
cargo run --bin franken-decision-demo >"${receipt_path}" 2>"${run_dir}/cargo.stderr"
cargo_exit=$?
set -e
end_ms="$(date +%s%3N)"
duration_ms=$((end_ms - start_ms))

validation_exit=0
if [[ "${cargo_exit}" -eq 0 ]]; then
  set +e
  jq -e '
  . as $receipt
  | (["allow", "challenge", "sandbox", "suspend", "terminate", "quarantine"] | index($receipt.decision) != null)
  and ($receipt.signature_hex | test("^[0-9a-f]{64}$"))
  and ($receipt.posterior_after_millionths | type == "number" and . >= 0 and . <= 1000000)
  ' "${receipt_path}" >/dev/null
  validation_exit=$?
  set -e
fi

decision="passed"
severity="info"
remediation=""
exit_code="${cargo_exit}"
failure_count=0
if [[ "${cargo_exit}" -ne 0 ]]; then
  decision="failed"
  severity="error"
  remediation="cargo run failed; inspect cargo.stderr and rerun the example verifier."
  failure_count=1
elif [[ "${validation_exit}" -ne 0 ]]; then
  decision="failed"
  severity="error"
  remediation="decision receipt did not satisfy the signed receipt schema checks."
  exit_code="${validation_exit}"
  failure_count=1
fi

receipt_sha256="$(proof_contract_sha256_file "${receipt_path}")"
receipt_path_rel="$(proof_contract_repo_relative_path "${receipt_path}")"
stderr_path_rel="$(proof_contract_repo_relative_path "${run_dir}/cargo.stderr")"
jq -nc \
  --arg schema_version "${PROOF_ARTIFACT_EVENT_SCHEMA_VERSION}" \
  --arg event_name "signed_decision_receipt.example_verified" \
  --arg severity "${severity}" \
  --arg step_id "signed-decision-receipt" \
  --arg command_id "cargo-run-franken-decision-demo" \
  --arg artifact_path "${receipt_path_rel}" \
  --arg artifact_sha256 "${receipt_sha256}" \
  --argjson exit_code "${exit_code}" \
  --argjson duration_ms "${duration_ms}" \
  --arg decision "${decision}" \
  --arg remediation "${remediation}" \
  --arg stderr_path "${stderr_path_rel}" \
  '{
    schema_version: $schema_version,
    event_name: $event_name,
    severity: $severity,
    step_id: $step_id,
    command_id: $command_id,
    artifact_path: $artifact_path,
    artifact_sha256: (if $artifact_sha256 == "" then null else $artifact_sha256 end),
    exit_code: $exit_code,
    duration_ms: $duration_ms,
    decision: $decision,
    remediation: (if $remediation == "" then null else $remediation end),
    stderr_path: $stderr_path
  }' >>"${events_path}"

proof_contract_write_standard_bundle \
  "${run_dir}" \
  "signed_decision_receipt_example" \
  "${decision}" \
  "./examples/02_signed_decision_receipt/verify.sh" \
  "${receipt_path}" \
  "${events_path}" \
  "${commands_path}" \
  "bd-3mp80,bd-1k59y" \
  "SIGNED-DECISION-RECEIPT" \
  "${failure_count}"

if [[ "${failure_count}" -ne 0 ]]; then
  echo "signed decision receipt verification failed; proof manifest: ${run_dir}/manifest.json" >&2
  exit 1
fi

cat "${receipt_path}"
