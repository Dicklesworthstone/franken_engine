#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root_dir}"
# shellcheck source=scripts/lib/proof_artifact_contract.sh
source "${root_dir}/scripts/lib/proof_artifact_contract.sh"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/focused_proof_cost_gate.sh <proof_cost_manifest.json> <budget.json> [output_dir]

The budget file uses schema franken-engine.focused-proof-cost-budget.v1:
{
  "schema_version": "franken-engine.focused-proof-cost-budget.v1",
  "suite": "focused_suite_name",
  "max_total_compiled_targets": 4,
  "max_total_linked_targets": 2,
  "max_unexpected_targets": 0,
  "max_targets_by_kind": {"lib": 1, "test": 1}
}

The gate writes diagnostics.json, events.jsonl, commands.txt, and report.md.
It exits 42 when the manifest breaches the configured proof-cost budget.
EOF
}

sha256_text() {
  local text="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s' "${text}" | sha256sum | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    printf '%s' "${text}" | shasum -a 256 | awk '{print $1}'
  else
    printf '%s' "${text}" | openssl dgst -sha256 | awk '{print $NF}'
  fi
}

manifest_path="${1:-${FOCUSED_PROOF_COST_MANIFEST:-}}"
budget_path="${2:-${FOCUSED_PROOF_COST_BUDGET:-}}"
artifact_root="${FOCUSED_PROOF_COST_GATE_ARTIFACT_ROOT:-artifacts/focused_proof_cost_gate}"
run_id="${FOCUSED_PROOF_COST_GATE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${3:-${FOCUSED_PROOF_COST_GATE_RUN_DIR:-${artifact_root}/${run_id}}}"
diagnostics_path="${run_dir}/diagnostics.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"

if [[ -z "${manifest_path}" || -z "${budget_path}" ]]; then
  usage
  exit 64
fi
if [[ ! -f "${manifest_path}" ]]; then
  printf 'focused-proof-cost-gate missing manifest: %s\n' "${manifest_path}" >&2
  exit 64
fi
if [[ ! -f "${budget_path}" ]]; then
  printf 'focused-proof-cost-gate missing budget: %s\n' "${budget_path}" >&2
  exit 64
fi
if ! jq empty "${manifest_path}" >/dev/null; then
  printf 'focused-proof-cost-gate manifest is not valid JSON: %s\n' "${manifest_path}" >&2
  exit 64
fi
if ! jq empty "${budget_path}" >/dev/null; then
  printf 'focused-proof-cost-gate budget is not valid JSON: %s\n' "${budget_path}" >&2
  exit 64
fi

mkdir -p "${run_dir}"

manifest_rel="$(proof_contract_repo_relative_path "${manifest_path}")"
budget_rel="$(proof_contract_repo_relative_path "${budget_path}")"
run_dir_rel="$(proof_contract_repo_relative_path "${run_dir}")"
diagnostics_rel="$(proof_contract_repo_relative_path "${diagnostics_path}")"
events_rel="$(proof_contract_repo_relative_path "${events_path}")"
report_rel="$(proof_contract_repo_relative_path "${report_path}")"
manifest_sha256="$(proof_contract_sha256_file "${manifest_path}")"
budget_sha256="$(proof_contract_sha256_file "${budget_path}")"
invocation="./scripts/focused_proof_cost_gate.sh ${manifest_rel} ${budget_rel} ${run_dir_rel}"

printf '%s\n' "${invocation}" >"${commands_path}"

breaches="$(
  jq -n \
    --slurpfile manifest "${manifest_path}" \
    --slurpfile budget "${budget_path}" '
    def breach($kind; $actual; $budget; $remediation):
      {
        kind: $kind,
        actual: $actual,
        budget: $budget,
        remediation: $remediation
      };

    ($manifest[0]) as $m
    | ($budget[0]) as $b
    | [
        if ($m.schema_version != "franken-engine.proof-cost-manifest.v1") then
          breach(
            "invalid_manifest_schema";
            ($m.schema_version // null);
            "franken-engine.proof-cost-manifest.v1";
            "Regenerate the receipt with scripts/focused_proof_runner.sh or the Rust proof-cost manifest API."
          )
        else empty end,
        if ($b.schema_version != "franken-engine.focused-proof-cost-budget.v1") then
          breach(
            "invalid_budget_schema";
            ($b.schema_version // null);
            "franken-engine.focused-proof-cost-budget.v1";
            "Fix the focused proof cost budget schema before using it as a gate."
          )
        else empty end,
        if (($b.suite // $m.focused_suite) != "*" and ($b.suite // $m.focused_suite) != $m.focused_suite) then
          breach(
            "suite_mismatch";
            $m.focused_suite;
            ($b.suite // null);
            "Use the budget for this focused_suite or create a suite-specific budget."
          )
        else empty end,
        if (($b.max_total_compiled_targets // null) != null and $m.total_compiled_targets > $b.max_total_compiled_targets) then
          breach(
            "compiled_target_budget";
            $m.total_compiled_targets;
            $b.max_total_compiled_targets;
            "Inspect proof_cost_manifest.operator_log, narrow the command, or explicitly budget the justified target fan-out."
          )
        else empty end,
        if (($b.max_total_linked_targets // null) != null and $m.total_linked_targets > $b.max_total_linked_targets) then
          breach(
            "linked_target_budget";
            $m.total_linked_targets;
            $b.max_total_linked_targets;
            "Split the proof target or adjust the focused command so unrelated linked harnesses are not pulled in."
          )
        else empty end,
        if (($m.unexpected_targets | length) > ($b.max_unexpected_targets // 0)) then
          breach(
            "unexpected_target_breach";
            ($m.unexpected_targets | length);
            ($b.max_unexpected_targets // 0);
            "Treat every unexpected target as suspect; either add it to the focused runner expected set with evidence or remove the hidden dependency."
          )
        else empty end,
        (($b.max_targets_by_kind // {}) | to_entries[]? as $entry
          | ($m.target_counts[$entry.key] // 0) as $actual
          | if $actual > $entry.value then
              breach(
                ("target_kind_budget:" + $entry.key);
                $actual;
                $entry.value;
                ("Reduce " + $entry.key + " target fan-out or raise the budget only with a proof receipt and operator note.")
              )
            else empty end)
      ]
  '
)"
breach_count="$(jq 'length' <<<"${breaches}")"
status="pass"
exit_code=0
if [[ "${breach_count}" -ne 0 ]]; then
  status="fail"
  exit_code=42
fi

diagnostics_id_input="$(
  jq -c -n \
    --arg manifest_sha256 "${manifest_sha256}" \
    --arg budget_sha256 "${budget_sha256}" \
    --argjson breaches "${breaches}" \
    '{manifest_sha256: $manifest_sha256, budget_sha256: $budget_sha256, breaches: $breaches}'
)"
diagnostics_id="focused-proof-cost-gate-$(sha256_text "${diagnostics_id_input}" | cut -c1-16)"

jq -n \
  --arg schema_version "franken-engine.focused-proof-cost-gate-report.v1" \
  --arg diagnostics_id "${diagnostics_id}" \
  --arg status "${status}" \
  --arg manifest_path "${manifest_rel}" \
  --arg budget_path "${budget_rel}" \
  --arg manifest_sha256 "${manifest_sha256}" \
  --arg budget_sha256 "${budget_sha256}" \
  --arg diagnostics_path "${diagnostics_rel}" \
  --arg events_path "${events_rel}" \
  --arg report_path "${report_rel}" \
  --slurpfile manifest "${manifest_path}" \
  --slurpfile budget "${budget_path}" \
  --argjson breaches "${breaches}" \
  '{
    schema_version: $schema_version,
    diagnostics_id: $diagnostics_id,
    status: $status,
    focused_suite: ($manifest[0].focused_suite // null),
    bead_id: ($manifest[0].bead_id // null),
    manifest_path: $manifest_path,
    budget_path: $budget_path,
    manifest_sha256: $manifest_sha256,
    budget_sha256: $budget_sha256,
    budget: $budget[0],
    observed: {
      total_compiled_targets: ($manifest[0].total_compiled_targets // null),
      total_linked_targets: ($manifest[0].total_linked_targets // null),
      target_counts: ($manifest[0].target_counts // {}),
      unexpected_targets: ($manifest[0].unexpected_targets // [])
    },
    breaches: $breaches,
    remediation: [
      "Inspect proof_cost_manifest.operator_log before changing budgets.",
      "If a new target is legitimate, add it to the focused runner expected target set and update this budget in the same review.",
      "If the target is unrelated, narrow the cargo command, split the proof suite, or remove the dependency that pulled it in.",
      "Rerun scripts/focused_proof_runner.sh and then this gate before publishing the proof."
    ],
    artifact_paths: {
      diagnostics_json: $diagnostics_path,
      events_jsonl: $events_path,
      report_md: $report_path
    }
  }' >"${diagnostics_path}"

severity="info"
if [[ "${status}" != "pass" ]]; then
  severity="error"
fi

jq -nc \
  --arg schema_version "${PROOF_ARTIFACT_EVENT_SCHEMA_VERSION}" \
  --arg event_name "focused_proof_cost_gate.evaluated" \
  --arg severity "${severity}" \
  --arg step_id "focused-proof-cost-gate" \
  --arg command_id "focused-proof-cost-gate" \
  --arg decision "${status}" \
  --arg diagnostics_path "${diagnostics_rel}" \
  --argjson breach_count "${breach_count}" \
  '{
    schema_version: $schema_version,
    event_name: $event_name,
    severity: $severity,
    step_id: $step_id,
    command_id: $command_id,
    decision: $decision,
    breach_count: $breach_count,
    diagnostics_path: $diagnostics_path,
    exit_code: 0,
    duration_ms: 0
  }' >"${events_path}"

{
  printf '# Focused Proof Cost Gate\n\n'
  printf -- "- Status: \`%s\`\n" "${status}"
  printf -- "- Manifest: \`%s\`\n" "${manifest_rel}"
  printf -- "- Budget: \`%s\`\n" "${budget_rel}"
  printf -- "- Diagnostics: \`%s\`\n" "${diagnostics_rel}"
  printf -- "- Breaches: \`%s\`\n\n" "${breach_count}"
  if [[ "${breach_count}" -eq 0 ]]; then
    printf 'The proof-cost receipt is within the configured budget.\n'
  else
    printf 'The proof-cost receipt breached the configured budget.\n\n'
    jq -r '.breaches[] | "- `\(.kind)`: actual=`\(.actual)` budget=`\(.budget)`; \(.remediation)"' "${diagnostics_path}"
    printf '\n## Remediation\n\n'
    jq -r '.remediation[] | "- \(.)"' "${diagnostics_path}"
  fi
} >"${report_path}"

printf 'focused_proof_cost_gate_diagnostics=%s\n' "${diagnostics_path}"
printf 'focused_proof_cost_gate_report=%s\n' "${report_path}"

exit "${exit_code}"
