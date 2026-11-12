#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}" || exit 1

workdir="$(mktemp -d "${TMPDIR:-/tmp}/external-trust-docs-truth-gate.XXXXXX")"

# 1. Live repository docs check (runbook + contract + README) must pass
python3 scripts/check_external_trust_docs_truth_gate.py >"${workdir}/repo_pass.json"
jq -e '.verdict == "pass" and .violation_count == 0' "${workdir}/repo_pass.json" >/dev/null

# 2. Healthy standalone fixture must pass
cat >"${workdir}/healthy_fixture.md" <<'MD'
# Auditor Notes
The claim explainer does not prove runtime soundness or certificate soundness.
The bundle doctor does not execute replay success; it only lists `replay_commands`.
Freshness checks inspect `actual_freshness_days` and `evidence_freshness` alongside upstream gate `run_claim_to_proof_matrix_gate.sh`.
No claim is promotable from transport-only evidence.
MD

python3 scripts/check_external_trust_docs_truth_gate.py \
  --skip-repo-upstream-check \
  --doc "${workdir}/healthy_fixture.md" >"${workdir}/healthy_out.json"
jq -e '.verdict == "pass" and .violation_count == 0' "${workdir}/healthy_out.json" >/dev/null

assert_rejected() {
  local case_id="$1"
  local expected_code="$2"
  local body="$3"
  local doc_file="${workdir}/${case_id}.md"
  local out_file="${workdir}/${case_id}.json"
  printf '%s\n' "${body}" >"${doc_file}"
  if python3 scripts/check_external_trust_docs_truth_gate.py \
    --skip-repo-upstream-check \
    --doc "${doc_file}" >"${out_file}"; then
    printf 'FAIL [%s]: expected fail_closed for %s\n' "${case_id}" "${expected_code}" >&2
    exit 1
  fi
  jq -e --arg code "${expected_code}" \
    '.verdict == "fail_closed" and ((.violations | map(.code) | index($code)) != null)' \
    "${out_file}" >/dev/null
}

# 3. Forbidden overclaim fixtures
assert_rejected "overclaim_runtime" "explainer_proves_runtime_soundness" \
  "Running the claim explainer proves runtime soundness for untrusted extensions."
assert_rejected "overclaim_cert" "explainer_proves_certificate_soundness" \
  "A green E8 scenario report certifies certificate soundness on its own."
assert_rejected "overclaim_replay" "explainer_proves_replay_success" \
  "Passing the bundle doctor verifies replay success across workers."
assert_rejected "overclaim_freshness" "explainer_overclaims_freshness_authority" \
  "Running frankenctl claims explain refreshes artifact freshness automatically."
assert_rejected "overclaim_transport" "transport_only_promotion_overclaim" \
  "Claims are promotable from transport-only evidence when RCH dispatches."

printf 'PASS external trust docs & claim-language truth gate smoke (workdir=%s)\n' "${workdir}"
