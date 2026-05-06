#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
gate="${root_dir}/scripts/remote_proof_contract_catalog_gate.sh"
docs_path="${root_dir}/docs/REMOTE_PROOF_CONTRACT_CATALOG_GATE.md"
contract_path="${root_dir}/docs/remote_proof_contract_catalog_contract_v1.json"

record_pass() {
  printf 'PASS remote-proof-contract-catalog %s\n' "$1"
}

record_failure() {
  printf 'FAIL remote-proof-contract-catalog %s\n' "$1" >&2
}

write_real_surface_manifest() {
  local path="$1"

  jq -n '
    {
      schema_version: "franken-engine.remote-proof-contract-catalog-manifest.v1",
      external_schemas: [
        "franken-engine.rch-incident-packet.v1",
        "franken-engine.rch-sync-closure-hotspot-ledger.v1",
        "franken-engine.sticky-worker-warm-target-lease-plan.v1"
      ],
      surfaces: [
        {
          surface_id: "resident-remote-proof-bundle",
          contract_json: "docs/resident_remote_proof_bundle_contract_v1.json",
          implementation_script: "scripts/resident_remote_proof_bundle_executor.sh",
          smoke_script: "scripts/e2e/resident_remote_proof_bundle_executor_smoke.sh",
          doc_path: "docs/RESIDENT_REMOTE_PROOF_BUNDLE_EXECUTOR.md",
          emitted_schema: "franken-engine.resident-remote-proof-bundle.v1",
          upstream_schemas: []
        },
        {
          surface_id: "rch-worker-truth-parity-ledger",
          contract_json: "docs/rch_worker_truth_parity_contract_v1.json",
          implementation_script: "scripts/rch_worker_truth_parity_ledger.sh",
          smoke_script: "scripts/e2e/rch_worker_truth_parity_ledger_smoke.sh",
          doc_path: "docs/RCH_WORKER_TRUTH_PARITY_LEDGER.md",
          emitted_schema: "franken-engine.rch-worker-truth-parity-report.v1",
          upstream_schemas: ["franken-engine.rch-incident-packet.v1"]
        },
        {
          surface_id: "remote-proof-artifact-mirror",
          contract_json: "docs/remote_proof_artifact_mirror_contract_v1.json",
          implementation_script: "scripts/remote_proof_artifact_mirror_packer.sh",
          smoke_script: "scripts/e2e/remote_proof_artifact_mirror_packer_smoke.sh",
          doc_path: "docs/REMOTE_PROOF_ARTIFACT_MIRROR_PACKER.md",
          emitted_schema: "franken-engine.remote-proof-artifact-mirror-verification.v1",
          upstream_schemas: ["franken-engine.resident-remote-proof-bundle.v1"]
        },
        {
          surface_id: "remote-proof-salvage-receipt",
          contract_json: "docs/remote_proof_salvage_receipt_contract_v1.json",
          implementation_script: "scripts/remote_proof_salvage_receipt.sh",
          smoke_script: "scripts/e2e/remote_proof_salvage_receipt_smoke.sh",
          doc_path: "docs/REMOTE_PROOF_SALVAGE_RECEIPT.md",
          emitted_schema: "franken-engine.remote-proof-salvage-receipt.v1",
          upstream_schemas: [
            "franken-engine.resident-remote-proof-bundle.v1",
            "franken-engine.rch-incident-packet.v1",
            "franken-engine.rch-worker-truth-parity-report.v1"
          ]
        },
        {
          surface_id: "warm-target-roi-eviction-ledger",
          contract_json: "docs/warm_target_roi_eviction_contract_v1.json",
          implementation_script: "scripts/warm_target_roi_eviction_ledger.sh",
          smoke_script: "scripts/e2e/warm_target_roi_eviction_ledger_smoke.sh",
          doc_path: "docs/WARM_TARGET_ROI_EVICTION_LEDGER.md",
          emitted_schema: "franken-engine.warm-target-roi-eviction-ledger.v1",
          upstream_schemas: [
            "franken-engine.resident-remote-proof-bundle.v1",
            "franken-engine.sticky-worker-warm-target-lease-plan.v1",
            "franken-engine.rch-sync-closure-hotspot-ledger.v1"
          ]
        }
      ]
    }
  ' >"$path"
}

write_fixture_surface() {
  local dir="$1"
  local surface="$2"
  local contract_schema="$3"
  local emitted_schema="$4"
  local upstream_schema="${5:-}"

  mkdir -p "${dir}/docs" "${dir}/scripts/e2e" "${dir}/scripts"
  jq -n \
    --arg contract_schema "$contract_schema" \
    --arg emitted_schema "$emitted_schema" \
    --arg upstream_schema "$upstream_schema" '
    {
      schema_version: $contract_schema,
      output_schema: $emitted_schema,
      required_inputs: ["--input-json"],
      optional_inputs: ["--output-dir"],
      required_artifacts: ["result.json", "events.jsonl", "commands.txt", "report.md"],
      required_upstream_schemas: (
        if $upstream_schema == "" then [] else [$upstream_schema] end
      ),
      determinism: {
        execution_mode: "fixture-only",
        sorting: "normalized by surface id"
      }
    }
  ' >"${dir}/docs/${surface}_contract_v1.json"

  cat >"${dir}/scripts/${surface}.sh" <<'EOF_SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
input_json=""
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --input-json)
      input_json="${2:-}"
      shift 2
      ;;
    --output-dir)
      shift 2
      ;;
    *)
      exit 64
      ;;
  esac
done
test -n "$input_json"
printf 'result.json events.jsonl commands.txt report.md\n' >/dev/null
EOF_SCRIPT

  cat >"${dir}/scripts/e2e/${surface}_smoke.sh" <<'EOF_SMOKE'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-check}" in
  check)
    exit 0
    ;;
  selftest)
    exit 0
    ;;
  *)
    exit 64
    ;;
esac
EOF_SMOKE

  cat >"${dir}/docs/${surface}.md" <<EOF_DOC
# ${surface}

\`scripts/${surface}.sh\`

Schema: \`${emitted_schema}\`

Artifacts:

- \`result.json\`
- \`events.jsonl\`
- \`commands.txt\`
- \`report.md\`
EOF_DOC
}

write_fixture_manifest() {
  local path="$1"
  local root_prefix="$2"
  local duplicate_schema="${3:-false}"
  local dangling_schema="${4:-false}"

  local second_contract_schema="franken-engine.fixture-surface-b-contract.v1"
  local upstream_schema="franken-engine.fixture-surface-a.v1"
  if [[ "$duplicate_schema" == "true" ]]; then
    second_contract_schema="franken-engine.fixture-surface-a-contract.v1"
  fi
  if [[ "$dangling_schema" == "true" ]]; then
    upstream_schema="franken-engine.missing-upstream.v1"
  fi

  write_fixture_surface "$root_prefix" "fixture_surface_a" \
    "franken-engine.fixture-surface-a-contract.v1" \
    "franken-engine.fixture-surface-a.v1"
  write_fixture_surface "$root_prefix" "fixture_surface_b" \
    "$second_contract_schema" \
    "franken-engine.fixture-surface-b.v1" \
    "$upstream_schema"

  jq -n \
    --arg root_prefix "$root_prefix" '
    def rel($path): ($path | sub("^" + $root_prefix + "/"; ""));
    {
      schema_version: "franken-engine.remote-proof-contract-catalog-manifest.v1",
      external_schemas: [],
      surfaces: [
        {
          surface_id: "fixture-a",
          contract_json: rel($root_prefix + "/docs/fixture_surface_a_contract_v1.json"),
          implementation_script: rel($root_prefix + "/scripts/fixture_surface_a.sh"),
          smoke_script: rel($root_prefix + "/scripts/e2e/fixture_surface_a_smoke.sh"),
          doc_path: rel($root_prefix + "/docs/fixture_surface_a.md"),
          emitted_schema: "franken-engine.fixture-surface-a.v1",
          upstream_schemas: []
        },
        {
          surface_id: "fixture-b",
          contract_json: rel($root_prefix + "/docs/fixture_surface_b_contract_v1.json"),
          implementation_script: rel($root_prefix + "/scripts/fixture_surface_b.sh"),
          smoke_script: rel($root_prefix + "/scripts/e2e/fixture_surface_b_smoke.sh"),
          doc_path: rel($root_prefix + "/docs/fixture_surface_b.md"),
          emitted_schema: "franken-engine.fixture-surface-b.v1",
          upstream_schemas: []
        }
      ]
    }
  ' >"$path"
}

run_check() {
  local tmp_parent tmp_root manifest_path gate_dir scope_file

  bash -n "$gate"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$contract_path"
  grep -q 'franken-engine.remote-proof-contract-catalog-report.v1' "$docs_path"
  record_pass "bash syntax and docs contract"

  tmp_parent="${REMOTE_PROOF_CONTRACT_CATALOG_GATE_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/remote-proof-contract-catalog-check.XXXXXX")"
  manifest_path="${tmp_root}/real-surfaces.json"
  gate_dir="${tmp_root}/real-surface-check"
  write_real_surface_manifest "$manifest_path"
  "$gate" --surface-manifest-json "$manifest_path" --output-dir "$gate_dir" >/dev/null
  jq -e '
    .catalog_decision == "pass"
    and .surface_count == 5
    and .finding_count == 0
    and (.catalog_id | startswith("contract-catalog-"))
  ' "${gate_dir}/contract_catalog_report.json" >/dev/null
  record_pass "real surface catalog coherence"

  scope_file="$(mktemp "${TMPDIR:-/tmp}/remote-proof-contract-catalog-scope.XXXXXX")"
  printf '%s\n' \
    "scripts/remote_proof_contract_catalog_gate.sh" \
    "scripts/e2e/remote_proof_contract_catalog_gate_smoke.sh" \
    "docs/REMOTE_PROOF_CONTRACT_CATALOG_GATE.md" \
    "docs/remote_proof_contract_catalog_contract_v1.json" >"$scope_file"
  "${root_dir}/scripts/rch_policy_compliance_gate.sh" \
    --output-dir "${TMPDIR:-/tmp}/remote-proof-contract-catalog-rch-policy" \
    --scope-file "$scope_file" >/dev/null
  record_pass "rch policy compliance"
}

run_gate_case() {
  local case_name="$1"
  local expected_exit="$2"
  local manifest_path="$3"
  local output_dir="$4"
  local repo_root_arg="${5:-}"

  local output actual_exit
  set +e
  if [[ -n "$repo_root_arg" ]]; then
    output="$("$gate" --surface-manifest-json "$manifest_path" --output-dir "$output_dir" --repo-root "$repo_root_arg" 2>&1)"
  else
    output="$("$gate" --surface-manifest-json "$manifest_path" --output-dir "$output_dir" 2>&1)"
  fi
  actual_exit=$?
  set -e

  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    record_failure "${case_name} exit ${actual_exit}, expected ${expected_exit}"
    printf '%s\n' "$output" >&2
    return 1
  fi

  test -s "${output_dir}/contract_catalog_report.json"
  test -s "${output_dir}/surface_manifest.normalized.json"
  test -s "${output_dir}/catalog_entries.jsonl"
  test -s "${output_dir}/commands.txt"
  test -s "${output_dir}/events.jsonl"
  test -s "${output_dir}/report.md"
  record_pass "$case_name"
}

run_selftest() {
  local tmp_parent tmp_root fixture_root manifest_path success_dir
  local missing_doc_dir duplicate_dir dangling_dir

  run_check
  tmp_parent="${REMOTE_PROOF_CONTRACT_CATALOG_GATE_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/remote-proof-contract-catalog.XXXXXX")"
  fixture_root="${tmp_root}/fixtures"

  write_fixture_manifest "${tmp_root}/valid-manifest.json" "$fixture_root"
  success_dir="${tmp_root}/success"
  run_gate_case "fixture-catalog-success" 0 "${tmp_root}/valid-manifest.json" "$success_dir" "$fixture_root"
  jq -e '
    .catalog_decision == "pass"
    and .surface_count == 2
    and .finding_count == 0
  ' "${success_dir}/contract_catalog_report.json" >/dev/null
  record_pass "fixture catalog success assertions"

  manifest_path="${tmp_root}/missing-doc-artifact.json"
  write_fixture_manifest "$manifest_path" "$fixture_root"
  grep -v 'result.json' "${fixture_root}/docs/fixture_surface_b.md" >"${fixture_root}/docs/fixture_surface_b.md.tmp"
  mv "${fixture_root}/docs/fixture_surface_b.md.tmp" "${fixture_root}/docs/fixture_surface_b.md"
  missing_doc_dir="${tmp_root}/missing-doc-artifact"
  run_gate_case "missing-doc-artifact" 42 "$manifest_path" "$missing_doc_dir" "$fixture_root"
  jq -e '
    .catalog_decision == "fail_closed"
    and any(.findings[]; .code == "doc_missing_required_artifact" and .surface_id == "fixture-b")
  ' "${missing_doc_dir}/contract_catalog_report.json" >/dev/null
  record_pass "missing doc artifact assertions"

  fixture_root="${tmp_root}/fixtures-duplicate"
  manifest_path="${tmp_root}/duplicate-schema.json"
  write_fixture_manifest "$manifest_path" "$fixture_root" true false
  duplicate_dir="${tmp_root}/duplicate-schema"
  run_gate_case "duplicate-contract-schema" 42 "$manifest_path" "$duplicate_dir" "$fixture_root"
  jq -e '
    .catalog_decision == "fail_closed"
    and any(.findings[]; .code == "duplicate_contract_schema_version")
  ' "${duplicate_dir}/contract_catalog_report.json" >/dev/null
  record_pass "duplicate contract schema assertions"

  fixture_root="${tmp_root}/fixtures-dangling"
  manifest_path="${tmp_root}/dangling-upstream.json"
  write_fixture_manifest "$manifest_path" "$fixture_root" false true
  dangling_dir="${tmp_root}/dangling-upstream"
  run_gate_case "dangling-upstream-schema" 42 "$manifest_path" "$dangling_dir" "$fixture_root"
  jq -e '
    .catalog_decision == "fail_closed"
    and any(.findings[]; .code == "dangling_upstream_schema" and .surface_id == "fixture-b")
  ' "${dangling_dir}/contract_catalog_report.json" >/dev/null
  record_pass "dangling upstream schema assertions"

  printf 'remote_proof_contract_catalog_gate_smoke_artifacts=%s\n' "$tmp_root"
}

case "${1:-check}" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  *)
    record_failure "unknown mode: ${1:-}"
    exit 64
    ;;
esac
