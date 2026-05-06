#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
packer="${root_dir}/scripts/locality_aware_remote_proof_batch_packer.sh"
docs_path="${root_dir}/docs/LOCALITY_AWARE_REMOTE_PROOF_BATCH_PACKER.md"
contract_path="${root_dir}/docs/locality_aware_remote_proof_batch_contract_v1.json"

record_pass() {
  printf 'PASS locality-aware-remote-proof-batch %s\n' "$1"
}

record_failure() {
  printf 'FAIL locality-aware-remote-proof-batch %s\n' "$1" >&2
}

write_bundle_reports() {
  local path="$1"
  local fairness_split="${2:-false}"
  local incompatible="${3:-false}"

  jq -n \
    --argjson incompatible "$incompatible" '
    {
      bundles: [
        {
          bundle_id: "bundle-a",
          expected_worker_id: "ts2",
          expected_target_dir: "/tmp/rch_target_shared",
          allowed_worker_ids: ["ts2"],
          allowed_target_dirs: ["/tmp/rch_target_shared"],
          closure_roots: ["crates/franken-engine", "/dp/frankensqlite"],
          predicted_cost_units: 2,
          phase_count: 2,
          source_revision: "rev-a"
        },
        {
          bundle_id: "bundle-b",
          expected_worker_id: (if $incompatible then "vmi1167313" else "ts2" end),
          expected_target_dir: (if $incompatible then "/tmp/rch_target_other" else "/tmp/rch_target_shared" end),
          allowed_worker_ids: (if $incompatible then ["vmi1167313"] else ["ts2"] end),
          allowed_target_dirs: (if $incompatible then ["/tmp/rch_target_other"] else ["/tmp/rch_target_shared"] end),
          closure_roots: ["crates/franken-engine", "/dp/frankensqlite"],
          predicted_cost_units: 1,
          phase_count: 1,
          source_revision: "rev-b"
        }
      ]
    }
  ' >"$path"
}

write_mirror_manifests() {
  local path="$1"

  jq -n '
    {
      bundles: [
        {
          bundle_id: "bundle-a",
          closure_roots: ["crates/franken-engine", "/dp/frankensqlite"],
          retrieval_pack_artifacts: [
            "artifacts/resident/bundle-a/run_manifest.json",
            "artifacts/resident/bundle-a/events.jsonl"
          ],
          mirror_manifest_hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        },
        {
          bundle_id: "bundle-b",
          closure_roots: ["crates/franken-engine", "/dp/frankensqlite"],
          retrieval_pack_artifacts: [
            "artifacts/resident/bundle-b/run_manifest.json",
            "artifacts/resident/bundle-b/events.jsonl"
          ],
          mirror_manifest_hash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        }
      ]
    }
  ' >"$path"
}

write_roi_ledgers() {
  local path="$1"
  local incompatible="${2:-false}"

  jq -n \
    --argjson incompatible "$incompatible" '
    {
      bundles: [
        {
          bundle_id: "bundle-a",
          decision: "retain",
          recommended_action: "retain_warm_target",
          expected_worker_id: "ts2",
          expected_target_dir: "/tmp/rch_target_shared",
          realized_reuse_score: 9,
          predicted_cost_units: 2,
          policy_findings: ["high_realized_reuse_value"]
        },
        {
          bundle_id: "bundle-b",
          decision: "retain",
          recommended_action: "retain_warm_target",
          expected_worker_id: (if $incompatible then "vmi1167313" else "ts2" end),
          expected_target_dir: (if $incompatible then "/tmp/rch_target_other" else "/tmp/rch_target_shared" end),
          realized_reuse_score: 8,
          predicted_cost_units: 1,
          policy_findings: ["high_realized_reuse_value"]
        }
      ]
    }
  ' >"$path"
}

write_fairness_policy() {
  local path="$1"
  local max_bundles="$2"

  jq -n \
    --argjson max_bundles "$max_bundles" '
    {
      max_bundles_per_worker: $max_bundles,
      max_total_cost_per_worker: 8,
      starvation_escape_bundle_ids: [],
      explicit_incompatibilities: []
    }
  ' >"$path"
}

run_check() {
  local scope_file

  bash -n "$packer"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$contract_path"
  grep -q 'franken-engine.locality-aware-remote-proof-batch-plan.v1' "$docs_path"
  record_pass "bash syntax and docs contract"

  scope_file="$(mktemp "${TMPDIR:-/tmp}/locality-aware-remote-proof-batch-scope.XXXXXX")"
  printf '%s\n' \
    "scripts/locality_aware_remote_proof_batch_packer.sh" \
    "scripts/e2e/locality_aware_remote_proof_batch_packer_smoke.sh" \
    "docs/LOCALITY_AWARE_REMOTE_PROOF_BATCH_PACKER.md" \
    "docs/locality_aware_remote_proof_batch_contract_v1.json" >"$scope_file"
  "${root_dir}/scripts/rch_policy_compliance_gate.sh" \
    --output-dir "${TMPDIR:-/tmp}/locality-aware-remote-proof-batch-rch-policy" \
    --scope-file "$scope_file" >/dev/null
  record_pass "rch policy compliance"
}

run_case() {
  local case_name="$1"
  local expected_exit="$2"
  local output_dir="$3"
  shift 3

  local output actual_exit
  set +e
  output="$("$packer" --output-dir "$output_dir" "$@" 2>&1)"
  actual_exit=$?
  set -e

  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    record_failure "${case_name} exit ${actual_exit}, expected ${expected_exit}"
    printf '%s\n' "$output" >&2
    return 1
  fi

  test -s "${output_dir}/batch_manifest.json"
  test -s "${output_dir}/commands.txt"
  test -s "${output_dir}/events.jsonl"
  test -s "${output_dir}/report.md"
  record_pass "$case_name"
}

run_selftest() {
  local tmp_parent tmp_root fixture_dir
  local shared_dir fairness_dir incompatible_dir repeat_dir
  local hash_a hash_b

  run_check
  tmp_parent="${LOCALITY_AWARE_REMOTE_PROOF_BATCH_PACKER_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/locality-aware-remote-proof-batch.XXXXXX")"
  fixture_dir="${tmp_root}/fixtures"
  mkdir -p "$fixture_dir"

  write_bundle_reports "${fixture_dir}/bundle-reports-shared.json" false false
  write_mirror_manifests "${fixture_dir}/mirror-manifests.json"
  write_roi_ledgers "${fixture_dir}/roi-ledgers-shared.json" false
  write_fairness_policy "${fixture_dir}/fairness-two.json" 2

  shared_dir="${tmp_root}/shared-locality"
  run_case "two-suite-shared-locality" 0 "$shared_dir" \
    --bundle-reports-json "${fixture_dir}/bundle-reports-shared.json" \
    --mirror-manifests-json "${fixture_dir}/mirror-manifests.json" \
    --roi-ledgers-json "${fixture_dir}/roi-ledgers-shared.json" \
    --fairness-policy-json "${fixture_dir}/fairness-two.json"
  jq -e '
    .packing_decision == "pass"
    and (.batches | length == 1)
    and (.batches[0].bundle_ids == ["bundle-a", "bundle-b"])
    and (.batches[0].worker_id == "ts2")
    and (.batches[0].target_dir == "/tmp/rch_target_shared")
    and (.batches[0].bundle_rows | length == 2)
    and (.batches[0].bundle_rows[0].pack_order == 1)
    and (.split_reasons == [])
  ' "${shared_dir}/batch_manifest.json" >/dev/null
  record_pass "shared locality packing assertions"

  write_fairness_policy "${fixture_dir}/fairness-one.json" 1
  fairness_dir="${tmp_root}/fairness-split"
  run_case "fairness-mandated-split" 0 "$fairness_dir" \
    --bundle-reports-json "${fixture_dir}/bundle-reports-shared.json" \
    --mirror-manifests-json "${fixture_dir}/mirror-manifests.json" \
    --roi-ledgers-json "${fixture_dir}/roi-ledgers-shared.json" \
    --fairness-policy-json "${fixture_dir}/fairness-one.json"
  jq -e '
    .packing_decision == "pass"
    and (.batches | length == 2)
    and (.split_reasons == ["fairness_split:max_bundles_per_worker"])
    and all(.batches[]; (.bundle_ids | length) == 1)
  ' "${fairness_dir}/batch_manifest.json" >/dev/null
  record_pass "fairness split assertions"

  write_bundle_reports "${fixture_dir}/bundle-reports-incompatible.json" false true
  write_roi_ledgers "${fixture_dir}/roi-ledgers-incompatible.json" true
  incompatible_dir="${tmp_root}/incompatible-split"
  run_case "incompatible-worker-target-split" 0 "$incompatible_dir" \
    --bundle-reports-json "${fixture_dir}/bundle-reports-incompatible.json" \
    --mirror-manifests-json "${fixture_dir}/mirror-manifests.json" \
    --roi-ledgers-json "${fixture_dir}/roi-ledgers-incompatible.json" \
    --fairness-policy-json "${fixture_dir}/fairness-two.json"
  jq -e '
    .packing_decision == "pass"
    and (.batches | length == 2)
    and (.split_reasons == ["compatibility_split:worker_or_target_incompatibility"])
    and (.batches | map(.worker_id) | sort == ["ts2", "vmi1167313"])
  ' "${incompatible_dir}/batch_manifest.json" >/dev/null
  record_pass "compatibility split assertions"

  repeat_dir="${tmp_root}/shared-locality-repeat"
  run_case "deterministic-pack-order-repeat" 0 "$repeat_dir" \
    --bundle-reports-json "${fixture_dir}/bundle-reports-shared.json" \
    --mirror-manifests-json "${fixture_dir}/mirror-manifests.json" \
    --roi-ledgers-json "${fixture_dir}/roi-ledgers-shared.json" \
    --fairness-policy-json "${fixture_dir}/fairness-two.json"
  hash_a="$(jq -r '.hash_basis.manifest_hash' "${shared_dir}/batch_manifest.json")"
  hash_b="$(jq -r '.hash_basis.manifest_hash' "${repeat_dir}/batch_manifest.json")"
  if [[ "$hash_a" != "$hash_b" ]]; then
    record_failure "deterministic batch manifest hash mismatch"
    exit 1
  fi
  if [[ "$(jq -r '.batch_manifest_id' "${shared_dir}/batch_manifest.json")" != "$(jq -r '.batch_manifest_id' "${repeat_dir}/batch_manifest.json")" ]]; then
    record_failure "deterministic batch manifest id mismatch"
    exit 1
  fi
  if [[ "$(jq -c '.batches | map(.batch_id)' "${shared_dir}/batch_manifest.json")" != "$(jq -c '.batches | map(.batch_id)' "${repeat_dir}/batch_manifest.json")" ]]; then
    record_failure "deterministic batch id ordering mismatch"
    exit 1
  fi
  record_pass "deterministic pack ordering assertions"

  printf 'locality_aware_remote_proof_batch_packer_smoke_artifacts=%s\n' "$tmp_root"
}

case "${1:-check}" in
  check)
    run_check
    ;;
  selftest)
    run_check
    run_selftest
    ;;
  *)
    record_failure "unknown mode: ${1:-}"
    exit 64
    ;;
esac
