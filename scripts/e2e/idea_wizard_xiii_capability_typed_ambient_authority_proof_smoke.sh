#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
proof_script="${root_dir}/scripts/idea_wizard_xiii_capability_typed_ambient_authority_proof.sh"
contract_json="${root_dir}/docs/idea_wizard_xiii_capability_typed_ambient_authority_proof_v1.json"
docs_path="${root_dir}/docs/IDEA_WIZARD_XIII_CAPABILITY_TYPED_AMBIENT_AUTHORITY_PROOF.md"
mode="${1:-check}"

record_pass() {
  printf 'PASS idea-wizard-xiii-capability-typed-ambient-authority-proof %s\n' "$1"
}

record_failure() {
  printf 'FAIL idea-wizard-xiii-capability-typed-ambient-authority-proof %s\n' "$1" >&2
  exit 1
}

write_runtime_fixture() {
  local path="$1"
  cat >"$path" <<'JSON'
{
  "schema_version": "franken-engine.idea-wizard-xiii-capability-typed-ambient-authority-proof.runtime.v1",
  "claim_id": "FE-CLAIM-006",
  "bead_id": "bd-ly6hp.4",
  "covered_input_subset": "capability_typed_manifest_ir_hostcall_v1",
  "requested_capabilities": ["fs_read"],
  "granted_capabilities": ["vm_dispatch", "heap_allocate", "fs_read"],
  "denied_ambient_authority": ["filesystem", "network", "hostcall"],
  "runtime_enforcement_verdict": "pass",
  "unsupported_contract": {
    "input_kind": "typed_ts_to_ir",
    "expected": "fail_closed",
    "actual": "fail_closed",
    "diagnostic_code": "capability_typed.unsupported_syntax",
    "reason": "typed TypeScript-to-IR onboarding is not shipped for FE-CLAIM-006"
  },
  "manifest_hash": "manifest-hash-smoke",
  "source_fixtures": {
    "typed_input_or_manifest_fixture": "typed-fixture-hash",
    "ambient_filesystem_rejection_fixture": "fs-fixture-hash",
    "ambient_network_rejection_fixture": "net-fixture-hash",
    "ambient_hostcall_rejection_fixture": "hostcall-fixture-hash"
  },
  "runtime_cases": [
    {
      "case_id": "declared_fs_read_allowed",
      "requested_capability": "fs:read",
      "granted_capabilities": ["vm_dispatch", "heap_allocate", "fs_read"],
      "expected": "allowed",
      "actual": "allowed",
      "diagnostic_code": null,
      "witness_events": ["CapabilityChecked", "HostcallDispatched"],
      "hostcall_decisions": [{"capability": "fs:read", "allowed": true, "instruction_index": 1}]
    },
    {
      "case_id": "ambient_filesystem_rejected",
      "requested_capability": "fs:read",
      "granted_capabilities": ["vm_dispatch", "heap_allocate"],
      "expected": "denied",
      "actual": "denied",
      "diagnostic_code": "runtime.capability.denied",
      "witness_events": ["CapabilityChecked"],
      "hostcall_decisions": [{"capability": "fs:read", "allowed": false, "instruction_index": 1}]
    },
    {
      "case_id": "ambient_network_rejected",
      "requested_capability": "net:connect",
      "granted_capabilities": ["vm_dispatch", "heap_allocate"],
      "expected": "denied",
      "actual": "denied",
      "diagnostic_code": "runtime.capability.denied",
      "witness_events": ["CapabilityChecked"],
      "hostcall_decisions": [{"capability": "net:connect", "allowed": false, "instruction_index": 1}]
    },
    {
      "case_id": "ambient_hostcall_rejected",
      "requested_capability": "hostcall.invoke",
      "granted_capabilities": ["vm_dispatch", "heap_allocate"],
      "expected": "denied",
      "actual": "denied",
      "diagnostic_code": "runtime.capability.denied",
      "witness_events": ["CapabilityChecked"],
      "hostcall_decisions": [{"capability": "hostcall.invoke", "allowed": false, "instruction_index": 1}]
    }
  ],
  "ambient_audit_cases": [
    {
      "case_id": "ambient_filesystem_source",
      "category": "filesystem",
      "source_hash": "fs-source-hash",
      "passed": false,
      "violation_count": 1,
      "finding_patterns": ["std_fs"]
    },
    {
      "case_id": "ambient_network_source",
      "category": "network",
      "source_hash": "net-source-hash",
      "passed": false,
      "violation_count": 1,
      "finding_patterns": ["std_net"]
    },
    {
      "case_id": "ambient_hostcall_source",
      "category": "hostcall",
      "source_hash": "hostcall-source-hash",
      "passed": false,
      "violation_count": 1,
      "finding_patterns": ["std_process"]
    }
  ]
}
JSON
}

run_proof_expect() {
  local expected_exit="$1"
  local runtime_fixture="$2"
  local output_dir="$3"
  local status

  set +e
  "$proof_script" \
    --runtime-result-json "$runtime_fixture" \
    --skip-rust-validation \
    --source-revision "smoke-capability-typed-proof" \
    --output-dir "$output_dir" >/dev/null 2>"${output_dir}.stderr"
  status=$?
  set -e

  if [[ "$status" -ne "$expected_exit" ]]; then
    cat "${output_dir}.stderr" >&2
    record_failure "proof script exit ${status}, expected ${expected_exit}"
  fi
}

run_check() {
  local tmpdir runtime_fixture output_dir
  tmpdir="$(mktemp -d)"
  runtime_fixture="${tmpdir}/runtime_result.json"
  output_dir="${tmpdir}/pass"
  write_runtime_fixture "$runtime_fixture"

  bash -n "$proof_script" "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "$proof_script" "${BASH_SOURCE[0]}"
  fi
  jq empty "$contract_json"
  grep -Fq "FE-CLAIM-006" "$docs_path"
  grep -Fq "does not claim that typed TypeScript-to-IR onboarding is shipped" "$docs_path"

  run_proof_expect 0 "$runtime_fixture" "$output_dir"
  jq -e '
    . as $root
    | .decision == "pass"
    and .claim_id == "FE-CLAIM-006"
    and .promotion_subset == "covered_capability_typed_input_subset_only"
    and .covered_input_subset == "capability_typed_manifest_ir_hostcall_v1"
    and .requested_capabilities == ["fs_read"]
    and all(["vm_dispatch", "heap_allocate", "fs_read"][]; . as $id | ($root.granted_capabilities | index($id)))
    and all(["filesystem", "network", "hostcall"][]; . as $id | ($root.denied_ambient_authority | index($id)))
    and .runtime_enforcement_verdict == "pass"
    and .unsupported_contract.actual == "fail_closed"
    and all(.checks[]; .passed == true)
  ' "${output_dir}/capability_typed_onboarding_report.json" >/dev/null \
    || record_failure "proof report mismatch"
  jq -e '
    .decision == "pass"
    and .replay_verifier_verdict == "pass"
    and all(.checks[]; .passed == true)
  ' "${output_dir}/replay_verifier_report.json" >/dev/null \
    || record_failure "replay verifier mismatch"
  jq -e '.decision == "fail_closed"' "${output_dir}/stale_evidence_fail_closed_fixture.json" >/dev/null \
    || record_failure "stale fixture did not fail closed"
  jq -e '.decision == "fail_closed"' "${output_dir}/synthetic_evidence_fail_closed_fixture.json" >/dev/null \
    || record_failure "synthetic fixture did not fail closed"
  jq -e '.decision == "fail_closed"' "${output_dir}/missing_evidence_fail_closed_fixture.json" >/dev/null \
    || record_failure "missing fixture did not fail closed"
  jq -e '.decision == "fail_closed"' "${output_dir}/tampered_evidence_fail_closed_fixture.json" >/dev/null \
    || record_failure "tampered fixture did not fail closed"
  jq -s 'length >= 5 and all(.[]; has("event") and has("status"))' "${output_dir}/events.jsonl" >/dev/null \
    || record_failure "events log mismatch"
  jq -e '.claim_id == "FE-CLAIM-006" and .bead_id == "bd-ly6hp.4"' "${output_dir}/run_manifest.json" >/dev/null \
    || record_failure "run manifest mismatch"
  grep -Fq "typed TypeScript-to-IR onboarding is not shipped" "${output_dir}/report.md" \
    || record_failure "human report lacks downgrade text"

  git -C "$root_dir" diff --check -- \
    "$docs_path" \
    "$contract_json" \
    "$proof_script" \
    "${BASH_SOURCE[0]}" \
    "${root_dir}/crates/franken-engine/tests/capability_typed_ambient_authority_proof.rs"
  record_pass "check"
}

run_selftest() {
  local tmpdir runtime_fixture bad_runtime output_dir
  tmpdir="$(mktemp -d)"
  runtime_fixture="${tmpdir}/runtime_result.json"
  bad_runtime="${tmpdir}/bad_runtime_result.json"
  output_dir="${tmpdir}/fail"
  write_runtime_fixture "$runtime_fixture"

  jq '.runtime_cases |= map(if .case_id == "ambient_hostcall_rejected" then .actual = "allowed" else . end)' \
    "$runtime_fixture" >"$bad_runtime"
  run_proof_expect 42 "$bad_runtime" "$output_dir"
  jq -e '
    .decision == "fail_closed"
    and any(.failures[]; .check == "runtime_result_contract")
  ' "${output_dir}/capability_typed_onboarding_report.json" >/dev/null \
    || record_failure "tampered runtime result did not fail closed"

  output_dir="${tmpdir}/missing"
  run_proof_expect 42 "${tmpdir}/missing_runtime_result.json" "$output_dir"
  jq -e '
    .decision == "fail_closed"
    and any(.failures[]; .check == "runtime_result_missing")
  ' "${output_dir}/capability_typed_onboarding_report.json" >/dev/null \
    || record_failure "missing runtime result did not fail closed"
  record_pass "selftest"
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_check
    run_selftest
    ;;
  -h|--help|help)
    printf 'Usage: %s [check|selftest]\n' "${BASH_SOURCE[0]}"
    ;;
  *)
    printf 'unknown mode: %s\n' "$mode" >&2
    exit 64
    ;;
esac
