#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
packer="${root_dir}/scripts/remote_proof_artifact_mirror_packer.sh"
docs_path="${root_dir}/docs/REMOTE_PROOF_ARTIFACT_MIRROR_PACKER.md"
contract_path="${root_dir}/docs/remote_proof_artifact_mirror_contract_v1.json"

record_pass() {
  printf 'PASS remote-proof-artifact-mirror %s\n' "$1"
}

record_failure() {
  printf 'FAIL remote-proof-artifact-mirror %s\n' "$1" >&2
}

write_bundle_report() {
  local path="$1"

  jq -n '
    {
      schema_version: "franken-engine.resident-remote-proof-bundle.v1",
      bundle_id: "semantic-dark-matter-resident-proof",
      bundle_decision: "pass",
      artifact_paths: {
        bundle_report_json: "artifacts/resident/semantic/bundle_report.json",
        run_manifest_json: "artifacts/resident/semantic/run_manifest.json",
        summary_md: "artifacts/resident/semantic/summary.md",
        commands_txt: "artifacts/resident/semantic/commands.txt",
        events_jsonl: "artifacts/resident/semantic/events.jsonl"
      },
      phase_results: [
        {
          phase: "check",
          command_id: "check-1",
          stdout_log: "artifacts/resident/semantic/phase_logs/check-1.stdout.log",
          stderr_log: "artifacts/resident/semantic/phase_logs/check-1.stderr.log"
        }
      ]
    }
  ' >"$path"
}

write_artifact_files() {
  local path="$1"

  jq -n '
    {
      schema_version: "franken-engine.remote-proof-artifact-files.v1",
      artifacts: [
        {
          path: "artifacts/resident/semantic/run_manifest.json",
          sha256: "1111111111111111111111111111111111111111111111111111111111111111",
          size_bytes: 1200,
          roles: ["replay"],
          replay_critical: true
        },
        {
          path: "artifacts/resident/semantic/events.jsonl",
          sha256: "2222222222222222222222222222222222222222222222222222222222222222",
          size_bytes: 2400,
          roles: ["replay", "inspect"],
          replay_critical: true
        },
        {
          path: "artifacts/resident/semantic/commands.txt",
          sha256: "3333333333333333333333333333333333333333333333333333333333333333",
          size_bytes: 600,
          roles: ["replay"],
          replay_critical: true
        },
        {
          path: "artifacts/resident/semantic/bundle_report.json",
          sha256: "4444444444444444444444444444444444444444444444444444444444444444",
          size_bytes: 1800,
          roles: ["status", "inspect"],
          replay_critical: false
        },
        {
          path: "artifacts/resident/semantic/summary.md",
          sha256: "5555555555555555555555555555555555555555555555555555555555555555",
          size_bytes: 800,
          roles: ["inspect"],
          replay_critical: false
        },
        {
          path: "artifacts/resident/semantic/phase_logs/check-1.stdout.log",
          sha256: "6666666666666666666666666666666666666666666666666666666666666666",
          size_bytes: 900,
          roles: ["inspect"],
          replay_critical: false
        }
      ]
    }
  ' >"$path"
}

write_request() {
  local path="$1"

  jq -n '
    {
      schema_version: "franken-engine.remote-proof-retrieval-request.v1",
      requested_roles: ["replay", "status"]
    }
  ' >"$path"
}

write_retrieved_success() {
  local path="$1"

  jq -n '
    [
      "artifacts/resident/semantic/bundle_report.json",
      "artifacts/resident/semantic/commands.txt",
      "artifacts/resident/semantic/events.jsonl",
      "artifacts/resident/semantic/run_manifest.json"
    ]
  ' >"$path"
}

run_check() {
  local scope_file

  bash -n "$packer"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$contract_path"
  grep -q 'franken-engine.remote-proof-artifact-mirror-verification.v1' "$docs_path"
  record_pass "bash syntax and docs contract"

  scope_file="$(mktemp "${TMPDIR:-/tmp}/remote-proof-artifact-mirror-scope.XXXXXX")"
  printf '%s\n' \
    "scripts/remote_proof_artifact_mirror_packer.sh" \
    "scripts/e2e/remote_proof_artifact_mirror_packer_smoke.sh" \
    "docs/REMOTE_PROOF_ARTIFACT_MIRROR_PACKER.md" \
    "docs/remote_proof_artifact_mirror_contract_v1.json" >"$scope_file"
  "${root_dir}/scripts/rch_policy_compliance_gate.sh" \
    --output-dir "${TMPDIR:-/tmp}/remote-proof-artifact-mirror-rch-policy" \
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

  test -s "${output_dir}/artifact_mirror_manifest.json"
  test -s "${output_dir}/retrieval_pack.json"
  test -s "${output_dir}/retrieval_verification_report.json"
  test -s "${output_dir}/commands.txt"
  test -s "${output_dir}/events.jsonl"
  test -s "${output_dir}/report.md"
  record_pass "$case_name"
}

run_selftest() {
  local tmp_parent tmp_root fixture_dir
  local success_dir collision_dir missing_dir overbroad_dir

  run_check
  tmp_parent="${REMOTE_PROOF_ARTIFACT_MIRROR_PACKER_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/remote-proof-artifact-mirror.XXXXXX")"
  fixture_dir="${tmp_root}/fixtures"
  mkdir -p "$fixture_dir"

  write_bundle_report "${fixture_dir}/bundle_report.json"
  write_artifact_files "${fixture_dir}/artifact_files.json"
  write_request "${fixture_dir}/request.json"
  write_retrieved_success "${fixture_dir}/retrieved-success.json"

  success_dir="${tmp_root}/success"
  run_case "minimal-retrieval-pack-success" 0 "$success_dir" \
    --bundle-report-json "${fixture_dir}/bundle_report.json" \
    --artifact-files-json "${fixture_dir}/artifact_files.json" \
    --retrieval-request-json "${fixture_dir}/request.json" \
    --retrieved-files-json "${fixture_dir}/retrieved-success.json"
  jq -e '
    .verification_decision == "pass"
    and (.retrieval_pack_artifacts | length == 4)
    and (.retrieved_artifacts | length == 4)
    and (.hash_basis.input_hash | length == 64)
    and (.hash_basis.verification_hash | length == 64)
  ' "${success_dir}/retrieval_verification_report.json" >/dev/null
  record_pass "minimal retrieval pack assertions"

  jq \
    '.artifacts[1].sha256 = "1111111111111111111111111111111111111111111111111111111111111111"' \
    "${fixture_dir}/artifact_files.json" >"${fixture_dir}/artifact_files-collision.json"
  collision_dir="${tmp_root}/collision"
  run_case "content-address-collision" 42 "$collision_dir" \
    --bundle-report-json "${fixture_dir}/bundle_report.json" \
    --artifact-files-json "${fixture_dir}/artifact_files-collision.json" \
    --retrieval-request-json "${fixture_dir}/request.json" \
    --retrieved-files-json "${fixture_dir}/retrieved-success.json"
  jq -e '
    .verification_decision == "fail_closed"
    and .reason == "duplicate content-address collision maps multiple logical paths"
    and (.content_address_collisions | length == 1)
  ' "${collision_dir}/retrieval_verification_report.json" >/dev/null
  record_pass "content-address collision assertions"

  jq -n '
    [
      "artifacts/resident/semantic/bundle_report.json",
      "artifacts/resident/semantic/commands.txt",
      "artifacts/resident/semantic/run_manifest.json"
    ]
  ' >"${fixture_dir}/retrieved-missing-critical.json"
  missing_dir="${tmp_root}/missing-critical"
  run_case "missing-replay-critical" 42 "$missing_dir" \
    --bundle-report-json "${fixture_dir}/bundle_report.json" \
    --artifact-files-json "${fixture_dir}/artifact_files.json" \
    --retrieval-request-json "${fixture_dir}/request.json" \
    --retrieved-files-json "${fixture_dir}/retrieved-missing-critical.json"
  jq -e '
    .verification_decision == "fail_closed"
    and .reason == "replay-critical artifact is missing from retrieved pack"
    and (.missing_replay_critical_artifacts == ["artifacts/resident/semantic/events.jsonl"])
  ' "${missing_dir}/retrieval_verification_report.json" >/dev/null
  record_pass "missing replay-critical assertions"

  jq -n '
    [
      "artifacts/resident/semantic/bundle_report.json",
      "artifacts/resident/semantic/commands.txt",
      "artifacts/resident/semantic/events.jsonl",
      "artifacts/resident/semantic/run_manifest.json",
      "/tmp/rch_target_franken_engine_bd_doi34_bundle/**"
    ]
  ' >"${fixture_dir}/retrieved-overbroad.json"
  overbroad_dir="${tmp_root}/overbroad"
  run_case "over-broad-retrieval" 42 "$overbroad_dir" \
    --bundle-report-json "${fixture_dir}/bundle_report.json" \
    --artifact-files-json "${fixture_dir}/artifact_files.json" \
    --retrieval-request-json "${fixture_dir}/request.json" \
    --retrieved-files-json "${fixture_dir}/retrieved-overbroad.json"
  jq -e '
    .verification_decision == "fail_closed"
    and .reason == "retrieval pack includes broad target-dir or wildcard paths"
    and (.broad_retrieved_artifacts == ["/tmp/rch_target_franken_engine_bd_doi34_bundle/**"])
  ' "${overbroad_dir}/retrieval_verification_report.json" >/dev/null
  record_pass "over-broad retrieval assertions"

  printf 'remote_proof_artifact_mirror_packer_smoke_artifacts=%s\n' "$tmp_root"
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
