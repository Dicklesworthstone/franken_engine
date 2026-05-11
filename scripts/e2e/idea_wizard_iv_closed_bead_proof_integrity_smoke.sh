#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
normalizer="${root_dir}/scripts/idea_wizard_iv_closed_bead_proof_integrity.sh"
mode="${1:-check}"

record_pass() {
  printf 'PASS idea-wizard-iv-closed-bead-proof %s\n' "$1"
}

record_failure() {
  printf 'FAIL idea-wizard-iv-closed-bead-proof %s\n' "$1" >&2
  exit 1
}

write_case_files() {
  local case_id="$1"
  local br_json="$2"
  local git_json="$3"
  local manifest_json="$4"

  case "$case_id" in
    all-closed-strong)
      cat >"$br_json" <<'JSON'
[
  {
    "id": "bd-strong",
    "title": "[IW4] Strong close proof",
    "status": "closed",
    "priority": 1,
    "assignee": "RainyBadger",
    "updated_at": "2026-05-11T00:00:00Z",
    "closed_at": "2026-05-11T00:00:00Z",
    "close_reason": "Done in commit abc1234. Validation passed: rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target cargo test -p frankenengine-engine closed_bead_proof",
    "labels": ["idea-wizard", "proof-integrity"],
    "dependencies": []
  }
]
JSON
      cat >"$git_json" <<'JSON'
[
  {"commit": "abc1234deadbeef", "subject": "Implement bd-strong proof integrity"}
]
JSON
      printf '[]\n' >"$manifest_json"
      ;;
    missing-commit-reference)
      cat >"$br_json" <<'JSON'
[
  {
    "id": "bd-missing-commit",
    "title": "[IW4] Missing direct commit proof",
    "status": "closed",
    "priority": 1,
    "assignee": "RainyBadger",
    "updated_at": "2026-05-11T00:01:00Z",
    "closed_at": "2026-05-11T00:01:00Z",
    "close_reason": "Validation passed: rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target cargo test -p frankenengine-engine closed_bead_proof",
    "labels": ["idea-wizard"],
    "dependencies": []
  }
]
JSON
      printf '[]\n' >"$git_json"
      printf '[]\n' >"$manifest_json"
      ;;
    artifact-manifest)
      cat >"$br_json" <<'JSON'
[
  {
    "id": "bd-artifact",
    "title": "[IW4] Artifact backed close",
    "status": "closed",
    "priority": 2,
    "assignee": "RainyBadger",
    "updated_at": "2026-05-11T00:02:00Z",
    "closed_at": "2026-05-11T00:02:00Z",
    "close_reason": "Done with run_manifest.json and report.md artifacts.",
    "labels": ["idea-wizard", "artifact"],
    "dependencies": []
  }
]
JSON
      printf '[]\n' >"$git_json"
      cat >"$manifest_json" <<'JSON'
[
  {"bead_id": "bd-artifact", "path": "artifacts/bd-artifact/run_manifest.json"}
]
JSON
      ;;
    weak-validation-proof)
      cat >"$br_json" <<'JSON'
[
  {
    "id": "bd-weak-validation",
    "title": "[IW4] Weak validation proof",
    "status": "closed",
    "priority": 1,
    "assignee": "RainyBadger",
    "updated_at": "2026-05-11T00:03:00Z",
    "closed_at": "2026-05-11T00:03:00Z",
    "close_reason": "Validation passed: cargo test",
    "labels": ["idea-wizard", "testing"],
    "dependencies": []
  }
]
JSON
      printf '[]\n' >"$git_json"
      printf '[]\n' >"$manifest_json"
      ;;
    git-log-match)
      cat >"$br_json" <<'JSON'
[
  {
    "id": "bd-gitlog",
    "title": "[IW4] Git log backed close",
    "status": "closed",
    "priority": 2,
    "assignee": "RainyBadger",
    "updated_at": "2026-05-11T00:04:00Z",
    "closed_at": "2026-05-11T00:04:00Z",
    "close_reason": "Done.",
    "labels": ["idea-wizard"],
    "dependencies": []
  }
]
JSON
      cat >"$git_json" <<'JSON'
[
  {"commit": "def5678", "subject": "Ship bd-gitlog proof report"}
]
JSON
      printf '[]\n' >"$manifest_json"
      ;;
    *)
      record_failure "unknown fixture ${case_id}"
      ;;
  esac
}

run_case() {
  local case_id="$1"
  local expected_decision="$2"
  local expected_weak="$3"
  local expected_direct="$4"
  local expected_validation="$5"
  local expected_artifact="$6"
  local tmpdir br_json git_json manifest_json output_dir status

  tmpdir="$(mktemp -d)"
  br_json="${tmpdir}/br.json"
  git_json="${tmpdir}/git.json"
  manifest_json="${tmpdir}/manifest.json"
  output_dir="${tmpdir}/out"
  write_case_files "$case_id" "$br_json" "$git_json" "$manifest_json"

  set +e
  IDEA_WIZARD_IV_CLOSED_BEAD_PROOF_GENERATED_AT_UTC="2026-05-11T00:00:00Z" \
    "$normalizer" \
    --br-list-json "$br_json" \
    --git-log-json "$git_json" \
    --artifact-manifest-json "$manifest_json" \
    --source-revision "smoke-${case_id}" \
    --output-dir "$output_dir" >"${tmpdir}/stdout.log" 2>"${tmpdir}/stderr.log"
  status=$?
  set -e

  if [[ "$status" -ne 0 ]]; then
    cat "${tmpdir}/stderr.log" >&2
    record_failure "unexpected exit for ${case_id}: ${status}"
  fi

  [[ -f "${output_dir}/closed_bead_proof_integrity.json" ]] || record_failure "missing report for ${case_id}"
  [[ -f "${output_dir}/weak_evidence.jsonl" ]] || record_failure "missing weak evidence for ${case_id}"
  [[ -f "${output_dir}/run_manifest.json" ]] || record_failure "missing manifest for ${case_id}"
  [[ -f "${output_dir}/events.jsonl" ]] || record_failure "missing events for ${case_id}"
  [[ -f "${output_dir}/commands.txt" ]] || record_failure "missing commands for ${case_id}"
  [[ -f "${output_dir}/trace_ids.json" ]] || record_failure "missing trace ids for ${case_id}"
  [[ -f "${output_dir}/report.md" ]] || record_failure "missing markdown report for ${case_id}"

  jq -e --arg decision "$expected_decision" '.decision == $decision' "${output_dir}/closed_bead_proof_integrity.json" >/dev/null \
    || record_failure "decision mismatch for ${case_id}"
  jq -e --argjson expected "$expected_weak" '.weak_evidence_count == $expected' "${output_dir}/closed_bead_proof_integrity.json" >/dev/null \
    || record_failure "weak count mismatch for ${case_id}"
  jq -e --argjson expected "$expected_direct" '.proof_strength_buckets.direct_commit_reference == $expected' "${output_dir}/closed_bead_proof_integrity.json" >/dev/null \
    || record_failure "direct bucket mismatch for ${case_id}"
  jq -e --argjson expected "$expected_validation" '.proof_strength_buckets.validation_command_present == $expected' "${output_dir}/closed_bead_proof_integrity.json" >/dev/null \
    || record_failure "validation bucket mismatch for ${case_id}"
  jq -e --argjson expected "$expected_artifact" '.proof_strength_buckets.artifact_manifest_present == $expected' "${output_dir}/closed_bead_proof_integrity.json" >/dev/null \
    || record_failure "artifact bucket mismatch for ${case_id}"
  jq -e '.mutation_policy.mutates_br == false and .mutation_policy.runs_cargo == false and .rch_policy.runs_rch == false' "${output_dir}/closed_bead_proof_integrity.json" >/dev/null \
    || record_failure "mutation boundary mismatch for ${case_id}"
  grep -Fq 'rch exec -- env CARGO_TARGET_DIR=' "${output_dir}/commands.txt" \
    || record_failure "missing rch recommendation for ${case_id}"

  record_pass "$case_id"
}

run_check() {
  bash -n "$normalizer" "${BASH_SOURCE[0]}"
  run_case "all-closed-strong" "green" 0 1 1 0
  run_case "missing-commit-reference" "degraded" 1 0 1 0
  run_case "artifact-manifest" "degraded" 1 0 0 1
  run_case "weak-validation-proof" "degraded" 1 0 1 0
  run_case "git-log-match" "green" 0 1 0 0
  git -C "$root_dir" diff --check -- \
    docs/IDEA_WIZARD_IV_CLOSED_BEAD_PROOF_INTEGRITY.md \
    scripts/idea_wizard_iv_closed_bead_proof_integrity.sh \
    scripts/e2e/idea_wizard_iv_closed_bead_proof_integrity_smoke.sh \
    docs/idea_wizard_iv_saturation_convergence_v1.json
  record_pass "check"
}

case "$mode" in
  check)
    run_check
    ;;
  -h|--help|help)
    printf 'Usage: ./scripts/e2e/idea_wizard_iv_closed_bead_proof_integrity_smoke.sh [check]\n'
    ;;
  *)
    printf 'unknown mode: %s\n' "$mode" >&2
    exit 64
    ;;
esac
