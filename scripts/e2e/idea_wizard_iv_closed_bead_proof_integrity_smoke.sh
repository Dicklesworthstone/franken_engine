#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
normalizer="${root_dir}/scripts/idea_wizard_iv_closed_bead_proof_integrity.sh"
golden_dir="${root_dir}/scripts/testdata/goldens"
mode="${1:-check}"

record_pass() {
  printf 'PASS idea-wizard-iv-closed-bead-proof %s\n' "$1"
}

record_failure() {
  printf 'FAIL idea-wizard-iv-closed-bead-proof %s\n' "$1" >&2
  exit 1
}

canonicalize_report() {
  local report_path="$1"
  jq '
    del(.artifact_paths)
    | del(.beads[].updated_at)
    | del(.beads[].closed_at)
  ' "$report_path"
}

compare_golden() {
  local case_id="$1"
  local actual_path="$2"
  local golden_path="$3"

  if [[ "${UPDATE_GOLDENS:-0}" == "1" ]]; then
    cp "$actual_path" "$golden_path"
    record_pass "updated golden ${case_id}"
    return
  fi

  [[ -f "$golden_path" ]] || record_failure "missing golden ${golden_path}"
  if ! diff -u "$golden_path" "$actual_path"; then
    record_failure "golden drift for ${case_id}; set UPDATE_GOLDENS=1 only after reviewing the diff"
  fi
  record_pass "golden matches ${case_id}"
}

write_case_files() {
  local case_id="$1"
  local br_json="$2"
  local git_json="$3"
  local manifest_json="$4"
  local marker_json="$5"

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
      printf '[]\n' >"$marker_json"
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
      printf '[]\n' >"$marker_json"
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
      printf '[]\n' >"$marker_json"
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
      printf '[]\n' >"$marker_json"
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
      printf '[]\n' >"$marker_json"
      ;;
    semantic-contradiction)
      cat >"$br_json" <<'JSON'
[
  {
    "id": "bd-zlvz8",
    "title": "[MOCK] CRITICAL: Implement async/await pending promise execution",
    "status": "closed",
    "priority": 1,
    "assignee": "ClaudeAlpha",
    "updated_at": "2026-05-03T04:00:49Z",
    "closed_at": "2026-05-03T04:00:49Z",
    "close_reason": "Done in commit cafefeed. Validation passed: rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target cargo test -p franken-core async_function_pending_await",
    "labels": ["async-await", "franken-core"],
    "dependencies": []
  },
  {
    "id": "bd-negative",
    "title": "[IW4] Legitimate negative unsupported fixture",
    "status": "closed",
    "priority": 2,
    "assignee": "RainyBadger",
    "updated_at": "2026-05-03T04:01:49Z",
    "closed_at": "2026-05-03T04:01:49Z",
    "close_reason": "Done in commit feedface. Validation passed: rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target cargo test -p frankenengine-engine negative_fixture",
    "labels": ["testing"],
    "dependencies": []
  }
]
JSON
      cat >"$git_json" <<'JSON'
[
  {"commit": "cafefeeddeadbeef", "subject": "Implement bd-zlvz8 async await pending promise scheduling"},
  {"commit": "feedface01234567", "subject": "Implement bd-negative fixture coverage"}
]
JSON
      printf '[]\n' >"$manifest_json"
      cat >"$marker_json" <<'JSON'
[
  {
    "bead_id": "bd-zlvz8",
    "file": "crates/franken-core/src/baseline_interpreter.rs",
    "line": 5408,
    "marker": "pending promise requires full async scheduling (not yet implemented)",
    "marker_class": "unsupported_semantic_marker",
    "detail": "Closed bead claims pending async/await execution is implemented, but source still fails closed for pending promise scheduling.",
    "confidence": "high",
    "suggested_next_bead_title": "[IDEA-WIZARD-XII-C] Reopen real pending-promise await execution from source evidence"
  },
  {
    "bead_id": "bd-negative",
    "file": "tests/negative_fixture.rs",
    "line": 12,
    "marker": "not yet implemented",
    "marker_class": "negative_fixture_marker",
    "detail": "Negative fixture intentionally includes unsupported wording.",
    "confidence": "high",
    "negative_fixture": true
  }
]
JSON
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
  local expected_semantic="${7:-0}"
  local tmpdir br_json git_json manifest_json marker_json output_dir status actual_golden

  tmpdir="$(mktemp -d)"
  br_json="${tmpdir}/br.json"
  git_json="${tmpdir}/git.json"
  manifest_json="${tmpdir}/manifest.json"
  marker_json="${tmpdir}/markers.json"
  output_dir="${tmpdir}/out"
  write_case_files "$case_id" "$br_json" "$git_json" "$manifest_json" "$marker_json"

  set +e
  IDEA_WIZARD_IV_CLOSED_BEAD_PROOF_GENERATED_AT_UTC="2026-05-11T00:00:00Z" \
    "$normalizer" \
    --br-list-json "$br_json" \
    --git-log-json "$git_json" \
    --artifact-manifest-json "$manifest_json" \
    --source-marker-json "$marker_json" \
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
  jq -e --argjson expected "$expected_semantic" '.semantic_contradiction_count == $expected and .proof_strength_buckets.semantic_contradiction_marker == $expected' "${output_dir}/closed_bead_proof_integrity.json" >/dev/null \
    || record_failure "semantic contradiction mismatch for ${case_id}"
  jq -e '.mutation_policy.mutates_br == false and .mutation_policy.runs_cargo == false and .rch_policy.runs_rch == false' "${output_dir}/closed_bead_proof_integrity.json" >/dev/null \
    || record_failure "mutation boundary mismatch for ${case_id}"
  grep -Fq 'rch exec -- env CARGO_TARGET_DIR=' "${output_dir}/commands.txt" \
    || record_failure "missing rch recommendation for ${case_id}"

  if [[ "$case_id" == "semantic-contradiction" ]]; then
    jq -e '
      .classification == "semantic_contradiction"
      and .beads[0].id == "bd-zlvz8"
      and .beads[0].source_marker_contradiction == true
      and (.beads[0].semantic_contradictions[0].file == "crates/franken-core/src/baseline_interpreter.rs")
      and (.beads | map(select(.id == "bd-negative" and .source_marker_contradiction == false)) | length) == 1
    ' "${output_dir}/closed_bead_proof_integrity.json" >/dev/null \
      || record_failure "semantic contradiction payload mismatch for ${case_id}"
    actual_golden="${tmpdir}/semantic-contradiction.actual.golden"
    canonicalize_report "${output_dir}/closed_bead_proof_integrity.json" >"$actual_golden"
    compare_golden \
      "semantic-contradiction" \
      "$actual_golden" \
      "${golden_dir}/idea_wizard_iv_closed_bead_proof_semantic_contradiction.golden"
  fi

  record_pass "$case_id"
}

run_check() {
  bash -n "$normalizer" "${BASH_SOURCE[0]}"
  run_case "all-closed-strong" "green" 0 1 1 0 0
  run_case "missing-commit-reference" "degraded" 1 0 1 0 0
  run_case "artifact-manifest" "degraded" 1 0 0 1 0
  run_case "weak-validation-proof" "degraded" 1 0 1 0 0
  run_case "git-log-match" "green" 0 1 0 0 0
  run_case "semantic-contradiction" "degraded" 1 2 2 0 1
  git -C "$root_dir" diff --check -- \
    docs/IDEA_WIZARD_IV_CLOSED_BEAD_PROOF_INTEGRITY.md \
    scripts/idea_wizard_iv_closed_bead_proof_integrity.sh \
    scripts/e2e/idea_wizard_iv_closed_bead_proof_integrity_smoke.sh \
    scripts/testdata/goldens/idea_wizard_iv_closed_bead_proof_semantic_contradiction.golden \
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
