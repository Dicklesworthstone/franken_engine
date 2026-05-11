#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
script_path="${root_dir}/scripts/swarm_proof_equivalence_classifier.sh"
docs_path="${root_dir}/docs/SWARM_PROOF_EQUIVALENCE_CLASSIFIER.md"
cases_path="${root_dir}/scripts/testdata/swarm_proof_equivalence_classifier/cases.json"
golden_dir="${SWARM_PROOF_EQUIVALENCE_CLASSIFIER_GOLDEN_DIR:-${root_dir}/scripts/testdata/goldens}"
mode="${1:-check}"
output_root="${2:-${SWARM_PROOF_EQUIVALENCE_CLASSIFIER_SMOKE_DIR:-${TMPDIR:-/tmp}/franken-engine-proof-equivalence-classifier-smoke-$$}}"
failures=0

record_pass() {
  printf 'PASS swarm-proof-equivalence-classifier %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-proof-equivalence-classifier %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_proof_equivalence_classifier_smoke.sh [check|selftest] [output_root]
EOF
}

docs_shape_ok() {
  grep -Fq 'never runs Cargo or RCH' "$docs_path" \
    && grep -Fq 'narrower candidate never satisfies a wider request' "$docs_path" \
    && grep -Fq 'shell wrappers, bare Cargo, and local fallback' "$docs_path" \
    && grep -Fq 'stable classifier hash' "$docs_path" \
    && grep -Fq 'reuse_refusal_receipt.json' "$docs_path"
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-proof-equivalence-classifier-fixtures.v1"
    and (.cases | length) == 7
    and all(.cases[]; has("case_id") and has("expected"))
    and ([.cases[].expected.verdict] | unique | sort) == ["human_review", "rerun_required", "reuse_allowed", "reuse_refused"]
    and ([.cases[].expected.reason_codes[]] | unique | sort) == [
      "candidate_narrower_than_requested",
      "candidate_wider_than_requested",
      "changed_dependency_root",
      "contaminated_command_shape",
      "dirty_lane_mismatch",
      "env_allowlist_mismatch",
      "identical_request"
    ]
  ' "$cases_path" >/dev/null
}

script_static_ok() {
  bash -n "$script_path"
  bash -n "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "$script_path" "${BASH_SOURCE[0]}"
  fi
}

expand_case() {
  local case_json="$1"

  jq -n \
    --slurpfile fixtures "$cases_path" \
    --argjson case "$case_json" '
      ($fixtures[0].base_request) as $base
      | def merged($field; $ref):
          if ($case[$ref] // "") == "base_request" then $base
          elif ($case[$field] // null) != null then ($base + $case[$field])
          else $base
          end;
      $case + {
        candidate: merged("candidate"; "candidate_ref"),
        requested: merged("requested"; "requested_ref")
      }
    '
}

canonicalize_report() {
  local report_path="$1"
  local tmp_root="$2"
  jq --arg tmp_root "$tmp_root" '
    def scrub:
      if type == "string" then
        gsub($tmp_root; "[SMOKE_ROOT]")
        | gsub("/tmp/rch_target_"; "[RCH_TARGET]/")
        | gsub("/tmp/[A-Za-z0-9._-]+"; "[TMP_PATH]")
      elif type == "array" then
        map(scrub)
      elif type == "object" then
        with_entries(.value |= scrub)
      else
        .
      end;
    scrub
  ' "$report_path"
}

assert_case_golden() {
  local case_id="$1"
  local report_path="$2"
  local tmp_root="$3"
  local golden_path="${golden_dir}/swarm_proof_equivalence_classifier_${case_id}.golden"

  if [[ "${UPDATE_GOLDENS:-0}" == "1" ]]; then
    mkdir -p "$golden_dir"
    canonicalize_report "$report_path" "$tmp_root" >"$golden_path"
    return
  fi

  if [[ ! -f "$golden_path" ]]; then
    record_failure "${case_id} missing golden"
    return
  fi

  if ! diff -u "$golden_path" <(canonicalize_report "$report_path" "$tmp_root"); then
    record_failure "${case_id} golden drift"
  fi
}

assert_case_output() {
  local case_json="$1"
  local output_dir="$2"
  local report_path="${output_dir}/equivalence_report.json"
  local receipt_path="${output_dir}/reuse_refusal_receipt.json"
  local case_id

  case_id="$(jq -r '.case_id' <<<"$case_json")"
  jq empty "$report_path" "$receipt_path" "${output_dir}/run_manifest.json" >/dev/null
  test -s "${output_dir}/events.jsonl"
  test -s "${output_dir}/commands.txt"
  test -s "${output_dir}/report.md"

  jq -e \
    --argjson expected "$(jq '.expected' <<<"$case_json")" \
    --arg case_id "$case_id" '
      .schema_version == "franken-engine.swarm-proof-equivalence-report.v1"
      and .case_id == $case_id
      and .verdict == $expected.verdict
      and .reason_codes == $expected.reason_codes
      and .partial_overlap.relation == $expected.relation
      and (.classifier_hash | test("^[0-9a-f]{64}$"))
      and (.remediation | length) >= 40
      and .non_mutation_attestation.runs_cargo == false
      and .non_mutation_attestation.runs_rch == false
    ' "$report_path" >/dev/null || record_failure "${case_id} equivalence report mismatch"

  jq -e --argjson expected "$(jq '.expected' <<<"$case_json")" '
    .reuse_eligible == $expected.reuse_eligible
    and .verdict == $expected.verdict
    and (.classifier_hash | test("^[0-9a-f]{64}$"))
  ' "$receipt_path" >/dev/null || record_failure "${case_id} receipt mismatch"
}

run_case() {
  local raw_case_json="$1"
  local tmp_root="$2"
  local case_json case_id case_dir fixture_path

  case_json="$(expand_case "$raw_case_json")"
  case_id="$(jq -r '.case_id' <<<"$case_json")"
  case_dir="${tmp_root}/${case_id}"
  fixture_path="${case_dir}/fixture.json"
  mkdir -p "$case_dir"
  jq '.' <<<"$case_json" >"$fixture_path"

  "$script_path" --fixture-json "$fixture_path" --output-dir "${case_dir}/out" >/dev/null
  assert_case_output "$case_json" "${case_dir}/out"
  assert_case_golden "$case_id" "${case_dir}/out/equivalence_report.json" "$tmp_root"
  record_pass "$case_id"
}

goldens_shape_ok() {
  if [[ "${UPDATE_GOLDENS:-0}" == "1" ]]; then
    return 0
  fi
  while IFS= read -r case_id; do
    local golden_path="${golden_dir}/swarm_proof_equivalence_classifier_${case_id}.golden"
    [[ -f "$golden_path" ]] || { record_failure "${case_id} missing checked-in golden"; continue; }
    jq empty "$golden_path" >/dev/null || record_failure "${case_id} invalid golden json"
  done < <(jq -r '.cases[].case_id' "$cases_path")
}

run_check() {
  jq empty "$cases_path" >/dev/null
  script_static_ok
  docs_shape_ok || record_failure "docs shape"
  fixtures_shape_ok || record_failure "fixture shape"
  goldens_shape_ok

  if [[ "$failures" -eq 0 ]]; then
    record_pass "check"
  fi
}

run_selftest() {
  local tmp_root="$1"

  run_check
  if [[ "$failures" -ne 0 ]]; then
    return
  fi

  while IFS= read -r case_json; do
    run_case "$case_json" "$tmp_root"
  done < <(jq -c '.cases[]' "$cases_path")
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_selftest "$output_root"
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage
    record_failure "unknown mode: ${mode}"
    exit 64
    ;;
esac

if [[ "$failures" -ne 0 ]]; then
  exit 1
fi
