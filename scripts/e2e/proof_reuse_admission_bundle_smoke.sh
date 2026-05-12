#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
bundle_script="${root_dir}/scripts/proof_reuse_admission_bundle.sh"
docs_path="${root_dir}/docs/PROOF_REUSE_ADMISSION_BUNDLE.md"
contract_path="${root_dir}/docs/proof_reuse_admission_bundle_contract_v1.json"
fixtures_path="${PROOF_REUSE_ADMISSION_FIXTURES:-${root_dir}/scripts/testdata/proof_reuse_admission_bundle/cases.json}"
mode="${1:-check}"
failures=0

record_pass() {
  printf 'PASS proof-reuse-admission %s\n' "$1"
}

record_failure() {
  printf 'FAIL proof-reuse-admission %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/proof_reuse_admission_bundle_smoke.sh [check|selftest]
EOF
}

check_no_mutation_claims() {
  local path="$1"
  if grep -Eiq 'automatically mutates|automatically claims|automatically closes|sends Agent Mail automatically|runs Cargo automatically|runs rch automatically|changes live queue policy' "$path"; then
    record_failure "${path#"$root_dir"/} contains forbidden mutation wording"
  fi
}

check_no_bare_heavy_cargo() {
  local path="$1"
  while IFS= read -r command; do
    if [[ "$command" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
      if [[ "$command" != *"rch exec -- env"* || "$command" != *"CARGO_TARGET_DIR="* ]]; then
        record_failure "${path#"$root_dir"/} has bare heavy Cargo command: ${command}"
      fi
    fi
  done < <(jq -r '.. | strings' "$path" 2>/dev/null || sed -n '1,260p' "$path")
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.proof-reuse-admission-bundle-contract.v1"
    and .bead_id == "bd-yb8kk"
    and .implementation_script == "scripts/proof_reuse_admission_bundle.sh"
    and .smoke_script == "scripts/e2e/proof_reuse_admission_bundle_smoke.sh"
    and (.reused_surfaces | index("scripts/proof_reuse_cache_planner.sh") != null)
    and ([.classification_values[]] | sort) == (["invalid","refresh_required","reusable","unknown"] | sort)
    and ([.required_fixture_cases[]] | sort) == (["changed_path_invalidation","direct_cargo_command_rejection","exact_hit","missing_metadata","stale_source_revision","unknown_missing_freshness"] | sort)
    and .mutation_policy.advisory_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_br == false
    and .mutation_policy.sends_agent_mail == false
  ' "$contract_path" >/dev/null
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.proof-reuse-admission-bundle-fixtures.v1"
    and ([.cases[].case_id] | sort) == (["changed_path_invalidation","direct_cargo_command_rejection","exact_hit","missing_metadata","stale_source_revision","unknown_missing_freshness"] | sort)
    and all(.cases[]; .sources.proof_index_json.schema_version == "franken-engine.proof-evidence-query.v1")
    and all(.cases[]; all(.sources.freshness_reports[]?; .schema_version == "franken-engine.proof-freshness-decay-report.v1"))
    and ([.cases[].expected.classification] | unique | sort) == (["invalid","refresh_required","reusable","unknown"] | sort)
  ' "$fixtures_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq "proof_reuse_cache_planner.sh" "$docs_path" \
    && grep -Fq "source revision/hash" "$docs_path" \
    && grep -Fq "direct heavy Cargo command" "$docs_path" \
    && grep -Fq "proof_reuse_admission_bundle.json" "$docs_path"
}

run_case() {
  local case_id="$1"
  local case_json tmpdir output_dir expected_exit expected_decision artifact_id expected_class required_reason actual_exit output
  case_json="$(jq -c --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id)' "$fixtures_path")"
  if [[ -z "$case_json" ]]; then
    record_failure "missing case ${case_id}"
    return
  fi

  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/proof-reuse-admission.XXXXXX")"
  output_dir="${tmpdir}/out"
  jq '.sources.proof_index_json' <<<"$case_json" >"${tmpdir}/proof_index.json"

  local args=(
    --proof-index-json "${tmpdir}/proof_index.json"
    --expected-source-revision "$(jq -r '.expected_source_revision' <<<"$case_json")"
    --source-revision "smoke-${case_id}"
    --output-dir "$output_dir"
  )

  local report_count i changed_count changed_path
  report_count="$(jq '.sources.freshness_reports | length' <<<"$case_json")"
  for ((i = 0; i < report_count; i++)); do
    jq --argjson i "$i" '.sources.freshness_reports[$i]' <<<"$case_json" >"${tmpdir}/freshness-${i}.json"
    args+=(--freshness-report "${tmpdir}/freshness-${i}.json")
  done
  changed_count="$(jq '.changed_paths | length' <<<"$case_json")"
  for ((i = 0; i < changed_count; i++)); do
    changed_path="$(jq -r --argjson i "$i" '.changed_paths[$i]' <<<"$case_json")"
    args+=(--changed-path "$changed_path")
  done

  expected_exit="$(jq -r '.expected.exit_code' <<<"$case_json")"
  expected_decision="$(jq -r '.expected.decision' <<<"$case_json")"
  artifact_id="$(jq -r '.expected.artifact_id' <<<"$case_json")"
  expected_class="$(jq -r '.expected.classification' <<<"$case_json")"
  required_reason="$(jq -r '.expected.required_reason' <<<"$case_json")"

  set +e
  output="$("$bundle_script" "${args[@]}" 2>&1)"
  actual_exit=$?
  set -e

  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    record_failure "${case_id} exit ${actual_exit}, expected ${expected_exit}"
    printf '%s\n' "$output" >&2
    return
  fi

  for artifact in proof_reuse_admission_bundle.json admission_rows.jsonl proof_reuse_cache/proof_cache_plan.json events.jsonl commands.txt report.md; do
    [[ -f "${output_dir}/${artifact}" ]] || record_failure "${case_id} missing ${artifact}"
  done

  local bundle="${output_dir}/proof_reuse_admission_bundle.json"
  jq -e --arg decision "$expected_decision" '.admission_decision == $decision' "$bundle" >/dev/null \
    || record_failure "${case_id} decision mismatch"
  jq -e '.mutation_policy.advisory_only == true and .mutation_policy.runs_cargo == false and .mutation_policy.runs_rch == false and .mutation_policy.mutates_br == false and .mutation_policy.sends_agent_mail == false' "$bundle" >/dev/null \
    || record_failure "${case_id} unsafe mutation policy"
  jq -e --arg artifact_id "$artifact_id" --arg class "$expected_class" --arg reason "$required_reason" '
    any(.admission_rows[]?;
      .artifact_id == $artifact_id
      and .classification == $class
      and (.deterministic_reasons | index($reason) != null)
    )
  ' "$bundle" >/dev/null || record_failure "${case_id} missing expected admission row"
  if [[ "$expected_class" == "reusable" ]]; then
    jq -e --arg artifact_id "$artifact_id" 'any(.admission_rows[]?; .artifact_id == $artifact_id and .admission_allowed == true)' "$bundle" >/dev/null \
      || record_failure "${case_id} did not admit reusable row"
  else
    jq -e --arg artifact_id "$artifact_id" 'any(.admission_rows[]?; .artifact_id == $artifact_id and .admission_allowed == false)' "$bundle" >/dev/null \
      || record_failure "${case_id} admitted non-reusable row"
  fi
  grep -Fq "./scripts/proof_reuse_cache_planner.sh" "${output_dir}/commands.txt" \
    || record_failure "${case_id} commands missing cache planner invocation"

  record_pass "$case_id"
}

run_check() {
  jq empty "$contract_path" "$fixtures_path"
  bash -n "$bundle_script" "${BASH_SOURCE[0]}"
  contract_shape_ok || record_failure "contract shape"
  fixtures_shape_ok || record_failure "fixture shape"
  docs_shape_ok || record_failure "docs shape"
  check_no_mutation_claims "$docs_path"
  check_no_mutation_claims "$contract_path"
  check_no_bare_heavy_cargo "$docs_path"
  check_no_bare_heavy_cargo "$contract_path"
  check_no_bare_heavy_cargo "$bundle_script"

  local case_id
  while IFS= read -r case_id; do
    run_case "$case_id"
  done < <(jq -r '.cases[].case_id' "$fixtures_path")

  if [[ "$failures" -ne 0 ]]; then
    exit 1
  fi
  record_pass "check"
}

run_selftest() {
  run_check
  for class in reusable refresh_required invalid unknown; do
    jq -e --arg class "$class" 'any(.cases[]; .expected.classification == $class)' "$fixtures_path" >/dev/null \
      || { record_failure "selftest missing ${class}"; exit 1; }
  done
  jq -e 'any(.cases[]; .case_id == "direct_cargo_command_rejection" and .expected.required_reason == "direct_cargo_command_rejected")' "$fixtures_path" >/dev/null \
    || { record_failure "selftest missing direct cargo rejection"; exit 1; }
  record_pass "selftest"
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
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
