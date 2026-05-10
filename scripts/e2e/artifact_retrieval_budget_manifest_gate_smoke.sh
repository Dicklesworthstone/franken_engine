#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
gate="${root_dir}/scripts/artifact_retrieval_budget_manifest_gate.sh"
docs_path="${root_dir}/docs/ARTIFACT_RETRIEVAL_BUDGET_MANIFEST_GATE.md"
golden_dir="${ARTIFACT_RETRIEVAL_BUDGET_MANIFEST_GATE_GOLDEN_DIR:-${root_dir}/scripts/testdata/goldens}"

record_pass() {
  printf 'PASS artifact-retrieval-budget %s\n' "$1"
}

record_failure() {
  printf 'FAIL artifact-retrieval-budget %s\n' "$1" >&2
}

golden_case_names() {
  cat <<'EOF'
minimal-successful-retrieval
over-broad-target-dir-retrieval
missing-replay-critical-artifact
deterministic-budget-a
deterministic-budget-b
EOF
}

write_suite_manifest() {
  local path="$1"

  jq -n '
    {
      schema_version: "franken-engine.semantic-dark-matter-pipeline.run-manifest.v1",
      suite_id: "semantic-dark-matter-pipeline",
      artifacts: {
        run_manifest: "artifacts/semantic_dark_matter_pipeline/20260505T234535Z/run_manifest.json",
        events: "artifacts/semantic_dark_matter_pipeline/20260505T234535Z/events.jsonl",
        commands: "artifacts/semantic_dark_matter_pipeline/20260505T234535Z/commands.txt",
        summary: "artifacts/semantic_dark_matter_pipeline/20260505T234535Z/summary.md"
      }
    }
  ' >"$path"
}

write_minimal_retrieval_manifest() {
  local path="$1"

  jq -n '
    {
      schema_version: "franken-engine.retrieval-budget-manifest.v1",
      suite_id: "semantic-dark-matter-pipeline",
      declared_artifacts: [
        "artifacts/semantic_dark_matter_pipeline/20260505T234535Z/commands.txt",
        "artifacts/semantic_dark_matter_pipeline/20260505T234535Z/events.jsonl",
        "artifacts/semantic_dark_matter_pipeline/20260505T234535Z/run_manifest.json"
      ],
      replay_critical_artifacts: [
        "artifacts/semantic_dark_matter_pipeline/20260505T234535Z/commands.txt",
        "artifacts/semantic_dark_matter_pipeline/20260505T234535Z/events.jsonl",
        "artifacts/semantic_dark_matter_pipeline/20260505T234535Z/run_manifest.json"
      ]
    }
  ' >"$path"
}

canonicalize_verdict() {
  local verdict_path="$1"
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
  ' "$verdict_path"
}

assert_case_golden() {
  local case_name="$1"
  local verdict_path="$2"
  local tmp_root="$3"
  local golden_path="${golden_dir}/artifact_retrieval_budget_manifest_gate_${case_name}.golden"

  if [[ "${UPDATE_GOLDENS:-0}" == "1" ]]; then
    mkdir -p "$golden_dir"
    canonicalize_verdict "$verdict_path" "$tmp_root" >"$golden_path"
    return 0
  fi

  if [[ ! -f "$golden_path" ]]; then
    record_failure "${case_name} missing golden"
    return 1
  fi

  if ! diff -u "$golden_path" <(canonicalize_verdict "$verdict_path" "$tmp_root"); then
    record_failure "${case_name} golden drift"
    return 1
  fi
}

goldens_shape_ok() {
  local missing=0
  local case_name golden_path

  if [[ "${UPDATE_GOLDENS:-0}" == "1" ]]; then
    return 0
  fi

  while IFS= read -r case_name; do
    golden_path="${golden_dir}/artifact_retrieval_budget_manifest_gate_${case_name}.golden"
    if [[ ! -f "$golden_path" ]]; then
      record_failure "${case_name} missing checked-in golden"
      missing=1
      continue
    fi
    jq empty "$golden_path" >/dev/null || {
      record_failure "${case_name} invalid golden json"
      missing=1
    }
  done < <(golden_case_names)

  [[ "$missing" -eq 0 ]]
}

run_check() {
  bash -n "$gate"
  bash -n "${BASH_SOURCE[0]}"
  grep -q 'franken-engine.artifact-retrieval-budget-manifest-gate.v1' "$docs_path"
  goldens_shape_ok
  record_pass "bash syntax and docs contract"
}

run_case() {
  local case_name="$1"
  local expected_exit="$2"
  local output_dir="$3"
  local tmp_root="$4"
  shift 4

  local output actual_exit
  set +e
  output="$("$gate" --output-dir "$output_dir" "$@" 2>&1)"
  actual_exit=$?
  set -e

  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    record_failure "${case_name} exit ${actual_exit}, expected ${expected_exit}"
    printf '%s\n' "$output" >&2
    return 1
  fi

  test -s "${output_dir}/artifact_retrieval_budget_verdict.json"
  test -s "${output_dir}/artifact_retrieval_budget_summary.md"
  test -s "${output_dir}/commands.txt"
  test -s "${output_dir}/events.jsonl"
  assert_case_golden "$case_name" "${output_dir}/artifact_retrieval_budget_verdict.json" "$tmp_root"
  record_pass "$case_name"
}

run_selftest() {
  local tmp_parent tmp_root fixture_dir

  run_check
  tmp_parent="${ARTIFACT_RETRIEVAL_BUDGET_MANIFEST_GATE_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/artifact-retrieval-budget.XXXXXX")"
  fixture_dir="${tmp_root}/fixtures"
  mkdir -p "$fixture_dir"

  write_suite_manifest "${fixture_dir}/suite_manifest.json"
  write_minimal_retrieval_manifest "${fixture_dir}/retrieval_manifest.json"

  jq -n '
    [
      "artifacts/semantic_dark_matter_pipeline/20260505T234535Z/commands.txt",
      "artifacts/semantic_dark_matter_pipeline/20260505T234535Z/events.jsonl",
      "artifacts/semantic_dark_matter_pipeline/20260505T234535Z/run_manifest.json"
    ]
  ' >"${fixture_dir}/retrieved-minimal.json"
  run_case "minimal-successful-retrieval" 0 "${tmp_root}/minimal" \
    "$tmp_root" \
    --suite-manifest-json "${fixture_dir}/suite_manifest.json" \
    --retrieval-manifest-json "${fixture_dir}/retrieval_manifest.json" \
    --retrieved-files-json "${fixture_dir}/retrieved-minimal.json"
  jq -e '
    .budget_verdict == "pass"
    and (.declared_artifacts | length == 3)
    and (.replay_critical_artifacts | length == 3)
    and (.retrieved_artifacts | length == 3)
    and (.hash_basis.input_hash | length == 64)
    and (.hash_basis.verdict_hash | length == 64)
  ' "${tmp_root}/minimal/artifact_retrieval_budget_verdict.json" >/dev/null
  record_pass "minimal successful retrieval assertions"

  jq -n '
    {
      schema_version: "franken-engine.retrieval-budget-manifest.v1",
      suite_id: "semantic-dark-matter-pipeline",
      declared_artifacts: [
        "artifacts/semantic_dark_matter_pipeline/20260505T234535Z/commands.txt",
        "/tmp/rch_target_franken_engine_semantic_dark_matter_pipeline_20260505/**"
      ],
      replay_critical_artifacts: [
        "artifacts/semantic_dark_matter_pipeline/20260505T234535Z/commands.txt"
      ]
    }
  ' >"${fixture_dir}/retrieval-overbroad.json"
  jq -n '
    [
      "artifacts/semantic_dark_matter_pipeline/20260505T234535Z/commands.txt",
      "/tmp/rch_target_franken_engine_semantic_dark_matter_pipeline_20260505/**"
    ]
  ' >"${fixture_dir}/retrieved-overbroad.json"
  run_case "over-broad-target-dir-retrieval" 42 "${tmp_root}/overbroad" \
    "$tmp_root" \
    --suite-manifest-json "${fixture_dir}/suite_manifest.json" \
    --retrieval-manifest-json "${fixture_dir}/retrieval-overbroad.json" \
    --retrieved-files-json "${fixture_dir}/retrieved-overbroad.json"
  jq -e '
    .budget_verdict == "fail_closed"
    and ((.broad_declared_artifacts | length) > 0 or (.broad_retrieved_artifacts | length) > 0)
  ' "${tmp_root}/overbroad/artifact_retrieval_budget_verdict.json" >/dev/null
  record_pass "over-broad target-dir retrieval assertions"

  jq -n '
    [
      "artifacts/semantic_dark_matter_pipeline/20260505T234535Z/commands.txt",
      "artifacts/semantic_dark_matter_pipeline/20260505T234535Z/run_manifest.json"
    ]
  ' >"${fixture_dir}/retrieved-missing-critical.json"
  run_case "missing-replay-critical-artifact" 42 "${tmp_root}/missing-critical" \
    "$tmp_root" \
    --suite-manifest-json "${fixture_dir}/suite_manifest.json" \
    --retrieval-manifest-json "${fixture_dir}/retrieval_manifest.json" \
    --retrieved-files-json "${fixture_dir}/retrieved-missing-critical.json"
  jq -e '
    .budget_verdict == "fail_closed"
    and (.missing_replay_critical_artifacts == ["artifacts/semantic_dark_matter_pipeline/20260505T234535Z/events.jsonl"])
  ' "${tmp_root}/missing-critical/artifact_retrieval_budget_verdict.json" >/dev/null
  record_pass "missing replay-critical artifact assertions"

  jq -n '
    [
      "artifacts/semantic_dark_matter_pipeline/20260505T234535Z/run_manifest.json",
      "artifacts/semantic_dark_matter_pipeline/20260505T234535Z/commands.txt",
      "artifacts/semantic_dark_matter_pipeline/20260505T234535Z/events.jsonl"
    ]
  ' >"${fixture_dir}/retrieved-reordered.json"
  run_case "deterministic-budget-a" 0 "${tmp_root}/deterministic-a" \
    "$tmp_root" \
    --suite-manifest-json "${fixture_dir}/suite_manifest.json" \
    --retrieval-manifest-json "${fixture_dir}/retrieval_manifest.json" \
    --retrieved-files-json "${fixture_dir}/retrieved-minimal.json"
  run_case "deterministic-budget-b" 0 "${tmp_root}/deterministic-b" \
    "$tmp_root" \
    --suite-manifest-json "${fixture_dir}/suite_manifest.json" \
    --retrieval-manifest-json "${fixture_dir}/retrieval_manifest.json" \
    --retrieved-files-json "${fixture_dir}/retrieved-reordered.json"
  test "$(jq -r '.hash_basis.input_hash' "${tmp_root}/deterministic-a/artifact_retrieval_budget_verdict.json")" = \
    "$(jq -r '.hash_basis.input_hash' "${tmp_root}/deterministic-b/artifact_retrieval_budget_verdict.json")"
  test "$(jq -r '.hash_basis.verdict_hash' "${tmp_root}/deterministic-a/artifact_retrieval_budget_verdict.json")" = \
    "$(jq -r '.hash_basis.verdict_hash' "${tmp_root}/deterministic-b/artifact_retrieval_budget_verdict.json")"
  record_pass "deterministic budget verdicts"

  printf 'artifact_retrieval_budget_manifest_gate_smoke_artifacts=%s\n' "$tmp_root"
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
