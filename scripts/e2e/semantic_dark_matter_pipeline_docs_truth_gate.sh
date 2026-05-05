#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
default_operator_ref="${root_dir}/docs/operator-gates/RGC_GATES_REFERENCE.md"
default_contract="${root_dir}/docs/rgc_module_composition_claim_ledger_v1.json"
operator_ref_path="${SEMANTIC_DARK_MATTER_PIPELINE_OPERATOR_REF:-${default_operator_ref}}"
contract_path="${SEMANTIC_DARK_MATTER_PIPELINE_CONTRACT:-${default_contract}}"
section_heading="## Semantic Dark-Matter Pipeline Proof Suite"
validation_failures=0

required_paths=(
  "crates/franken-engine/src/semantic_dark_matter_engine.rs"
  "crates/franken-engine/tests/semantic_dark_matter_engine_integration.rs"
  "docs/operator-gates/RGC_GATES_REFERENCE.md"
  "docs/rgc_module_composition_claim_ledger_v1.json"
  "scripts/run_semantic_dark_matter_pipeline_suite.sh"
  "scripts/e2e/semantic_dark_matter_pipeline_replay.sh"
  "scripts/e2e/semantic_dark_matter_pipeline_docs_truth_gate.sh"
)

required_operator_patterns=(
  "## Semantic Dark-Matter Pipeline Proof Suite"
  "docs/rgc_module_composition_claim_ledger_v1.json"
  "./scripts/run_semantic_dark_matter_pipeline_suite.sh ci"
  "./scripts/e2e/semantic_dark_matter_pipeline_replay.sh ci"
  "./scripts/e2e/semantic_dark_matter_pipeline_docs_truth_gate.sh check"
  "./scripts/e2e/semantic_dark_matter_pipeline_docs_truth_gate.sh selftest"
  "artifacts/semantic_dark_matter_pipeline/<timestamp>/run_manifest.json"
  "artifacts/semantic_dark_matter_pipeline/<timestamp>/events.jsonl"
  "artifacts/semantic_dark_matter_pipeline/<timestamp>/commands.txt"
  "artifacts/semantic_dark_matter_pipeline/<timestamp>/summary.md"
  "artifacts/semantic_dark_matter_pipeline/<timestamp>/step_logs/step_*.log"
  "SEMANTIC_DARK_MATTER_PIPELINE_REPLAY_RUN_DIR=artifacts/semantic_dark_matter_pipeline/<timestamp>"
)

record_pass() {
  printf 'PASS semantic-dark-matter-pipeline-docs %s\n' "$1"
}

record_failure() {
  printf 'FAIL semantic-dark-matter-pipeline-docs %s\n' "$1" >&2
  validation_failures=$((validation_failures + 1))
}

check_repo_path_exists() {
  local path="$1"

  if [[ ! -e "${root_dir}/${path}" ]]; then
    record_failure "missing referenced repo path ${path}"
  else
    record_pass "referenced repo path exists ${path}"
  fi
}

extract_operator_section() {
  awk -v heading="$section_heading" '
    $0 == heading {
      in_section = 1
    }
    in_section {
      if ($0 ~ /^## / && $0 != heading) {
        exit
      }
      print
    }
  ' "$operator_ref_path"
}

extract_claim_surface_json() {
  jq -c '.claims[] | select(.composition_id == "rgc_707_semantic_dark_matter_engine")' "$contract_path"
}

validate_required_paths() {
  local path

  for path in "${required_paths[@]}"; do
    check_repo_path_exists "$path"
  done
}

validate_operator_reference() {
  local pattern
  local path
  local operator_section

  if [[ ! -f "$operator_ref_path" ]]; then
    record_failure "operator reference is missing: ${operator_ref_path}"
    return
  fi

  operator_section="$(extract_operator_section)"
  if [[ -z "$operator_section" ]]; then
    record_failure "operator reference is missing section: ${section_heading}"
    return
  fi

  for pattern in "${required_operator_patterns[@]}"; do
    if ! grep -Fq "$pattern" <<<"$operator_section"; then
      record_failure "operator reference missing required pattern: ${pattern}"
    else
      record_pass "operator reference contains ${pattern}"
    fi
  done

  while IFS= read -r path; do
    [[ -n "$path" ]] || continue
    check_repo_path_exists "$path"
  done < <(grep -Eo '\./scripts/[A-Za-z0-9_./-]+' <<<"$operator_section" | sed 's#^\./##' | sort -u)

  while IFS= read -r path; do
    [[ -n "$path" ]] || continue
    check_repo_path_exists "$path"
  done < <(grep -Eo 'docs/[A-Za-z0-9_./-]+' <<<"$operator_section" | sort -u)
}

validate_claim_surface() {
  local claim_json

  if [[ ! -f "$contract_path" ]]; then
    record_failure "claim ledger is missing: ${contract_path}"
    return
  fi
  if ! jq empty "$contract_path" >/dev/null; then
    record_failure "claim ledger is not valid JSON: ${contract_path}"
    return
  fi

  claim_json="$(extract_claim_surface_json)"
  if [[ -z "$claim_json" ]]; then
    record_failure "claim ledger missing rgc_707_semantic_dark_matter_engine entry"
    return
  fi

  if ! jq -e '
    .proof_posture == "observed"
    and (.allowed_provisional_fallbacks | length) == 0
    and (.primary_paths | index("crates/franken-engine/src/semantic_dark_matter_engine.rs") != null)
    and (.primary_paths | index("crates/franken-engine/tests/semantic_dark_matter_engine_integration.rs") != null)
    and (.primary_paths | index("scripts/run_semantic_dark_matter_pipeline_suite.sh") != null)
    and (.primary_paths | index("scripts/e2e/semantic_dark_matter_pipeline_replay.sh") != null)
    and (.primary_paths | index("scripts/e2e/semantic_dark_matter_pipeline_docs_truth_gate.sh") != null)
    and (.verification_commands | index("./scripts/run_semantic_dark_matter_pipeline_suite.sh ci") != null)
    and (.verification_commands | index("./scripts/e2e/semantic_dark_matter_pipeline_replay.sh ci") != null)
    and (.verification_commands | index("./scripts/e2e/semantic_dark_matter_pipeline_docs_truth_gate.sh check") != null)
    and (.verification_commands | index("./scripts/e2e/semantic_dark_matter_pipeline_docs_truth_gate.sh selftest") != null)
  ' <<<"$claim_json" >/dev/null; then
    record_failure "claim ledger entry is missing observed-proof surface requirements"
  else
    record_pass "claim ledger entry carries observed proof and docs truth handles"
  fi
}

validate_heavy_cargo_command_shape() {
  local line
  local operator_section
  local claim_json

  operator_section="$(extract_operator_section)"
  claim_json="$(extract_claim_surface_json)"

  if [[ -n "$operator_section" ]]; then
    while IFS= read -r line; do
      if [[ "$line" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
        if [[ "$line" != *"rch exec -- env"* || "$line" != *"CARGO_TARGET_DIR="* ]]; then
          record_failure "bare or non-target-dir heavy cargo command in ${operator_ref_path}: ${line}"
        else
          record_pass "heavy cargo command is rch-target-dir wrapped in ${operator_ref_path}"
        fi
      fi
    done <<<"$operator_section"
  fi

  if [[ -n "$claim_json" ]]; then
    while IFS= read -r line; do
      if [[ "$line" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
        if [[ "$line" != *"rch exec -- env"* || "$line" != *"CARGO_TARGET_DIR="* ]]; then
          record_failure "bare or non-target-dir heavy cargo command in ${contract_path}: ${line}"
        else
          record_pass "heavy cargo command is rch-target-dir wrapped in ${contract_path}"
        fi
      fi
    done < <(jq -r '.. | strings' <<<"$claim_json")
  fi
}

validate_all() {
  validation_failures=0
  validate_required_paths
  validate_operator_reference
  validate_claim_surface
  validate_heavy_cargo_command_shape

  if (( validation_failures > 0 )); then
    return 1
  fi
}

run_selftest() {
  local tmp_dir
  local bad_operator_ref
  local bad_contract

  tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/semantic-dark-matter-pipeline-docs.XXXXXX")"
  bad_operator_ref="${tmp_dir}/bad-operator-ref.md"
  bad_contract="${tmp_dir}/bad-contract.json"

  awk '
    { print }
    $0 == "## Semantic Dark-Matter Pipeline Proof Suite" && !injected {
      print ""
      print "```bash"
      print "cargo test -p frankenengine-engine --test semantic_dark_matter_engine_integration"
      print "```"
      injected = 1
    }
  ' "$operator_ref_path" >"$bad_operator_ref"
  if (operator_ref_path="$bad_operator_ref"; validate_all) >/dev/null 2>&1; then
    record_failure "selftest expected bare cargo example rejection"
  else
    record_pass "selftest rejects bare cargo example"
  fi

  jq '(.claims |= map(if .composition_id == "rgc_707_semantic_dark_matter_engine" then .verification_commands |= map(select(. != "./scripts/run_semantic_dark_matter_pipeline_suite.sh ci")) else . end))' "$contract_path" >"$bad_contract"
  if (contract_path="$bad_contract"; validate_all) >/dev/null 2>&1; then
    record_failure "selftest expected missing suite command rejection"
  else
    record_pass "selftest rejects missing suite command"
  fi
}

case "${1:-check}" in
  check)
    validate_all
    ;;
  selftest)
    validate_all
    run_selftest
    ;;
  *)
    echo "usage: $0 [check|selftest]" >&2
    exit 64
    ;;
esac
