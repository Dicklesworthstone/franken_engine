#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
doc_path="${TYPED_PERSISTENCE_ENFORCEMENT_DOC:-${root_dir}/docs/TYPED_PERSISTENCE_ENFORCEMENT_CONTRACT.md}"
contract_path="${TYPED_PERSISTENCE_ENFORCEMENT_CONTRACT:-${root_dir}/docs/typed_persistence_enforcement_contract_v1.json}"
drill_path="${TYPED_PERSISTENCE_NO_MOCK_DRILL:-${root_dir}/scripts/e2e/typed_persistence_no_mock_drill.sh}"
suite_json_default="${root_dir}/scripts/testdata/typed_persistence_no_mock_drill/cases.json"
artifact_root="${TYPED_PERSISTENCE_TRUTH_GATE_ROOT:-${TMPDIR:-/tmp}/franken-engine-typed-persistence-truth-gate}"
run_id="${TYPED_PERSISTENCE_TRUTH_GATE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${TYPED_PERSISTENCE_TRUTH_GATE_RUN_DIR:-${artifact_root}/${run_id}}"
mode="${1:-check}"
if [[ "$#" -gt 0 ]]; then
  shift
fi
suite_json="$suite_json_default"

report_path=""
summary_path=""
commands_path=""

required_runbook_claims=(
  "fixture-fed, proof-only, and advisory-only"
  "healthy typed writes"
  "supported lossless legacy backfill planning"
  "unsupported legacy rejection"
  "generic-authority rejection"
  "does not run Cargo or RCH"
  "does not mutate live storage"
  "does not update, reopen, close, or reassign beads"
  "does not release file reservations"
  "does not send Agent Mail"
  "does not query live Agent Mail"
)

required_surface_paths=(
  "crates/franken-engine/src/replacement_lineage_log.rs"
  "crates/franken-engine/src/ifc_provenance_index.rs"
  "crates/franken-engine/src/specialization_index.rs"
  "crates/franken-engine/src/storage_adapter.rs"
  "crates/franken-engine/src/typed_persistence_models.rs"
  "scripts/e2e/typed_persistence_no_mock_drill.sh"
  "scripts/e2e/typed_persistence_truth_gate.sh"
  "scripts/e2e/typed_persistence_no_mock_drill_smoke.sh"
)

required_artifacts=(
  "typed_persistence_no_mock_drill_report.json"
  "case_results.jsonl"
  "commands.txt"
  "events.jsonl"
  "report.md"
)

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/typed_persistence_truth_gate.sh [check|selftest] [OPTIONS]

Options:
  --output-dir DIR
  --suite-json PATH
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --output-dir)
      run_dir="${2:-}"
      shift 2
      ;;
    --suite-json)
      suite_json="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown option: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

record_pass() {
  printf 'PASS typed-persistence-truth-gate %s\n' "$1"
}

record_failure() {
  printf 'FAIL typed-persistence-truth-gate %s\n' "$1" >&2
}

refresh_paths() {
  report_path="${run_dir}/truth_gate_report.json"
  summary_path="${run_dir}/summary.md"
  commands_path="${run_dir}/commands.txt"
}

ensure_run_dir() {
  mkdir -p "$run_dir"
  run_dir="$(cd "$run_dir" && pwd)"
  refresh_paths
  for artifact in "$report_path" "$summary_path" "$commands_path"; do
    if [[ -e "$artifact" ]]; then
      printf 'refusing to overwrite existing artifact: %s\n' "$artifact" >&2
      exit 73
    fi
  done
}

assert_no_forbidden_live_claims() {
  local path="$1"
  local forbidden_lines

  forbidden_lines="$(grep -Ein \
    'runs cargo|runs rch|mutate[s]? live storage|reassigns beads|releases file reservations|sends Agent Mail|queries live Agent Mail|generic authority remains authoritative|legacy inputs are accepted implicitly' \
    "$path" \
    | grep -Eiv 'does not|forbidden|rejects|must become non-authoritative|proof-only|advisory-only' || true)"
  if [[ -n "$forbidden_lines" ]]; then
    printf '%s\n' "$forbidden_lines" >&2
    record_failure "forbidden live mutation or implicit legacy claim"
    return 1
  fi
}

assert_contract_shape() {
  jq -e '
    .schema_version == "franken-engine.typed-persistence-enforcement-contract.v1"
    and .no_mock_drill.script == "scripts/e2e/typed_persistence_no_mock_drill.sh"
    and .no_mock_drill.truth_gate_script == "scripts/e2e/typed_persistence_truth_gate.sh"
    and .no_mock_drill.smoke_script == "scripts/e2e/typed_persistence_no_mock_drill_smoke.sh"
    and .no_mock_drill.suite_json == "scripts/testdata/typed_persistence_no_mock_drill/cases.json"
    and (.no_mock_drill.case_ids | sort == [
      "generic_authority_rejection",
      "healthy_typed_primary_authority",
      "supported_lossless_legacy_backfill_planning",
      "unsupported_legacy_rejection"
    ])
    and (.mutation_policy.fixture_fed_only == true)
    and (.mutation_policy.proof_only == true)
    and (.mutation_policy.advisory_only == true)
    and (.mutation_policy.runs_cargo == false)
    and (.mutation_policy.runs_rch == false)
    and (.mutation_policy.mutates_live_storage == false)
    and (.mutation_policy.mutates_br == false)
    and (.mutation_policy.reassigns_beads == false)
    and (.mutation_policy.releases_reservations == false)
    and (.mutation_policy.sends_agent_mail == false)
    and (.mutation_policy.queries_live_agent_mail == false)
    and (.mutation_policy.mutates_remote_workers == false)
  ' "$contract_path" >/dev/null
}

assert_runbook_claims() {
  local claim
  local surface
  local artifact

  for claim in "${required_runbook_claims[@]}"; do
    grep -Fq "$claim" "$doc_path" || return 1
  done
  for surface in "${required_surface_paths[@]}"; do
    grep -Fq "$surface" "$doc_path" || return 1
    grep -Fq "$surface" "$contract_path" || return 1
  done
  for artifact in "${required_artifacts[@]}"; do
    grep -Fq "$artifact" "$doc_path" || return 1
    grep -Fq "$artifact" "$contract_path" || return 1
  done
  assert_no_forbidden_live_claims "$doc_path"
}

run_check() {
  local drill_output_dir="${run_dir}/drill"

  ensure_run_dir
  printf 'typed_persistence_truth_gate.sh mode=%s suite_json=%s output_dir=%s\n' "$mode" "$suite_json" "$run_dir" >"$commands_path"

  [[ -f "$doc_path" ]] || { record_failure "missing doc ${doc_path}"; return 1; }
  [[ -f "$contract_path" ]] || { record_failure "missing contract ${contract_path}"; return 1; }
  [[ -f "$drill_path" ]] || { record_failure "missing drill ${drill_path}"; return 1; }
  [[ -f "$suite_json" ]] || { record_failure "missing suite ${suite_json}"; return 1; }

  jq empty "$contract_path" >/dev/null
  jq empty "$suite_json" >/dev/null
  assert_contract_shape
  assert_runbook_claims

  bash "$drill_path" check --output-dir "$drill_output_dir" --suite-json "$suite_json" >/dev/null

  jq -e '
    .schema_version == "franken-engine.typed-persistence-no-mock-drill-report.v1"
    and .decision == "pass"
    and .case_count == 4
    and (.case_ids | sort == [
      "generic_authority_rejection",
      "healthy_typed_primary_authority",
      "supported_lossless_legacy_backfill_planning",
      "unsupported_legacy_rejection"
    ])
    and .mutation_policy.fixture_fed_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.advisory_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_live_storage == false
  ' "${drill_output_dir}/typed_persistence_no_mock_drill_report.json" >/dev/null

  jq -n \
    --arg schema_version "franken-engine.typed-persistence-truth-gate-report.v1" \
    --arg drill_report "${drill_output_dir}/typed_persistence_no_mock_drill_report.json" \
    --arg commands_path "$commands_path" \
    --arg summary_path "$summary_path" \
    '{
      schema_version:$schema_version,
      decision:"pass",
      drill_report_json:$drill_report,
      artifact_paths:{
        commands_txt:$commands_path,
        summary_md:$summary_path
      }
    }' >"$report_path"

  {
    printf '# Typed Persistence Truth Gate\n\n'
    printf "Decision: \`pass\`\n\n"
    printf 'Validated the no-mock drill, contract shape, and runbook claims.\n'
  } >"$summary_path"

  record_pass "contract drill and runbook truth validate"
}

run_selftest() {
  local tmp_root bad_doc bad_suite bad_contract

  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/typed-persistence-truth-gate.XXXXXX")"

  TYPED_PERSISTENCE_TRUTH_GATE_RUN_DIR="${tmp_root}/baseline" \
    bash "$0" check >/dev/null
  record_pass "selftest baseline check"

  bad_doc="${tmp_root}/bad-doc.md"
  cp "$doc_path" "$bad_doc"
  printf '\nThe drill runs Cargo and RCH, mutates live storage, and sends Agent Mail.\n' >>"$bad_doc"
  if TYPED_PERSISTENCE_ENFORCEMENT_DOC="$bad_doc" \
     TYPED_PERSISTENCE_TRUTH_GATE_RUN_DIR="${tmp_root}/bad-doc-run" \
     bash "$0" check >/dev/null 2>&1; then
    record_failure "selftest forbidden runbook wording should fail"
    return 1
  fi
  record_pass "selftest forbidden runbook wording rejection"

  bad_suite="${tmp_root}/bad-suite.json"
  jq '.cases[3].evidence[0].must_contain[0] = "missing_non_authoritative_token"' "$suite_json" >"$bad_suite"
  if TYPED_PERSISTENCE_TRUTH_GATE_RUN_DIR="${tmp_root}/bad-suite-run" \
     bash "$0" check --suite-json "$bad_suite" >/dev/null 2>&1; then
    record_failure "selftest bad suite should fail"
    return 1
  fi
  record_pass "selftest bad suite rejection"

  bad_contract="${tmp_root}/bad-contract.json"
  jq 'del(.no_mock_drill.case_ids[0])' "$contract_path" >"$bad_contract"
  if TYPED_PERSISTENCE_ENFORCEMENT_CONTRACT="$bad_contract" \
     TYPED_PERSISTENCE_TRUTH_GATE_RUN_DIR="${tmp_root}/bad-contract-run" \
     bash "$0" check >/dev/null 2>&1; then
    record_failure "selftest bad contract should fail"
    return 1
  fi
  record_pass "selftest bad contract rejection"
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  *)
    usage
    exit 64
    ;;
esac
