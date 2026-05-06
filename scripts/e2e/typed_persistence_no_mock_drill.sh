#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
doc_path="${TYPED_PERSISTENCE_ENFORCEMENT_DOC:-${root_dir}/docs/TYPED_PERSISTENCE_ENFORCEMENT_CONTRACT.md}"
contract_path="${TYPED_PERSISTENCE_ENFORCEMENT_CONTRACT:-${root_dir}/docs/typed_persistence_enforcement_contract_v1.json}"
suite_json_default="${root_dir}/scripts/testdata/typed_persistence_no_mock_drill/cases.json"
artifact_root="${TYPED_PERSISTENCE_NO_MOCK_DRILL_ROOT:-${TMPDIR:-/tmp}/franken-engine-typed-persistence-no-mock-drill}"
run_id="${TYPED_PERSISTENCE_NO_MOCK_DRILL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${TYPED_PERSISTENCE_NO_MOCK_DRILL_RUN_DIR:-${artifact_root}/${run_id}}"
mode="${1:-check}"
if [[ "$#" -gt 0 ]]; then
  shift
fi
suite_json="$suite_json_default"

report_path=""
events_path=""
commands_path=""
summary_path=""
case_results_path=""
failures=0

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/typed_persistence_no_mock_drill.sh [check|run|selftest] [OPTIONS]

Options:
  --output-dir DIR
  --suite-json PATH

The drill is fixture-fed, proof-only, and advisory-only. It reads checked-in
case fixtures together with the real typed persistence source and test surfaces.
It does not run Cargo or RCH, and it does not mutate live storage, beads,
reservations, or Agent Mail.
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
  printf 'PASS typed-persistence-no-mock-drill %s\n' "$1"
}

record_failure() {
  printf 'FAIL typed-persistence-no-mock-drill %s\n' "$1" >&2
  failures=$((failures + 1))
}

refresh_paths() {
  report_path="${run_dir}/typed_persistence_no_mock_drill_report.json"
  events_path="${run_dir}/events.jsonl"
  commands_path="${run_dir}/commands.txt"
  summary_path="${run_dir}/report.md"
  case_results_path="${run_dir}/case_results.jsonl"
}

ensure_run_dir() {
  mkdir -p "$run_dir"
  run_dir="$(cd "$run_dir" && pwd)"
  refresh_paths
  for artifact in "$report_path" "$events_path" "$commands_path" "$summary_path" "$case_results_path"; do
    if [[ -e "$artifact" ]]; then
      printf 'refusing to overwrite existing artifact: %s\n' "$artifact" >&2
      exit 73
    fi
  done
  : >"$events_path"
  : >"$commands_path"
  : >"$case_results_path"
}

write_event() {
  local case_id="$1"
  local title="$2"
  local decision="$3"
  local evidence_file_count="$4"

  jq -nc \
    --arg schema_version "franken-engine.typed-persistence-no-mock-drill.event.v1" \
    --arg case_id "$case_id" \
    --arg title "$title" \
    --arg decision "$decision" \
    --argjson evidence_file_count "$evidence_file_count" \
    '{
      schema_version:$schema_version,
      event_name:"typed_persistence_no_mock_drill.case",
      case_id:$case_id,
      title:$title,
      decision:$decision,
      evidence_file_count:$evidence_file_count
    }' >>"$events_path"
}

append_command() {
  printf '%s\n' "$1" >>"$commands_path"
}

safe_name() {
  printf '%s' "$1" | sed 's#[/.]#_#g'
}

run_case() {
  local case_doc="$1"
  local case_id title category case_dir evidence_count evidence_index
  local failures_json="[]"
  local excerpts_json="[]"

  case_id="$(jq -r '.case_id' <<<"$case_doc")"
  title="$(jq -r '.title' <<<"$case_doc")"
  category="$(jq -r '.category' <<<"$case_doc")"
  case_dir="${run_dir}/cases/${case_id}"
  mkdir -p "$case_dir"
  evidence_count="$(jq '.evidence | length' <<<"$case_doc")"

  for ((evidence_index = 0; evidence_index < evidence_count; evidence_index++)); do
    local rel_path abs_path excerpt_path token
    rel_path="$(jq -r ".evidence[$evidence_index].path" <<<"$case_doc")"
    abs_path="${root_dir}/${rel_path}"
    excerpt_path="${case_dir}/$(safe_name "$rel_path").txt"
    : >"$excerpt_path"

    if [[ ! -f "$abs_path" ]]; then
      failures_json="$(jq -nc --argjson failures "$failures_json" --arg path "$rel_path" '$failures + ["missing evidence path: " + $path]')"
      printf 'MISSING PATH %s\n' "$rel_path" >>"$excerpt_path"
      excerpts_json="$(jq -nc --argjson excerpts "$excerpts_json" --arg path "$excerpt_path" '$excerpts + [$path]')"
      continue
    fi

    while IFS= read -r token; do
      [[ -z "$token" ]] && continue
      if grep -Fq "$token" "$abs_path"; then
        grep -Fn "$token" "$abs_path" >>"$excerpt_path"
      else
        printf 'MISSING TOKEN %s\n' "$token" >>"$excerpt_path"
        failures_json="$(jq -nc --argjson failures "$failures_json" --arg path "$rel_path" --arg token "$token" '$failures + [($path + " missing token: " + $token)]')"
      fi
    done < <(jq -r ".evidence[$evidence_index].must_contain[]" <<<"$case_doc")
    excerpts_json="$(jq -nc --argjson excerpts "$excerpts_json" --arg path "$excerpt_path" '$excerpts + [$path]')"
  done

  local passed="true"
  if [[ "$(jq 'length' <<<"$failures_json")" -ne 0 ]]; then
    passed="false"
    failures=$((failures + 1))
  fi

  write_event "$case_id" "$title" "$(if [[ "$passed" == "true" ]]; then printf pass; else printf fail; fi)" "$evidence_count"

  jq -nc \
    --arg case_id "$case_id" \
    --arg title "$title" \
    --arg category "$category" \
    --argjson passed "$passed" \
    --argjson failures "$failures_json" \
    --argjson excerpts "$excerpts_json" \
    '{
      case_id:$case_id,
      title:$title,
      category:$category,
      passed:$passed,
      failures:$failures,
      artifact_paths:{evidence_excerpts:$excerpts}
    }' >>"$case_results_path"
}

write_summary() {
  {
    printf '# Typed Persistence No-Mock Drill\n\n'
    printf "Decision: \`%s\`\n\n" "$(jq -r '.decision' "$report_path")"
    printf 'Case results:\n'
    while IFS=$'\t' read -r case_id title passed; do
      if [[ "$passed" == "true" ]]; then
        printf -- "- \`%s\`: pass - %s\n" "$case_id" "$title"
      else
        printf -- "- \`%s\`: fail - %s\n" "$case_id" "$title"
      fi
    done < <(jq -r '.cases[] | [.case_id, .title, (.passed | tostring)] | @tsv' "$report_path")
  } >"$summary_path"
}

run_check() {
  ensure_run_dir

  append_command "typed_persistence_no_mock_drill.sh mode=${mode} suite_json=${suite_json}"

  [[ -f "$doc_path" ]] || { record_failure "missing doc ${doc_path}"; return 1; }
  [[ -f "$contract_path" ]] || { record_failure "missing contract ${contract_path}"; return 1; }
  [[ -f "$suite_json" ]] || { record_failure "missing suite ${suite_json}"; return 1; }

  jq empty "$contract_path" >/dev/null
  jq empty "$suite_json" >/dev/null
  jq -e '
    .schema_version == "franken-engine.typed-persistence-no-mock-drill-suite.v1"
    and (.cases | type == "array")
    and (.cases | length == 4)
  ' "$suite_json" >/dev/null || {
    record_failure "suite shape mismatch"
    return 1
  }

  while IFS= read -r case_doc; do
    run_case "$case_doc"
  done < <(jq -c '.cases[]' "$suite_json")

  local report_tmp
  report_tmp="${run_dir}/typed_persistence_no_mock_drill_report.tmp.json"

  jq -s \
    --arg doc_path "$doc_path" \
    --arg contract_path "$contract_path" \
    --arg suite_json "$suite_json" \
    --arg report_path "$report_path" \
    --arg events_path "$events_path" \
    --arg commands_path "$commands_path" \
    --arg summary_path "$summary_path" \
    '{
      schema_version:"franken-engine.typed-persistence-no-mock-drill-report.v1",
      bead_id:"bd-p2k9v",
      docs:$doc_path,
      contract_json:$contract_path,
      suite_json:$suite_json,
      decision:(if all(.[]; .passed) then "pass" else "fail_closed" end),
      case_count:length,
      passed_case_count:([.[] | select(.passed)] | length),
      failed_case_count:([.[] | select(.passed | not)] | length),
      case_ids:map(.case_id),
      covered_categories:map(.category),
      mutation_policy:{
        fixture_fed_only:true,
        proof_only:true,
        advisory_only:true,
        runs_cargo:false,
        runs_rch:false,
        mutates_live_storage:false,
        mutates_br:false,
        reassigns_beads:false,
        releases_reservations:false,
        sends_agent_mail:false,
        queries_live_agent_mail:false,
        mutates_remote_workers:false
      },
      artifact_paths:{
        report_json:$report_path,
        events_jsonl:$events_path,
        commands_txt:$commands_path,
        summary_md:$summary_path,
        case_results_jsonl:"'"$case_results_path"'"
      },
      cases:.
    }' "$case_results_path" >"$report_tmp"

  mv "$report_tmp" "$report_path"

  write_summary

  if [[ "$(jq -r '.decision' "$report_path")" != "pass" ]]; then
    record_failure "case suite reported fail_closed"
    return 1
  fi
  record_pass "typed persistence proof categories validate"
}

run_selftest() {
  local tmp_root bad_suite bad_shape

  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/typed-persistence-no-mock-drill.XXXXXX")"

  TYPED_PERSISTENCE_NO_MOCK_DRILL_RUN_DIR="${tmp_root}/baseline" \
    bash "$0" check >/dev/null
  record_pass "selftest baseline check"

  bad_suite="${tmp_root}/bad-suite.json"
  jq '.cases[0].evidence[0].must_contain[0] = "totally_missing_typed_boundary_symbol"' "$suite_json" >"$bad_suite"
  if TYPED_PERSISTENCE_NO_MOCK_DRILL_RUN_DIR="${tmp_root}/bad-suite-run" \
     bash "$0" check --suite-json "$bad_suite" >/dev/null 2>&1; then
    record_failure "selftest missing evidence token should fail"
    return 1
  fi
  record_pass "selftest missing evidence token rejection"

  bad_shape="${tmp_root}/bad-shape.json"
  jq 'del(.cases[0])' "$suite_json" >"$bad_shape"
  if TYPED_PERSISTENCE_NO_MOCK_DRILL_RUN_DIR="${tmp_root}/bad-shape-run" \
     bash "$0" check --suite-json "$bad_shape" >/dev/null 2>&1; then
    record_failure "selftest bad suite shape should fail"
    return 1
  fi
  record_pass "selftest bad suite shape rejection"
}

case "$mode" in
  check|run)
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
