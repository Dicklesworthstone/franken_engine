#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
docs_path="${SWARM_OPS_STATE_DOC:-${root_dir}/docs/SWARM_OPS_STATE_CONTRACT.md}"
contract_path="${SWARM_OPS_STATE_CONTRACT:-${root_dir}/docs/swarm_ops_state_contract_v1.json}"
fixtures_path="${SWARM_OPS_STATE_FIXTURES:-${root_dir}/scripts/testdata/swarm_ops_state_contract/cases.json}"
mode="${1:-check}"
output_dir="${2:-${SWARM_OPS_STATE_OUTPUT_DIR:-}}"
failures=0

record_pass() {
  printf 'PASS swarm-ops-state-contract %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-ops-state-contract %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_ops_state_contract_smoke.sh [check|run|selftest] [output_dir]
EOF
}

check_no_mutation_claims() {
  local path="$1"
  if grep -Eiq 'automatically updates beads|automatically closes beads|automatically reopens beads|automatically reassigns beads|automatically releases reservations|sends Agent Mail automatically|live Agent Mail query is allowed|may query live Agent Mail|may mutate remote workers|can mutate remote workers|changes active queue policy automatically|repairs target directories automatically|autonomous destructive operator' "$path"; then
    record_failure "${path#"$root_dir"/} contains forbidden live-mutation wording"
  fi
}

check_no_bare_heavy_cargo() {
  local path="$1"
  while IFS= read -r command; do
    if [[ "$command" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
      if [[ "$command" != *"rch exec --"* || "$command" != *"CARGO_TARGET_DIR="* ]]; then
        record_failure "${path#"$root_dir"/} has bare heavy Cargo command: ${command}"
      fi
    fi
  done < <(jq -r '.. | strings' "$path" 2>/dev/null || sed -n '1,240p' "$path")
}

contract_shape_ok() {
  local path="$1"
  jq -e '
    .schema_version == "franken-engine.swarm-ops-state-contract.v1"
    and .bead_id == "bd-eozx0"
    and .parent_bead_id == "bd-3rebe"
    and .track == "SWARM-OPS-P0"
    and .bundle_schema_version == "franken-engine.swarm-ops-state-bundle.v1"
    and .event_schema_version == "franken-engine.swarm-ops-state-event.v1"
    and .report_schema_version == "franken-engine.swarm-ops-state-contract-report.v1"
    and .fixture_schema_version == "franken-engine.swarm-ops-state-contract-fixtures.v1"
    and .docs.runbook == "docs/SWARM_OPS_STATE_CONTRACT.md"
    and .docs.contract == "docs/swarm_ops_state_contract_v1.json"
    and .docs.fixtures == "scripts/testdata/swarm_ops_state_contract/cases.json"
    and .docs.smoke_gate == "scripts/e2e/swarm_ops_state_contract_smoke.sh"
    and (.source_components | map(.component) | index("br_ready") != null)
    and (.source_components | map(.component) | index("bv_plan") != null)
    and (.source_components | map(.component) | index("agent_mail") != null)
    and (.source_components | map(.component) | index("rch") != null)
    and (.source_components | map(.component) | index("git") != null)
    and (.source_components | map(.component) | index("proof_cache_locality") != null)
    and (.required_artifacts | index("swarm_ops_state_bundle.json") != null)
    and (.required_artifacts | index("events.jsonl") != null)
    and (.required_artifacts | index("commands.txt") != null)
    and (.required_artifacts | index("report.md") != null)
    and (.required_event_keys | index("trace_id") != null)
    and (.required_event_keys | index("component") != null)
    and (.required_event_keys | index("event") != null)
    and (.required_event_keys | index("outcome") != null)
    and (.required_event_keys | index("error_code") != null)
    and (.required_event_keys | index("evidence_path") != null)
    and (.proof_categories | map(.case_id) | index("healthy") != null)
    and (.proof_categories | map(.case_id) | index("stale_jsonl") != null)
    and (.proof_categories | map(.case_id) | index("mail_missing") != null)
    and (.proof_categories | map(.case_id) | index("rch_degraded") != null)
    and (.fail_closed_classes | index("stale_br_jsonl") != null)
    and (.fail_closed_classes | index("contradictory_capacity_inputs") != null)
    and (.degraded_classes | index("missing_agent_mail_snapshot") != null)
    and (.degraded_classes | index("degraded_rch_worker_state") != null)
    and .mutation_policy.fixture_fed_only == true
    and .mutation_policy.proof_only == true
    and .mutation_policy.advisory_only == true
    and .mutation_policy.mutates_br == false
    and .mutation_policy.releases_reservations == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.queries_live_agent_mail == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.changes_live_queue_policy == false
    and .mutation_policy.repairs_target_dirs == false
  ' "$path" >/dev/null
}

docs_shape_ok() {
  local path="$1"
  grep -Fq 'Machine-readable contract:' "$path" \
    && grep -Fq 'Smoke gate:' "$path" \
    && grep -Fq 'Fixture cases:' "$path" \
    && grep -Fq 'The bundle records evidence. It is not an autonomous operator.' "$path" \
    && grep -Fq 'br sync --status --json' "$path" \
    && grep -Fq 'bv --recipe actionable --robot-plan' "$path" \
    && grep -Fq 'Agent Mail agent, inbox, contact, and reservation snapshots' "$path" \
    && grep -Fq 'rch status --workers --jobs --json' "$path" \
    && grep -Fq 'git status --short' "$path" \
    && grep -Fq 'proof-cache and locality artifacts' "$path" \
    && grep -Fq 'healthy' "$path" \
    && grep -Fq 'stale_jsonl' "$path" \
    && grep -Fq 'mail_missing' "$path" \
    && grep -Fq 'rch_degraded' "$path" \
    && grep -Fq 'trace_id' "$path" \
    && grep -Fq 'evidence_path' "$path" \
    && grep -Fq 'does not run Cargo or RCH' "$path" \
    && grep -Fq 'does not write outside the requested output directory' "$path"
}

fixtures_shape_ok() {
  local path="$1"
  jq -e '
    .schema_version == "franken-engine.swarm-ops-state-contract-fixtures.v1"
    and (.cases | length == 4)
    and (.cases | map(.case_id) | index("healthy") != null)
    and (.cases | map(.case_id) | index("stale_jsonl") != null)
    and (.cases | map(.case_id) | index("mail_missing") != null)
    and (.cases | map(.case_id) | index("rch_degraded") != null)
    and all(.cases[]; has("signals") and has("expected"))
    and (.cases[] | select(.case_id == "healthy") | .expected.outcome == "pass" and .expected.error_code == null)
    and (.cases[] | select(.case_id == "stale_jsonl") | .signals.br.db_newer == true and .expected.outcome == "fail_closed" and .expected.error_code == "FE-SWARM-OPS-STALE-JSONL")
    and (.cases[] | select(.case_id == "mail_missing") | .signals.agent_mail.available == false and .expected.outcome == "degraded" and .expected.error_code == "FE-SWARM-OPS-MAIL-MISSING")
    and (.cases[] | select(.case_id == "rch_degraded") | .signals.rch.state == "degraded" and .expected.outcome == "degraded" and .expected.error_code == "FE-SWARM-OPS-RCH-DEGRADED")
  ' "$path" >/dev/null
}

run_check_with_paths() {
  local docs="$1"
  local contract="$2"
  local fixtures="$3"

  jq empty "$contract" >/dev/null || record_failure "contract JSON is invalid"
  jq empty "$fixtures" >/dev/null || record_failure "fixture JSON is invalid"

  if contract_shape_ok "$contract"; then
    record_pass "contract shape"
  else
    record_failure "contract shape mismatch"
  fi

  if docs_shape_ok "$docs"; then
    record_pass "docs shape"
  else
    record_failure "docs shape mismatch"
  fi

  if fixtures_shape_ok "$fixtures"; then
    record_pass "fixture shape"
  else
    record_failure "fixture shape mismatch"
  fi

  check_no_mutation_claims "$docs"
  check_no_mutation_claims "$contract"
  check_no_mutation_claims "$fixtures"
  check_no_bare_heavy_cargo "$docs"
  check_no_bare_heavy_cargo "$contract"
  check_no_bare_heavy_cargo "$fixtures"
}

run_check() {
  bash -n "${BASH_SOURCE[0]}"
  run_check_with_paths "$docs_path" "$contract_path" "$fixtures_path"
}

evaluate_case_json() {
  local case_json="$1"
  jq -r '
    if (.signals.br.db_newer == true) or (.signals.br.jsonl_fresh == false) or (.signals.br.jsonl_newer == true) then
      "fail_closed|FE-SWARM-OPS-STALE-JSONL|fail_closed"
    elif .signals.capacity.contradictory_inputs == true then
      "blocked|FE-SWARM-OPS-CONTRADICTORY-CAPACITY|blocked"
    elif (.signals.git.dirty_unowned_files > 0) or (.signals.git.diff_check_passed == false) then
      "blocked|FE-SWARM-OPS-DIRTY-UNOWNED|blocked"
    elif .signals.rch.local_fallback_observed == true then
      "fail_closed|FE-SWARM-OPS-RCH-LOCAL-FALLBACK|fail_closed"
    elif .signals.agent_mail.available == false then
      "degraded|FE-SWARM-OPS-MAIL-MISSING|degraded"
    elif .signals.rch.state != "healthy" then
      "degraded|FE-SWARM-OPS-RCH-DEGRADED|degraded"
    elif .signals.proof_cache.locality_evidence == "missing" then
      "degraded|FE-SWARM-OPS-PROOF-CACHE-MISSING|degraded"
    else
      "pass||trusted"
    end
  ' <<<"$case_json"
}

write_case_event() {
  local case_json="$1"
  local events_path="$2"
  local case_id result outcome error_code trust_state expected_outcome expected_error_code expected_trust_state evidence_path

  case_id="$(jq -r '.case_id' <<<"$case_json")"
  result="$(evaluate_case_json "$case_json")"
  outcome="${result%%|*}"
  result="${result#*|}"
  error_code="${result%%|*}"
  trust_state="${result#*|}"
  expected_outcome="$(jq -r '.expected.outcome' <<<"$case_json")"
  expected_error_code="$(jq -r '.expected.error_code // ""' <<<"$case_json")"
  expected_trust_state="$(jq -r '.expected.trust_state' <<<"$case_json")"
  evidence_path="scripts/testdata/swarm_ops_state_contract/cases.json#${case_id}"

  if [[ "$outcome" != "$expected_outcome" ]]; then
    record_failure "case ${case_id} expected outcome ${expected_outcome}, got ${outcome}"
  fi
  if [[ "$error_code" != "$expected_error_code" ]]; then
    record_failure "case ${case_id} expected error_code ${expected_error_code:-null}, got ${error_code:-null}"
  fi
  if [[ "$trust_state" != "$expected_trust_state" ]]; then
    record_failure "case ${case_id} expected trust_state ${expected_trust_state}, got ${trust_state}"
  fi

  jq -cn \
    --arg schema_version "franken-engine.swarm-ops-state-event.v1" \
    --arg trace_id "trace-swarm-ops-state-${case_id}" \
    --arg component "swarm_ops_state_contract_smoke" \
    --arg event "case_evaluated" \
    --arg outcome "$outcome" \
    --arg error_code "$error_code" \
    --arg evidence_path "$evidence_path" \
    --arg trust_state "$trust_state" \
    '{
      schema_version: $schema_version,
      trace_id: $trace_id,
      component: $component,
      event: $event,
      outcome: $outcome,
      error_code: (if $error_code == "" then null else $error_code end),
      evidence_path: $evidence_path,
      trust_state: $trust_state
    }' >>"$events_path"
}

run_artifacts() {
  local dir="$1"
  local events_path commands_path report_path bundle_path case_count

  if [[ -z "$dir" ]]; then
    dir="$(mktemp -d "${TMPDIR:-/tmp}/swarm-ops-state-contract.XXXXXX")"
  fi
  mkdir -p "$dir"

  events_path="${dir}/events.jsonl"
  commands_path="${dir}/commands.txt"
  report_path="${dir}/report.md"
  bundle_path="${dir}/swarm_ops_state_bundle.json"
  : >"$events_path"

  while IFS= read -r case_json; do
    write_case_event "$case_json" "$events_path"
  done < <(jq -c '.cases[]' "$fixtures_path")

  case_count="$(jq '.cases | length' "$fixtures_path")"
  jq -n \
    --arg schema_version "franken-engine.swarm-ops-state-bundle.v1" \
    --arg contract_schema_version "franken-engine.swarm-ops-state-contract.v1" \
    --arg source_revision "fixture-revision" \
    --arg events_path "$events_path" \
    --arg commands_path "$commands_path" \
    --arg report_path "$report_path" \
    --argjson case_count "$case_count" \
    '{
      schema_version: $schema_version,
      contract_schema_version: $contract_schema_version,
      source_revision: $source_revision,
      decision: "fixture_validated",
      case_count: $case_count,
      artifact_paths: {
        events_jsonl: $events_path,
        commands_txt: $commands_path,
        report_md: $report_path
      }
    }' >"$bundle_path"

  cat >"$commands_path" <<EOF
jq empty docs/swarm_ops_state_contract_v1.json scripts/testdata/swarm_ops_state_contract/cases.json
bash scripts/e2e/swarm_ops_state_contract_smoke.sh run ${dir}
EOF

  cat >"$report_path" <<EOF
# SWARM OPS STATE CONTRACT SMOKE

- contract: docs/swarm_ops_state_contract_v1.json
- fixtures: scripts/testdata/swarm_ops_state_contract/cases.json
- cases: ${case_count}
- events: ${events_path}
EOF

  jq -n \
    --arg schema_version "franken-engine.swarm-ops-state-contract-report.v1" \
    --arg bundle_path "$bundle_path" \
    --arg events_path "$events_path" \
    --arg commands_path "$commands_path" \
    --arg report_path "$report_path" \
    --argjson case_count "$case_count" \
    '{
      schema_version: $schema_version,
      decision: "pass",
      case_count: $case_count,
      artifact_paths: {
        swarm_ops_state_bundle_json: $bundle_path,
        events_jsonl: $events_path,
        commands_txt: $commands_path,
        report_md: $report_path
      }
    }' >"${dir}/swarm_ops_state_contract_report.json"

  record_pass "wrote artifacts to ${dir}"
}

run_selftest() {
  local tmp_root run_dir bad_docs bad_fixtures saved_failures observed_failures
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/swarm-ops-state-contract-selftest.XXXXXX")"
  run_dir="${tmp_root}/run"

  run_artifacts "$run_dir"

  if jq -s '
      length == 4
      and all(.[]; has("trace_id") and has("component") and has("event") and has("outcome") and has("error_code") and has("evidence_path"))
      and (map(.outcome) | index("pass") != null)
      and (map(.outcome) | index("degraded") != null)
      and (map(.outcome) | index("fail_closed") != null)
    ' "${run_dir}/events.jsonl" >/dev/null; then
    record_pass "selftest events have stable keys and expected outcomes"
  else
    record_failure "selftest events missing keys or outcomes"
  fi

  bad_docs="${tmp_root}/bad.md"
  cp "$docs_path" "$bad_docs"
  printf '\nThis gate automatically updates beads.\n' >>"$bad_docs"
  saved_failures="$failures"
  failures=0
  run_check_with_paths "$bad_docs" "$contract_path" "$fixtures_path"
  observed_failures="$failures"
  failures="$saved_failures"
  if [[ "$observed_failures" -eq 0 ]]; then
    record_failure "selftest expected forbidden wording failure"
  else
    record_pass "selftest forbidden wording is rejected"
  fi

  bad_fixtures="${tmp_root}/bad-cases.json"
  jq 'del(.cases[] | select(.case_id == "rch_degraded"))' "$fixtures_path" >"$bad_fixtures"
  saved_failures="$failures"
  failures=0
  run_check_with_paths "$docs_path" "$contract_path" "$bad_fixtures"
  observed_failures="$failures"
  failures="$saved_failures"
  if [[ "$observed_failures" -eq 0 ]]; then
    record_failure "selftest expected missing fixture failure"
  else
    record_pass "selftest missing fixture is rejected"
  fi
}

case "$mode" in
  check)
    run_check
    ;;
  run)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      run_artifacts "$output_dir"
    fi
    ;;
  selftest)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      run_selftest
    fi
    ;;
  -h|--help)
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
