#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
adapter="${root_dir}/scripts/swarm_frankentui_dashboard_bundle.sh"
fixtures_path="${SWARM_FRANKENTUI_DASHBOARD_BUNDLE_FIXTURES:-${root_dir}/scripts/testdata/swarm_frankentui_dashboard_bundle/cases.json}"
contract_path="${root_dir}/docs/swarm_frankentui_dashboard_bundle_contract_v1.json"
docs_path="${root_dir}/docs/SWARM_FRANKENTUI_DASHBOARD_BUNDLE.md"
mode="${1:-check}"
output_dir="${2:-${SWARM_FRANKENTUI_DASHBOARD_BUNDLE_OUTPUT_DIR:-}}"
failures=0

input_ids=(
  resource_envelope_json
  admission_budget_plan_json
  stale_recovery_receipts_json
  worker_truth_report_json
  proof_cache_locality_plan_json
  rch_rehabilitation_ledger_json
)

record_pass() {
  printf 'PASS swarm-frankentui-dashboard-bundle %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-frankentui-dashboard-bundle %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_frankentui_dashboard_bundle_smoke.sh [check|run|selftest] [output_dir]
EOF
}

bundle_required_sections_ok() {
  local bundle="$1"
  jq -e '
    ([.panels[].panel_id] | sort) == (["admitted_lanes","capacity","proof_cache_locality","rch_workers","recovery_receipts","stale_ownership"] | sort)
    and (.panels | length == 6)
    and ([.panels[].panel_id] | unique | length == 6)
  ' "$bundle" >/dev/null
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-frankentui-dashboard-bundle-fixtures.v1"
    and (.cases | length == 4)
    and any(.cases[]; .case_id == "healthy" and .expected.decision == "pass")
    and any(.cases[]; .case_id == "brownout" and .expected.required_reason_code == "missing_capacity_telemetry")
    and any(.cases[]; .case_id == "stale_owner" and .expected.required_reason_code == "stale_owner_needs_contact")
    and any(.cases[]; .case_id == "rch_drained" and .expected.required_reason_code == "rch_worker_drained")
    and all(.cases[];
      (.expected.panel_states | keys | sort) == (["admitted_lanes","capacity","proof_cache_locality","rch_workers","recovery_receipts","stale_ownership"] | sort)
      and .inputs.resource_envelope_json.schema_version == "franken-engine.swarm-resource-envelope.v1"
      and .inputs.admission_budget_plan_json.schema_version == "franken-engine.swarm-admission-budget-plan.v1"
      and .inputs.stale_recovery_receipts_json.schema_version == "franken-engine.swarm-ops-stale-recovery-receipts.v1"
      and .inputs.worker_truth_report_json.schema_version == "franken-engine.rch-worker-truth-parity-report.v1"
      and .inputs.proof_cache_locality_plan_json.schema_version == "franken-engine.swarm-proof-cache-locality-plan.v1"
      and .inputs.rch_rehabilitation_ledger_json.schema_version == "franken-engine.swarm-rch-stall-rehabilitation-ledger.v1"
    )
  ' "$fixtures_path" >/dev/null
}

contract_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-frankentui-dashboard-bundle-contract.v1"
    and .bead_id == "bd-wql3k"
    and .script == "scripts/swarm_frankentui_dashboard_bundle.sh"
    and .smoke_script == "scripts/e2e/swarm_frankentui_dashboard_bundle_smoke.sh"
    and .operator_docs == "docs/SWARM_FRANKENTUI_DASHBOARD_BUNDLE.md"
    and .fixture_bundle == "scripts/testdata/swarm_frankentui_dashboard_bundle/cases.json"
    and .output_schema_version == "franken-engine.swarm-frankentui-dashboard-bundle.v1"
    and .dashboard_event_schema_version == "franken-engine.swarm-frankentui-dashboard-event.v1"
    and .renderer_contract.provider == "/dp/frankentui"
    and .renderer_contract.shipped_in_franken_engine == false
    and .renderer_contract.local_renderer == false
    and .renderer_contract.no_local_tui_runtime == true
    and (.required_inputs | index("resource_envelope_json") != null)
    and (.required_inputs | index("admission_budget_plan_json") != null)
    and (.required_inputs | index("stale_recovery_receipts_json") != null)
    and (.required_inputs | index("worker_truth_report_json") != null)
    and (.required_inputs | index("proof_cache_locality_plan_json") != null)
    and (.required_inputs | index("rch_rehabilitation_ledger_json") != null)
    and (.required_outputs | index("dashboard_bundle.json") != null)
    and (.required_outputs | index("dashboard_events.ndjson") != null)
    and (.required_panels | sort) == (["admitted_lanes","capacity","proof_cache_locality","rch_workers","recovery_receipts","stale_ownership"] | sort)
    and (.display_states | sort) == (["blocked","degraded","fail_closed","healthy","missing","stale"] | sort)
    and any(.degraded_mode_requirements[]; .class == "missing_capacity_telemetry" and .panel_id == "capacity" and .required_display_state == "missing")
    and any(.degraded_mode_requirements[]; .class == "stale_owner_needs_contact" and .panel_id == "stale_ownership" and .required_display_state == "stale")
    and any(.degraded_mode_requirements[]; .class == "rch_worker_drained" and .panel_id == "rch_workers" and .required_display_state == "degraded")
    and .mutation_policy.fixture_fed_only == true
    and .mutation_policy.adapter_only == true
    and .mutation_policy.advisory_only == true
    and .mutation_policy.renders_tui == false
    and .mutation_policy.mutates_br == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.changes_live_queue_policy == false
  ' "$contract_path" >/dev/null
}

docs_shape_ok() {
  grep -Fq 'Machine-readable contract:' "$docs_path" \
    && grep -Fq 'Smoke gate:' "$docs_path" \
    && grep -Fq 'Fixture cases:' "$docs_path" \
    && grep -Fq '/dp/frankentui' "$docs_path" \
    && grep -Fq 'not a TUI runtime' "$docs_path" \
    && grep -Fq 'does not query live Agent Mail' "$docs_path" \
    && grep -Fq 'does not execute them' "$docs_path"
}

check_no_forbidden_commands() {
  local path="$1"
  while IFS= read -r command; do
    if [[ "$command" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
      record_failure "${path#"$root_dir"/} has heavy Cargo command string: ${command}"
    fi
    if [[ "$command" =~ (^|[[:space:]])rch[[:space:]]+exec([[:space:]]|$) ]]; then
      record_failure "${path#"$root_dir"/} has RCH execution command string: ${command}"
    fi
  done < <(jq -r '.. | strings' "$path" 2>/dev/null || sed -n '1,260p' "$path")
}

check_no_mutation_claims() {
  local path="$1"
  if grep -Eiq 'automatically updates beads|automatically closes beads|automatically reopens beads|automatically reassigns beads|automatically releases reservations|sends Agent Mail automatically|queries live Agent Mail automatically|executes operator commands automatically|mutates workers automatically|changes queue policy automatically|renders a local TUI runtime' "$path"; then
    record_failure "${path#"$root_dir"/} contains forbidden live-mutation wording"
  fi
}

materialize_case() {
  local case_json="$1"
  local case_dir="$2"
  local input_id

  mkdir -p "$case_dir"
  for input_id in "${input_ids[@]}"; do
    jq --arg input_id "$input_id" '.inputs[$input_id]' <<<"$case_json" >"${case_dir}/${input_id}.json"
  done
}

validate_bundle() {
  local bundle="$1"
  local expected="$2"
  local dashboard_events="$3"
  local case_id="$4"

  if ! bundle_required_sections_ok "$bundle"; then
    record_failure "${case_id} missing required dashboard panel"
    return
  fi

  jq -e --slurpfile expected "$expected" '
    . as $bundle
    | .schema_version == "franken-engine.swarm-frankentui-dashboard-bundle.v1"
    and .bead_id == "bd-wql3k"
    and .decision == $expected[0].decision
    and .renderer_contract.provider == "/dp/frankentui"
    and .renderer_contract.shipped_in_franken_engine == false
    and .renderer_contract.local_renderer == false
    and .renderer_contract.no_local_tui_runtime == true
    and .frankentui_compatibility.requires_tui_runtime_in_this_repo == false
    and (.frankentui_compatibility.semantic_theme_tokens | index("success") != null)
    and (.display_state_policy.allowed | sort) == (["blocked","degraded","fail_closed","healthy","missing","stale"] | sort)
    and .display_state_policy.missing_telemetry_visible == true
    and .display_state_policy.stale_evidence_visible == true
    and .display_state_policy.drained_workers_visible == true
    and .status_bar.summary.panel_count == 6
    and all(.panels[]; (.display_state | IN("healthy","degraded","missing","stale","blocked","fail_closed")))
    and all(.panels[]; ((.semantic_theme_token // "") | length) > 0 and (.focus_order | type) == "number" and .supports_tiny_layout == true and ((.aria_label // "") | length) > 0 and (.visible_reasons | type) == "array")
    and all($expected[0].panel_states | to_entries[]; . as $entry | any($bundle.panels[]; .panel_id == $entry.key and .display_state == $entry.value))
    and (
      (($expected[0].required_reason_code // "") | length) == 0
      or (([$bundle.fail_closed_reasons[], $bundle.blocked_reasons[], $bundle.degraded_reasons[]] | map(.code) | index($expected[0].required_reason_code)) != null)
    )
    and .mutation_policy.fixture_fed_only == true
    and .mutation_policy.adapter_only == true
    and .mutation_policy.advisory_only == true
    and .mutation_policy.renders_tui == false
    and .mutation_policy.mutates_br == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.changes_live_queue_policy == false
  ' "$bundle" >/dev/null || {
    record_failure "${case_id} bundle shape mismatch"
    return
  }

  jq -s '
    length == 6
    and all(.[]; .schema_version == "franken-engine.swarm-frankentui-dashboard-event.v1" and .component == "swarm_frankentui_dashboard_bundle" and .event == "panel_emitted" and ((.panel_id // "") | length) > 0 and ((.display_state // "") | length) > 0 and ((.evidence_path // "") | length) > 0)
    and ([.[].panel_id] | sort) == (["admitted_lanes","capacity","proof_cache_locality","rch_workers","recovery_receipts","stale_ownership"] | sort)
  ' "$dashboard_events" >/dev/null || record_failure "${case_id} dashboard events missing stable panel events"
}

run_case() {
  local case_json="$1"
  local root="$2"
  local case_id case_dir expected expected_code bundle dashboard_events code prior_failures

  case_id="$(jq -r '.case_id' <<<"$case_json")"
  case_dir="${root}/${case_id}"
  expected="${case_dir}/expected.json"
  materialize_case "$case_json" "$case_dir"
  jq '.expected' <<<"$case_json" >"$expected"
  expected_code="$(jq -r '.expected.expected_exit_code' <<<"$case_json")"

  set +e
  bash "$adapter" \
    --resource-envelope-json "${case_dir}/resource_envelope_json.json" \
    --admission-budget-plan-json "${case_dir}/admission_budget_plan_json.json" \
    --stale-recovery-receipts-json "${case_dir}/stale_recovery_receipts_json.json" \
    --worker-truth-report-json "${case_dir}/worker_truth_report_json.json" \
    --proof-cache-locality-plan-json "${case_dir}/proof_cache_locality_plan_json.json" \
    --rch-rehabilitation-ledger-json "${case_dir}/rch_rehabilitation_ledger_json.json" \
    --source-revision fixture-revision \
    --output-dir "${case_dir}/out" >/dev/null
  code=$?
  set -e

  if [[ "$code" -ne "$expected_code" ]]; then
    record_failure "${case_id} expected exit ${expected_code}, got ${code}"
    return
  fi

  bundle="${case_dir}/out/dashboard_bundle.json"
  dashboard_events="${case_dir}/out/dashboard_events.ndjson"
  test -s "$bundle" || {
    record_failure "${case_id} missing dashboard_bundle.json"
    return
  }
  test -s "$dashboard_events" || record_failure "${case_id} missing dashboard_events.ndjson"
  test -s "${case_dir}/out/events.jsonl" || record_failure "${case_id} missing events.jsonl"
  test -s "${case_dir}/out/commands.txt" || record_failure "${case_id} missing commands.txt"
  test -s "${case_dir}/out/report.md" || record_failure "${case_id} missing report.md"

  prior_failures="$failures"
  validate_bundle "$bundle" "$expected" "$dashboard_events" "$case_id"
  if [[ "$failures" -eq "$prior_failures" ]]; then
    record_pass "${case_id} dashboard bundle"
  fi
}

run_check() {
  bash -n "$adapter"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$fixtures_path" "$contract_path"

  if fixtures_shape_ok; then
    record_pass "fixture shape"
  else
    record_failure "fixture shape mismatch"
  fi
  if contract_shape_ok; then
    record_pass "contract shape"
  else
    record_failure "contract shape mismatch"
  fi
  if docs_shape_ok; then
    record_pass "operator docs shape"
  else
    record_failure "operator docs shape mismatch"
  fi

  check_no_forbidden_commands "$adapter"
  check_no_forbidden_commands "$fixtures_path"
  check_no_forbidden_commands "$contract_path"
  check_no_forbidden_commands "$docs_path"
  check_no_mutation_claims "$adapter"
  check_no_mutation_claims "$contract_path"
  check_no_mutation_claims "$docs_path"
}

run_all_cases() {
  local root="$1"
  mkdir -p "$root"
  while IFS= read -r case_json; do
    run_case "$case_json" "$root"
  done < <(jq -c '.cases[]' "$fixtures_path")
  printf 'swarm_frankentui_dashboard_bundle_smoke_artifacts=%s\n' "$root"
}

run_selftest() {
  local tmp_root hash_a hash_b bad_bundle
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/swarm-frankentui-dashboard-bundle-selftest.XXXXXX")"
  run_all_cases "$tmp_root"

  hash_a="$(jq -r '.hash_basis.bundle_hash' "${tmp_root}/healthy/out/dashboard_bundle.json")"
  bash "$adapter" \
    --resource-envelope-json "${tmp_root}/healthy/resource_envelope_json.json" \
    --admission-budget-plan-json "${tmp_root}/healthy/admission_budget_plan_json.json" \
    --stale-recovery-receipts-json "${tmp_root}/healthy/stale_recovery_receipts_json.json" \
    --worker-truth-report-json "${tmp_root}/healthy/worker_truth_report_json.json" \
    --proof-cache-locality-plan-json "${tmp_root}/healthy/proof_cache_locality_plan_json.json" \
    --rch-rehabilitation-ledger-json "${tmp_root}/healthy/rch_rehabilitation_ledger_json.json" \
    --source-revision fixture-revision \
    --output-dir "${tmp_root}/healthy_repeat" >/dev/null
  hash_b="$(jq -r '.hash_basis.bundle_hash' "${tmp_root}/healthy_repeat/dashboard_bundle.json")"
  if [[ "$hash_a" != "$hash_b" ]]; then
    record_failure "stable bundle hash mismatch for repeated healthy case"
  else
    record_pass "stable bundle hash"
  fi

  bad_bundle="${tmp_root}/missing-proof-cache-panel.json"
  jq '.panels |= map(select(.panel_id != "proof_cache_locality"))' "${tmp_root}/healthy/out/dashboard_bundle.json" >"$bad_bundle"
  if bundle_required_sections_ok "$bad_bundle"; then
    record_failure "selftest expected missing required panel rejection"
  else
    record_pass "selftest missing required panel is rejected"
  fi
}

case "$mode" in
  check)
    run_check
    ;;
  run)
    run_check
    if [[ "$failures" -eq 0 ]]; then
      if [[ -z "$output_dir" ]]; then
        output_dir="$(mktemp -d "${TMPDIR:-/tmp}/swarm-frankentui-dashboard-bundle-run.XXXXXX")"
      fi
      run_all_cases "$output_dir"
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
