#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
normalizer="${root_dir}/scripts/swarm_execution_queue_input_normalizer.sh"
docs_path="${root_dir}/docs/SWARM_EXECUTION_QUEUE_INPUT_NORMALIZER.md"
contract_path="${root_dir}/docs/swarm_execution_queue_input_contract_v1.json"
parent_contract_path="${root_dir}/docs/swarm_execution_queue_contract_v1.json"
seed_fixture_dir="${root_dir}/scripts/testdata/swarm_execution_queue"

record_pass() {
  printf 'PASS swarm-execution-queue-input-normalizer %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-execution-queue-input-normalizer %s\n' "$1" >&2
  exit 1
}

write_json() {
  local path="$1"
  local content="$2"
  printf '%s\n' "$content" >"$path"
}

write_fixture_set() {
  local dir="$1"
  local scenario="$2"
  local priority=2
  local owner=""
  local owner_age=0
  local status="open"
  local reservation_holder=""
  local proof_state="remote_only_ok"
  local local_fallback=false
  local remaining=720000
  local consumed=280000
  local deps='[]'

  case "$scenario" in
    healthy)
      priority=1
      ;;
    stale_owner)
      priority=1
      owner="DormantAgent"
      owner_age=90000
      status="in_progress"
      ;;
    proof_brownout)
      proof_state="brownout"
      remaining=180000
      consumed=820000
      reservation_holder="ProofAgent"
      ;;
    blocked_parent)
      deps='["bd-child-contract"]'
      ;;
    bad_shape)
      ;;
    local_fallback)
      proof_state="remote_only_ok"
      local_fallback=true
      ;;
    cycle)
      deps='["bd-cycle-b"]'
      ;;
    *)
      record_failure "unknown fixture scenario ${scenario}"
      ;;
  esac

  if [[ "$scenario" == "bad_shape" ]]; then
    write_json "${dir}/br_ready.json" '{"issues":{}}'
    write_json "${dir}/br_list.json" '{"issues":{}}'
    write_json "${dir}/bv_plan.json" '{"plan":{"tracks":[]}}'
    write_json "${dir}/agent_mail.json" '{"agents":[],"messages":[]}'
    write_json "${dir}/reservations.json" '{"reservations":[]}'
    write_json "${dir}/stale.json" '{"stale_lock_recommendations":[]}'
    write_json "${dir}/proof.json" '{"state":"remote_only_ok","local_fallback_detected":false}'
    return
  fi

  local primary_id="bd-ready-a"
  local primary_title="Ready execution queue lane"
  if [[ "$scenario" == "stale_owner" ]]; then
    primary_id="bd-stale-owner"
    primary_title="Stale high-impact proof lane"
  elif [[ "$scenario" == "proof_brownout" ]]; then
    primary_id="bd-brownout-ready"
    primary_title="Broad proof lane during brownout"
  elif [[ "$scenario" == "blocked_parent" ]]; then
    primary_id="bd-parent"
    primary_title="Parent blocked by contract child"
  elif [[ "$scenario" == "local_fallback" ]]; then
    # rch-policy-waive: local_fallback_not_rejected reason=fixture branch names the rejected fallback scenario
    primary_id="bd-local-fallback"
    primary_title="Local fallback proof lane"
  elif [[ "$scenario" == "cycle" ]]; then
    primary_id="bd-cycle-a"
    primary_title="Cycle A"
  fi

  write_json "${dir}/br_ready.json" "$(jq -n \
    --arg id "$primary_id" \
    --arg title "$primary_title" \
    --arg status "$status" \
    --arg assignee "$owner" \
    --argjson priority "$priority" \
    '[
      {
        id:$id,
        title:$title,
        status:$status,
        priority:$priority,
        assignee:$assignee
      }
    ]')"

  if [[ "$scenario" == "blocked_parent" ]]; then
    write_json "${dir}/br_list.json" "$(jq -n \
      --argjson deps "$deps" \
      '{
        issues: [
          {
            id:"bd-parent",
            title:"Parent blocked by contract child",
            status:"open",
            priority:2,
            assignee:"",
            dependencies: ($deps | map({id:.})),
            dependents:[]
          },
          {
            id:"bd-child-contract",
            title:"Ready contract child",
            status:"open",
            priority:2,
            assignee:"",
            dependencies:[],
            dependents:[{id:"bd-parent"}]
          }
        ]
      }')"
  elif [[ "$scenario" == "cycle" ]]; then
    write_json "${dir}/br_list.json" '{
      "issues": [
        {"id":"bd-cycle-a","title":"Cycle A","status":"open","priority":2,"assignee":"","dependencies":[{"id":"bd-cycle-b"}],"dependents":[{"id":"bd-cycle-b"}]},
        {"id":"bd-cycle-b","title":"Cycle B","status":"open","priority":2,"assignee":"","dependencies":[{"id":"bd-cycle-a"}],"dependents":[{"id":"bd-cycle-a"}]}
      ]
    }'
  else
    write_json "${dir}/br_list.json" "$(jq -n \
      --arg id "$primary_id" \
      --arg title "$primary_title" \
      --arg status "$status" \
      --arg assignee "$owner" \
      --argjson priority "$priority" \
      '{
        issues: [
          {
            id:$id,
            title:$title,
            status:$status,
            priority:$priority,
            assignee:$assignee,
            dependencies:[],
            dependents:[{id:"bd-parent"}]
          },
          {
            id:"bd-parent",
            title:"Parent track",
            status:"open",
            priority:2,
            assignee:"",
            dependencies:[{id:$id}],
            dependents:[]
          }
        ]
      }')"
  fi

  write_json "${dir}/bv_plan.json" "$(jq -n \
    --arg id "$primary_id" \
    --arg title "$primary_title" \
    --arg status "$status" \
    --argjson priority "$priority" \
    '{
      generated_at:"2026-05-06T09:00:00Z",
      plan:{
        tracks:[
          {
            track_id:"track-A",
            items:[
              {id:$id,title:$title,priority:$priority,status:$status,unblocks:["bd-parent"]}
            ],
            reason:"fixture"
          }
        ],
        total_actionable:1,
        total_blocked:1,
        summary:{highest_impact:$id}
      }
    }')"

  write_json "${dir}/agent_mail.json" "$(jq -n \
    --arg owner "$owner" \
    --argjson owner_age "$owner_age" \
    '{
      schema_version:"franken-engine.agent-mail-activity-fixture.v1",
      agents: (if $owner == "" then [] else [{name:$owner,last_active_age_seconds:$owner_age}] end),
      messages:[]
    }')"

  write_json "${dir}/reservations.json" "$(jq -n \
    --arg id "$primary_id" \
    --arg holder "$reservation_holder" \
    '{
      schema_version:"franken-engine.file-reservations-fixture.v1",
      reservations: (if $holder == "" then [] else [{bead_id:$id,agent_name:$holder,path_pattern:"scripts/shared.sh",exclusive:true}] end)
    }')"

  write_json "${dir}/stale.json" "$(jq -n \
    --arg id "$primary_id" \
    --arg scenario "$scenario" \
    '{
      schema_version:"franken-engine.stale-lock-recommendations.v1",
      generated_epoch_seconds:1800000000,
      stale_lock_recommendations: (if $scenario == "stale_owner" then [{bead_id:$id,safe_to_reopen:true,contact_first:false,recommendation:"safe_to_reopen"}] else [] end),
      safe_to_reopen: (if $scenario == "stale_owner" then [$id] else [] end),
      contact_first:[]
    }')"

  write_json "${dir}/proof.json" "$(jq -n \
    --arg id "$primary_id" \
    --arg state "$proof_state" \
    --argjson local_fallback "$local_fallback" \
    --argjson remaining "$remaining" \
    --argjson consumed "$consumed" \
    '{
      schema_version:"franken-engine.proof-transport-health.v1",
      state:$state,
      local_fallback_detected:$local_fallback,
      risk_budget:{
        remaining_millionths:$remaining,
        consumed_millionths:$consumed,
        conservative_threshold_millionths:200000
      },
      tasks:[
        {
          bead_id:$id,
          state:$state,
          local_fallback_detected:$local_fallback
        }
      ]
    }')"
}

run_normalizer() {
  local fixture_dir="$1"
  local output_dir="$2"

  "$normalizer" \
    --br-ready-json "${fixture_dir}/br_ready.json" \
    --br-list-json "${fixture_dir}/br_list.json" \
    --bv-actionable-plan-json "${fixture_dir}/bv_plan.json" \
    --agent-mail-activity-json "${fixture_dir}/agent_mail.json" \
    --file-reservations-json "${fixture_dir}/reservations.json" \
    --stale-lock-recommendations-json "${fixture_dir}/stale.json" \
    --proof-transport-health-json "${fixture_dir}/proof.json" \
    --source-revision fixture-rev \
    --generated-epoch-seconds 1800000000 \
    --stale-after-seconds 3600 \
    --output-dir "$output_dir" >/dev/null
}

expect_fail_closed() {
  local fixture_dir="$1"
  local output_dir="$2"
  set +e
  run_normalizer "$fixture_dir" "$output_dir" >/dev/null 2>&1
  local code=$?
  set -e
  if [[ "$code" -ne 42 ]]; then
    record_failure "expected fail_closed exit 42, got ${code}"
  fi
  [[ -f "${output_dir}/normalized_input.json" ]] || record_failure "fail_closed case did not emit normalized input"
}

check_no_mutation_claims() {
  local path="$1"
  if grep -Eiq 'automatic reopen is allowed|automatically reopens|runs br update|will run br update|br update .*--status|release_file_reservations|will release reservations|sends Agent Mail automatically|mutates remote workers|runs cargo' "$path"; then
    record_failure "${path#"$root_dir"/} contains live-mutation wording"
  fi
}

check_no_bare_heavy_cargo() {
  local path="$1"
  local command
  while IFS= read -r command; do
    if [[ "$command" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
      if [[ "$command" != *"rch exec --"* || "$command" != *"CARGO_TARGET_DIR="* ]]; then
        record_failure "${path#"$root_dir"/} has bare heavy Cargo command: ${command}"
      fi
    fi
  done < <(jq -r '.. | strings' "$path")
}

run_check() {
  bash -n "$normalizer"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$contract_path" "$parent_contract_path" "${seed_fixture_dir}"/*.json
  jq -e '
    .schema_version == "franken-engine.swarm-execution-queue-input-normalizer-contract.v1"
    and .bead_id == "bd-lb6j0"
    and .input_schema_version == "franken-engine.swarm-execution-queue-input.v1"
    and .mutation_policy.mutates_br == false
    and .mutation_policy.sends_agent_mail == false
    and .mutation_policy.mutates_remote_workers == false
  ' "$contract_path" >/dev/null
  grep -q 'advisory-only' "$docs_path"
  grep -q 'normalized_input.json' "$docs_path"
  grep -q 'scripts/swarm_execution_queue_input_normalizer.sh' "$docs_path"
  check_no_mutation_claims "$docs_path"
  check_no_mutation_claims "$contract_path"
  check_no_bare_heavy_cargo "$contract_path"

  local scope_file
  scope_file="$(mktemp "${TMPDIR:-/tmp}/swarm-execution-queue-input-scope.XXXXXX")"
  printf '%s\n' \
    "scripts/swarm_execution_queue_input_normalizer.sh" \
    "scripts/e2e/swarm_execution_queue_input_normalizer_smoke.sh" \
    "docs/SWARM_EXECUTION_QUEUE_INPUT_NORMALIZER.md" \
    "docs/swarm_execution_queue_input_contract_v1.json" >"$scope_file"
  "${root_dir}/scripts/rch_policy_compliance_gate.sh" \
    --output-dir "${TMPDIR:-/tmp}/swarm-execution-queue-input-rch-policy" \
    --scope-file "$scope_file" >/dev/null

  record_pass "syntax docs contract seed fixtures and rch policy"
}

run_selftest() {
  local tmp_parent tmp_root healthy_dir stale_dir brownout_dir blocked_dir bad_shape_dir fallback_dir cycle_dir run_a run_b
  tmp_parent="${SWARM_EXECUTION_QUEUE_INPUT_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/swarm-execution-queue-input.XXXXXX")"

  run_check

  healthy_dir="${tmp_root}/healthy"
  stale_dir="${tmp_root}/stale_owner"
  brownout_dir="${tmp_root}/proof_brownout"
  blocked_dir="${tmp_root}/blocked_parent"
  bad_shape_dir="${tmp_root}/bad_shape"
  fallback_dir="${tmp_root}/local_fallback"
  cycle_dir="${tmp_root}/cycle"
  mkdir -p "$healthy_dir" "$stale_dir" "$brownout_dir" "$blocked_dir" "$bad_shape_dir" "$fallback_dir" "$cycle_dir"

  write_fixture_set "$healthy_dir" healthy
  write_fixture_set "$stale_dir" stale_owner
  write_fixture_set "$brownout_dir" proof_brownout
  write_fixture_set "$blocked_dir" blocked_parent
  write_fixture_set "$bad_shape_dir" bad_shape
  write_fixture_set "$fallback_dir" local_fallback
  write_fixture_set "$cycle_dir" cycle

  run_a="${healthy_dir}/out-a"
  run_b="${healthy_dir}/out-b"
  mkdir -p "$run_a" "$run_b"
  run_normalizer "$healthy_dir" "$run_a"
  run_normalizer "$healthy_dir" "$run_b"
  jq -e '
    .schema_version == "franken-engine.swarm-execution-queue-input.v1"
    and .decision == "pass"
    and .summary.task_count == 2
    and .summary.ready_task_count == 1
    and (.tasks[0].task_id == "bd-ready-a")
    and (.tasks[0].first_action | length > 0)
    and .risk_budget.conservative_mode == false
    and (.fail_closed_reasons | length) == 0
  ' "${run_a}/normalized_input.json" >/dev/null
  diff -u \
    <(jq -cS 'del(.artifact_paths)' "${run_a}/normalized_input.json") \
    <(jq -cS 'del(.artifact_paths)' "${run_b}/normalized_input.json") >/dev/null
  record_pass "healthy fixture normalizes deterministically"

  mkdir -p "${stale_dir}/out"
  run_normalizer "$stale_dir" "${stale_dir}/out"
  jq -e '
    .decision == "degraded"
    and any(.tasks[]?; .task_id == "bd-stale-owner" and .owner_freshness.state == "stale" and .fallback_trigger == "contact_or_reopen_required")
    and any(.degraded_inputs[]?; .kind == "stale_owner")
  ' "${stale_dir}/out/normalized_input.json" >/dev/null
  record_pass "stale owner evidence degrades with contact/reopen first action"

  mkdir -p "${brownout_dir}/out"
  run_normalizer "$brownout_dir" "${brownout_dir}/out"
  jq -e '
    .decision == "degraded"
    and .risk_budget.conservative_mode == true
    and any(.tasks[]?; .proof_transport.state == "brownout" and .fallback_trigger == "proof_brownout_conservative_mode")
  ' "${brownout_dir}/out/normalized_input.json" >/dev/null
  record_pass "proof brownout degrades into conservative mode"

  mkdir -p "${blocked_dir}/out"
  run_normalizer "$blocked_dir" "${blocked_dir}/out"
  jq -e '
    .decision == "pass"
    and .tasks[0].task_id == "bd-child-contract"
    and any(.tasks[]?; .task_id == "bd-parent" and .open_blocker_count == 1 and .fallback_trigger == "blocked_parent")
  ' "${blocked_dir}/out/normalized_input.json" >/dev/null
  record_pass "blocked parent keeps ready child ahead of parent"

  mkdir -p "${bad_shape_dir}/out"
  expect_fail_closed "$bad_shape_dir" "${bad_shape_dir}/out"
  jq -e 'any(.fail_closed_reasons[]?; .kind == "malformed_required_shape")' "${bad_shape_dir}/out/normalized_input.json" >/dev/null
  record_pass "malformed required br shape fails closed"

  mkdir -p "${fallback_dir}/out"
  expect_fail_closed "$fallback_dir" "${fallback_dir}/out"
  jq -e 'any(.fail_closed_reasons[]?; .kind == "local_rch_fallback_detected")' "${fallback_dir}/out/normalized_input.json" >/dev/null
  record_pass "local-rch fallback promotion fails closed"

  mkdir -p "${cycle_dir}/out"
  expect_fail_closed "$cycle_dir" "${cycle_dir}/out"
  jq -e 'any(.fail_closed_reasons[]?; .kind == "dependency_cycle")' "${cycle_dir}/out/normalized_input.json" >/dev/null
  record_pass "dependency cycle fails closed"

  printf 'swarm_execution_queue_input_normalizer_smoke_artifacts=%s\n' "$tmp_root"
}

case "${1:-check}" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  *)
    printf 'FAIL swarm-execution-queue-input-normalizer unknown mode: %s\n' "${1:-}" >&2
    exit 64
    ;;
esac
