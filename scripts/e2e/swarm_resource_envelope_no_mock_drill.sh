#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_root="${SWARM_RESOURCE_ENVELOPE_NO_MOCK_DRILL_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-resource-envelope-no-mock-drill}"
run_id="${SWARM_RESOURCE_ENVELOPE_NO_MOCK_DRILL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_RESOURCE_ENVELOPE_NO_MOCK_DRILL_RUN_DIR:-${artifact_root}/${run_id}}"
mode="${1:-run}"
if [[ "$#" -gt 0 ]]; then
  shift
fi

normalizer="${root_dir}/scripts/swarm_resource_envelope_normalizer.sh"
planner="${root_dir}/scripts/swarm_fair_share_batch_planner.sh"
operator_status="${root_dir}/scripts/swarm_operator_status_report.sh"
truth_gate="${root_dir}/scripts/e2e/swarm_resource_envelope_runbook_truth_gate.sh"
docs_path="${root_dir}/docs/SWARM_RESOURCE_ENVELOPE.md"
contract_path="${root_dir}/docs/swarm_resource_envelope_contract_v1.json"

events_path=""
commands_path=""
report_md=""
receipt_json=""
case_rows_jsonl=""
failures=0

cases=(
  healthy_high_core_host
  missing_optional_host_telemetry
  blocked_saturated_capacity
  contaminated_local_rch_fallback
  contradictory_slot_or_memory_evidence
  unsafe_mutation_wording
)

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_resource_envelope_no_mock_drill.sh [check|run|selftest] [OPTIONS]

Composes the real SWARM-SCALE-I resource envelope normalizer, fair-share batch
planner, and operator-status report over deterministic fixtures. The drill is
fixture-fed, proof-only, and advisory-only. It does not query live br, Agent
Mail, RCH, Cargo, ps, df, queue state, reservations, or workers, and it does not
mutate beads, release reservations, send Agent Mail, change workers, or repair
stalled builds.

Options:
  --output-dir DIR
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --output-dir)
      run_dir="${2:-}"
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
  printf 'PASS swarm-resource-envelope-no-mock-drill %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-resource-envelope-no-mock-drill %s\n' "$1" >&2
  failures=$((failures + 1))
}

refresh_paths() {
  events_path="${run_dir}/events.jsonl"
  commands_path="${run_dir}/commands.txt"
  report_md="${run_dir}/report.md"
  receipt_json="${run_dir}/swarm_resource_envelope_receipt.json"
  case_rows_jsonl="${run_dir}/case_rows.jsonl"
}

ensure_run_dir() {
  refresh_paths
  mkdir -p "$run_dir"
  : >"$events_path"
  : >"$commands_path"
  : >"$case_rows_jsonl"
}

exit_code_is_expected() {
  local actual="$1"
  local expected_csv="$2"
  local expected

  IFS=',' read -r -a expected_list <<<"$expected_csv"
  for expected in "${expected_list[@]}"; do
    if [[ "$actual" == "$expected" ]]; then
      return 0
    fi
  done
  return 1
}

write_event() {
  local step="$1"
  local decision="$2"
  local exit_code="$3"
  local stdout_path="$4"
  local stderr_path="$5"

  jq -nc \
    --arg schema_version "franken-engine.swarm-resource-envelope-no-mock-drill.event.v1" \
    --arg event_name "swarm_resource_envelope_no_mock_drill.step" \
    --arg step_id "$step" \
    --arg decision "$decision" \
    --arg stdout_path "$stdout_path" \
    --arg stderr_path "$stderr_path" \
    --argjson exit_code "$exit_code" \
    '{
      schema_version:$schema_version,
      event_name:$event_name,
      step_id:$step_id,
      decision:$decision,
      exit_code:$exit_code,
      artifact_paths:{stdout_log:$stdout_path,stderr_log:$stderr_path}
    }' >>"$events_path"
}

run_step() {
  local step="$1"
  local expected_codes="$2"
  shift 2
  local step_dir="${run_dir}/steps/${step}"
  local stdout_path="${step_dir}/stdout.log"
  local stderr_path="${step_dir}/stderr.log"
  local exit_code decision

  mkdir -p "$step_dir"
  {
    printf '%s: ' "$step"
    printf '%q ' "$@"
    printf '\n'
  } >>"$commands_path"

  set +e
  (cd "$root_dir" && "$@") >"$stdout_path" 2>"$stderr_path"
  exit_code=$?
  set -e

  if exit_code_is_expected "$exit_code" "$expected_codes"; then
    decision="pass"
  else
    decision="fail"
  fi
  write_event "$step" "$decision" "$exit_code" "$stdout_path" "$stderr_path"
  if [[ "$decision" != "pass" ]]; then
    printf 'step %s exited %s, expected %s\nstdout=%s\nstderr=%s\n' "$step" "$exit_code" "$expected_codes" "$stdout_path" "$stderr_path" >&2
    return 1
  fi
}

write_common_fixtures() {
  local dir="$1"

  mkdir -p "$dir"
  jq -n '{
    schema_version:"franken-engine.host-topology-snapshot.v1",
    host_id:"host-64c-256g",
    hostname:"swarm-host-a",
    architecture:"x86_64",
    cpu_logical_cores:96,
    cpu_physical_cores:48,
    numa_nodes:2,
    load_average_1m:18,
    observed_at:"2026-05-06T20:00:00Z"
  }' >"${dir}/host_topology.json"
  jq -n '{
    schema_version:"franken-engine.memory-pressure-snapshot.v1",
    total_bytes:274877906944,
    available_bytes:206158430208,
    swap_available_bytes:34359738368,
    telemetry_complete:true,
    observed_at:"2026-05-06T20:00:00Z"
  }' >"${dir}/memory_pressure.json"
  jq -n '{
    schema_version:"franken-engine.disk-pressure-snapshot.v1",
    filesystems:[{mount:"/data", available_bytes:549755813888, available_inodes:4000000}],
    target_dirs:[{path:"/mnt/rch/franken_engine", available_bytes:322122547200, warm:true}],
    telemetry_complete:true,
    observed_at:"2026-05-06T20:00:00Z"
  }' >"${dir}/disk_pressure.json"
  jq -n '{
    schema_version:"franken-engine.rch-queue-status-snapshot.v1",
    host_id:"host-64c-256g",
    workers:[
      {worker_id:"rch-a", slots_total:8, slots_available:6},
      {worker_id:"rch-b", slots_total:8, slots_available:6}
    ],
    build_slots:{total:16, active:4, available:12},
    queue_depth:0,
    observed_at:"2026-05-06T20:00:00Z"
  }' >"${dir}/rch_queue.json"
  jq -n '{leases:[{slot:"compile", holder:"AgentAlpha", expires_ts:"2026-05-06T20:30:00Z"}]}' >"${dir}/rch_build_slot.json"
  jq -n '{proof_cache_decision:"cache_hit", cache_hit_artifacts:["proof-a.json"]}' >"${dir}/proof_cache.json"
  jq -n '{advisory:"prefetch_recommended", expected_savings_seconds:180}' >"${dir}/warm_target_roi.json"
  jq -n '{scoreboard_status:"ok", archive_pressure:"low"}' >"${dir}/archive_pressure.json"
  jq -n '[{id:"bd-frd5i-next", title:"Next shell lane", status:"open", priority:1}]' >"${dir}/br_ready.json"
  jq -n '{issues:[{id:"bd-frd5i", status:"in_progress", assignee:"BrownCreek"}]}' >"${dir}/br_in_progress.json"
  jq -n '{dirty_count:0, db_newer:false, jsonl_newer:false}' >"${dir}/br_sync_status.json"
  jq -n '{
    plan:{
      tracks:[
        {track_id:"swarm-scale",items:[
          {id:"bd-heavy-a", title:"Heavy A", priority:1, agent_id:"AgentA", command_kind:"cargo_check", requested_command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch cargo check -p frankenengine-engine --lib", requested_rch_slots:1, requested_memory_bytes:4294967296, planned_write_paths:["crates/franken-engine/src/a.rs"]},
          {id:"bd-heavy-b", title:"Heavy B", priority:1, agent_id:"AgentB", command_kind:"cargo_test", requested_command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch cargo test -p frankenengine-engine --lib", requested_rch_slots:1, requested_memory_bytes:4294967296, planned_write_paths:["crates/franken-engine/src/b.rs"]},
          {id:"bd-script", title:"Script lane", priority:2, agent_id:"AgentA", command_kind:"script", requested_command:"bash scripts/e2e/example.sh", planned_write_paths:["scripts/e2e/example.sh"]}
        ]}
      ]
    }
  }' >"${dir}/bv_plan.json"
  jq -n '{reservations:[]}' >"${dir}/reservations.json"
  jq -n '{paths:["scripts/e2e/swarm_resource_envelope_no_mock_drill.sh"]}' >"${dir}/write_set.json"
  jq -n '{decision:"pass", anomalies:[]}' >"${dir}/causal_trace.json"
  jq -n '{commands:[
    {display:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch cargo check -p frankenengine-engine --lib", cost_class:"heavy", budget_class:"build_lane"},
    {display:"bash scripts/e2e/example.sh", cost_class:"script", budget_class:"script_lane"}
  ]}' >"${dir}/validation_costs.json"
}

rewrite_case_fixtures() {
  local case_id="$1"
  local fixture_dir="$2"
  local tmp_path

  case "$case_id" in
    healthy_high_core_host)
      ;;
    missing_optional_host_telemetry)
      tmp_path="${fixture_dir}/memory_pressure.tmp"
      jq '.telemetry_complete = false' "${fixture_dir}/memory_pressure.json" >"$tmp_path"
      mv "$tmp_path" "${fixture_dir}/memory_pressure.json"
      ;;
    blocked_saturated_capacity)
      tmp_path="${fixture_dir}/host_topology.tmp"
      jq '.load_average_1m = 128' "${fixture_dir}/host_topology.json" >"$tmp_path"
      mv "$tmp_path" "${fixture_dir}/host_topology.json"
      tmp_path="${fixture_dir}/rch_queue.tmp"
      jq '.build_slots.available = 0
        | .build_slots.active = 16
        | .queue_depth = 7
        | .workers[0].slots_available = 0
        | .workers[1].slots_available = 0' "${fixture_dir}/rch_queue.json" >"$tmp_path"
      mv "$tmp_path" "${fixture_dir}/rch_queue.json"
      ;;
    contaminated_local_rch_fallback)
      tmp_path="${fixture_dir}/rch_queue.tmp"
      jq '.local_fallback_detected = true
        | .last_stderr = "[RCH] local fallback marker rejected by no-mock drill"' "${fixture_dir}/rch_queue.json" >"$tmp_path"
      mv "$tmp_path" "${fixture_dir}/rch_queue.json"
      ;;
    contradictory_slot_or_memory_evidence)
      tmp_path="${fixture_dir}/memory_pressure.tmp"
      jq '.available_bytes = (.total_bytes + 1)' "${fixture_dir}/memory_pressure.json" >"$tmp_path"
      mv "$tmp_path" "${fixture_dir}/memory_pressure.json"
      tmp_path="${fixture_dir}/rch_queue.tmp"
      jq '.build_slots.total = 99' "${fixture_dir}/rch_queue.json" >"$tmp_path"
      mv "$tmp_path" "${fixture_dir}/rch_queue.json"
      ;;
    unsafe_mutation_wording)
      tmp_path="${fixture_dir}/causal_trace.tmp"
      jq '.operator_claim = "mutates live workers and changes live queue policy"' "${fixture_dir}/causal_trace.json" >"$tmp_path"
      mv "$tmp_path" "${fixture_dir}/causal_trace.json"
      ;;
    *)
      record_failure "unknown fixture case ${case_id}"
      return 1
      ;;
  esac
}

normalizer_expected_exit() {
  case "$1" in
    healthy_high_core_host|missing_optional_host_telemetry) printf '0\n' ;;
    blocked_saturated_capacity) printf '75\n' ;;
    contaminated_local_rch_fallback|contradictory_slot_or_memory_evidence|unsafe_mutation_wording) printf '42\n' ;;
    *) printf '64\n' ;;
  esac
}

planner_expected_exit() {
  case "$1" in
    healthy_high_core_host|missing_optional_host_telemetry) printf '0\n' ;;
    blocked_saturated_capacity) printf '75\n' ;;
    contaminated_local_rch_fallback|contradictory_slot_or_memory_evidence|unsafe_mutation_wording) printf '42\n' ;;
    *) printf '64\n' ;;
  esac
}

expected_envelope_decision() {
  case "$1" in
    healthy_high_core_host) printf 'pass\n' ;;
    missing_optional_host_telemetry) printf 'degraded\n' ;;
    blocked_saturated_capacity) printf 'blocked\n' ;;
    contaminated_local_rch_fallback|contradictory_slot_or_memory_evidence|unsafe_mutation_wording) printf 'fail_closed\n' ;;
    *) printf 'unknown\n' ;;
  esac
}

expected_plan_decision() {
  case "$1" in
    healthy_high_core_host|missing_optional_host_telemetry) printf 'admit\n' ;;
    blocked_saturated_capacity) printf 'defer\n' ;;
    contaminated_local_rch_fallback|contradictory_slot_or_memory_evidence|unsafe_mutation_wording) printf 'fail_closed\n' ;;
    *) printf 'unknown\n' ;;
  esac
}

run_normalizer_case() {
  local case_id="$1"
  local fixture_dir="$2"
  local output_dir="$3"
  local cmd=(
    "$normalizer"
    --bead-id bd-frd5i
    --source-revision fixture-rev
    --reference-time "2026-05-06T20:10:00Z"
    --host-topology-json "${fixture_dir}/host_topology.json"
    --memory-pressure-json "${fixture_dir}/memory_pressure.json"
    --disk-pressure-json "${fixture_dir}/disk_pressure.json"
    --rch-queue-status-json "${fixture_dir}/rch_queue.json"
    --output-dir "$output_dir"
  )

  if [[ "$case_id" != "missing_optional_host_telemetry" ]]; then
    cmd+=(
      --rch-build-slot-json "${fixture_dir}/rch_build_slot.json"
      --proof-cache-plan-json "${fixture_dir}/proof_cache.json"
      --warm-target-prefetch-roi-json "${fixture_dir}/warm_target_roi.json"
      --archive-pressure-scoreboard-json "${fixture_dir}/archive_pressure.json"
      --br-ready-json "${fixture_dir}/br_ready.json"
      --br-in-progress-json "${fixture_dir}/br_in_progress.json"
      --br-sync-status-json "${fixture_dir}/br_sync_status.json"
      --bv-actionable-plan-json "${fixture_dir}/bv_plan.json"
      --agent-mail-file-reservations-json "${fixture_dir}/reservations.json"
      --declared-write-set-json "${fixture_dir}/write_set.json"
      --causal-trace-summary-json "${fixture_dir}/causal_trace.json"
      --validation-cost-hints-json "${fixture_dir}/validation_costs.json"
    )
  fi

  run_step "${case_id}/normalizer" "$(normalizer_expected_exit "$case_id")" "${cmd[@]}"
}

run_planner_case() {
  local case_id="$1"
  local fixture_dir="$2"
  local normalizer_dir="$3"
  local output_dir="$4"

  run_step "${case_id}/fair_share_planner" "$(planner_expected_exit "$case_id")" \
    "$planner" \
    --source-revision fixture-rev \
    --reference-time "2026-05-06T20:10:00Z" \
    --resource-envelope-json "${normalizer_dir}/swarm_resource_envelope.json" \
    --bv-actionable-plan-json "${fixture_dir}/bv_plan.json" \
    --validation-cost-hints-json "${fixture_dir}/validation_costs.json" \
    --proof-cache-plan-json "${fixture_dir}/proof_cache.json" \
    --active-reservations-json "${fixture_dir}/reservations.json" \
    --causal-trace-summary-json "${fixture_dir}/causal_trace.json" \
    --output-dir "$output_dir"
}

run_operator_status_case() {
  local case_id="$1"
  local normalizer_dir="$2"
  local planner_dir="$3"
  local output_dir="$4"

  run_step "${case_id}/operator_status" "0" \
    "$operator_status" \
    --bead-id bd-frd5i \
    --source-revision fixture-rev \
    --agent-mail-status ok \
    --rch-status ok \
    --proof-index-status ok \
    --swarm-resource-envelope-json "${normalizer_dir}/swarm_resource_envelope.json" \
    --swarm-fair-share-batch-plan-json "${planner_dir}/swarm_fair_share_batch_plan.json" \
    --output-dir "$output_dir"
}

append_case_result() {
  local case_id="$1"
  local normalizer_dir="$2"
  local planner_dir="$3"
  local status_dir="$4"
  local expected_envelope expected_plan

  expected_envelope="$(expected_envelope_decision "$case_id")"
  expected_plan="$(expected_plan_decision "$case_id")"

  jq -n \
    --arg case_id "$case_id" \
    --arg expected_envelope "$expected_envelope" \
    --arg expected_plan "$expected_plan" \
    --slurpfile envelope "${normalizer_dir}/swarm_resource_envelope.json" \
    --slurpfile plan "${planner_dir}/swarm_fair_share_batch_plan.json" \
    --slurpfile status "${status_dir}/status.json" '
      ($envelope[0]) as $env
      | ($plan[0]) as $plan_doc
      | ($status[0]) as $status_doc
      | [
          if ($env.decision // "") != $expected_envelope then "unexpected_envelope_decision" else empty end,
          if ($plan_doc.decision // "") != $expected_plan then "unexpected_fair_share_decision" else empty end,
          if (($status_doc.summary.resource_envelope_readiness // "") | length) == 0 then "missing_operator_resource_envelope_readiness" else empty end,
          if (($status_doc.summary.fair_share_decision // "") | length) == 0 then "missing_operator_fair_share_decision" else empty end,
          if (($env.artifact_paths.envelope_json // "") | length) == 0 then "missing_envelope_artifact_path" else empty end,
          if (($plan_doc.artifact_paths.swarm_fair_share_batch_plan_json // "") | length) == 0 then "missing_plan_artifact_path" else empty end
        ] as $failures
      | {
          case_id:$case_id,
          passed:(($failures | length) == 0),
          failures:$failures,
          expected:{envelope_decision:$expected_envelope,fair_share_decision:$expected_plan},
          actual:{
            envelope_decision:$env.decision,
            envelope_readiness:$env.readiness,
            fair_share_decision:$plan_doc.decision,
            admitted_count:($plan_doc.summary.admitted_count // 0),
            deferred_count:($plan_doc.summary.deferred_count // 0),
            operator_status:($status_doc.status // "unknown"),
            operator_resource_envelope_readiness:($status_doc.summary.resource_envelope_readiness // "missing"),
            operator_fair_share_decision:($status_doc.summary.fair_share_decision // "missing")
          },
          artifact_paths:{
            swarm_resource_envelope_json:($env.artifact_paths.envelope_json // ""),
            swarm_fair_share_batch_plan_json:($plan_doc.artifact_paths.swarm_fair_share_batch_plan_json // ""),
            status_json:($status_doc.artifact_paths.status_json // "")
          }
        }
    ' >>"$case_rows_jsonl"
}

run_case() {
  local case_id="$1"
  local fixture_dir="${run_dir}/fixtures/${case_id}"
  local case_dir="${run_dir}/cases/${case_id}"
  local normalizer_dir="${case_dir}/normalizer"
  local planner_dir="${case_dir}/fair_share"
  local status_dir="${case_dir}/operator_status"

  write_common_fixtures "$fixture_dir"
  rewrite_case_fixtures "$case_id" "$fixture_dir"
  run_normalizer_case "$case_id" "$fixture_dir" "$normalizer_dir"
  run_planner_case "$case_id" "$fixture_dir" "$normalizer_dir" "$planner_dir"
  run_operator_status_case "$case_id" "$normalizer_dir" "$planner_dir" "$status_dir"
  append_case_result "$case_id" "$normalizer_dir" "$planner_dir" "$status_dir"
}

write_receipt() {
  local healthy_case_dir="${run_dir}/cases/healthy_high_core_host"

  cp "${healthy_case_dir}/normalizer/swarm_resource_envelope.json" "${run_dir}/swarm_resource_envelope.json"
  cp "${healthy_case_dir}/fair_share/swarm_fair_share_batch_plan.json" "${run_dir}/swarm_fair_share_batch_plan.json"
  cp "${healthy_case_dir}/operator_status/status.json" "${run_dir}/status.json"

  # shellcheck disable=SC2094
  jq -s \
    --arg receipt_json "$receipt_json" \
    --arg envelope_json "${run_dir}/swarm_resource_envelope.json" \
    --arg plan_json "${run_dir}/swarm_fair_share_batch_plan.json" \
    --arg status_json "${run_dir}/status.json" \
    --arg events_path "$events_path" \
    --arg commands_path "$commands_path" \
    --arg report_md "$report_md" '
      {
        schema_version:"franken-engine.swarm-resource-envelope-no-mock-drill-receipt.v1",
        decision:(if all(.[]; .passed) and (length == 6) then "pass" else "fail_closed" end),
        case_count:length,
        passed_count:(map(select(.passed)) | length),
        failed_count:(map(select(.passed | not)) | length),
        required_coverage:{
          healthy_high_core_host:any(.[]; .case_id == "healthy_high_core_host" and .passed),
          missing_optional_host_telemetry:any(.[]; .case_id == "missing_optional_host_telemetry" and .passed),
          blocked_saturated_capacity:any(.[]; .case_id == "blocked_saturated_capacity" and .passed),
          contaminated_local_rch_fallback:any(.[]; .case_id == "contaminated_local_rch_fallback" and .passed),
          contradictory_slot_or_memory_evidence:any(.[]; .case_id == "contradictory_slot_or_memory_evidence" and .passed),
          unsafe_mutation_wording:any(.[]; .case_id == "unsafe_mutation_wording" and .passed)
        },
        cases:.,
        mutation_policy:{
          fixture_fed_only:true,
          proof_only:true,
          advisory_only:true,
          queries_live_agent_mail:false,
          mutates_br:false,
          reassigns_beads:false,
          releases_reservations:false,
          sends_agent_mail:false,
          runs_cargo:false,
          runs_rch:false,
          mutates_remote_workers:false,
          changes_live_queue_policy:false,
          repairs_stalled_builds:false
        },
        producer_chain:[
          "scripts/swarm_resource_envelope_normalizer.sh",
          "scripts/swarm_fair_share_batch_planner.sh",
          "scripts/swarm_operator_status_report.sh"
        ],
        artifact_paths:{
          swarm_resource_envelope_receipt_json:$receipt_json,
          swarm_resource_envelope_json:$envelope_json,
          swarm_fair_share_batch_plan_json:$plan_json,
          status_json:$status_json,
          events_jsonl:$events_path,
          commands_txt:$commands_path,
          report_md:$report_md
        }
      }
    ' "$case_rows_jsonl" >"$receipt_json"

  jq -r '
    "# Swarm Resource Envelope No-Mock Drill",
    "",
    ("- Decision: `" + .decision + "`"),
    ("- Cases: `" + (.case_count | tostring) + "`"),
    ("- Passed: `" + (.passed_count | tostring) + "`"),
    ("- Failed: `" + (.failed_count | tostring) + "`"),
    "",
    "## Coverage",
    "",
    (.required_coverage | to_entries[] | "- `" + .key + "`: `" + (.value | tostring) + "`"),
    "",
    "## Cases",
    "",
    (.cases[] | "- `" + .case_id + "`: `" + .actual.envelope_decision + "` / `" + .actual.fair_share_decision + "` / operator `" + .actual.operator_resource_envelope_readiness + "`"),
    "",
    "## Artifacts",
    "",
    (.artifact_paths | to_entries[] | "- `" + .key + "`: `" + .value + "`")
  ' "$receipt_json" >"$report_md"
}

run_check() {
  bash -n "$normalizer" "$planner" "$operator_status" "$truth_gate" "${BASH_SOURCE[0]}"
  jq empty "$contract_path"
  grep -Fq 'scripts/swarm_resource_envelope_normalizer.sh' "$docs_path"
  grep -Fq 'scripts/swarm_fair_share_batch_planner.sh' "$docs_path"
  grep -Fq 'scripts/swarm_operator_status_report.sh' "$docs_path"
  grep -Fq 'scripts/e2e/swarm_resource_envelope_no_mock_drill.sh' "$docs_path"
  grep -Fq 'scripts/e2e/swarm_resource_envelope_runbook_truth_gate.sh' "$docs_path"
  jq -e '
    .no_mock_drill.script == "scripts/e2e/swarm_resource_envelope_no_mock_drill.sh"
    and .no_mock_drill.truth_gate_script == "scripts/e2e/swarm_resource_envelope_runbook_truth_gate.sh"
    and (.no_mock_drill.required_artifacts | index("swarm_resource_envelope_receipt.json") != null)
    and (.mutation_policy.runs_cargo == false)
    and (.mutation_policy.runs_rch == false)
  ' "$contract_path" >/dev/null
  record_pass "syntax docs and contract"
}

run_drill() {
  local case_id

  ensure_run_dir
  printf './scripts/e2e/swarm_resource_envelope_no_mock_drill.sh %q --output-dir %q\n' "$mode" "$run_dir" >"$commands_path"
  for case_id in "${cases[@]}"; do
    run_case "$case_id"
  done
  write_receipt
  jq -e '.decision == "pass"' "$receipt_json" >/dev/null || exit 42
  printf 'swarm_resource_envelope_no_mock_drill_receipt=%s\n' "$receipt_json"
}

run_selftest() {
  local tmp_root receipt

  run_check
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/franken-engine-resource-envelope-drill.XXXXXX")"
  "${BASH_SOURCE[0]}" run --output-dir "$tmp_root" >/dev/null
  receipt="${tmp_root}/swarm_resource_envelope_receipt.json"
  jq -e '
    .decision == "pass"
    and .case_count == 6
    and .passed_count == 6
    and .failed_count == 0
    and all(.required_coverage[]; . == true)
    and .mutation_policy.fixture_fed_only == true
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_br == false
    and any(.cases[]; .case_id == "healthy_high_core_host" and .actual.envelope_decision == "pass" and .actual.fair_share_decision == "admit")
    and any(.cases[]; .case_id == "missing_optional_host_telemetry" and .actual.envelope_decision == "degraded")
    and any(.cases[]; .case_id == "blocked_saturated_capacity" and .actual.envelope_decision == "blocked" and .actual.fair_share_decision == "defer")
    and any(.cases[]; .case_id == "contaminated_local_rch_fallback" and .actual.envelope_decision == "fail_closed" and .actual.fair_share_decision == "fail_closed")
    and any(.cases[]; .case_id == "contradictory_slot_or_memory_evidence" and .actual.envelope_decision == "fail_closed")
    and any(.cases[]; .case_id == "unsafe_mutation_wording" and .actual.envelope_decision == "fail_closed")
  ' "$receipt" >/dev/null
  find "$tmp_root" -type f -name '*.json' -print0 | xargs -0 -n1 jq empty >/dev/null
  "$truth_gate" check >/dev/null
  record_pass "selftest composed producers and receipt"
  printf 'swarm_resource_envelope_no_mock_drill_artifacts=%s\n' "$tmp_root"
}

case "$mode" in
  check)
    run_check
    ;;
  run)
    run_drill
    ;;
  selftest)
    run_selftest
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
