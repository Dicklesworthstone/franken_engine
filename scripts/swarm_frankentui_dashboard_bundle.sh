#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_FRANKENTUI_DASHBOARD_BUNDLE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-frankentui-dashboard-bundle}"
run_id="${SWARM_FRANKENTUI_DASHBOARD_BUNDLE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_FRANKENTUI_DASHBOARD_BUNDLE_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

source_revision="${SWARM_FRANKENTUI_DASHBOARD_BUNDLE_SOURCE_REVISION:-}"
resource_envelope_json=""
admission_budget_plan_json=""
stale_recovery_receipts_json=""
worker_truth_report_json=""
proof_cache_locality_plan_json=""
rch_rehabilitation_ledger_json=""
snapshot_bundle_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_frankentui_dashboard_bundle.sh [OPTIONS]

Builds a frankentui-compatible operator dashboard data bundle for the SWARM-OPS
plane. This script is an adapter only: it does not render a TUI, query live
systems, run Cargo/RCH, mutate beads, release reservations, or change workers.

Required inputs:
  --resource-envelope-json FILE
  --admission-budget-plan-json FILE
  --stale-recovery-receipts-json FILE
  --worker-truth-report-json FILE
  --proof-cache-locality-plan-json FILE
  --rch-rehabilitation-ledger-json FILE

Other options:
  --source-revision REV
  --output-dir DIR
  --snapshot-bundle-json FILE  Optional live read-only snapshot bundle from scripts/swarm_live_readonly_snapshot_bundle.sh

Artifacts:
  dashboard_bundle.json
  dashboard_events.ndjson
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  dashboard bundle emitted; decision may be pass or degraded
  42 fail-closed evidence prevents trusted rendering
  64 invalid option or malformed input
  75 trusted evidence is blocked
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --resource-envelope-json)
      resource_envelope_json="${2:-}"
      shift 2
      ;;
    --admission-budget-plan-json)
      admission_budget_plan_json="${2:-}"
      shift 2
      ;;
    --stale-recovery-receipts-json)
      stale_recovery_receipts_json="${2:-}"
      shift 2
      ;;
    --worker-truth-report-json)
      worker_truth_report_json="${2:-}"
      shift 2
      ;;
    --proof-cache-locality-plan-json)
      proof_cache_locality_plan_json="${2:-}"
      shift 2
      ;;
    --rch-rehabilitation-ledger-json)
      rch_rehabilitation_ledger_json="${2:-}"
      shift 2
      ;;
    --snapshot-bundle-json)
      snapshot_bundle_json="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    --output-dir)
      run_dir="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

if [[ -z "$resource_envelope_json" || -z "$admission_budget_plan_json" || -z "$stale_recovery_receipts_json" || -z "$worker_truth_report_json" || -z "$proof_cache_locality_plan_json" || -z "$rch_rehabilitation_ledger_json" ]]; then
  printf 'frankentui dashboard bundle requires all input JSON files\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for the frankentui dashboard bundle\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for the frankentui dashboard bundle\n' >&2
  exit 2
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
bundle_path="${run_dir}/dashboard_bundle.json"
bundle_core_path="${run_dir}/dashboard_bundle.core.json"
bundle_tmp="${bundle_path}.tmp"
dashboard_events_path="${run_dir}/dashboard_events.ndjson"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"

resource_normalized="${run_dir}/resource_envelope.normalized.json"
admission_normalized="${run_dir}/admission_budget_plan.normalized.json"
stale_normalized="${run_dir}/stale_recovery_receipts.normalized.json"
worker_normalized="${run_dir}/worker_truth_report.normalized.json"
locality_normalized="${run_dir}/proof_cache_locality_plan.normalized.json"
rehab_normalized="${run_dir}/rch_rehabilitation_ledger.normalized.json"
snapshot_normalized="${run_dir}/snapshot_bundle.normalized.json"

: >"$events_path"
: >"$dashboard_events_path"
printf './scripts/swarm_frankentui_dashboard_bundle.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-frankentui-dashboard-bundle.event.v1" \
    --arg component "swarm_frankentui_dashboard_bundle" \
    --arg event "$1" \
    --arg outcome "$2" \
    --arg detail "$3" \
    --arg evidence_path "$4" \
    '{schema_version:$schema_version,component:$component,event:$event,outcome:$outcome,detail:$detail,evidence_path:$evidence_path}' \
    >>"$events_path"
}

normalize_required_json() {
  local input_path="$1"
  local output_path="$2"
  local label="$3"
  if [[ ! -f "$input_path" ]]; then
    printf 'frankentui dashboard bundle missing %s JSON: %s\n' "$label" "$input_path" >&2
    exit 64
  fi
  if ! jq empty "$input_path" >/dev/null 2>&1; then
    printf 'frankentui dashboard bundle invalid %s JSON: %s\n' "$label" "$input_path" >&2
    exit 64
  fi
  jq -cS . "$input_path" >"$output_path"
  write_event "input.loaded" "ok" "$label" "$input_path"
}

normalize_required_json "$resource_envelope_json" "$resource_normalized" "resource envelope"
normalize_required_json "$admission_budget_plan_json" "$admission_normalized" "admission budget plan"
normalize_required_json "$stale_recovery_receipts_json" "$stale_normalized" "stale recovery receipts"
normalize_required_json "$worker_truth_report_json" "$worker_normalized" "worker truth report"
normalize_required_json "$proof_cache_locality_plan_json" "$locality_normalized" "proof-cache locality plan"
normalize_required_json "$rch_rehabilitation_ledger_json" "$rehab_normalized" "RCH rehabilitation ledger"
snapshot_bundle_status="missing"
if [[ -n "$snapshot_bundle_json" ]]; then
  normalize_required_json "$snapshot_bundle_json" "$snapshot_normalized" "live read-only snapshot bundle"
  snapshot_bundle_status="provided"
else
  jq -cS -n '{
    schema_version:"franken-engine.swarm-live-readonly-capture-bundle.v1",
    decision:"missing",
    fail_closed_reasons:[],
    blocked_reasons:[],
    degraded_reasons:["missing_live_readonly_snapshot"],
    sources:[],
    non_mutation_attestation:{
      fixture_fed_only:true,
      advisory_only:true,
      mutates_br:false,
      sends_agent_mail:false,
      queries_live_agent_mail:false,
      runs_cargo:false,
      runs_rch_exec:false,
      mutates_remote_workers:false
    },
    swarm_ops_state_bundle:{
      schema_version:"franken-engine.swarm-ops-state-bundle.v1",
      decision:"missing",
      source_components:[]
    },
    artifact_paths:{}
  }' >"$snapshot_normalized"
fi

jq -n \
  --slurpfile resource "$resource_normalized" \
  --slurpfile admission "$admission_normalized" \
  --slurpfile stale "$stale_normalized" \
  --slurpfile worker "$worker_normalized" \
  --slurpfile locality "$locality_normalized" \
  --slurpfile rehab "$rehab_normalized" \
  --slurpfile snapshot "$snapshot_normalized" \
  --arg schema_version "franken-engine.swarm-frankentui-dashboard-bundle.v1" \
  --arg dashboard_event_schema_version "franken-engine.swarm-frankentui-dashboard-event.v1" \
  --arg source_revision "$source_revision" \
  --arg resource_envelope_json "$resource_envelope_json" \
  --arg admission_budget_plan_json "$admission_budget_plan_json" \
  --arg stale_recovery_receipts_json "$stale_recovery_receipts_json" \
  --arg worker_truth_report_json "$worker_truth_report_json" \
  --arg proof_cache_locality_plan_json "$proof_cache_locality_plan_json" \
  --arg rch_rehabilitation_ledger_json "$rch_rehabilitation_ledger_json" \
  --arg snapshot_bundle_json "$snapshot_bundle_json" \
  --arg snapshot_bundle_status "$snapshot_bundle_status" \
  --arg bundle_path "$bundle_path" \
  --arg dashboard_events_path "$dashboard_events_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" '
  def low($value): (($value // "") | tostring | ascii_downcase);
  def arr($value): if ($value | type) == "array" then $value else [] end;
  def present($value): (($value // "") | tostring | length) > 0;
  def source_bad($doc; $schema):
    (($doc.schema_version // "") != $schema);
  def display_from_decision($decision):
    (low($decision)) as $d
    | if $d == "fail_closed" or $d == "contaminated" then "fail_closed"
      elif $d == "blocked" then "blocked"
      elif $d == "missing" then "missing"
      elif $d == "stale" then "stale"
      elif $d == "degraded" then "degraded"
      else "healthy" end;
  def severity_rank($state):
    if $state == "fail_closed" then 5
    elif $state == "blocked" then 4
    elif $state == "missing" then 3
    elif $state == "stale" then 3
    elif $state == "degraded" then 2
    else 1 end;
  def summary_number($doc; $path; $fallback):
    ($doc | getpath($path) // $fallback // 0) | tonumber;
  def reason($code; $source; $detail): {code:$code,source_id:$source,detail:$detail};
  def panel($id; $title; $state; $theme; $summary; $metrics; $rows; $reasons):
    {
      panel_id:$id,
      title:$title,
      display_state:$state,
      semantic_theme_token:$theme,
      focus_order:0,
      aria_label:($title + " panel, state " + $state),
      supports_tiny_layout:true,
      summary:$summary,
      metrics:$metrics,
      rows:$rows,
      visible_reasons:$reasons
    };

  ($resource[0]) as $resource_doc
  | ($admission[0]) as $admission_doc
  | ($stale[0]) as $stale_doc
  | ($worker[0]) as $worker_doc
  | ($locality[0]) as $locality_doc
  | ($rehab[0]) as $rehab_doc
  | ($snapshot[0]) as $snapshot_doc
  | (arr($admission_doc.recommendations)
      | map(select((low(.decision) | IN("admit", "admitted", "admit_narrow", "admitted_narrow", "pass"))))) as $admitted_rows
  | (arr($admission_doc.recommendations)
      | map(select((low(.decision) | IN("defer", "deferred", "blocked", "reject"))))) as $deferred_rows
  | (arr($stale_doc.recovery_receipts)) as $stale_receipts
  | (arr($worker_doc.worker_rows)) as $worker_rows
  | (arr($locality_doc.recommendations)) as $locality_recommendations
  | (arr($rehab_doc.workers) + arr($rehab_doc.worker_receipts) + arr($rehab_doc.rehabilitation_receipts) + arr($rehab_doc.receipts)) as $rehab_receipts
  | ($worker_rows | map(select((.drained // false) == true or (low(.daemon_status // .status // .worker_state) | contains("drain"))))) as $drained_workers
  | (
      {
        artifact_status:$snapshot_bundle_status,
        decision:($snapshot_doc.decision // "missing"),
        freshness_state:(
          if $snapshot_bundle_status == "missing" then "missing"
          elif any($snapshot_doc.sources[]?; (.freshness_state // "") == "stale") then "stale"
          elif any($snapshot_doc.sources[]?; (.freshness_state // "") == "missing") then "missing"
          else "fresh" end
        ),
        source_count:(arr($snapshot_doc.sources) | length),
        source_components:(arr($snapshot_doc.sources) | map({component, trust_state, freshness_state, local_fallback_observed:(.local_fallback_observed // false), error_code})),
        fail_closed_reasons:($snapshot_doc.fail_closed_reasons // []),
        blocked_reasons:($snapshot_doc.blocked_reasons // []),
        degraded_reasons:($snapshot_doc.degraded_reasons // []),
        local_fallback_observed:any($snapshot_doc.sources[]?; (.local_fallback_observed // false) == true),
        artifact_paths:($snapshot_doc.artifact_paths // {}),
        mutation_policy:($snapshot_doc.non_mutation_attestation // {})
      }
    ) as $snapshot_summary
  | ([
      if source_bad($resource_doc; "franken-engine.swarm-resource-envelope.v1") then reason("bad_schema"; "resource_envelope_json"; "resource envelope schema is unexpected") else empty end,
      if source_bad($admission_doc; "franken-engine.swarm-admission-budget-plan.v1") then reason("bad_schema"; "admission_budget_plan_json"; "admission budget schema is unexpected") else empty end,
      if source_bad($stale_doc; "franken-engine.swarm-ops-stale-recovery-receipts.v1") then reason("bad_schema"; "stale_recovery_receipts_json"; "stale recovery schema is unexpected") else empty end,
      if source_bad($worker_doc; "franken-engine.rch-worker-truth-parity-report.v1") then reason("bad_schema"; "worker_truth_report_json"; "worker truth schema is unexpected") else empty end,
      if source_bad($locality_doc; "franken-engine.swarm-proof-cache-locality-plan.v1") then reason("bad_schema"; "proof_cache_locality_plan_json"; "proof-cache locality schema is unexpected") else empty end,
      if source_bad($rehab_doc; "franken-engine.swarm-rch-stall-rehabilitation-ledger.v1") then reason("bad_schema"; "rch_rehabilitation_ledger_json"; "RCH rehabilitation schema is unexpected") else empty end,
      if $snapshot_bundle_status == "provided" and source_bad($snapshot_doc; "franken-engine.swarm-live-readonly-capture-bundle.v1") then reason("bad_schema"; "snapshot_bundle_json"; "live read-only snapshot schema is unexpected") else empty end,
      if (($resource_doc.mutation_policy.runs_cargo // false) == true) or (($resource_doc.mutation_policy.runs_rch // false) == true) or (($resource_doc.mutation_policy.mutates_remote_workers // false) == true) then reason("unsafe_mutation_policy"; "resource_envelope_json"; "resource envelope claims live mutation authority") else empty end,
      if (($locality_doc.mutation_policy.runs_cargo // false) == true) or (($locality_doc.mutation_policy.runs_rch // false) == true) or (($locality_doc.mutation_policy.mutates_remote_workers // false) == true) then reason("unsafe_mutation_policy"; "proof_cache_locality_plan_json"; "proof-cache locality plan claims live mutation authority") else empty end,
      if $snapshot_bundle_status == "provided" and ((($snapshot_summary.mutation_policy.mutates_br // false) == true) or (($snapshot_summary.mutation_policy.sends_agent_mail // false) == true) or (($snapshot_summary.mutation_policy.queries_live_agent_mail // false) == true) or (($snapshot_summary.mutation_policy.runs_cargo // false) == true) or (($snapshot_summary.mutation_policy.runs_rch_exec // false) == true) or (($snapshot_summary.mutation_policy.mutates_remote_workers // false) == true)) then reason("unsafe_mutation_policy"; "snapshot_bundle_json"; "live read-only snapshot claims mutation authority") else empty end,
      if (($stale_doc.decision // "") == "fail_closed") then reason("stale_recovery_fail_closed"; "stale_recovery_receipts_json"; "stale ownership recovery evidence failed closed") else empty end,
      if (($worker_doc.decision // "") == "fail_closed") then reason("worker_truth_fail_closed"; "worker_truth_report_json"; "RCH worker truth evidence failed closed") else empty end,
      if (($locality_doc.decision // "") == "fail_closed") then reason("proof_cache_locality_fail_closed"; "proof_cache_locality_plan_json"; "proof-cache locality evidence failed closed") else empty end,
      if (($rehab_doc.decision // "") == "fail_closed") then reason("rch_rehabilitation_fail_closed"; "rch_rehabilitation_ledger_json"; "RCH rehabilitation evidence failed closed") else empty end,
      if $snapshot_bundle_status == "provided" and (($snapshot_doc.decision // "") == "fail_closed") then reason("live_snapshot_fail_closed"; "snapshot_bundle_json"; "live read-only snapshot evidence failed closed") else empty end
    ] | unique_by([.code, .source_id, .detail])) as $fail_closed_reasons
  | ([
      if (low($resource_doc.decision) == "blocked") or (low($resource_doc.readiness) == "blocked") then reason("capacity_blocked"; "resource_envelope_json"; "resource envelope reports saturated capacity") else empty end,
      if (low($stale_doc.decision) == "blocked") then reason("active_owner_blocked"; "stale_recovery_receipts_json"; "stale ownership policy reports an active owner or reservation") else empty end,
      if (low($locality_doc.decision) == "blocked") then reason("proof_cache_locality_blocked"; "proof_cache_locality_plan_json"; "proof-cache locality evidence is blocked") else empty end,
      if (low($rehab_doc.decision) == "blocked") then reason("rch_rehabilitation_blocked"; "rch_rehabilitation_ledger_json"; "RCH rehabilitation evidence is blocked") else empty end
    ] | unique_by([.code, .source_id, .detail])) as $blocked_reasons
  | ([
      if (($resource_doc.telemetry_status // $resource_doc.snapshot_status.telemetry // $resource_doc.snapshot_status.memory_pressure // "") == "missing") then reason("missing_capacity_telemetry"; "resource_envelope_json"; "capacity telemetry is missing and must be rendered visibly") else empty end,
      if (low($resource_doc.decision) == "degraded") or (low($resource_doc.readiness) == "degraded") then reason("capacity_degraded"; "resource_envelope_json"; "resource envelope is degraded") else empty end,
      if (low($admission_doc.decision) | IN("defer", "deferred", "degraded")) or (($deferred_rows | length) > 0) then reason("lanes_deferred"; "admission_budget_plan_json"; "one or more admission lanes are deferred") else empty end,
      if (low($stale_doc.decision) == "degraded") or (summary_number($stale_doc; ["summary","needs_contact"]; 0) > 0) then reason("stale_owner_needs_contact"; "stale_recovery_receipts_json"; "stale owner evidence requires contact") else empty end,
      if (($stale_doc.snapshot_status.mail_activity // "") == "missing") or (($stale_doc.snapshot_status.file_reservations // "") == "missing") then reason("missing_ownership_telemetry"; "stale_recovery_receipts_json"; "ownership telemetry is missing") else empty end,
      if (($drained_workers | length) > 0) then reason("rch_worker_drained"; "worker_truth_report_json"; "at least one RCH worker is drained") else empty end,
      if (low($rehab_doc.decision) == "degraded") then reason("rch_rehabilitation_degraded"; "rch_rehabilitation_ledger_json"; "RCH rehabilitation ledger is degraded") else empty end,
      if (low($locality_doc.decision) == "degraded") then reason("proof_cache_locality_degraded"; "proof_cache_locality_plan_json"; "proof-cache locality plan is degraded") else empty end
      ,
      if $snapshot_bundle_status == "provided" and (low($snapshot_doc.decision) == "degraded") then reason("live_snapshot_degraded"; "snapshot_bundle_json"; "live read-only snapshot contains degraded source evidence") else empty end
    ] | unique_by([.code, .source_id, .detail])) as $degraded_reasons
  | (
      if ($fail_closed_reasons | length) > 0 then "fail_closed"
      elif ($blocked_reasons | length) > 0 then "blocked"
      elif ($degraded_reasons | length) > 0 then "degraded"
      else "pass" end
    ) as $decision
  | (
      if any($degraded_reasons[]?; .code == "missing_capacity_telemetry") then "missing"
      elif any($blocked_reasons[]?; .code == "capacity_blocked") then "blocked"
      elif any($degraded_reasons[]?; .source_id == "resource_envelope_json") then "degraded"
      else display_from_decision($resource_doc.decision // $resource_doc.readiness // "pass") end
    ) as $capacity_state
  | (
      if any($degraded_reasons[]?; .code == "lanes_deferred") then "degraded"
      else display_from_decision($admission_doc.decision // "pass") end
    ) as $admission_state
  | (
      if any($degraded_reasons[]?; .code == "missing_ownership_telemetry") then "missing"
      elif any($degraded_reasons[]?; .code == "stale_owner_needs_contact") then "stale"
      else display_from_decision($stale_doc.decision // "pass") end
    ) as $stale_state
  | (
      if any($fail_closed_reasons[]?; .source_id == "worker_truth_report_json" or .source_id == "rch_rehabilitation_ledger_json") then "fail_closed"
      elif any($blocked_reasons[]?; .source_id == "rch_rehabilitation_ledger_json") then "blocked"
      elif any($degraded_reasons[]?; .code == "rch_worker_drained" or .code == "rch_rehabilitation_degraded") then "degraded"
      else display_from_decision($worker_doc.decision // "pass") end
    ) as $rch_state
  | (display_from_decision($locality_doc.decision // "pass")) as $locality_state
  | (
      if $stale_state == "missing" then "missing"
      elif $stale_state == "stale" or $rch_state == "degraded" then "degraded"
      elif $stale_state == "blocked" or $rch_state == "blocked" then "blocked"
      elif $stale_state == "fail_closed" or $rch_state == "fail_closed" then "fail_closed"
      else "healthy" end
    ) as $recovery_state
  | [
      panel(
        "capacity";
        "Capacity";
        $capacity_state;
        (if $capacity_state == "healthy" then "success" elif $capacity_state == "missing" then "warning" elif $capacity_state == "blocked" then "danger" else "caution" end);
        {
          readiness: ($resource_doc.readiness // $resource_doc.decision // "unknown"),
          host_profile: ($resource_doc.host_profile // "unknown"),
          telemetry_status: ($resource_doc.telemetry_status // $resource_doc.snapshot_status.telemetry // $resource_doc.snapshot_status.memory_pressure // "provided")
        };
        {
          remote_rch_slots_available: ($resource_doc.rch_slots.available // $resource_doc.capacity_budget.remote_rch_slot_limit // null),
          memory_available_bytes: ($resource_doc.memory_pressure.available_bytes // null),
          target_dir_available_bytes: ($resource_doc.disk_pressure.target_dir_available_bytes // null)
        };
        [];
        ([$fail_closed_reasons[], $blocked_reasons[], $degraded_reasons[]] | map(select(.source_id == "resource_envelope_json")))
      ),
      panel(
        "admitted_lanes";
        "Admitted Lanes";
        $admission_state;
        (if $admission_state == "healthy" then "success" else "caution" end);
        {
          decision: ($admission_doc.decision // "unknown"),
          budget_profile: ($admission_doc.budget_profile // "unknown"),
          admitted_count: ($admitted_rows | length),
          deferred_count: ($deferred_rows | length)
        };
        {};
        (arr($admission_doc.recommendations) | map({
          bead_id:(.bead_id // .request_id // "unknown"),
          lane_class:(.lane_class // .budget_class // "unknown"),
          decision:(.decision // "unknown"),
          command:(.requested_command // .command // null)
        }));
        ([$fail_closed_reasons[], $blocked_reasons[], $degraded_reasons[]] | map(select(.source_id == "admission_budget_plan_json")))
      ),
      panel(
        "stale_ownership";
        "Stale Ownership";
        $stale_state;
        (if $stale_state == "healthy" then "success" elif $stale_state == "missing" or $stale_state == "stale" then "warning" else "danger" end);
        {
          decision: ($stale_doc.decision // "unknown"),
          healthy: summary_number($stale_doc; ["summary","healthy"]; 0),
          needs_contact: summary_number($stale_doc; ["summary","needs_contact"]; 0),
          safe_to_reopen: summary_number($stale_doc; ["summary","safe_to_reopen"]; 0),
          manual_review: summary_number($stale_doc; ["summary","manual_review"]; 0)
        };
        {};
        ($stale_receipts | map({
          bead_id,
          assignee,
          classification,
          reason_code,
          suggested_operator_commands:(.suggested_operator_commands // [])
        }));
        ([$fail_closed_reasons[], $blocked_reasons[], $degraded_reasons[]] | map(select(.source_id == "stale_recovery_receipts_json")))
      ),
      panel(
        "rch_workers";
        "RCH Workers";
        $rch_state;
        (if $rch_state == "healthy" then "success" elif $rch_state == "degraded" then "warning" else "danger" end);
        {
          worker_truth_decision: ($worker_doc.decision // "unknown"),
          rehabilitation_decision: ($rehab_doc.decision // "unknown"),
          worker_count: ($worker_rows | length),
          drained_worker_count: ($drained_workers | length),
          finding_count: (arr($worker_doc.findings) | length)
        };
        {};
        ($worker_rows | map({
          worker_id:(.worker_id // "unknown"),
          daemon_status:(.daemon_status // .status // "unknown"),
          probe_schedulable:(.probe_schedulable // .schedulable // null),
          queue_schedulable:(.queue_schedulable // null),
          drained: ((.drained // false) == true or (low(.daemon_status // .status // .worker_state) | contains("drain")))
        }));
        ([$fail_closed_reasons[], $blocked_reasons[], $degraded_reasons[]] | map(select(.source_id == "worker_truth_report_json" or .source_id == "rch_rehabilitation_ledger_json")))
      ),
      panel(
        "proof_cache_locality";
        "Proof Cache Locality";
        $locality_state;
        (if $locality_state == "healthy" then "success" elif $locality_state == "degraded" then "warning" else "danger" end);
        {
          decision: ($locality_doc.decision // "unknown"),
          target_dir: ($locality_doc.target_dir // null),
          worker_id: ($locality_doc.worker_id // null),
          recommendation_count: ($locality_recommendations | length)
        };
        {
          cache_hit_count: ($locality_doc.proof_cache_summary.cache_hit_count // null),
          refresh_count: ($locality_doc.proof_cache_summary.refresh_count // null)
        };
        ($locality_recommendations | map({
          recommendation_id,
          action,
          target_dir,
          worker_id,
          confidence,
          manual_confirmation_required
        }));
        ([$fail_closed_reasons[], $blocked_reasons[], $degraded_reasons[]] | map(select(.source_id == "proof_cache_locality_plan_json")))
      ),
      panel(
        "recovery_receipts";
        "Recovery Receipts";
        $recovery_state;
        (if $recovery_state == "healthy" then "success" elif $recovery_state == "degraded" or $recovery_state == "missing" then "warning" else "danger" end);
        {
          stale_recovery_decision: ($stale_doc.decision // "unknown"),
          rch_rehabilitation_decision: ($rehab_doc.decision // "unknown"),
          stale_receipt_count: ($stale_receipts | length),
          rch_receipt_count: ($rehab_receipts | length)
        };
        {};
        {
          stale_recovery_receipts: ($stale_receipts | map({bead_id, classification, reason_code})),
          rch_rehabilitation_receipts: $rehab_receipts
        };
        ([$fail_closed_reasons[], $blocked_reasons[], $degraded_reasons[]] | map(select(.source_id == "stale_recovery_receipts_json" or .source_id == "rch_rehabilitation_ledger_json")))
      )
    ] as $panels
  | ($panels | map(.display_state)) as $panel_states
  | {
      schema_version:$schema_version,
      bead_id:"bd-wql3k",
      source_revision:$source_revision,
      decision:$decision,
      renderer_contract:{
        provider:"/dp/frankentui",
        shipped_in_franken_engine:false,
        local_renderer:false,
        no_local_tui_runtime:true,
        handoff_note:"franken_engine emits data adapters and fixtures only; /dp/frankentui owns any rich interactive renderer."
      },
      frankentui_compatibility:{
        global_shell_slot:"swarm_ops",
        status_bar:true,
        semantic_theme_tokens:["success","caution","warning","danger","muted"],
        focus_order:["capacity","admitted_lanes","stale_ownership","rch_workers","proof_cache_locality","recovery_receipts"],
        tiny_layout_order:["capacity","rch_workers","stale_ownership","proof_cache_locality","admitted_lanes","recovery_receipts"],
        requires_one_writer_runtime:false,
        requires_tui_runtime_in_this_repo:false
      },
      display_state_policy:{
        allowed:["healthy","degraded","missing","stale","blocked","fail_closed"],
        missing_telemetry_visible:true,
        stale_evidence_visible:true,
        drained_workers_visible:true,
        hidden_panel_policy:"reject_bundle"
      },
      status_bar:{
        title:"SWARM-OPS",
        state:(if $decision == "pass" then "healthy" else $decision end),
        summary:({
          panel_count:($panels | length),
          degraded_panel_count:($panel_states | map(select(. == "degraded" or . == "missing" or . == "stale")) | length),
          blocked_panel_count:($panel_states | map(select(. == "blocked" or . == "fail_closed")) | length),
          admitted_lane_count:($admitted_rows | length),
          drained_worker_count:($drained_workers | length)
        })
      },
      panels:($panels | to_entries | map(.value + {focus_order:(.key + 1), live_readonly_snapshot:$snapshot_summary})),
      source_freshness:{
        live_readonly_snapshot:$snapshot_summary
      },
      fail_closed_reasons:$fail_closed_reasons,
      blocked_reasons:$blocked_reasons,
      degraded_reasons:$degraded_reasons,
      mutation_policy:{
        fixture_fed_only:true,
        adapter_only:true,
        advisory_only:true,
        renders_tui:false,
        mutates_br:false,
        releases_reservations:false,
        sends_agent_mail:false,
        queries_live_agent_mail:false,
        runs_cargo:false,
        runs_rch:false,
        mutates_remote_workers:false,
        changes_live_queue_policy:false,
        writes_outside_output_dir:false
      },
      source_artifacts:{
        resource_envelope_json:$resource_envelope_json,
        admission_budget_plan_json:$admission_budget_plan_json,
        stale_recovery_receipts_json:$stale_recovery_receipts_json,
        worker_truth_report_json:$worker_truth_report_json,
        proof_cache_locality_plan_json:$proof_cache_locality_plan_json,
        rch_rehabilitation_ledger_json:$rch_rehabilitation_ledger_json,
        snapshot_bundle_json:(if $snapshot_bundle_status == "provided" then $snapshot_bundle_json else null end)
      },
      artifact_paths:{
        dashboard_bundle_json:$bundle_path,
        dashboard_events_ndjson:$dashboard_events_path,
        events_jsonl:$events_path,
        commands_txt:$commands_path,
        report_md:$report_path
      }
    }' >"$bundle_core_path"

bundle_hash="$(jq -cS 'del(.artifact_paths)' "$bundle_core_path" | sha256sum | awk '{print $1}')"
bundle_id="swarm-frankentui-dashboard-${bundle_hash:0:16}"
jq --arg bundle_id "$bundle_id" --arg bundle_hash "$bundle_hash" \
  '. + {bundle_id:$bundle_id, hash_basis:{bundle_hash:$bundle_hash}}' \
  "$bundle_core_path" >"$bundle_tmp"
mv "$bundle_tmp" "$bundle_path"

jq -c --arg schema_version "franken-engine.swarm-frankentui-dashboard-event.v1" '
  .panels[]
  | {
      schema_version:$schema_version,
      component:"swarm_frankentui_dashboard_bundle",
      event:"panel_emitted",
      panel_id,
      display_state,
      semantic_theme_token,
      evidence_path:("dashboard_bundle.json#panels/" + .panel_id)
    }
' "$bundle_path" >>"$dashboard_events_path"

decision="$(jq -r '.decision' "$bundle_path")"
write_event "dashboard_bundle.emitted" "$decision" "emitted frankentui-compatible dashboard bundle" "$bundle_path"

{
  printf '# Swarm FrankenTUI Dashboard Bundle\n\n'
  printf -- "- Decision: \`%s\`\n" "$decision"
  printf -- "- Bundle: \`%s\`\n" "$bundle_path"
  printf -- "- Renderer provider: \`%s\`\n" "$(jq -r '.renderer_contract.provider' "$bundle_path")"
  printf -- "- Local renderer: \`%s\`\n" "$(jq -r '.renderer_contract.local_renderer' "$bundle_path")"
  printf -- "- Panels: \`%s\`\n\n" "$(jq '.panels | length' "$bundle_path")"
  printf '## Panel States\n'
  jq -r '.panels[] | "- `" + .panel_id + "` `" + .display_state + "` `" + .semantic_theme_token + "`"' "$bundle_path"
  printf '\n'
  if [[ "$(jq '.degraded_reasons | length' "$bundle_path")" -gt 0 ]]; then
    printf '## Degraded Reasons\n'
    jq -r '.degraded_reasons[] | "- `" + .code + "` `" + .source_id + "`: " + .detail' "$bundle_path"
    printf '\n'
  fi
} >"$report_path"

printf 'dashboard_bundle_json=%s\n' "$bundle_path"
printf 'dashboard_events_ndjson=%s\n' "$dashboard_events_path"
printf 'dashboard_report_md=%s\n' "$report_path"

case "$decision" in
  fail_closed)
    exit 42
    ;;
  blocked)
    exit 75
    ;;
  *)
    exit 0
    ;;
esac
