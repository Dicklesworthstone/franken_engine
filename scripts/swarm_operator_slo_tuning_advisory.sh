#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_OPERATOR_SLO_TUNING_ADVISORY_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-operator-slo-tuning-advisory}"
run_id="${SWARM_OPERATOR_SLO_TUNING_ADVISORY_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_OPERATOR_SLO_TUNING_ADVISORY_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

threshold_receipt_json=""
capacity_forecast_json=""
admission_budget_plan_json=""
lease_exchange_salvage_simulation_json=""
warm_target_prefetch_roi_advisory_json=""
chaos_conformance_report_json=""
source_revision=""
now_epoch_seconds="$(date -u +%s)"
stale_after_seconds="1800"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_operator_slo_tuning_advisory.sh [OPTIONS]

Builds a deterministic, advisory-only SWARM-CTRL-IX operator SLO tuning handoff.
The advisory composes the reviewed threshold receipt, capacity forecast, chaos
conformance report, admission budget plan, lease exchange / salvage simulation,
and warm-target ROI advisory into bounded operator recommendations.

Required:
  --threshold-receipt-json FILE
  --capacity-forecast-json FILE
  --admission-budget-plan-json FILE
  --lease-exchange-salvage-simulation-json FILE
  --warm-target-prefetch-roi-advisory-json FILE
  --chaos-conformance-report-json FILE

Optional:
  --source-revision REV
  --now-epoch-seconds N
  --stale-after-seconds N
  --output-dir DIR

Artifacts:
  swarm_operator_slo_tuning_advisory.json
  report.md
  commands.txt
  events.jsonl

Exit codes:
  0  advisory emitted without fail-closed gate findings
  42 fail-closed because evidence links are missing, unsupported SLO claims
     appeared, the forecast reference is stale, or upstream reviewed artifacts
     are already fail-closed
  64 invalid or missing input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --threshold-receipt-json)
      threshold_receipt_json="${2:-}"
      shift 2
      ;;
    --capacity-forecast-json)
      capacity_forecast_json="${2:-}"
      shift 2
      ;;
    --admission-budget-plan-json)
      admission_budget_plan_json="${2:-}"
      shift 2
      ;;
    --lease-exchange-salvage-simulation-json)
      lease_exchange_salvage_simulation_json="${2:-}"
      shift 2
      ;;
    --warm-target-prefetch-roi-advisory-json)
      warm_target_prefetch_roi_advisory_json="${2:-}"
      shift 2
      ;;
    --chaos-conformance-report-json)
      chaos_conformance_report_json="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    --now-epoch-seconds)
      now_epoch_seconds="${2:-}"
      shift 2
      ;;
    --stale-after-seconds)
      stale_after_seconds="${2:-}"
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
      printf 'unknown option: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

is_int() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

normalize_json() {
  local input_path="$1"
  local output_path="$2"
  local label="$3"

  if [[ -z "$input_path" ]]; then
    printf 'swarm operator SLO tuning advisory missing %s\n' "$label" >&2
    exit 64
  fi
  if [[ ! -f "$input_path" ]]; then
    printf 'swarm operator SLO tuning advisory missing %s JSON: %s\n' "$label" "$input_path" >&2
    exit 64
  fi
  if ! jq empty "$input_path" >/dev/null 2>&1; then
    printf 'swarm operator SLO tuning advisory invalid %s JSON: %s\n' "$label" "$input_path" >&2
    exit 64
  fi
  jq -c . "$input_path" >"$output_path"
}

if [[ -z "$threshold_receipt_json" || -z "$capacity_forecast_json" || -z "$admission_budget_plan_json" || -z "$lease_exchange_salvage_simulation_json" || -z "$warm_target_prefetch_roi_advisory_json" || -z "$chaos_conformance_report_json" ]]; then
  printf 'swarm operator SLO tuning advisory requires all reviewed child artifacts\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm operator SLO tuning advisory\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for swarm operator SLO tuning advisory\n' >&2
  exit 2
fi
if ! is_int "$now_epoch_seconds" || ! is_int "$stale_after_seconds"; then
  printf 'now/stale thresholds must be non-negative integers\n' >&2
  exit 64
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
advisory_path="${run_dir}/swarm_operator_slo_tuning_advisory.json"
advisory_tmp="${advisory_path}.tmp"
core_path="${run_dir}/swarm_operator_slo_tuning_advisory.core.json"
report_path="${run_dir}/report.md"
commands_path="${run_dir}/commands.txt"
events_path="${run_dir}/events.jsonl"
gate_failures_jsonl="${run_dir}/gate_failures.jsonl"

printf './scripts/swarm_operator_slo_tuning_advisory.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

threshold_normalized="${run_dir}/threshold_receipt.normalized.json"
forecast_normalized="${run_dir}/capacity_forecast.normalized.json"
admission_normalized="${run_dir}/admission_budget_plan.normalized.json"
salvage_normalized="${run_dir}/lease_exchange_salvage_simulation.normalized.json"
roi_normalized="${run_dir}/warm_target_prefetch_roi_advisory.normalized.json"
chaos_normalized="${run_dir}/chaos_conformance_report.normalized.json"

normalize_json "$threshold_receipt_json" "$threshold_normalized" "threshold receipt"
normalize_json "$capacity_forecast_json" "$forecast_normalized" "capacity forecast"
normalize_json "$admission_budget_plan_json" "$admission_normalized" "admission budget plan"
normalize_json "$lease_exchange_salvage_simulation_json" "$salvage_normalized" "lease exchange salvage simulation"
normalize_json "$warm_target_prefetch_roi_advisory_json" "$roi_normalized" "warm-target ROI advisory"
normalize_json "$chaos_conformance_report_json" "$chaos_normalized" "chaos conformance report"

if ! jq -e '.schema_version == "franken-engine.swarm-slo-threshold-receipt.v1"' "$threshold_normalized" >/dev/null 2>&1; then
  printf 'expected franken-engine.swarm-slo-threshold-receipt.v1\n' >&2
  exit 64
fi
if ! jq -e '.schema_version == "franken-engine.swarm-capacity-forecast.v1" and (.decision | type == "string") and (.generated_epoch_seconds | type == "number")' "$forecast_normalized" >/dev/null 2>&1; then
  printf 'capacity forecast shape mismatch for SLO tuning advisory\n' >&2
  exit 64
fi
if ! jq -e '.schema_version == "franken-engine.swarm-admission-budget-plan.v1" and (.decision | type == "string")' "$admission_normalized" >/dev/null 2>&1; then
  printf 'admission budget plan shape mismatch for SLO tuning advisory\n' >&2
  exit 64
fi
if ! jq -e '.schema_version == "franken-engine.swarm-lease-exchange-cancellation-salvage-simulation.v1" and (.decision | type == "string")' "$salvage_normalized" >/dev/null 2>&1; then
  printf 'lease exchange salvage simulation shape mismatch for SLO tuning advisory\n' >&2
  exit 64
fi
if ! jq -e '.schema_version == "franken-engine.swarm-warm-target-prefetch-roi-advisory.v1" and (.advisory | type == "string")' "$roi_normalized" >/dev/null 2>&1; then
  printf 'warm-target ROI advisory shape mismatch for SLO tuning advisory\n' >&2
  exit 64
fi
if ! jq -e '.schema_version == "franken-engine.swarm-high-core-chaos-conformance-report.v1" and (.decision | type == "string")' "$chaos_normalized" >/dev/null 2>&1; then
  printf 'chaos conformance report shape mismatch for SLO tuning advisory\n' >&2
  exit 64
fi

: >"$events_path"
: >"$gate_failures_jsonl"

append_gate_failure() {
  jq -nc \
    --arg code "$1" \
    --arg detail "$2" \
    '{code:$code, detail:$detail}' >>"$gate_failures_jsonl"
}

require_artifact_path() {
  local json_path="$1"
  local jq_expr="$2"
  local code="$3"
  local label="$4"
  local value
  value="$(jq -r "$jq_expr // empty" "$json_path")"
  if [[ -z "$value" || "$value" == "null" ]]; then
    append_gate_failure "$code" "$label is missing a deterministic evidence link"
  fi
}

supported_claims_json='[
  "queue_wait_budget_band",
  "validation_latency_band",
  "rch_fallback_rate_tolerance",
  "starvation_brownout_guardrails",
  "proof_cache_freshness_and_warm_target_roi",
  "archive_salvage_pressure_thresholds"
]'

while IFS= read -r unsupported_claim; do
  [[ -n "$unsupported_claim" ]] || continue
  append_gate_failure "unsupported_slo_claim" "threshold receipt carried unsupported claim ${unsupported_claim}"
done < <(
  jq -r --argjson supported "$supported_claims_json" '
    (.thresholds | keys[]) as $claim
    | select(($supported | index($claim)) | not)
    | $claim
  ' "$threshold_normalized"
)

while IFS= read -r unsupported_claim; do
  [[ -n "$unsupported_claim" ]] || continue
  append_gate_failure "unsupported_slo_claim" "chaos conformance report carried unsupported claim ${unsupported_claim}"
done < <(
  jq -r --argjson supported "$supported_claims_json" '
    (.rows // [])
    | map(.claim_id)
    | unique[]
    | select(($supported | index(.)) | not)
  ' "$chaos_normalized"
)

forecast_epoch="$(jq -r '.generated_epoch_seconds' "$forecast_normalized")"
forecast_age=$((now_epoch_seconds - forecast_epoch))
if (( forecast_age > stale_after_seconds )); then
  append_gate_failure "stale_forecast_reference" "capacity forecast age ${forecast_age}s exceeds ${stale_after_seconds}s"
fi

if [[ "$(jq -r '.decision' "$threshold_normalized")" == "fail_closed" ]]; then
  append_gate_failure "threshold_receipt_fail_closed" "threshold receipt is already fail-closed"
fi
if [[ "$(jq -r '.decision' "$chaos_normalized")" == "fail_closed" ]]; then
  append_gate_failure "chaos_conformance_fail_closed" "chaos conformance report is already fail-closed"
fi

require_artifact_path "$threshold_normalized" '.artifact_paths.swarm_slo_threshold_receipt_json' "missing_evidence_link" "threshold receipt"
require_artifact_path "$forecast_normalized" '.artifact_paths.swarm_capacity_forecast_json' "missing_evidence_link" "capacity forecast"
require_artifact_path "$admission_normalized" '.artifact_paths.swarm_admission_budget_plan_json' "missing_evidence_link" "admission budget plan"
require_artifact_path "$salvage_normalized" '.artifact_paths.swarm_lease_exchange_cancellation_salvage_simulation_json // .artifact_paths.lease_exchange_cancellation_salvage_simulation_json' "missing_evidence_link" "lease exchange salvage simulation"
require_artifact_path "$roi_normalized" '.artifact_paths.swarm_warm_target_prefetch_roi_advisory_json' "missing_evidence_link" "warm-target ROI advisory"
require_artifact_path "$chaos_normalized" '.artifact_paths.swarm_high_core_chaos_conformance_report_json' "missing_evidence_link" "chaos conformance report"

threshold_hash="$(jq -cS . "$threshold_normalized" | sha256sum | awk '{print $1}')"
forecast_hash="$(jq -cS . "$forecast_normalized" | sha256sum | awk '{print $1}')"
admission_hash="$(jq -cS . "$admission_normalized" | sha256sum | awk '{print $1}')"
salvage_hash="$(jq -cS . "$salvage_normalized" | sha256sum | awk '{print $1}')"
roi_hash="$(jq -cS . "$roi_normalized" | sha256sum | awk '{print $1}')"
chaos_hash="$(jq -cS . "$chaos_normalized" | sha256sum | awk '{print $1}')"

jq -n \
  --arg schema_version "franken-engine.swarm-operator-slo-tuning-advisory.v1" \
  --arg source_revision "$source_revision" \
  --argjson now_epoch_seconds "$now_epoch_seconds" \
  --argjson stale_after_seconds "$stale_after_seconds" \
  --arg threshold_input_path "$threshold_receipt_json" \
  --arg forecast_input_path "$capacity_forecast_json" \
  --arg admission_input_path "$admission_budget_plan_json" \
  --arg salvage_input_path "$lease_exchange_salvage_simulation_json" \
  --arg roi_input_path "$warm_target_prefetch_roi_advisory_json" \
  --arg chaos_input_path "$chaos_conformance_report_json" \
  --arg threshold_hash "$threshold_hash" \
  --arg forecast_hash "$forecast_hash" \
  --arg admission_hash "$admission_hash" \
  --arg salvage_hash "$salvage_hash" \
  --arg roi_hash "$roi_hash" \
  --arg chaos_hash "$chaos_hash" \
  --argjson supported_claims "$supported_claims_json" \
  --slurpfile threshold "$threshold_normalized" \
  --slurpfile forecast "$forecast_normalized" \
  --slurpfile admission "$admission_normalized" \
  --slurpfile salvage "$salvage_normalized" \
  --slurpfile roi "$roi_normalized" \
  --slurpfile chaos "$chaos_normalized" \
  --slurpfile gate_failures "$gate_failures_jsonl" \
  '
  def low($value): ($value // "" | tostring | ascii_downcase);
  def recommended($action; $state; $reason):
    {action:$action, state:$state, reason:$reason, advisory_only:true};
  ($threshold[0]) as $threshold |
  ($forecast[0]) as $forecast |
  ($admission[0]) as $admission |
  ($salvage[0]) as $salvage |
  ($roi[0]) as $roi |
  ($chaos[0]) as $chaos |
  ($gate_failures) as $gate_failures |
  (($threshold.thresholds // {}) | to_entries | map({
    claim_id:.key,
    status:(.value.status // "unknown"),
    confidence_class:(.value.confidence_class // "unknown"),
    current_band:(.value.current_band // "unknown"),
    reason:(.value.reason // "unknown")
  })) as $threshold_rows |
  ((($threshold.thresholds // {}) | keys) - $supported_claims) as $unsupported_threshold_claims |
  (((($chaos.rows // []) | map(.claim_id) | unique) - $supported_claims)) as $unsupported_chaos_claims |
  ((($unsupported_threshold_claims + $unsupported_chaos_claims) | unique | sort)) as $unsupported_claims |
  (
    [
      ($threshold.confidence_class // null),
      ($forecast.confidence_band // null),
      (($threshold_rows | map(.confidence_class))[]? // empty)
    ]
    | map(select(. != null))
  ) as $confidence_inputs |
  (
    if any($confidence_inputs[]?; . == "low") then "low"
    elif any($confidence_inputs[]?; . == "medium") then "medium"
    else "high"
    end
  ) as $confidence_band |
  (
    if ($gate_failures | length) > 0 then "fail_closed"
    elif (($threshold.summary.downgraded_threshold_count // 0) > 0)
      or (low($forecast.summary.overall_state) | test("degraded|brownout|blocked|contradictory"))
      or (low($admission.decision) | test("admit_narrow|defer|safe_mode"))
      or (low($salvage.decision) | test("manual|salvage"))
    then "degraded"
    else "reviewed"
    end
  ) as $evidence_quality |
  (low($forecast.summary.overall_state // "unknown")) as $overall_state |
  (low($admission.decision // "unknown")) as $admission_decision |
  (low($salvage.decision // "unknown")) as $salvage_decision |
  (low($salvage.upstream_summary.archive_pressure_advisory // "retain")) as $archive_pressure_advisory |
  (low($roi.advisory // "unknown")) as $roi_advisory |
  (low($roi.recommended_action // "")) as $roi_action |
  ([
    if $admission_decision == "admit" and $evidence_quality == "reviewed" then
      recommended("admit"; "recommended"; "admission budget and reviewed threshold evidence both allow full admission")
    else
      recommended("admit"; "hold"; "full admission is not the current bounded recommendation")
    end,
    if $admission_decision == "admit_narrow"
      or (($admission.recommendations // []) | any((.decision // "") == "admit_narrow"))
      or ($overall_state | test("degraded|brownout"))
    then
      recommended("narrow"; "recommended"; "narrow the validation scope because forecast or admission posture is constrained")
    else
      recommended("narrow"; "hold"; "narrowing is not required while reviewed evidence stays healthy")
    end,
    if $admission_decision == "defer" or ($overall_state | test("blocked|brownout|contradictory")) then
      recommended("defer"; "recommended"; "defer new heavy work until the forecast and admission posture recover")
    else
      recommended("defer"; "hold"; "defer is not currently required")
    end,
    if ($roi_advisory == "prefetch_recommended" or $roi_advisory == "reuse_hot_cache" or ($roi_action | test("warm|prefetch|retain_target"))) then
      recommended("prewarm"; "recommended"; "warm-target ROI supports prewarming before the next protected proof")
    else
      recommended("prewarm"; "hold"; "warm-target ROI does not justify prewarming")
    end,
    if ($archive_pressure_advisory | test("archive|cool|compact|evict")) then
      recommended("archive"; "recommended"; "archive pressure advisory is no longer retain-only")
    else
      recommended("archive"; "hold"; "archive pressure remains bounded and retain-only")
    end,
    if (($salvage.summary.salvage_promotion_candidate_count // 0) > 0 or ($salvage_decision | test("salvage"))) then
      recommended("salvage"; "recommended"; "salvage candidates are present and should be reviewed before canceling work")
    else
      recommended("salvage"; "hold"; "no salvage promotion is currently justified")
    end,
    if $evidence_quality != "reviewed" or $confidence_band == "low" or ($overall_state | test("brownout|contradictory|blocked")) then
      recommended("require_human_coordination"; "recommended"; "operators should coordinate manually because the advisory evidence is degraded or confidence-bounded")
    else
      recommended("require_human_coordination"; "hold"; "human coordination is not required while evidence remains reviewed and high confidence")
    end
  ]) as $recommended_actions |
  {
    schema_version: $schema_version,
    source_revision: $source_revision,
    generated_epoch_seconds: $now_epoch_seconds,
    stale_after_seconds: $stale_after_seconds,
    decision: (if ($gate_failures | length) > 0 then "fail_closed" else "pass" end),
    exit_code: (if ($gate_failures | length) > 0 then 42 else 0 end),
    evidence_quality: {
      decision: $evidence_quality,
      confidence_band: $confidence_band,
      reviewed_inputs: 6,
      accepted_threshold_count: ($threshold.summary.accepted_threshold_count // 0),
      downgraded_threshold_count: ($threshold.summary.downgraded_threshold_count // 0),
      rejected_threshold_count: ($threshold.summary.rejected_threshold_count // 0),
      overall_state: ($forecast.summary.overall_state // "unknown"),
      chaos_conformance_decision: ($chaos.decision // "unknown")
    },
    calibrated_thresholds: {
      receipt_id: ($threshold.receipt_id // null),
      accepted_threshold_count: ($threshold.summary.accepted_threshold_count // 0),
      downgraded_threshold_count: ($threshold.summary.downgraded_threshold_count // 0),
      rejected_threshold_count: ($threshold.summary.rejected_threshold_count // 0),
      thresholds: $threshold_rows
    },
    claim_support: {
      supported_claims: $supported_claims,
      unsupported_claims: $unsupported_claims,
      reviewed_claims: (($chaos.rows // []) | map(.claim_id) | unique | sort)
    },
    forecast_summary: {
      forecast_id: ($forecast.forecast_id // null),
      decision: ($forecast.decision // "unknown"),
      confidence_band: ($forecast.confidence_band // "unknown"),
      overall_state: ($forecast.summary.overall_state // "unknown"),
      blocked_categories: ($forecast.summary.blocked_categories // []),
      degraded_categories: ($forecast.summary.degraded_categories // [])
    },
    recommended_actions: $recommended_actions,
    dashboard_handoff: {
      future_section_path: "predictive_dashboard.slo_tuning_advisory",
      renderer_provider: "/dp/frankentui",
      shipped_in_franken_engine: false,
      local_renderer: false,
      producer_integration: false,
      contract_json: "docs/swarm_predictive_dashboard_contract_v1.json",
      handoff_note: "This standalone advisory is a future dashboard handoff only; scripts/swarm_operator_status_report.sh remains the only predictive dashboard producer in franken_engine."
    },
    evidence_links: [
      {
        input_id: "threshold_receipt_json",
        input_path: $threshold_input_path,
        artifact_path: ($threshold.artifact_paths.swarm_slo_threshold_receipt_json // null),
        schema_version: ($threshold.schema_version // null),
        hash: $threshold_hash
      },
      {
        input_id: "capacity_forecast_json",
        input_path: $forecast_input_path,
        artifact_path: ($forecast.artifact_paths.swarm_capacity_forecast_json // null),
        schema_version: ($forecast.schema_version // null),
        hash: $forecast_hash
      },
      {
        input_id: "admission_budget_plan_json",
        input_path: $admission_input_path,
        artifact_path: ($admission.artifact_paths.swarm_admission_budget_plan_json // null),
        schema_version: ($admission.schema_version // null),
        hash: $admission_hash
      },
      {
        input_id: "lease_exchange_salvage_simulation_json",
        input_path: $salvage_input_path,
        artifact_path: ($salvage.artifact_paths.swarm_lease_exchange_cancellation_salvage_simulation_json // $salvage.artifact_paths.lease_exchange_cancellation_salvage_simulation_json // null),
        schema_version: ($salvage.schema_version // null),
        hash: $salvage_hash
      },
      {
        input_id: "warm_target_prefetch_roi_advisory_json",
        input_path: $roi_input_path,
        artifact_path: ($roi.artifact_paths.swarm_warm_target_prefetch_roi_advisory_json // null),
        schema_version: ($roi.schema_version // null),
        hash: $roi_hash
      },
      {
        input_id: "chaos_conformance_report_json",
        input_path: $chaos_input_path,
        artifact_path: ($chaos.artifact_paths.swarm_high_core_chaos_conformance_report_json // null),
        schema_version: ($chaos.schema_version // null),
        hash: $chaos_hash
      }
    ],
    upstream_summary: {
      admission_decision: ($admission.decision // "unknown"),
      budget_profile: ($admission.budget_profile // "unknown"),
      lease_exchange_decision: ($salvage.decision // "unknown"),
      archive_pressure_advisory: ($salvage.upstream_summary.archive_pressure_advisory // "unknown"),
      roi_advisory: ($roi.advisory // "unknown"),
      roi_recommended_action: ($roi.recommended_action // "unknown")
    },
    gate_failures: $gate_failures,
    truth_notes: [
      "The advisory is report-only and does not mutate queue, lease, archive, or worker state.",
      "Any future rich dashboard for this advisory must be implemented through /dp/frankentui.",
      "scripts/swarm_operator_status_report.sh remains the only predictive dashboard producer in franken_engine."
    ]
  }
  ' >"$core_path"

advisory_hash="$(jq -cS . "$core_path" | sha256sum | awk '{print $1}')"
advisory_id="swarm-operator-slo-tuning-${advisory_hash:0:16}"

jq \
  --arg advisory_id "$advisory_id" \
  --arg advisory_hash "$advisory_hash" \
  --arg advisory_path "$advisory_path" \
  --arg report_path "$report_path" \
  --arg commands_path "$commands_path" \
  --arg events_path "$events_path" \
  '
  . + {
    advisory_id: $advisory_id,
    hash_basis: {
      advisory_hash: $advisory_hash
    },
    artifact_paths: {
      swarm_operator_slo_tuning_advisory_json: $advisory_path,
      report_md: $report_path,
      commands_txt: $commands_path,
      events_jsonl: $events_path
    }
  }
  ' "$core_path" >"$advisory_tmp"
mv "$advisory_tmp" "$advisory_path"

{
  jq -c --arg source_revision "$source_revision" '
    .recommended_actions[]
    | {
        schema_version: "franken-engine.swarm-operator-slo-tuning-advisory.event.v1",
        event_name: "operator_action_evaluated",
        action: .action,
        state: .state,
        reason: .reason,
        source_revision: $source_revision
      }
  ' "$advisory_path"

  jq -c --arg source_revision "$source_revision" '
    .gate_failures[]
    | {
        schema_version: "franken-engine.swarm-operator-slo-tuning-advisory.event.v1",
        event_name: "gate_failure_detected",
        action: "gate",
        state: "fail_closed",
        reason: (.code + ": " + .detail),
        source_revision: $source_revision
      }
  ' "$advisory_path"

  jq -c --arg source_revision "$source_revision" '
    {
      schema_version: "franken-engine.swarm-operator-slo-tuning-advisory.event.v1",
      event_name: "advisory_generated",
      action: "summary",
      state: .decision,
      reason: (
        if .decision == "fail_closed" then
          "reviewed child artifacts were stale, unsupported, or missing deterministic evidence links"
        else
          "operator SLO tuning advisory was emitted from reviewed child artifacts"
        end
      ),
      source_revision: $source_revision
    }
  ' "$advisory_path"
} >>"$events_path"

{
  printf '# Operator SLO Tuning Advisory\n\n'
  printf -- "- Advisory ID: \`%s\`\n" "$(jq -r '.advisory_id' "$advisory_path")"
  printf -- "- Decision: \`%s\`\n" "$(jq -r '.decision' "$advisory_path")"
  printf -- "- Evidence quality: \`%s\`\n" "$(jq -r '.evidence_quality.decision' "$advisory_path")"
  printf -- "- Confidence: \`%s\`\n" "$(jq -r '.evidence_quality.confidence_band' "$advisory_path")"
  printf -- "- Forecast state: \`%s\`\n" "$(jq -r '.forecast_summary.overall_state' "$advisory_path")"
  printf -- "- Dashboard handoff: \`%s\` via \`%s\`\n\n" \
    "$(jq -r '.dashboard_handoff.future_section_path' "$advisory_path")" \
    "$(jq -r '.dashboard_handoff.renderer_provider' "$advisory_path")"
  printf '## Recommended Actions\n\n'
  jq -r '
    .recommended_actions[]
    | "- `" + .action + "` `" + .state + "`: " + .reason
  ' "$advisory_path"
  printf '\n## Evidence Links\n\n'
  jq -r '
    .evidence_links[]
    | "- `" + .input_id + "` -> `" + (.artifact_path // .input_path) + "` (`" + .schema_version + "`)"
  ' "$advisory_path"
  if [[ "$(jq -r '.decision' "$advisory_path")" == "fail_closed" ]]; then
    printf '\n## Gate Failures\n\n'
    jq -r '
      .gate_failures[]
      | "- `" + .code + "`: " + .detail
    ' "$advisory_path"
  fi
} >"$report_path"

if [[ "$(jq -r '.decision' "$advisory_path")" == "fail_closed" ]]; then
  exit 42
fi
