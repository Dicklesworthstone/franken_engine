#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_HIGH_CORE_CHAOS_CONFORMANCE_GATE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-high-core-chaos-conformance-gate}"
run_id="${SWARM_HIGH_CORE_CHAOS_CONFORMANCE_GATE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_HIGH_CORE_CHAOS_CONFORMANCE_GATE_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

scenario_matrix_report_json=""
threshold_receipt_json=""
capacity_forecast_json=""
source_revision=""
now_epoch_seconds="$(date -u +%s)"
stale_after_seconds="1800"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_high_core_chaos_conformance_gate.sh --scenario-matrix-report-json FILE --threshold-receipt-json FILE --capacity-forecast-json FILE [OPTIONS]

Builds a deterministic SWARM-CTRL-IX conformance matrix that checks the
reviewed high-core scenario classes against the calibrated threshold receipt and
forecast freshness expectations. The gate is fixture-fed and report-only; it
does not execute cargo, mutate workers, or spawn new fault injection.

Required:
  --scenario-matrix-report-json FILE
  --threshold-receipt-json FILE
  --capacity-forecast-json FILE

Optional:
  --source-revision REV
  --now-epoch-seconds N
  --stale-after-seconds N
  --output-dir DIR

Artifacts:
  swarm_high_core_chaos_conformance_report.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  conformance report emitted without gate failures
  42 fail-closed due to missing evidence, bare cargo commands, stale forecast
     artifacts, unexpected local fallback traceability, or failing conformance
     rows
  64 invalid or missing input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --scenario-matrix-report-json)
      scenario_matrix_report_json="${2:-}"
      shift 2
      ;;
    --threshold-receipt-json)
      threshold_receipt_json="${2:-}"
      shift 2
      ;;
    --capacity-forecast-json)
      capacity_forecast_json="${2:-}"
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

json_copy() {
  local input_path="$1"
  local output_path="$2"
  local label="$3"

  if [[ -z "$input_path" ]]; then
    printf 'high-core chaos conformance gate missing %s\n' "$label" >&2
    exit 64
  fi
  if [[ ! -f "$input_path" ]]; then
    printf 'high-core chaos conformance gate missing %s JSON: %s\n' "$label" "$input_path" >&2
    exit 64
  fi
  if ! jq empty "$input_path" >/dev/null 2>&1; then
    printf 'high-core chaos conformance gate invalid %s JSON: %s\n' "$label" "$input_path" >&2
    exit 64
  fi
  jq -c . "$input_path" >"$output_path"
}

if [[ -z "$scenario_matrix_report_json" || -z "$threshold_receipt_json" || -z "$capacity_forecast_json" ]]; then
  printf 'high-core chaos conformance gate requires the matrix report, threshold receipt, and capacity forecast\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for the high-core chaos conformance gate\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for the high-core chaos conformance gate\n' >&2
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
report_path="${run_dir}/swarm_high_core_chaos_conformance_report.json"
report_tmp="${report_path}.tmp"
core_path="${run_dir}/swarm_high_core_chaos_conformance_report.core.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
markdown_path="${run_dir}/report.md"
gate_failures_jsonl="${run_dir}/gate_failures.jsonl"

matrix_normalized="${run_dir}/scenario_matrix_report.normalized.json"
receipt_normalized="${run_dir}/threshold_receipt.normalized.json"
forecast_normalized="${run_dir}/capacity_forecast.normalized.json"

: >"$events_path"
: >"$gate_failures_jsonl"

printf './scripts/swarm_high_core_chaos_conformance_gate.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

json_copy "$scenario_matrix_report_json" "$matrix_normalized" "scenario matrix report"
json_copy "$threshold_receipt_json" "$receipt_normalized" "threshold receipt"
json_copy "$capacity_forecast_json" "$forecast_normalized" "capacity forecast"

if ! jq -e '.schema_version == "franken-engine.swarm-high-core-scenario-matrix-report.v1"' "$matrix_normalized" >/dev/null 2>&1; then
  printf 'expected franken-engine.swarm-high-core-scenario-matrix-report.v1\n' >&2
  exit 64
fi
if ! jq -e '.schema_version == "franken-engine.swarm-slo-threshold-receipt.v1"' "$receipt_normalized" >/dev/null 2>&1; then
  printf 'expected franken-engine.swarm-slo-threshold-receipt.v1\n' >&2
  exit 64
fi
if ! jq -e '
  .schema_version == "franken-engine.swarm-capacity-forecast.v1"
  and (.decision | type == "string")
  and (.generated_epoch_seconds | type == "number")
  and (.summary.overall_state | type == "string")
' "$forecast_normalized" >/dev/null 2>&1; then
  printf 'capacity forecast shape mismatch for chaos conformance gate\n' >&2
  exit 64
fi

append_gate_failure() {
  jq -nc \
    --arg code "$1" \
    --arg detail "$2" \
    '{code:$code, detail:$detail}' >>"$gate_failures_jsonl"
}

matrix_hash="$(jq -cS . "$matrix_normalized" | sha256sum | awk '{print $1}')"
receipt_hash="$(jq -cS . "$receipt_normalized" | sha256sum | awk '{print $1}')"
forecast_hash="$(jq -cS . "$forecast_normalized" | sha256sum | awk '{print $1}')"

matrix_root="$(cd "$(dirname "$scenario_matrix_report_json")" && pwd)"
forecast_epoch="$(jq -r '.generated_epoch_seconds' "$forecast_normalized")"
forecast_age=$((now_epoch_seconds - forecast_epoch))
if (( forecast_age > stale_after_seconds )); then
  append_gate_failure "stale_forecast_artifact" "capacity forecast age ${forecast_age}s exceeds ${stale_after_seconds}s"
fi

if ! jq -e '.failure_count == 0 and ((.summary.mismatch_case_ids // []) | length) == 0' "$matrix_normalized" >/dev/null 2>&1; then
  append_gate_failure "scenario_matrix_drift" "scenario matrix contains mismatches or failing cases"
fi

if ! jq -e '.decision == "pass"' "$receipt_normalized" >/dev/null 2>&1; then
  append_gate_failure "threshold_receipt_fail_closed" "threshold receipt is not in a passing state"
fi

while IFS= read -r command_path; do
  [[ -n "$command_path" ]] || continue
  if [[ "$command_path" == *"/degraded_worker_pool_local_fallback/"* ]]; then
    continue
  fi
  if grep -nE '(^|[[:space:]])cargo([[:space:]]|$)' "$command_path" | grep -vq 'rch exec --'; then
    append_gate_failure "bare_cargo_command_detected" "bare cargo command found in ${command_path}"
    break
  fi
done < <(find "${matrix_root}/cases" -type f -name 'commands.txt' | sort)

while IFS= read -r unexpected_case; do
  [[ -n "$unexpected_case" ]] || continue
  append_gate_failure "unexpected_local_or_unknown_traceability" "${unexpected_case}"
done < <(
  jq -r '
    .cases[]
    | select(
        .scenario_class != "degraded_worker_pool_local_fallback"
        and (
          [
            .actual.traceability.stress,
            .actual.traceability.tail,
            .actual.traceability.chaos,
            .actual.traceability.claim_map
          ] | any(. != "rch_backed")
        )
      )
    | "\(.case_id): \(.actual.traceability | tojson)"
  ' "$matrix_normalized"
)

jq -n \
  --arg schema_version "franken-engine.swarm-high-core-chaos-conformance-report.v1" \
  --arg source_revision "$source_revision" \
  --arg matrix_hash "$matrix_hash" \
  --arg receipt_hash "$receipt_hash" \
  --arg forecast_hash "$forecast_hash" \
  --arg matrix_path "$scenario_matrix_report_json" \
  --arg receipt_path "$threshold_receipt_json" \
  --arg forecast_path "$capacity_forecast_json" \
  --arg matrix_root "$matrix_root" \
  --slurpfile matrix "$matrix_normalized" \
  --slurpfile receipt "$receipt_normalized" \
  --slurpfile forecast "$forecast_normalized" \
  --slurpfile gate_failures "$gate_failures_jsonl" \
  '
  def claims:
    [
      "queue_wait_budget_band",
      "validation_latency_band",
      "rch_fallback_rate_tolerance",
      "starvation_brownout_guardrails",
      "proof_cache_freshness_and_warm_target_roi",
      "archive_salvage_pressure_thresholds"
    ];
  def requirement_level($claim; $scenario):
    if $claim == "archive_salvage_pressure_thresholds" then "MAY"
    elif $claim == "proof_cache_freshness_and_warm_target_roi" then
      if $scenario == "proof_cache_hit" or $scenario == "proof_cache_stale_miss" then "MUST" else "MAY" end
    elif $claim == "starvation_brownout_guardrails" then
      if $scenario == "chaos_recovery_saturated_queue" or $scenario == "manual_confirmation_lock_pressure" or $scenario == "degraded_worker_pool_local_fallback" then "MUST" else "SHOULD" end
    elif $claim == "queue_wait_budget_band" or $claim == "validation_latency_band" then
      if $scenario == "degraded_worker_pool_local_fallback" then "MAY" else "MUST" end
    else
      "MUST"
    end;
  def non_rch_count($case):
    [
      $case.actual.traceability.stress,
      $case.actual.traceability.tail,
      $case.actual.traceability.chaos,
      $case.actual.traceability.claim_map
    ] | map(select(. != "rch_backed")) | length;
  def eval_queue($case; $receipt):
    ($case.capacity_snapshot.swarm_capacity_snapshot.swarm_slo_inputs.tail_latency_control_plane.queue_adjusted_p99_ns // 0) as $queue_p99
    | if $case.scenario_class == "degraded_worker_pool_local_fallback" then
        {
          verdict: "expected_fail",
          reason: "direct queue-band comparison is intentionally skipped for the degraded-worker local-fallback case",
          deviation_note: "queue wait conformance is not authoritative when the scenario exists to prove fail-closed local fallback behavior"
        }
      elif $case.actual.capacity_decision != "pass" then
        {verdict: "fail", reason: "scenario did not preserve a passing capacity decision"}
      elif $queue_p99 <= ($receipt.thresholds.queue_wait_budget_band.near_limit_upper_bound_ns // 0) then
        {verdict: "pass", reason: "scenario queue-adjusted p99 stays inside the calibrated reviewed band"}
      else
        {verdict: "fail", reason: "scenario queue-adjusted p99 exceeded the calibrated reviewed band"}
      end;
  def eval_latency($case; $receipt):
    ($case.capacity_snapshot.swarm_capacity_snapshot.swarm_slo_inputs.tail_latency_control_plane.observed_p99_ns // 0) as $p99
    | if $case.scenario_class == "degraded_worker_pool_local_fallback" then
        {
          verdict: "expected_fail",
          reason: "latency-band comparison is intentionally skipped for the degraded-worker local-fallback case",
          deviation_note: "latency conformance is not authoritative when the scenario exists to prove fail-closed local fallback behavior"
        }
      elif $case.actual.capacity_decision != "pass" then
        {verdict: "fail", reason: "scenario did not preserve a passing capacity decision"}
      elif $p99 <= ($receipt.thresholds.validation_latency_band.p99_near_limit_upper_bound_ns // 0) then
        {verdict: "pass", reason: "scenario p99 latency stays inside the calibrated reviewed band"}
      else
        {verdict: "fail", reason: "scenario p99 latency exceeded the calibrated reviewed band"}
      end;
  def eval_rch($case):
    (non_rch_count($case)) as $non_rch
    | if $case.scenario_class == "degraded_worker_pool_local_fallback" then
        if $non_rch > 0 and $case.actual.capacity_decision == "fail_closed" then
          {verdict: "pass", reason: "degraded-worker scenario correctly fails closed once local fallback appears"}
        else
          {verdict: "fail", reason: "degraded-worker scenario did not fail closed on local fallback"}
        end
      elif $non_rch == 0 then
        {verdict: "pass", reason: "all four high-core evidence surfaces stayed rch-backed"}
      else
        {verdict: "fail", reason: "non-degraded scenario leaked local or unknown high-core traceability"}
      end;
  def eval_brownout($case):
    ($case.input_summary.collision_risk // "unknown") as $risk
    | ($case.capacity_snapshot.swarm_capacity_snapshot.swarm_slo_inputs.tail_latency_control_plane.guardrail_state // "unknown") as $guardrail
    | if $case.scenario_class == "chaos_recovery_saturated_queue" then
        if $risk == "saturated_queue" and $guardrail == "near_limit" then
          {verdict: "pass", reason: "chaos saturation stayed in the reviewed near-limit guardrail posture"}
        else
          {verdict: "fail", reason: "chaos scenario did not preserve the reviewed saturation guardrail posture"}
        end
      elif $case.scenario_class == "manual_confirmation_lock_pressure" then
        if $risk == "manual_confirmation" then
          {verdict: "pass", reason: "manual-confirmation pressure preserved the documented operator-review posture"}
        else
          {verdict: "fail", reason: "manual-confirmation scenario lost the documented operator-review posture"}
        end
      elif $case.scenario_class == "degraded_worker_pool_local_fallback" then
        if $case.actual.capacity_decision == "fail_closed" then
          {verdict: "pass", reason: "degraded-worker scenario preserved the reviewed fail-closed guardrail"}
        else
          {verdict: "fail", reason: "degraded-worker scenario did not preserve the reviewed fail-closed guardrail"}
        end
      elif $guardrail == "healthy" then
        {verdict: "pass", reason: "scenario preserved the healthy reviewed brownout posture"}
      else
        {verdict: "fail", reason: "non-chaos scenario unexpectedly deviated from the healthy reviewed brownout posture"}
      end;
  def eval_proof_cache($case):
    ($case.capacity_snapshot.swarm_capacity_snapshot.proof_freshness.freshness_state // "unknown") as $freshness
    | if $case.scenario_class == "proof_cache_hit" then
        if $freshness == "fresh" then
          {verdict: "pass", reason: "proof-cache hit preserved fresh proof reuse evidence"}
        else
          {verdict: "fail", reason: "proof-cache hit scenario did not preserve fresh proof reuse evidence"}
        end
      elif $case.scenario_class == "proof_cache_stale_miss" then
        if $freshness == "stale" then
          {verdict: "pass", reason: "proof-cache stale miss preserved the stale freshness state used by the calibrator"}
        else
          {verdict: "fail", reason: "proof-cache stale miss did not preserve the stale freshness state"}
        end
      else
        {
          verdict: "expected_fail",
          reason: "scenario does not directly exercise proof-cache freshness or warm-target ROI drift",
          deviation_note: "proof-cache conformance outside the hit/stale pair remains advisory-only in this bead"
        }
      end;
  def eval_archive($case):
    {
      verdict: "expected_fail",
      reason: "IX scenario matrix does not vary archive or salvage pressure directly",
      deviation_note: "archive and salvage thresholds remain advisory-only and are intentionally documented as non-exercised by the high-core scenario matrix"
    };
  def eval_claim($claim; $case; $receipt):
    if $claim == "queue_wait_budget_band" then eval_queue($case; $receipt)
    elif $claim == "validation_latency_band" then eval_latency($case; $receipt)
    elif $claim == "rch_fallback_rate_tolerance" then eval_rch($case)
    elif $claim == "starvation_brownout_guardrails" then eval_brownout($case)
    elif $claim == "proof_cache_freshness_and_warm_target_roi" then eval_proof_cache($case)
    else eval_archive($case)
    end;
  ($matrix[0]) as $matrix_report |
  ($receipt[0]) as $threshold_receipt |
  ($forecast[0]) as $capacity_forecast |
  ($gate_failures // []) as $gate_failures |
  [
    $matrix_report.cases[] as $case
    | claims[] as $claim
    | (eval_claim($claim; $case; $threshold_receipt)) as $evaluation
    | {
        claim_id: $claim,
        scenario_class: $case.scenario_class,
        requirement_level: requirement_level($claim; $case.scenario_class),
        verdict: $evaluation.verdict,
        reason: $evaluation.reason,
        deviation_note: ($evaluation.deviation_note // null),
        evidence_source_paths: [
          $matrix_path,
          ($matrix_root + "/" + $case.artifact_paths.swarm_capacity_snapshot_json),
          ($matrix_root + "/" + $case.artifact_paths.swarm_slo_input_snapshot_json),
          $receipt_path,
          $forecast_path
        ],
        evidence_hashes: {
          scenario_matrix_report_sha256: $matrix_hash,
          threshold_receipt_sha256: $receipt_hash,
          capacity_forecast_sha256: $forecast_hash
        }
      }
  ] as $rows |
  ([ $rows[] | select(.verdict == "pass") ] | length) as $pass_count |
  ([ $rows[] | select(.verdict == "fail") ] | length) as $fail_count |
  ([ $rows[] | select(.verdict == "expected_fail") ] | length) as $expected_fail_count |
  ([ $rows[] | select(.requirement_level == "MUST") ] | length) as $must_count |
  ([ $rows[] | select(.requirement_level == "SHOULD") ] | length) as $should_count |
  ([ $rows[] | select(.requirement_level == "MAY") ] | length) as $may_count |
  (if (($gate_failures | length) > 0 or $fail_count > 0) then "fail_closed" else "pass" end) as $decision |
  {
    schema_version: $schema_version,
    source_revision: $source_revision,
    decision: $decision,
    exit_code: (if $decision == "fail_closed" then 42 else 0 end),
    evidence_hashes: {
      scenario_matrix_report_sha256: $matrix_hash,
      threshold_receipt_sha256: $receipt_hash,
      capacity_forecast_sha256: $forecast_hash
    },
    summary: {
      total_rows: ($rows | length),
      pass_count: $pass_count,
      fail_count: $fail_count,
      expected_fail_count: $expected_fail_count,
      must_count: $must_count,
      should_count: $should_count,
      may_count: $may_count
    },
    gate_failures: $gate_failures,
    deviations: [ $rows[] | select(.verdict == "expected_fail") ],
    rows: $rows
  }
  ' >"$core_path"

report_hash="$(jq -cS . "$core_path" | sha256sum | awk '{print $1}')"
report_id="high-core-chaos-conformance-${report_hash:0:16}"

jq \
  --arg report_id "$report_id" \
  --arg report_hash "$report_hash" \
  --arg report_path "$report_path" \
  --arg markdown_path "$markdown_path" \
  --arg commands_path "$commands_path" \
  --arg events_path "$events_path" \
  '
  . + {
    report_id: $report_id,
    hash_basis: {
      report_hash: $report_hash
    },
    artifact_paths: {
      swarm_high_core_chaos_conformance_report_json: $report_path,
      report_md: $markdown_path,
      commands_txt: $commands_path,
      events_jsonl: $events_path
    }
  }
  ' "$core_path" >"$report_tmp"
mv "$report_tmp" "$report_path"

{
  jq -c --arg source_revision "$source_revision" '
    .rows[]
    | {
        schema_version: "franken-engine.swarm-high-core-chaos-conformance-gate.event.v1",
        event_name: "conformance_row_evaluated",
        claim_id: .claim_id,
        scenario_class: .scenario_class,
        requirement_level: .requirement_level,
        verdict: .verdict,
        reason: .reason,
        source_revision: $source_revision
      }
  ' "$report_path"

  jq -c --arg source_revision "$source_revision" '
    .gate_failures[]
    | {
        schema_version: "franken-engine.swarm-high-core-chaos-conformance-gate.event.v1",
        event_name: "gate_failure_detected",
        claim_id: "gate",
        scenario_class: "gate",
        requirement_level: "MUST",
        verdict: "fail_closed",
        reason: (.code + ": " + .detail),
        source_revision: $source_revision
      }
  ' "$report_path"

  jq -c --arg source_revision "$source_revision" '
    {
      schema_version: "franken-engine.swarm-high-core-chaos-conformance-gate.event.v1",
      event_name: "conformance_report_generated",
      claim_id: "summary",
      scenario_class: "summary",
      requirement_level: "MUST",
      verdict: .decision,
      reason: (
        if .decision == "fail_closed" then
          "gate failures or failing conformance rows prevented a clean pass"
        else
          "all MUST/SHOULD rows passed and documented deviations stayed expected-fail only"
        end
      ),
      source_revision: $source_revision
    }
  ' "$report_path"
} >>"$events_path"

{
  printf '# High-Core Chaos Conformance Report\n\n'
  printf -- "- Report ID: \`%s\`\n" "$(jq -r '.report_id' "$report_path")"
  printf -- "- Decision: \`%s\`\n" "$(jq -r '.decision' "$report_path")"
  printf -- "- Pass rows: \`%s\`\n" "$(jq -r '.summary.pass_count' "$report_path")"
  printf -- "- Fail rows: \`%s\`\n" "$(jq -r '.summary.fail_count' "$report_path")"
  printf -- "- Expected-fail rows: \`%s\`\n" "$(jq -r '.summary.expected_fail_count' "$report_path")"
  printf -- "- MUST rows: \`%s\`\n" "$(jq -r '.summary.must_count' "$report_path")"
  printf -- "- SHOULD rows: \`%s\`\n" "$(jq -r '.summary.should_count' "$report_path")"
  printf -- "- MAY rows: \`%s\`\n\n" "$(jq -r '.summary.may_count' "$report_path")"
  printf '| Claim | Scenario | Level | Verdict | Reason |\n'
  printf '| --- | --- | --- | --- | --- |\n'
  jq -r '
    .rows[]
    | "| \(.claim_id) | \(.scenario_class) | \(.requirement_level) | \(.verdict) | \(.reason | gsub("\\|"; "\\\\|")) |"
  ' "$report_path"
  printf '\n## Documented Deviations\n\n'
  jq -r '
    if (.deviations | length) == 0 then
      "- None."
    else
      .deviations[]
      | "- \(.claim_id) / \(.scenario_class): \(.deviation_note // .reason)"
    end
  ' "$report_path"
  if jq -e '(.gate_failures | length) > 0' "$report_path" >/dev/null; then
    printf '\n## Gate Failures\n\n'
    jq -r '.gate_failures[] | "- \(.code): \(.detail)"' "$report_path"
  fi
} >"$markdown_path"

printf 'swarm_high_core_chaos_conformance_report=%s\n' "$report_path"
printf 'swarm_high_core_chaos_conformance_markdown=%s\n' "$markdown_path"
exit "$(jq -r '.exit_code' "$report_path")"
