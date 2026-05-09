#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_PROOF_BATCH_PLANNER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-proof-batch-planner}"
run_id="${SWARM_PROOF_BATCH_PLANNER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_PROOF_BATCH_PLANNER_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

fixture_json=""
input_json=""
case_id=""
source_revision="${SWARM_PROOF_BATCH_PLANNER_SOURCE_REVISION:-}"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_proof_batch_planner.sh [OPTIONS]

Recommend advisory proof batching, reuse, rerun, isolation, or human-review
actions without mutating queues, workers, or target directories.

Options:
  --fixture-json FILE    Single fixture case with requests and evidence.
  --input-json FILE      Planner input JSON.
  --case-id ID           Deterministic case id.
  --source-revision REV  Source revision recorded in artifacts.
  --output-dir DIR       Artifact directory.
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --fixture-json)
      fixture_json="${2:-}"
      shift 2
      ;;
    --input-json)
      input_json="${2:-}"
      shift 2
      ;;
    --case-id)
      case_id="${2:-}"
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

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm proof batch planning\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for swarm proof batch planning\n' >&2
  exit 2
fi
if [[ -n "$fixture_json" ]]; then
  input_json="$fixture_json"
fi
if [[ -z "$input_json" || ! -f "$input_json" ]]; then
  printf 'input JSON not found: %s\n' "${input_json:-}" >&2
  exit 64
fi
if ! jq empty "$input_json" >/dev/null 2>&1; then
  printf 'invalid input JSON: %s\n' "$input_json" >&2
  exit 64
fi
if [[ -z "$case_id" ]]; then
  case_id="$(jq -r '.case_id // "manual"' "$input_json")"
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse --short HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
input_path="${run_dir}/input.normalized.json"
plan_path="${run_dir}/batch_plan.json"
plan_tmp="${plan_path}.tmp"
recommendations_jsonl="${run_dir}/recommendations.jsonl"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"

for artifact_path in "$input_path" "$plan_path" "$plan_tmp" "$recommendations_jsonl" "$events_path" "$commands_path" "$report_path"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

: >"$events_path"
printf './scripts/swarm_proof_batch_planner.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

jq -cS . "$input_json" >"$input_path"

jq -n \
  --slurpfile input "$input_path" \
  --arg schema_version "franken-engine.swarm-proof-batch-plan.v1" \
  --arg case_id "$case_id" \
  --arg source_revision "$source_revision" \
  --arg input_path "$input_path" \
  --arg plan_path "$plan_path" \
  --arg recommendations_jsonl "$recommendations_jsonl" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" '
  def arr($v): if ($v | type) == "array" then $v else [] end;
  def rows($name): arr($input[0][$name]);
  def artifact_for($fingerprint):
    (rows("artifact_index") | map(select(.proof_fingerprint == $fingerprint)) | .[0] // {});
  def worker_for($request):
    (rows("workers") | map(select((.worker_id // "") == ($request.preferred_worker // ""))) | .[0] // (rows("workers")[0] // {}));
  def duplicate_count($fingerprint):
    rows("requests") | map(select(.proof_fingerprint == $fingerprint)) | length;
  def fairness_debt($request):
    ((rows("fairness_debt") | map(select((.agent // "") == ($request.agent // ""))) | .[0].deferred_count) // 0);
  def evidence_paths($request):
    [($request.evidence_path // "proof-request"), ($input[0].artifact_index_evidence_path // "artifact-index"), ($input[0].worker_evidence_path // "worker-posture")];
  def rollback($action):
    if $action == "coalesce" then "Split the duplicate requests and rerun each proof independently."
    elif $action == "reuse" then "Invalidate the reuse receipt and schedule a fresh proof."
    elif $action == "rerun_now" then "Move the request back to normal proof scheduling."
    elif $action == "rerun_later" then "Refresh stale evidence and re-enter the request into the planner."
    elif $action == "keep_isolated" then "Keep separate target-dir policy and avoid warm-cache sharing."
    else "Escalate to operator review before scheduling any proof."
    end;
  def action_for($request):
    artifact_for($request.proof_fingerprint) as $artifact
    | worker_for($request) as $worker
    | ($input[0].operator_policy // {}) as $policy
    | if (($policy.conflict // false) == true) then {action:"human_review", reason:"conflicting_operator_intent_policy"}
      elif duplicate_count($request.proof_fingerprint) > 1 then {action:"coalesce", reason:"duplicate_proof_request"}
      elif (($artifact.reuse_eligible // false) == true) then {action:"reuse", reason:"fresh_reusable_artifact"}
      elif fairness_debt($request) >= 3 then {action:"rerun_now", reason:"fairness_debt_recovery"}
      elif (($request.isolation_required // false) == true) or (($worker.target_isolation // "compatible") == "incompatible") then {action:"keep_isolated", reason:"incompatible_target_isolation"}
      elif (($artifact.freshness // "") == "expired" or (($artifact.invalidation_reasons // []) | length) > 0) then {action:"rerun_later", reason:"stale_artifact_refusal"}
      elif ((arr($worker.warm_cache_fingerprints) | index($request.proof_fingerprint)) != null) then {action:"rerun_now", reason:"compatible_warm_cache_ordering"}
      else {action:"rerun_now", reason:"default_safe_rerun"}
      end;
  (rows("requests") | map(
    . as $request
    | action_for($request) as $decision
    | {
        recommendation_id: ("proof-batch-" + ($request.request_id // $request.proof_fingerprint)),
        request_id: ($request.request_id // ""),
        agent: ($request.agent // "unknown"),
        proof_fingerprint: ($request.proof_fingerprint // ""),
        action: $decision.action,
        reason: $decision.reason,
        fairness_debt: fairness_debt($request),
        warm_cache_advisory_only: true,
        evidence_paths: evidence_paths($request),
        rollback_note: rollback($decision.action),
        remediation: rollback($decision.action)
      }
  )) as $recommendations
  | {
      schema_version: $schema_version,
      case_id: $case_id,
      source_revision: $source_revision,
      recommendation_count: ($recommendations | length),
      recommendations: $recommendations,
      action_counts: ($recommendations | group_by(.action) | map({action: .[0].action, count: length})),
      artifact_paths: {
        input_normalized_json: $input_path,
        batch_plan_json: $plan_path,
        recommendations_jsonl: $recommendations_jsonl,
        events_jsonl: $events_path,
        commands_txt: $commands_path,
        report_md: $report_path
      },
      non_mutation_attestation: {
        runs_cargo: false,
        runs_rch: false,
        mutates_br: false,
        sends_agent_mail: false,
        mutates_remote_workers: false,
        changes_live_queue_policy: false,
        creates_deletes_target_dirs: false
      }
    }
  ' >"$plan_tmp"

plan_hash="$(jq -cS '{case_id,recommendations}' "$plan_tmp" | sha256sum | awk '{print $1}')"
jq --arg plan_hash "$plan_hash" '. + {plan_hash: $plan_hash}' "$plan_tmp" >"$plan_path"
jq -c '.recommendations[]' "$plan_path" >"$recommendations_jsonl"

jq -nc --arg schema_version "franken-engine.swarm-proof-batch-planner.event.v1" --arg case_id "$case_id" --arg plan_hash "$plan_hash" '{schema_version:$schema_version,case_id:$case_id,event:"batch_plan.emitted",plan_hash:$plan_hash}' >"$events_path"
{
  printf '# Swarm Proof Batch Planner\n\n'
  printf -- "- case_id: \`%s\`\n" "$case_id"
  printf -- "- plan_hash: \`%s\`\n" "$plan_hash"
  printf -- "- recommendation_count: \`%s\`\n" "$(jq -r '.recommendation_count' "$plan_path")"
} >"$report_path"
