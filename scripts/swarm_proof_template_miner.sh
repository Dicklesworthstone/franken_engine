#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_PROOF_TEMPLATE_MINER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-proof-template-miner}"
run_id="${SWARM_PROOF_TEMPLATE_MINER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_PROOF_TEMPLATE_MINER_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

fixture_json=""
input_json=""
case_id=""
source_revision="${SWARM_PROOF_TEMPLATE_MINER_SOURCE_REVISION:-}"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_proof_template_miner.sh [OPTIONS]

Mine preserved proof-broker history for reusable proof-template promotion
candidates and non-promotion receipts. This script is advisory-only and never
edits AGENTS.md, scripts, br, Agent Mail, Cargo, or RCH state.

Options:
  --fixture-json FILE    Single fixture case with proof_history rows.
  --input-json FILE      Template miner input JSON.
  --case-id ID           Deterministic case id.
  --source-revision REV  Source revision recorded in artifacts.
  --output-dir DIR       Artifact directory.

Artifacts:
  template_mining_report.json
  promotion_candidates.jsonl
  non_promotion_receipts.jsonl
  events.jsonl
  commands.txt
  report.md
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
  printf 'jq is required for swarm proof template mining\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for swarm proof template mining\n' >&2
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
report_json="${run_dir}/template_mining_report.json"
report_tmp="${report_json}.tmp"
promotion_jsonl="${run_dir}/promotion_candidates.jsonl"
non_promotion_jsonl="${run_dir}/non_promotion_receipts.jsonl"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_md="${run_dir}/report.md"

for artifact_path in \
  "$input_path" \
  "$report_json" \
  "$report_tmp" \
  "$promotion_jsonl" \
  "$non_promotion_jsonl" \
  "$events_path" \
  "$commands_path" \
  "$report_md"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

: >"$events_path"
printf './scripts/swarm_proof_template_miner.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  local event="$1"
  local outcome="$2"
  local detail="$3"

  jq -nc \
    --arg schema_version "franken-engine.swarm-proof-template-miner.event.v1" \
    --arg component "swarm_proof_template_miner" \
    --arg event "$event" \
    --arg outcome "$outcome" \
    --arg detail "$detail" \
    --arg case_id "$case_id" \
    '{schema_version:$schema_version,component:$component,event:$event,outcome:$outcome,detail:$detail,case_id:$case_id}' >>"$events_path"
}

jq -cS . "$input_json" >"$input_path"
write_event "template_mining.started" "ok" "$case_id"

jq -n \
  --slurpfile input "$input_path" \
  --arg schema_version "franken-engine.swarm-proof-template-mining-report.v1" \
  --arg case_id "$case_id" \
  --arg source_revision "$source_revision" \
  --arg input_path "$input_path" \
  --arg report_json "$report_json" \
  --arg promotion_jsonl "$promotion_jsonl" \
  --arg non_promotion_jsonl "$non_promotion_jsonl" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_md "$report_md" '
  def arr($v): if ($v | type) == "array" then $v else [] end;
  def rows($doc): arr($doc.proof_history) + arr($doc.artifact_index.rows) + arr($doc.reuse_receipts) + arr($doc.refusal_receipts) + arr($doc.chaos_replay_outcomes) + arr($doc.lifecycle_bundles);
  def key($r): ($r.template_key // $r.command_template // $r.command // "unknown");
  def slug($s): ($s | ascii_downcase | gsub("[^a-z0-9]+"; "-") | gsub("^-+"; "") | gsub("-+$"; ""));
  def source_links($rows): [$rows[]? | .source_proof_link?, .source_proof_links[]?] | map(select(type == "string" and length > 0)) | unique;
  def reason_list($row):
    if (($row.reason_codes // null) | type) == "array" then $row.reason_codes
    elif (($row.invalidation_reasons // null) | type) == "array" then $row.invalidation_reasons
    elif (($row.fail_closed_reasons // null) | type) == "array" then $row.fail_closed_reasons
    elif (($row.reason // "") | length) > 0 then [$row.reason]
    else []
    end;
  def is_success($r): (($r.status // "") | IN("passed", "reuse_allowed", "promotion_success")) or (($r.reuse_eligible // false) == true);
  def is_refusal($r): (($r.status // "") | IN("reuse_refused", "failed", "stale", "contaminated", "non_promotion")) or (($r.reuse_eligible // null) == false);
  def has_reason($rows; $reason): any($rows[]?; (reason_list(.) | index($reason)) != null);
  def current_successes($rows): [$rows[]? | select(is_success(.) and ((.current // true) == true))];
  def remediation($reason):
    if $reason == "promote" then "Promote this as a documented validation recipe after a human reviews the candidate; do not edit AGENTS.md automatically."
    elif $reason == "insufficient_evidence" then "Keep collecting current successful proof rows and refusal examples before promoting this template."
    elif $reason == "stale_artifact_refusal" then "Refresh the stale artifact evidence and rerun the miner before considering promotion."
    elif $reason == "contradictory_failure_history" then "Resolve contradictory failure history and document applicability boundaries before promotion."
    elif $reason == "local_fallback_contamination" then "Discard contaminated local-fallback proof rows and collect remote-only evidence before promotion."
    else "Keep this as a stable non-promotion receipt with source proof links and revisit only if new evidence changes the applicability boundary."
    end;
  def decision($rows; $policy):
    ([$rows[]? | select(is_success(.))]) as $successes
    | ([$rows[]? | select(is_refusal(.))]) as $refusals
    | (current_successes($rows)) as $current
    | if has_reason($rows; "local_fallback_contamination") then {kind:"non_promotion", reason:"local_fallback_contamination"}
      elif has_reason($rows; "expired_ttl") or any($rows[]?; (.freshness // "") == "expired") then {kind:"non_promotion", reason:"stale_artifact_refusal"}
      elif has_reason($rows; "contradictory_failure_history") or any($rows[]?; (.contradictory // false) == true) then {kind:"non_promotion", reason:"contradictory_failure_history"}
      elif (($successes | length) < (($policy.min_success_count // 3) | tonumber)) or (($current | length) < (($policy.min_current_success_count // 2) | tonumber)) or (($refusals | length) < (($policy.min_refusal_count // 1) | tonumber)) then {kind:"non_promotion", reason:"insufficient_evidence"}
      elif any($rows[]?; (.stable_non_promotion // false) == true) then {kind:"non_promotion", reason:"stable_non_promotion"}
      else {kind:"promotion_candidate", reason:"promote"}
      end;

  ($input[0] // {}) as $doc
  | ($doc.policy // {}) as $policy
  | (rows($doc) | group_by(key(.)) | map(
      . as $group
      | (key($group[0])) as $template_key
      | (decision($group; $policy)) as $decision
      | ([$group[]? | select(is_success(.))] | length) as $success_count
      | ([$group[]? | select(is_refusal(.))] | length) as $refusal_count
      | (current_successes($group) | length) as $current_success_count
      | {
          candidate_id: ("spt-" + slug($template_key)),
          template_key: $template_key,
          command_template: ($group[0].command_template // $group[0].command // $template_key),
          lane: ($group[0].lane // "unknown"),
          decision: $decision.kind,
          reason_code: $decision.reason,
          success_count: $success_count,
          current_success_count: $current_success_count,
          refusal_count: $refusal_count,
          source_proof_links: source_links($group),
          applicability_notes: ($group[0].applicability_notes // []),
          remediation: remediation($decision.reason),
          automatic_edit_policy: {
            edits_agents_md: false,
            edits_scripts: false,
            advisory_only: true
          }
        }
    )) as $candidates
  | {
      schema_version: $schema_version,
      case_id: $case_id,
      source_revision: $source_revision,
      candidate_count: ($candidates | length),
      promotion_candidate_count: ($candidates | map(select(.decision == "promotion_candidate")) | length),
      non_promotion_count: ($candidates | map(select(.decision == "non_promotion")) | length),
      candidates: $candidates,
      artifact_paths: {
        input_normalized_json: $input_path,
        template_mining_report_json: $report_json,
        promotion_candidates_jsonl: $promotion_jsonl,
        non_promotion_receipts_jsonl: $non_promotion_jsonl,
        events_jsonl: $events_path,
        commands_txt: $commands_path,
        report_md: $report_md
      },
      non_mutation_attestation: {
        runs_cargo: false,
        runs_rch: false,
        mutates_br: false,
        sends_agent_mail: false,
        edits_agents_md: false,
        edits_scripts: false
      }
    }
  ' >"$report_tmp"

report_hash="$(jq -cS '{case_id,candidates}' "$report_tmp" | sha256sum | awk '{print $1}')"
jq --arg report_hash "$report_hash" '. + {report_hash: $report_hash}' "$report_tmp" >"$report_json"
jq -c '.candidates[] | select(.decision == "promotion_candidate")' "$report_json" >"$promotion_jsonl"
jq -c '.candidates[] | select(.decision == "non_promotion")' "$report_json" >"$non_promotion_jsonl"

promotion_count="$(jq -r '.promotion_candidate_count' "$report_json")"
non_promotion_count="$(jq -r '.non_promotion_count' "$report_json")"
write_event "template_mining.completed" "ok" "promotion=${promotion_count} non_promotion=${non_promotion_count}"

{
  printf '# Swarm Proof Template Miner\n\n'
  printf -- "- case_id: \`%s\`\n" "$case_id"
  printf -- "- report_hash: \`%s\`\n" "$report_hash"
  printf -- "- promotion_candidate_count: \`%s\`\n" "$promotion_count"
  printf -- "- non_promotion_count: \`%s\`\n" "$non_promotion_count"
} >"$report_md"
