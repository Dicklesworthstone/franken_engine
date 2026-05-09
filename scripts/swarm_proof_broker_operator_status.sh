#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_PROOF_BROKER_OPERATOR_STATUS_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-proof-broker-operator-status}"
run_id="${SWARM_PROOF_BROKER_OPERATOR_STATUS_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_PROOF_BROKER_OPERATOR_STATUS_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

fixture_json=""
input_json=""
case_id=""
source_revision="${SWARM_PROOF_BROKER_OPERATOR_STATUS_SOURCE_REVISION:-}"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_proof_broker_operator_status.sh [OPTIONS]

Build an advisory proof-broker operator-status bundle and a frankentui renderer
contract from proof requests, artifact-index rows, equivalence receipts, batch
recommendations, and fairness-debt snapshots. This script never runs Cargo or
RCH and never mutates live queues.

Options:
  --fixture-json FILE    Single fixture case with proof-broker status input.
  --input-json FILE      Operator-status input JSON.
  --case-id ID           Deterministic case id.
  --source-revision REV  Source revision recorded in artifacts.
  --output-dir DIR       Artifact directory.

Artifacts:
  operator_status_bundle.json
  frankentui_panel_contract.json
  operator_status_rows.jsonl
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
  printf 'jq is required for swarm proof broker operator status\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for swarm proof broker operator status\n' >&2
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
bundle_path="${run_dir}/operator_status_bundle.json"
bundle_tmp="${bundle_path}.tmp"
panel_path="${run_dir}/frankentui_panel_contract.json"
panel_tmp="${panel_path}.tmp"
rows_jsonl="${run_dir}/operator_status_rows.jsonl"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"

for artifact_path in \
  "$input_path" \
  "$bundle_path" \
  "$bundle_tmp" \
  "$panel_path" \
  "$panel_tmp" \
  "$rows_jsonl" \
  "$events_path" \
  "$commands_path" \
  "$report_path"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

: >"$events_path"
printf './scripts/swarm_proof_broker_operator_status.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  local event="$1"
  local outcome="$2"
  local detail="$3"

  jq -nc \
    --arg schema_version "franken-engine.swarm-proof-broker-operator-status.event.v1" \
    --arg component "swarm_proof_broker_operator_status" \
    --arg event "$event" \
    --arg outcome "$outcome" \
    --arg detail "$detail" \
    --arg case_id "$case_id" \
    '{schema_version:$schema_version,component:$component,event:$event,outcome:$outcome,detail:$detail,case_id:$case_id}' >>"$events_path"
}

jq -cS . "$input_json" >"$input_path"
write_event "operator_status.started" "ok" "$case_id"

jq -n \
  --slurpfile input "$input_path" \
  --arg schema_version "franken-engine.swarm-proof-broker-operator-status.v1" \
  --arg case_id "$case_id" \
  --arg source_revision "$source_revision" \
  --arg input_path "$input_path" \
  --arg bundle_path "$bundle_path" \
  --arg panel_path "$panel_path" \
  --arg rows_jsonl "$rows_jsonl" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" '
  def arr($v): if ($v | type) == "array" then $v else [] end;
  def object_values($v):
    if ($v | type) == "object" then [$v[]? | tostring | select(length > 0)]
    elif ($v | type) == "array" then [$v[]? | tostring | select(length > 0)]
    elif ($v | type) == "string" and ($v | length) > 0 then [$v]
    else []
    end;
  def rows($doc; $name): arr($doc[$name]);
  def requests($doc): arr($doc.proof_requests // $doc.requests);
  def evidence_paths($row; $fallback):
    (
      object_values($row.source_evidence)
      + object_values($row.evidence_paths)
      + object_values($row.artifact_paths)
      + [($row.evidence_path // empty), $fallback]
    )
    | map(tostring | select(length > 0))
    | unique;
  def fingerprint($row): ($row.proof_fingerprint // $row.request_fingerprint // $row.fingerprint // "");
  def command_from_row($row):
    if (($row.command // "") | length) > 0 then $row.command
    elif (($row.requested_command // "") | length) > 0 then $row.requested_command
    elif (($row.normalized_command // "") | length) > 0 then $row.normalized_command
    elif (($row.normalized_command_argv // []) | type) == "array" and (($row.normalized_command_argv // []) | length) > 0 then ($row.normalized_command_argv | join(" "))
    elif (($row.partial_overlap.requested_command // "") | length) > 0 then $row.partial_overlap.requested_command
    elif (($row.requested.normalized_command_argv // []) | type) == "array" and (($row.requested.normalized_command_argv // []) | length) > 0 then ($row.requested.normalized_command_argv | join(" "))
    else ""
    end;
  def command_for($doc; $fp; $row):
    command_from_row($row) as $direct
    | if ($direct | length) > 0 then $direct
      else
        (
          requests($doc)
          | map(select(fingerprint(.) == $fp))
          | .[0] // {}
          | command_from_row(.)
        )
      end;
  def reasons($row):
    if (($row.invalidation_reasons // null) | type) == "array" then $row.invalidation_reasons
    elif (($row.reason_codes // null) | type) == "array" then $row.reason_codes
    elif (($row.fail_closed_reasons // null) | type) == "array" then $row.fail_closed_reasons
    elif (($row.reason_summary // "") | length) > 0 then ($row.reason_summary | split(",") | map(select(length > 0)))
    elif (($row.reason // "") | length) > 0 then [$row.reason]
    else []
    end;
  def stale($row):
    (reasons($row) | index("expired_ttl")) != null
    or (reasons($row) | index("stale_br_snapshot")) != null
    or (($row.freshness // "") | IN("expired", "stale"));
  def contaminated($row):
    (reasons($row) | index("local_fallback_contamination")) != null
    or (reasons($row) | index("contaminated_command_shape")) != null
    or (($row.rch_posture // "") == "local_fallback")
    or (($row.local_fallback_observed // false) == true);
  def refusal_status($row):
    if contaminated($row) then "contaminated_refused"
    elif stale($row) then "stale_refused"
    else "reuse_refused"
    end;
  def refusal_action($row):
    if contaminated($row) then "Discard this proof and rerun through direct remote RCH before showing any green status."
    elif stale($row) then "Rerun or refresh the stale proof evidence before reuse."
    else "Keep the refusal visible and schedule a fresh proof or human review."
    end;
  def requested_action($row):
    if (($row.action // "") == "coalesce") then "Coalesce duplicate requests behind one proof, then show every coalesced request id."
    elif (($row.action // "") == "reuse") then "Reuse only while artifact freshness and exact command identity remain visible."
    elif (($row.action // "") == "rerun_now") then "Schedule the proof now with the recorded command text."
    elif (($row.action // "") == "rerun_later") then "Refresh stale evidence before putting this request back into proof scheduling."
    elif (($row.action // "") == "keep_isolated") then "Keep this proof isolated from batching and warm-cache sharing."
    else "Ask an operator to inspect the source evidence before changing proof status."
    end;

  ($input[0] // {}) as $doc
  | (requests($doc)) as $requests
  | (rows($doc; "artifact_index")) as $artifact_index
  | (rows($doc; "batch_recommendations")) as $batch
  | (rows($doc; "equivalence_receipts")) as $equiv
  | (rows($doc; "fairness_debt")) as $fairness
  | ($doc.operator_policy // {}) as $policy
  | ($requests | map(
      . as $request
      | fingerprint($request) as $fp
      | {
          row_id: ("pending-" + (($request.request_id // $request.proof_request_id // $fp // "unknown") | tostring)),
          kind: "pending_proof_request",
          status: "pending",
          request_id: ($request.request_id // $request.proof_request_id // ""),
          proof_fingerprint: $fp,
          agent: ($request.agent // "unknown"),
          command: command_for($doc; $fp; $request),
          source_evidence: evidence_paths($request; "proof-request-snapshot"),
          refusal_reasons: [],
          recommended_next_action: "Compare this request against reusable evidence or schedule a fresh proof before marking it green."
        }
    )) as $pending_rows
  | ($artifact_index | map(
      . as $artifact
      | fingerprint($artifact) as $fp
      | (reasons($artifact)) as $reasons
      | if (($artifact.reuse_eligible // false) == true) then
          {
            row_id: ("reuse-" + ($fp | tostring)),
            kind: "reusable_verdict",
            status: "reuse_allowed",
            proof_fingerprint: $fp,
            command: command_for($doc; $fp; $artifact),
            source_evidence: evidence_paths($artifact; "artifact-index-snapshot"),
            refusal_reasons: [],
            recommended_next_action: "Reuse this proof only while freshness, exact command text, and artifact retrieval remain visible."
          }
        else
          {
            row_id: ("refusal-" + ($fp | tostring)),
            kind: "reuse_refusal",
            status: refusal_status($artifact),
            proof_fingerprint: $fp,
            command: command_for($doc; $fp; $artifact),
            source_evidence: evidence_paths($artifact; "artifact-index-snapshot"),
            refusal_reasons: $reasons,
            recommended_next_action: refusal_action($artifact)
          }
        end
    )) as $artifact_rows
  | ($equiv | map(
      . as $receipt
      | fingerprint($receipt) as $fp
      | (reasons($receipt)) as $reasons
      | if (($receipt.reuse_eligible // false) == true) or (($receipt.verdict // "") == "reuse_allowed") then
          {
            row_id: ("equivalence-reuse-" + (($receipt.classifier_hash // $fp // "unknown") | tostring)),
            kind: "equivalence_reuse_verdict",
            status: "reuse_allowed",
            proof_fingerprint: $fp,
            command: command_for($doc; $fp; $receipt),
            source_evidence: evidence_paths($receipt; "equivalence-receipt"),
            refusal_reasons: [],
            recommended_next_action: "Treat the equivalent proof as reusable only while the classifier receipt and command text stay visible."
          }
        else
          {
            row_id: ("equivalence-refusal-" + (($receipt.classifier_hash // $fp // "unknown") | tostring)),
            kind: "equivalence_reuse_refusal",
            status: refusal_status($receipt),
            proof_fingerprint: $fp,
            command: command_for($doc; $fp; $receipt),
            source_evidence: evidence_paths($receipt; "equivalence-receipt"),
            refusal_reasons: $reasons,
            recommended_next_action: refusal_action($receipt)
          }
        end
    )) as $equiv_rows
  | ($batch | map(select((.action // "") == "coalesce")) | map(
      . as $rec
      | fingerprint($rec) as $fp
      | {
          row_id: ("coalesced-" + (($rec.recommendation_id // $rec.request_id // $fp // "unknown") | tostring)),
          kind: "duplicate_storm_coalesced",
          status: "coalesced",
          request_id: ($rec.request_id // ""),
          proof_fingerprint: $fp,
          command: command_for($doc; $fp; $rec),
          source_evidence: evidence_paths($rec; "batch-recommendation"),
          refusal_reasons: [],
          recommended_next_action: requested_action($rec)
        }
    )) as $coalesced_rows
  | ($fairness | map(
      . as $debt
      | {
          row_id: ("fairness-" + (($debt.agent // "unknown") | tostring)),
          kind: "fairness_debt",
          status: (if (($debt.deferred_count // 0) | tonumber) > 0 then "fairness_debt_visible" else "fairness_clear" end),
          agent: ($debt.agent // "unknown"),
          command: "not_applicable",
          source_evidence: evidence_paths($debt; "fairness-debt-snapshot"),
          refusal_reasons: [],
          fairness_debt: (($debt.deferred_count // 0) | tonumber),
          recommended_next_action: (if (($debt.deferred_count // 0) | tonumber) > 0 then "Pay down deferred proof work before accepting more warm-cache coalescing." else "No fairness action is needed for this agent." end)
        }
    )) as $fairness_rows
  | ($pending_rows + $artifact_rows + $equiv_rows + $coalesced_rows + $fairness_rows) as $status_rows
  | ($artifact_index | map(select((.reuse_eligible // false) == true)) | length) as $artifact_reuse_count
  | ($artifact_index | map(select((.reuse_eligible // false) != true)) | length) as $artifact_refusal_count
  | ($equiv | map(select(((.reuse_eligible // false) == true) or ((.verdict // "") == "reuse_allowed"))) | length) as $equiv_reuse_count
  | ($equiv | map(select((((.reuse_eligible // false) == true) or ((.verdict // "") == "reuse_allowed")) | not)) | length) as $equiv_refusal_count
  | ($artifact_index + $equiv | map(select(stale(.))) | length) as $stale_count
  | ($artifact_index + $equiv | map(select(contaminated(.))) | length) as $contaminated_count
  | ($fairness | map((.deferred_count // 0) | tonumber) | add // 0) as $fairness_total
  | ($batch | map(select((.action // "") == "coalesce")) | length) as $coalesced_count
  | {
      pending_request_count: ($requests | length),
      reusable_verdict_count: ($artifact_reuse_count + $equiv_reuse_count),
      reuse_refusal_count: ($artifact_refusal_count + $equiv_refusal_count),
      stale_proof_count: $stale_count,
      contaminated_proof_count: $contaminated_count,
      fairness_debt_total: $fairness_total,
      coalesced_count: $coalesced_count
    } as $summary
  | (
      [
        if (($policy.panel_claims_mutation_authority // false) == true or ($doc.panel_claims_mutation_authority // false) == true) then "panel_claims_live_mutation_authority" else empty end,
        if ((($policy.hide_stale_evidence // false) == true or ($doc.hide_stale_evidence // false) == true) and $stale_count > 0) then "panel_hides_stale_evidence" else empty end,
        if ((($policy.omit_refusal_reasons // false) == true or ($doc.omit_refusal_reasons // false) == true) and ($summary.reuse_refusal_count > 0)) or any($status_rows[]; (.status | test("refused$")) and ((.refusal_reasons // []) | length) == 0) then "panel_omits_refusal_reasons" else empty end
      ]
    ) as $failures
  | ($failures | length) == 0 as $passed
  | {
      schema_version: $schema_version,
      case_id: $case_id,
      source_revision: $source_revision,
      decision: (if $passed then "pass" else "fail_closed" end),
      overall_status: (if $passed then "advisory" else "blocked" end),
      fail_closed_reasons: $failures,
      hidden_green_status: false,
      summary_counts: $summary,
      rows: $status_rows,
      recommended_next_actions: ($status_rows | map({row_id, action: .recommended_next_action})),
      frankentui_boundary: {
        renderer_boundary: "frankentui",
        renderer_repo: "/dp/frankentui",
        implemented_here: false,
        mutation_authority: false
      },
      artifact_paths: {
        input_normalized_json: $input_path,
        operator_status_bundle_json: $bundle_path,
        frankentui_panel_contract_json: $panel_path,
        operator_status_rows_jsonl: $rows_jsonl,
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
        claims_live_mutation_authority: false
      }
    }
  ' >"$bundle_tmp"

status_hash="$(jq -cS '{case_id,decision,fail_closed_reasons,summary_counts,rows}' "$bundle_tmp" | sha256sum | awk '{print $1}')"
jq --arg status_hash "$status_hash" '. + {status_hash: $status_hash}' "$bundle_tmp" >"$bundle_path"

jq -n \
  --slurpfile bundle "$bundle_path" \
  --arg schema_version "franken-engine.swarm-proof-broker-frankentui-panel-contract.v1" \
  --arg case_id "$case_id" \
  --arg source_revision "$source_revision" \
  --arg bundle_path "$bundle_path" \
  --arg panel_path "$panel_path" \
  '($bundle[0]) as $bundle_doc | {
    schema_version: $schema_version,
    case_id: $case_id,
    source_revision: $source_revision,
    renderer_boundary: "frankentui",
    renderer_repo: "/dp/frankentui",
    local_rich_renderer_implemented: false,
    mutation_authority: false,
    live_mutation_authority: false,
    advisory_only: true,
    may_render_rows: true,
    may_mutate_proofs: false,
    may_close_beads: false,
    required_summary_counts: ($bundle_doc.summary_counts | keys | sort),
    required_row_fields: ["row_id", "kind", "status", "command", "source_evidence", "recommended_next_action"],
    source_status_bundle_json: $bundle_path,
    panel_contract_json: $panel_path,
    hidden_green_status: false,
    fail_closed_reasons: $bundle_doc.fail_closed_reasons
  }' >"$panel_tmp"
mv "$panel_tmp" "$panel_path"

jq -c '.rows[]' "$bundle_path" >"$rows_jsonl"
decision="$(jq -r '.decision' "$bundle_path")"
reason_summary="$(jq -r '.fail_closed_reasons | join(",")' "$bundle_path")"
write_event "operator_status.completed" "$decision" "$reason_summary"

{
  printf '# Swarm Proof Broker Operator Status\n\n'
  printf -- "- case_id: \`%s\`\n" "$case_id"
  printf -- "- decision: \`%s\`\n" "$decision"
  printf -- "- status_hash: \`%s\`\n" "$status_hash"
  printf -- "- pending_request_count: \`%s\`\n" "$(jq -r '.summary_counts.pending_request_count' "$bundle_path")"
  printf -- "- reuse_refusal_count: \`%s\`\n" "$(jq -r '.summary_counts.reuse_refusal_count' "$bundle_path")"
  if [[ -n "$reason_summary" ]]; then
    printf -- "- fail_closed_reasons: \`%s\`\n" "$reason_summary"
  fi
} >"$report_path"

if [[ "$decision" == "fail_closed" ]]; then
  exit 42
fi
exit 0
