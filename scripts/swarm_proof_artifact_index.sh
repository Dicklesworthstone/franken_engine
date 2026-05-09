#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_PROOF_ARTIFACT_INDEX_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-proof-artifact-index}"
run_id="${SWARM_PROOF_ARTIFACT_INDEX_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_PROOF_ARTIFACT_INDEX_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

fixture_json=""
input_json=""
case_id=""
source_revision="${SWARM_PROOF_ARTIFACT_INDEX_SOURCE_REVISION:-}"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_proof_artifact_index.sh [OPTIONS]

Build deterministic proof artifact index rows from prior proof receipts and
artifact bundles. The index is advisory-only and never runs Cargo or RCH.

Options:
  --fixture-json FILE    Single fixture case with proofs[] rows.
  --input-json FILE      JSON object with proofs[] rows.
  --case-id ID           Deterministic case id.
  --source-revision REV  Source revision recorded in artifacts.
  --output-dir DIR       Artifact directory.

Artifacts:
  proof_artifact_index.json
  proof_artifact_index.jsonl
  reuse_receipts.jsonl
  reuse_refusal_receipts.jsonl
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
  printf 'jq is required for swarm proof artifact indexing\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for swarm proof artifact indexing\n' >&2
  exit 2
fi

if [[ -n "$fixture_json" ]]; then
  input_json="$fixture_json"
fi
if [[ -z "$input_json" ]]; then
  printf 'input JSON is required\n' >&2
  usage
  exit 64
fi
if [[ ! -f "$input_json" ]]; then
  printf 'input JSON not found: %s\n' "$input_json" >&2
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
input_normalized_path="${run_dir}/input.normalized.json"
index_path="${run_dir}/proof_artifact_index.json"
index_tmp="${index_path}.tmp"
index_jsonl="${run_dir}/proof_artifact_index.jsonl"
reuse_receipts_jsonl="${run_dir}/reuse_receipts.jsonl"
refusal_receipts_jsonl="${run_dir}/reuse_refusal_receipts.jsonl"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"

for artifact_path in \
  "$input_normalized_path" \
  "$index_path" \
  "$index_tmp" \
  "$index_jsonl" \
  "$reuse_receipts_jsonl" \
  "$refusal_receipts_jsonl" \
  "$events_path" \
  "$commands_path" \
  "$report_path"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

: >"$events_path"
printf './scripts/swarm_proof_artifact_index.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  local event="$1"
  local outcome="$2"
  local detail="$3"

  jq -nc \
    --arg schema_version "franken-engine.swarm-proof-artifact-index.event.v1" \
    --arg component "swarm_proof_artifact_index" \
    --arg event "$event" \
    --arg outcome "$outcome" \
    --arg detail "$detail" \
    --arg case_id "$case_id" \
    '{schema_version:$schema_version,component:$component,event:$event,outcome:$outcome,detail:$detail,case_id:$case_id}' >>"$events_path"
}

jq -cS . "$input_json" >"$input_normalized_path"
write_event "index.started" "ok" "$case_id"

jq -n \
  --slurpfile input "$input_normalized_path" \
  --arg schema_version "franken-engine.swarm-proof-artifact-index.v1" \
  --arg case_id "$case_id" \
  --arg source_revision "$source_revision" \
  --arg input_path "$input_normalized_path" \
  --arg index_path "$index_path" \
  --arg index_jsonl "$index_jsonl" \
  --arg reuse_receipts_jsonl "$reuse_receipts_jsonl" \
  --arg refusal_receipts_jsonl "$refusal_receipts_jsonl" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" '
  def proofs($doc): if ($doc.proofs? | type) == "array" then $doc.proofs else [] end;
  def arr($v): if ($v | type) == "array" then $v else [] end;
  def reason_codes($p):
    [
      if (($p.local_fallback_observed // false) == true or ($p.rch_posture // "") == "local_fallback") then "local_fallback_contamination" else empty end,
      if (($p.verdict_status // "") != "passed") then "failed_proof_reuse_refusal" else empty end,
      if (($p.now_epoch // 0) > ($p.expires_at_epoch // 0)) then "expired_ttl" else empty end,
      if (($p.dependency_closure_fingerprint // "") != ($p.expected_dependency_closure_fingerprint // $p.dependency_closure_fingerprint // "")) then "changed_dependency_root" else empty end,
      if (($p.source_revision // "") != ($p.expected_source_revision // $p.source_revision // "")) then "changed_source_revision" else empty end,
      if (($p.toolchain // "") != ($p.expected_toolchain // $p.toolchain // "")) then "changed_toolchain" else empty end,
      if (($p.rch_version // "") != ($p.expected_rch_version // $p.rch_version // "")) then "changed_rch_version" else empty end,
      if (($p | has("retrieval_complete")) and ($p.retrieval_complete == false)) then "incomplete_rch_artifact_retrieval" else empty end,
      if (($p.artifact_bundle | type) == "object" and ($p.artifact_bundle | has("complete")) and ($p.artifact_bundle.complete == false)) then "missing_artifact_members" else empty end,
      if (($p.dirty_state // "known_clean") == "unknown") then "unknown_dirty_state" else empty end
    ];
  def decision($reasons):
    if ($reasons | length) == 0 then "reuse_allowed" else "reuse_refused" end;
  def freshness($reasons):
    if ($reasons | index("expired_ttl")) != null then "expired"
    elif ($reasons | length) == 0 then "fresh"
    else "invalidated"
    end;
  def remediation($reasons):
    if ($reasons | length) == 0 then "Reuse is allowed while the source, dependency, toolchain, RCH, dirty-state, and artifact bundle remain unchanged."
    elif ($reasons | index("expired_ttl")) != null then "Rerun the proof because the indexed receipt exceeded its TTL."
    elif ($reasons | index("changed_dependency_root")) != null then "Rerun after dependency root drift; do not reuse a receipt from the old closure."
    elif ($reasons | index("incomplete_rch_artifact_retrieval")) != null or ($reasons | index("missing_artifact_members")) != null then "Recover or regenerate the complete RCH artifact bundle before considering reuse."
    elif ($reasons | index("local_fallback_contamination")) != null then "Discard the receipt and rerun through a remote-only RCH path."
    elif ($reasons | index("failed_proof_reuse_refusal")) != null then "Treat the receipt as failure evidence only; it cannot satisfy green proof."
    else "Rerun or refresh evidence before reusing this proof."
    end;

  (proofs($input[0])) as $proofs
  | ($proofs | map(
      . as $p
      | (reason_codes($p)) as $reasons
      | {
          proof_fingerprint: ($p.proof_fingerprint // $p.request_fingerprint // "unknown"),
          verdict_status: ($p.verdict_status // "unknown"),
          index_decision: decision($reasons),
          reuse_eligible: (($reasons | length) == 0),
          freshness: freshness($reasons),
          invalidation_reasons: $reasons,
          remediation: remediation($reasons),
          source_revision: ($p.source_revision // ""),
          dependency_closure_fingerprint: ($p.dependency_closure_fingerprint // ""),
          rch_version: ($p.rch_version // ""),
          toolchain: ($p.toolchain // ""),
          expires_at_epoch: ($p.expires_at_epoch // null),
          artifact_bundle: ($p.artifact_bundle // {}),
          artifact_paths: ($p.artifact_paths // {}),
          receipt_kind: (if ($reasons | length) == 0 then "positive_reuse_receipt" else "negative_reuse_refusal_receipt" end)
        }
    )) as $rows
  | {
      schema_version: $schema_version,
      case_id: $case_id,
      source_revision: $source_revision,
      row_count: ($rows | length),
      reusable_count: ($rows | map(select(.reuse_eligible == true)) | length),
      refused_count: ($rows | map(select(.reuse_eligible == false)) | length),
      rows: $rows,
      artifact_paths: {
        input_normalized_json: $input_path,
        proof_artifact_index_json: $index_path,
        proof_artifact_index_jsonl: $index_jsonl,
        reuse_receipts_jsonl: $reuse_receipts_jsonl,
        reuse_refusal_receipts_jsonl: $refusal_receipts_jsonl,
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
        changes_live_queue_policy: false
      }
    }
  ' >"$index_tmp"

index_hash="$(jq -cS '{case_id,row_count,reusable_count,refused_count,rows}' "$index_tmp" | sha256sum | awk '{print $1}')"
jq --arg index_hash "$index_hash" '. + {index_hash: $index_hash}' "$index_tmp" >"$index_path"

jq -c '.rows[]' "$index_path" >"$index_jsonl"
jq -c '.rows[] | select(.reuse_eligible == true)' "$index_path" >"$reuse_receipts_jsonl"
jq -c '.rows[] | select(.reuse_eligible == false)' "$index_path" >"$refusal_receipts_jsonl"

reusable_count="$(jq -r '.reusable_count' "$index_path")"
refused_count="$(jq -r '.refused_count' "$index_path")"
write_event "index.completed" "ok" "reusable=${reusable_count} refused=${refused_count}"

{
  printf '# Swarm Proof Artifact Index\n\n'
  printf -- "- case_id: \`%s\`\n" "$case_id"
  printf -- "- index_hash: \`%s\`\n" "$index_hash"
  printf -- "- reusable_count: \`%s\`\n" "$reusable_count"
  printf -- "- refused_count: \`%s\`\n" "$refused_count"
} >"$report_path"
