#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_BENCHMARK_BUNDLE_REPLAY_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-benchmark-bundle-replay}"
run_id="${SWARM_BENCHMARK_BUNDLE_REPLAY_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_BENCHMARK_BUNDLE_REPLAY_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

bundle_request_json=""
workspace_root="$root_dir"
source_revision="${SWARM_BENCHMARK_BUNDLE_REPLAY_SOURCE_REVISION:-}"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_benchmark_bundle_replay_normalizer.sh --bundle-request-json FILE [OPTIONS]

Normalize fixture-fed benchmark run manifests, throughput baseline evidence, and
optional remote-stall receipts into one advisory benchmark bundle.

Required:
  --bundle-request-json FILE

Optional:
  --workspace-root DIR
  --source-revision REV
  --output-dir DIR

Artifacts:
  swarm_benchmark_bundle.json
  benchmark_findings.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  bundle emitted with decision pass or degraded
  42 fail-closed contradiction, contamination, malformed evidence, or placeholder claim
  64 invalid arguments or malformed request
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --bundle-request-json)
      bundle_request_json="${2:-}"
      shift 2
      ;;
    --workspace-root)
      workspace_root="${2:-}"
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
  printf 'jq is required for benchmark bundle normalization\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for benchmark bundle normalization\n' >&2
  exit 2
fi
if [[ -z "$bundle_request_json" ]]; then
  printf '%s\n' '--bundle-request-json is required' >&2
  usage
  exit 64
fi
if [[ ! -f "$bundle_request_json" ]]; then
  printf 'bundle request does not exist: %s\n' "$bundle_request_json" >&2
  exit 64
fi
if [[ ! -d "$workspace_root" ]]; then
  printf 'workspace root does not exist: %s\n' "$workspace_root" >&2
  exit 64
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi
if ! jq empty "$bundle_request_json" >/dev/null 2>&1; then
  printf 'bundle request is not valid JSON: %s\n' "$bundle_request_json" >&2
  exit 64
fi
if ! jq -e '(.schema_version | type == "string") and (.evidence_rows | type == "array") and (.source_manifest_json | type == "string")' "$bundle_request_json" >/dev/null; then
  printf 'bundle request is missing schema_version, source_manifest_json, or evidence_rows\n' >&2
  exit 64
fi

resolve_workspace_path() {
  local path="$1"
  if [[ "$path" = /* ]]; then
    printf '%s\n' "$path"
  else
    printf '%s/%s\n' "$workspace_root" "$path"
  fi
}

source_manifest_rel="$(jq -r '.source_manifest_json' "$bundle_request_json")"
source_manifest_json="$(resolve_workspace_path "$source_manifest_rel")"
if [[ ! -f "$source_manifest_json" ]]; then
  printf 'source manifest does not exist: %s\n' "$source_manifest_rel" >&2
  exit 64
fi
if ! jq empty "$source_manifest_json" >/dev/null 2>&1; then
  printf 'source manifest is not valid JSON: %s\n' "$source_manifest_rel" >&2
  exit 64
fi
if ! jq -e '(.source_inventory | type == "array") and (.schema_version | type == "string")' "$source_manifest_json" >/dev/null; then
  printf 'source manifest must contain schema_version and source_inventory: %s\n' "$source_manifest_rel" >&2
  exit 64
fi

mkdir -p "$run_dir"
bundle_path="${run_dir}/swarm_benchmark_bundle.json"
findings_path="${run_dir}/benchmark_findings.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
request_normalized="${run_dir}/bundle_request.normalized.json"
source_manifest_normalized="${run_dir}/source_manifest.normalized.json"
source_inventory_json="${run_dir}/source_inventory.json"
rows_jsonl="${run_dir}/bundle_rows.jsonl"
findings_jsonl="${run_dir}/findings.jsonl"
duplicate_workload_ids_path="${run_dir}/duplicate_workload_ids.txt"

: >"$events_path"
: >"$rows_jsonl"
: >"$findings_jsonl"
: >"$duplicate_workload_ids_path"

printf './scripts/swarm_benchmark_bundle_replay_normalizer.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

jq -cS . "$bundle_request_json" >"$request_normalized"
jq -cS . "$source_manifest_json" >"$source_manifest_normalized"
jq -cS '.source_inventory' "$source_manifest_json" >"$source_inventory_json"
request_hash="$(sha256sum "$request_normalized" | awk '{print $1}')"
source_manifest_hash="$(sha256sum "$source_manifest_normalized" | awk '{print $1}')"
jq -r '.evidence_rows[].workload_id // empty' "$bundle_request_json" | sort | uniq -d >"$duplicate_workload_ids_path"

fail_closed_count=0
degraded_count=0

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-benchmark-bundle.event.v1" \
    --arg event_name "$1" \
    --arg detail "$2" \
    --arg source_revision "$source_revision" \
    '{schema_version:$schema_version,event_name:$event_name,detail:$detail,source_revision:$source_revision}' >>"$events_path"
}

append_finding() {
  local severity="$1"
  local code="$2"
  local workload_id="$3"
  local field="$4"
  local detail="$5"

  jq -nc \
    --arg severity "$severity" \
    --arg code "$code" \
    --arg workload_id "$workload_id" \
    --arg field "$field" \
    --arg detail "$detail" \
    '{severity:$severity,code:$code,workload_id:$workload_id,field:$field,detail:$detail}' >>"$findings_jsonl"

  if [[ "$severity" == "fail_closed" ]]; then
    fail_closed_count=$((fail_closed_count + 1))
  elif [[ "$severity" == "degraded" ]]; then
    degraded_count=$((degraded_count + 1))
  fi
  write_event "$severity" "${workload_id}:${code}:${detail}"
}

json_file_exists_and_parseable() {
  local abs_path="$1"
  [[ -f "$abs_path" ]] || return 1
  jq empty "$abs_path" >/dev/null 2>&1
}

jsonl_count_or_fail() {
  local abs_path="$1"
  if [[ ! -f "$abs_path" ]]; then
    return 1
  fi
  if ! jq -s 'length > 0 and all(.[]; type == "object")' "$abs_path" >/dev/null 2>&1; then
    return 1
  fi
  jq -s 'length' "$abs_path"
}

evidence_count="$(jq '.evidence_rows | length' "$bundle_request_json")"
for ((idx = 0; idx < evidence_count; idx++)); do
  row="$(jq -c ".evidence_rows[$idx]" "$bundle_request_json")"
  workload_id="$(jq -r '.workload_id // ""' <<<"$row")"
  if [[ -z "$workload_id" ]]; then
    workload_id="row_index_${idx}"
  fi
  evidence_kind="$(jq -r '.evidence_kind // ""' <<<"$row")"

  row_failed=false
  row_degraded=false
  row_state="observed"
  events_status="not_provided"
  events_line_count=0
  stall_truth_state="not_provided"
  stall_capture_decision="not_provided"
  primary_summary=""

  if grep -Fxq "$workload_id" "$duplicate_workload_ids_path"; then
    append_finding "fail_closed" "FE-SWARM-BUNDLE-DUPLICATE-WORKLOAD" "$workload_id" "workload_id" "duplicate workload_id in bundle request"
    row_failed=true
  fi

  source_row="$(jq -c --arg workload_id "$workload_id" '.source_inventory[] | select(.workload_id == $workload_id)' "$source_manifest_json" | head -n 1)"
  if [[ -z "$source_row" ]]; then
    append_finding "fail_closed" "FE-SWARM-BUNDLE-UNKNOWN-WORKLOAD" "$workload_id" "workload_id" "workload id is not present in the source manifest"
    row_failed=true
    source_row='{}'
  fi

  primary_artifact_rel="$(jq -r '.primary_artifact_json // ""' <<<"$row")"
  primary_artifact_abs="$(resolve_workspace_path "$primary_artifact_rel")"
  if [[ -z "$primary_artifact_rel" || ! -f "$primary_artifact_abs" ]]; then
    append_finding "fail_closed" "FE-SWARM-BUNDLE-MALFORMED-MANIFEST" "$workload_id" "primary_artifact_json" "primary artifact is missing: ${primary_artifact_rel}"
    row_failed=true
  elif ! jq empty "$primary_artifact_abs" >/dev/null 2>&1; then
    append_finding "fail_closed" "FE-SWARM-BUNDLE-MALFORMED-MANIFEST" "$workload_id" "primary_artifact_json" "primary artifact is not valid JSON: ${primary_artifact_rel}"
    row_failed=true
  fi

  events_rel="$(jq -r '.events_jsonl // ""' <<<"$row")"
  if [[ -n "$events_rel" ]]; then
    events_abs="$(resolve_workspace_path "$events_rel")"
    if events_count_candidate="$(jsonl_count_or_fail "$events_abs" 2>/dev/null)"; then
      events_status="provided"
      events_line_count="$events_count_candidate"
    else
      append_finding "fail_closed" "FE-SWARM-BUNDLE-MALFORMED-EVENTS" "$workload_id" "events_jsonl" "events jsonl is missing or malformed: ${events_rel}"
      row_failed=true
    fi
  fi

  stall_rel="$(jq -r '.stall_bundle_json // ""' <<<"$row")"
  if [[ -n "$stall_rel" ]]; then
    stall_abs="$(resolve_workspace_path "$stall_rel")"
    if ! json_file_exists_and_parseable "$stall_abs"; then
      append_finding "fail_closed" "FE-SWARM-BUNDLE-MALFORMED-MANIFEST" "$workload_id" "stall_bundle_json" "stall bundle JSON is missing or malformed: ${stall_rel}"
      row_failed=true
    elif ! jq -e '(.truth_state | type == "string" and length > 0) and (.capture_decision | type == "string" and length > 0) and ((.local_fallback_observed | type) == "boolean")' "$stall_abs" >/dev/null; then
      append_finding "fail_closed" "FE-SWARM-BUNDLE-MALFORMED-MANIFEST" "$workload_id" "stall_bundle_json" "stall bundle JSON lacks truth_state, capture_decision, or local_fallback_observed"
      row_failed=true
    else
      stall_truth_state="$(jq -r '.truth_state' "$stall_abs")"
      stall_capture_decision="$(jq -r '.capture_decision' "$stall_abs")"
    fi
  fi

  if [[ "$row_failed" == "false" ]]; then
    case "$evidence_kind" in
      run_manifest)
        component="$(jq -r '.component // ""' "$primary_artifact_abs")"
        outcome="$(jq -r '.outcome // ""' "$primary_artifact_abs")"
        generated_at_utc="$(jq -r '.generated_at_utc // ""' "$primary_artifact_abs")"
        manifest_artifact_path="$(jq -r '.artifacts.manifest // ""' "$primary_artifact_abs")"

        if [[ -z "$component" ]]; then
          append_finding "fail_closed" "FE-SWARM-BUNDLE-MISSING-PRIMARY-IDENTIFIER" "$workload_id" "component" "run manifest component is missing"
          row_failed=true
        fi
        if [[ -z "$generated_at_utc" && -z "$manifest_artifact_path" ]]; then
          append_finding "fail_closed" "FE-SWARM-BUNDLE-MISSING-PRIMARY-IDENTIFIER" "$workload_id" "generated_at_utc" "run manifest lacks generated_at_utc and artifacts.manifest"
          row_failed=true
        fi
        if [[ "$outcome" != "pass" && "$outcome" != "fail" ]]; then
          append_finding "fail_closed" "FE-SWARM-BUNDLE-MALFORMED-MANIFEST" "$workload_id" "outcome" "run manifest outcome must be pass or fail"
          row_failed=true
        fi

        if [[ "$row_failed" == "false" ]]; then
          primary_summary="$component"
          if [[ -n "$stall_rel" ]]; then
            if jq -e '.local_fallback_observed == true or .truth_state == "contaminated"' "$stall_abs" >/dev/null; then
              append_finding "fail_closed" "FE-SWARM-BUNDLE-LOCAL-FALLBACK-CONTAMINATION" "$workload_id" "stall_bundle_json" "remote-stall receipt is contaminated by local fallback"
              row_failed=true
            elif [[ "$outcome" == "pass" ]]; then
              append_finding "fail_closed" "FE-SWARM-BUNDLE-CONTRADICTORY-STATE" "$workload_id" "stall_bundle_json" "observed manifest cannot also be paired with a remote-stall receipt"
              row_failed=true
            elif [[ "$stall_truth_state" == "confirmed" || "$stall_truth_state" == "degraded" ]]; then
              row_state="recovered_remote_stall"
              row_degraded=true
            elif [[ "$stall_truth_state" == "blocked" ]]; then
              row_state="blocked_remote_validation"
              row_degraded=true
            else
              append_finding "fail_closed" "FE-SWARM-BUNDLE-MALFORMED-MANIFEST" "$workload_id" "stall_bundle_json" "unsupported stall bundle truth_state: ${stall_truth_state}"
              row_failed=true
            fi
          elif [[ "$outcome" == "pass" ]]; then
            row_state="observed"
          else
            row_state="blocked"
            row_degraded=true
          fi
        fi
        ;;
      throughput_baselines)
        if ! jq -e '(.schema_version | type == "string" and length > 0) and (.runtimes | type == "object") and (.runtimes.frankenengine | type == "object")' "$primary_artifact_abs" >/dev/null; then
          append_finding "fail_closed" "FE-SWARM-BUNDLE-MISSING-PRIMARY-IDENTIFIER" "$workload_id" "runtimes.frankenengine" "throughput baseline artifact lacks the frankenengine runtime row"
          row_failed=true
        else
          measurement_status="$(jq -r '.runtimes.frankenengine.measurement_status // ""' "$primary_artifact_abs")"
          baseline_ops_per_second="$(jq -r '.runtimes.frankenengine.baseline_ops_per_second // 0' "$primary_artifact_abs")"
          workload_results_count="$(jq '.runtimes.frankenengine.workload_results | if type == "object" then length else 0 end' "$primary_artifact_abs")"
          blocker_count="$(jq '.runtimes.frankenengine.blockers | if type == "array" then length else 0 end' "$primary_artifact_abs")"
          primary_summary="frankenengine"

          case "$measurement_status" in
            observed)
              if [[ "$baseline_ops_per_second" -le 0 ]]; then
                append_finding "fail_closed" "FE-SWARM-BUNDLE-MISSING-PRIMARY-IDENTIFIER" "$workload_id" "baseline_ops_per_second" "observed throughput row must publish a positive baseline_ops_per_second"
                row_failed=true
              else
                row_state="observed"
              fi
              ;;
            blocked)
              if [[ "$baseline_ops_per_second" -gt 0 || "$workload_results_count" -gt 0 ]]; then
                append_finding "fail_closed" "FE-SWARM-BUNDLE-PLACEHOLDER-THROUGHPUT" "$workload_id" "runtimes.frankenengine" "blocked throughput row still publishes placeholder ops/sec or workload results"
                row_failed=true
              elif [[ "$blocker_count" -le 0 ]]; then
                append_finding "fail_closed" "FE-SWARM-BUNDLE-MISSING-PRIMARY-IDENTIFIER" "$workload_id" "runtimes.frankenengine.blockers" "blocked throughput row must preserve at least one blocker"
                row_failed=true
              else
                row_state="blocked"
                row_degraded=true
              fi
              ;;
            *)
              append_finding "fail_closed" "FE-SWARM-BUNDLE-MALFORMED-MANIFEST" "$workload_id" "measurement_status" "unsupported throughput measurement_status: ${measurement_status}"
              row_failed=true
              ;;
          esac
        fi
        ;;
      *)
        append_finding "fail_closed" "FE-SWARM-BUNDLE-MALFORMED-MANIFEST" "$workload_id" "evidence_kind" "unsupported evidence_kind: ${evidence_kind}"
        row_failed=true
        ;;
    esac
  fi

  if [[ "$row_failed" == "true" ]]; then
    row_state="fail_closed"
  elif [[ "$row_degraded" == "true" ]]; then
    degraded_count=$((degraded_count + 1))
  fi

  row_hash="$(jq -cS . <<<"$row" | sha256sum | awk '{print $1}')"
  jq -cS \
    --arg workload_id "$workload_id" \
    --arg evidence_kind "$evidence_kind" \
    --arg row_state "$row_state" \
    --arg primary_summary "$primary_summary" \
    --arg row_hash "$row_hash" \
    --arg events_status "$events_status" \
    --arg stall_truth_state "$stall_truth_state" \
    --arg stall_capture_decision "$stall_capture_decision" \
    --argjson events_line_count "$events_line_count" \
    --arg source_manifest_row "$source_row" \
    '
      . as $request_row
      | ($source_manifest_row | fromjson) as $source_row
      | {
          workload_id: $workload_id,
          evidence_kind: $evidence_kind,
          row_state: $row_state,
          primary_summary: $primary_summary,
          row_hash: $row_hash,
          source_contract: {
            benchmark_class: ($source_row.benchmark_class // null),
            benchmark_entrypoint: ($source_row.benchmark_entrypoint // null),
            replay_entrypoint: ($source_row.replay_entrypoint // null),
            result_state: ($source_row.result_schema.result_state // null)
          },
          evidence_request: $request_row,
          events_status: $events_status,
          events_line_count: $events_line_count,
          stall_receipt: {
            truth_state: $stall_truth_state,
            capture_decision: $stall_capture_decision
          }
        }
    ' <<<"$row" >>"$rows_jsonl"
done

rows_json="${run_dir}/bundle_rows.json"
findings_json="${run_dir}/findings.json"
jq -s . "$rows_jsonl" >"$rows_json"
jq -s . "$findings_jsonl" >"$findings_json"

if [[ "$fail_closed_count" -gt 0 ]]; then
  decision="fail_closed"
  exit_code=42
elif jq -e 'any(.[]?; .row_state != "observed")' "$rows_json" >/dev/null; then
  decision="degraded"
  exit_code=0
else
  decision="pass"
  exit_code=0
fi

# shellcheck disable=SC2094
jq -n \
  --arg schema_version "franken-engine.swarm-benchmark-bundle.v1" \
  --arg request_schema_version "$(jq -r '.schema_version' "$bundle_request_json")" \
  --arg source_manifest_schema_version "$(jq -r '.schema_version' "$source_manifest_json")" \
  --arg source_revision "$source_revision" \
  --arg source_manifest_json "$source_manifest_rel" \
  --arg request_hash "$request_hash" \
  --arg source_manifest_hash "$source_manifest_hash" \
  --arg decision "$decision" \
  --arg bundle_json "$bundle_path" \
  --arg findings_json_path "$findings_path" \
  --arg events_jsonl "$events_path" \
  --arg commands_txt "$commands_path" \
  --arg report_md "$report_path" \
  --arg bundle_request_json "$bundle_request_json" \
  --argjson fail_closed_count "$fail_closed_count" \
  --argjson degraded_count "$degraded_count" \
  --slurpfile rows "$rows_json" \
  --slurpfile findings "$findings_json" \
  '{
    schema_version: $schema_version,
    request_schema_version: $request_schema_version,
    source_manifest_schema_version: $source_manifest_schema_version,
    source_revision: $source_revision,
    source_manifest_json: $source_manifest_json,
    bundle_request_json: $bundle_request_json,
    request_hash: $request_hash,
    source_manifest_hash: $source_manifest_hash,
    decision: $decision,
    rows: $rows[0],
    findings: $findings[0],
    summary: {
      row_count: ($rows[0] | length),
      observed_count: ([$rows[0][] | select(.row_state == "observed")] | length),
      blocked_count: ([$rows[0][] | select(.row_state == "blocked")] | length),
      blocked_remote_validation_count: ([$rows[0][] | select(.row_state == "blocked_remote_validation")] | length),
      recovered_remote_stall_count: ([$rows[0][] | select(.row_state == "recovered_remote_stall")] | length),
      fail_closed_row_count: ([$rows[0][] | select(.row_state == "fail_closed")] | length),
      fail_closed_finding_count: $fail_closed_count,
      degraded_row_count: ([$rows[0][] | select(.row_state != "observed" and .row_state != "fail_closed")] | length),
      degraded_finding_count: $degraded_count
    },
    artifact_paths: {
      swarm_benchmark_bundle_json: $bundle_json,
      benchmark_findings_json: $findings_json_path,
      events_jsonl: $events_jsonl,
      commands_txt: $commands_txt,
      report_md: $report_md
    },
    mutation_policy: {
      advisory_only: true,
      proof_only: true,
      fixture_fed_only: true,
      mutates_br: false,
      sends_agent_mail: false,
      runs_cargo: false,
      runs_rch: false,
      changes_live_queue_policy: false
    }
  }' >"$bundle_path"

jq -n \
  --arg schema_version "franken-engine.swarm-benchmark-findings.v1" \
  --arg decision "$decision" \
  --arg request_hash "$request_hash" \
  --slurpfile findings "$findings_json" \
  '{schema_version:$schema_version,decision:$decision,request_hash:$request_hash,findings:$findings[0]}' >"$findings_path"

{
  printf '# Swarm Benchmark Bundle Replay Normalization\n\n'
  printf -- "- decision: \`%s\`\n" "$decision"
  printf -- "- rows: \`%s\`\n" "$(jq '.summary.row_count' "$bundle_path")"
  printf -- "- observed rows: \`%s\`\n" "$(jq '.summary.observed_count' "$bundle_path")"
  printf -- "- degraded rows: \`%s\`\n" "$(jq '.summary.degraded_row_count' "$bundle_path")"
  printf -- "- fail_closed rows: \`%s\`\n" "$(jq '.summary.fail_closed_row_count' "$bundle_path")"
  printf -- "- fail_closed findings: \`%s\`\n" "$(jq '.summary.fail_closed_finding_count' "$bundle_path")"
  printf '\n## Rows\n'
  jq -r '.rows[] | "- `" + .workload_id + "` `" + .evidence_kind + "` `" + .row_state + "`"' "$bundle_path"
  if [[ "$(jq '.findings | length' "$bundle_path")" -ne 0 ]]; then
    printf '\n## Findings\n'
    jq -r '.findings[] | "- `" + .workload_id + "` `" + .code + "`: " + .detail' "$bundle_path"
  fi
} >"$report_path"

write_event "bundle_emitted" "$decision"
exit "$exit_code"
