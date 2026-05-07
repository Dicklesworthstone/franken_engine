#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_BENCHMARK_WORKLOAD_CATALOG_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-benchmark-workload-catalog}"
run_id="${SWARM_BENCHMARK_WORKLOAD_CATALOG_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_BENCHMARK_WORKLOAD_CATALOG_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

source_manifest_json=""
workspace_root="$root_dir"
source_revision="${SWARM_BENCHMARK_WORKLOAD_CATALOG_SOURCE_REVISION:-}"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_benchmark_workload_catalog_normalizer.sh --source-manifest-json FILE [OPTIONS]

Normalize a fixture-fed SWARM-BENCH-I benchmark workload manifest into a
deterministic catalog. This script is advisory only: it reads explicit
repo-local files and does not query live br, Agent Mail, RCH, git, cargo,
or workers.

Required:
  --source-manifest-json FILE

Optional:
  --workspace-root DIR
  --source-revision REV
  --output-dir DIR

Artifacts:
  swarm_benchmark_workload_catalog.json
  catalog_findings.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  catalog emitted with decision pass or degraded
  42 fail-closed workload catalog violation
  64 invalid arguments or malformed source manifest
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --source-manifest-json)
      source_manifest_json="${2:-}"
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
  printf 'jq is required for swarm benchmark workload catalog normalization\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for swarm benchmark workload catalog normalization\n' >&2
  exit 2
fi
if [[ -z "$source_manifest_json" ]]; then
  printf '%s\n' '--source-manifest-json is required' >&2
  usage
  exit 64
fi
if [[ ! -f "$source_manifest_json" ]]; then
  printf 'source manifest does not exist: %s\n' "$source_manifest_json" >&2
  exit 64
fi
if [[ ! -d "$workspace_root" ]]; then
  printf 'workspace root does not exist: %s\n' "$workspace_root" >&2
  exit 64
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi
if ! jq empty "$source_manifest_json" >/dev/null 2>&1; then
  printf 'source manifest is not valid JSON: %s\n' "$source_manifest_json" >&2
  exit 64
fi
if ! jq -e '(.source_inventory | type == "array") and (.required_workload_fields | type == "array")' "$source_manifest_json" >/dev/null; then
  printf 'source manifest must contain source_inventory and required_workload_fields arrays\n' >&2
  exit 64
fi

mkdir -p "$run_dir"
catalog_path="${run_dir}/swarm_benchmark_workload_catalog.json"
findings_path="${run_dir}/catalog_findings.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
source_manifest_normalized="${run_dir}/source_manifest.normalized.json"
source_workloads_json="${run_dir}/source_workloads.json"
normalized_workloads_jsonl="${run_dir}/normalized_workloads.jsonl"
findings_jsonl="${run_dir}/findings.jsonl"
duplicate_workload_ids_path="${run_dir}/duplicate_workload_ids.txt"

: >"$events_path"
: >"$findings_jsonl"
: >"$normalized_workloads_jsonl"
: >"$duplicate_workload_ids_path"

printf './scripts/swarm_benchmark_workload_catalog_normalizer.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

jq -cS . "$source_manifest_json" >"$source_manifest_normalized"
source_manifest_hash="$(sha256sum "$source_manifest_normalized" | awk '{print $1}')"
jq -cS '.source_inventory' "$source_manifest_json" >"$source_workloads_json"
required_fields_json="$(jq -c '.required_workload_fields' "$source_manifest_json")"
jq -r '.[].workload_id // empty' "$source_workloads_json" | sort | uniq -d >"$duplicate_workload_ids_path"

fail_closed_count=0
degraded_count=0

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-benchmark-workload-catalog.event.v1" \
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

check_existing_path() {
  local severity="$1"
  local code="$2"
  local workload_id="$3"
  local field="$4"
  local path_value="$5"
  local detail_prefix="$6"

  if [[ -z "$path_value" ]]; then
    append_finding "$severity" "$code" "$workload_id" "$field" "${detail_prefix}: path is empty"
    return 1
  fi
  if [[ ! -f "${workspace_root}/${path_value}" ]]; then
    append_finding "$severity" "$code" "$workload_id" "$field" "${detail_prefix}: ${path_value}"
    return 1
  fi
  return 0
}

global_runbook_doc="$(jq -r '.docs.runbook // ""' "$source_manifest_json")"
global_contract_json="$(jq -r '.docs.contract // ""' "$source_manifest_json")"
if ! check_existing_path "fail_closed" "FE-SWARM-BENCH-MISSING-DOC" "__catalog__" "docs.runbook" "$global_runbook_doc" "global runbook not found"; then
  :
fi
if check_existing_path "fail_closed" "FE-SWARM-BENCH-MISSING-CONTRACT" "__catalog__" "docs.contract" "$global_contract_json" "global contract not found"; then
  if ! jq empty "${workspace_root}/${global_contract_json}" >/dev/null 2>&1; then
    append_finding "fail_closed" "FE-SWARM-BENCH-MALFORMED-CONTRACT" "__catalog__" "docs.contract" "global contract JSON is not parseable: ${global_contract_json}"
  elif ! jq -e '(.schema_version | type == "string" and length > 0)' "${workspace_root}/${global_contract_json}" >/dev/null; then
    append_finding "fail_closed" "FE-SWARM-BENCH-MALFORMED-CONTRACT" "__catalog__" "docs.contract" "global contract JSON lacks schema_version: ${global_contract_json}"
  fi
fi

workload_count="$(jq 'length' "$source_workloads_json")"
for ((idx = 0; idx < workload_count; idx++)); do
  row="$(jq -c ".[$idx]" "$source_workloads_json")"
  workload_id="$(jq -r '.workload_id // ""' <<<"$row")"
  if [[ -z "$workload_id" ]]; then
    workload_id="workload_index_${idx}"
  fi

  workload_failed=false
  workload_degraded=false
  replay_evidence_state="provided"

  while IFS= read -r missing_field; do
    append_finding "fail_closed" "FE-SWARM-BENCH-MALFORMED-CONTRACT" "$workload_id" "$missing_field" "missing required workload row field"
    workload_failed=true
  done < <(jq -r --argjson required_fields "$required_fields_json" '
    . as $row
    | $required_fields[] as $field
    | select($row | has($field) | not)
    | $field
  ' <<<"$row")

  if grep -Fxq "$workload_id" "$duplicate_workload_ids_path"; then
    append_finding "fail_closed" "FE-SWARM-BENCH-DUPLICATE-WORKLOAD" "$workload_id" "workload_id" "duplicate workload_id in manifest"
    workload_failed=true
  fi

  benchmark_entrypoint="$(jq -r '.benchmark_entrypoint // ""' <<<"$row")"
  if ! check_existing_path "fail_closed" "FE-SWARM-BENCH-MISSING-BENCHMARK" "$workload_id" "benchmark_entrypoint" "$benchmark_entrypoint" "benchmark entrypoint not found"; then
    workload_failed=true
  fi

  measurement_path="$(jq -r '.measurement_source.path // ""' <<<"$row")"
  if [[ -n "$measurement_path" ]]; then
    if ! check_existing_path "fail_closed" "FE-SWARM-BENCH-MISSING-BENCHMARK" "$workload_id" "measurement_source.path" "$measurement_path" "measurement source path not found"; then
      workload_failed=true
    fi
  fi

  if jq -e 'has("runbook_doc")' <<<"$row" >/dev/null; then
    runbook_doc="$(jq -r '.runbook_doc // ""' <<<"$row")"
    if ! check_existing_path "fail_closed" "FE-SWARM-BENCH-MISSING-DOC" "$workload_id" "runbook_doc" "$runbook_doc" "runbook doc not found"; then
      workload_failed=true
    fi
  fi

  if jq -e 'has("contract_json")' <<<"$row" >/dev/null; then
    contract_json="$(jq -r '.contract_json // ""' <<<"$row")"
    if check_existing_path "fail_closed" "FE-SWARM-BENCH-MISSING-CONTRACT" "$workload_id" "contract_json" "$contract_json" "contract JSON not found"; then
      if ! jq empty "${workspace_root}/${contract_json}" >/dev/null 2>&1; then
        append_finding "fail_closed" "FE-SWARM-BENCH-MALFORMED-CONTRACT" "$workload_id" "contract_json" "contract JSON is not parseable: ${contract_json}"
        workload_failed=true
      elif ! jq -e '(.schema_version | type == "string" and length > 0)' "${workspace_root}/${contract_json}" >/dev/null; then
        append_finding "fail_closed" "FE-SWARM-BENCH-MALFORMED-CONTRACT" "$workload_id" "contract_json" "contract JSON lacks schema_version: ${contract_json}"
        workload_failed=true
      fi
    else
      workload_failed=true
    fi
  fi

  replay_has_field="$(jq -r 'has("replay_entrypoint")' <<<"$row")"
  if [[ "$replay_has_field" == "true" ]]; then
    replay_entrypoint="$(jq -r '.replay_entrypoint // ""' <<<"$row")"
    if [[ -z "$replay_entrypoint" ]]; then
      append_finding "degraded" "FE-SWARM-BENCH-STALE-SOURCE" "$workload_id" "replay_entrypoint" "optional replay entrypoint is not declared for this workload"
      workload_degraded=true
      replay_evidence_state="missing_optional"
    elif [[ ! -f "${workspace_root}/${replay_entrypoint}" ]]; then
      append_finding "degraded" "FE-SWARM-BENCH-STALE-SOURCE" "$workload_id" "replay_entrypoint" "optional replay entrypoint is missing: ${replay_entrypoint}"
      workload_degraded=true
      replay_evidence_state="missing_optional"
    fi
  fi

  if jq -e '
    (.mutation_policy // {}) as $m
    | any([
        "mutates_br",
        "claims_beads",
        "reassigns_beads",
        "closes_beads",
        "releases_reservations",
        "sends_agent_mail",
        "queries_live_agent_mail",
        "mutates_git",
        "runs_cargo",
        "runs_rch",
        "mutates_remote_workers",
        "changes_live_queue_policy",
        "replaces_operator_status_report"
      ][]; $m[.] == true)
  ' <<<"$row" >/dev/null; then
    append_finding "fail_closed" "FE-SWARM-BENCH-UNSAFE-MUTATION" "$workload_id" "mutation_policy" "workload row claims unsupported live mutation"
    workload_failed=true
  fi

  if jq -e '
    [((.validation_commands // []) | if type == "array" then . else [] end)[]?
      | tostring
      | select(
          test("(^|[[:space:]])cargo (check|test|clippy|run|bench)")
          and (startswith("rch exec -- env CARGO_TARGET_DIR=") | not)
        )
    ] | length > 0
  ' <<<"$row" >/dev/null; then
    append_finding "fail_closed" "FE-SWARM-BENCH-BARE-HEAVY-CARGO" "$workload_id" "validation_commands" "heavy Cargo command is not rch exec -- env CARGO_TARGET_DIR= wrapped"
    workload_failed=true
  fi

  if [[ "$workload_failed" == "true" ]]; then
    workload_state="fail_closed"
  elif [[ "$workload_degraded" == "true" ]]; then
    workload_state="degraded"
  else
    workload_state="pass"
  fi

  workload_hash="$(jq -cS . <<<"$row" | sha256sum | awk '{print $1}')"
  jq -cS \
    --arg workload_state "$workload_state" \
    --arg workload_hash "$workload_hash" \
    --arg replay_evidence_state "$replay_evidence_state" \
    '. + {
      workload_state: $workload_state,
      workload_hash: $workload_hash,
      replay_evidence_state: $replay_evidence_state
    }' <<<"$row" >>"$normalized_workloads_jsonl"
done

if [[ "$fail_closed_count" -gt 0 ]]; then
  decision="fail_closed"
  exit_code=42
elif [[ "$degraded_count" -gt 0 ]]; then
  decision="degraded"
  exit_code=0
else
  decision="pass"
  exit_code=0
fi

jq -s . "$normalized_workloads_jsonl" >"${run_dir}/normalized_workloads.json"
jq -s . "$findings_jsonl" >"${run_dir}/findings.json"

# shellcheck disable=SC2094
jq -n \
  --arg schema_version "franken-engine.swarm-benchmark-workload-catalog.v1" \
  --arg source_revision "$source_revision" \
  --arg source_manifest "$source_manifest_json" \
  --arg source_manifest_hash "$source_manifest_hash" \
  --arg decision "$decision" \
  --arg catalog_json "$catalog_path" \
  --arg findings_json "$findings_path" \
  --arg events_jsonl "$events_path" \
  --arg commands_txt "$commands_path" \
  --arg report_md "$report_path" \
  --arg global_runbook_doc "$global_runbook_doc" \
  --arg global_contract_json "$global_contract_json" \
  --argjson workload_count "$workload_count" \
  --argjson fail_closed_count "$fail_closed_count" \
  --argjson degraded_count "$degraded_count" \
  --slurpfile workloads "${run_dir}/normalized_workloads.json" \
  --slurpfile findings "${run_dir}/findings.json" \
  '{
    schema_version: $schema_version,
    source_revision: $source_revision,
    source_manifest: $source_manifest,
    source_manifest_hash: $source_manifest_hash,
    decision: $decision,
    workload_count: $workload_count,
    fail_closed_count: $fail_closed_count,
    degraded_count: $degraded_count,
    docs: {
      runbook_doc: $global_runbook_doc,
      contract_json: $global_contract_json
    },
    workloads: $workloads[0],
    findings: $findings[0],
    artifact_paths: {
      swarm_benchmark_workload_catalog_json: $catalog_json,
      catalog_findings_json: $findings_json,
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
  }' >"$catalog_path"

jq -n \
  --arg schema_version "franken-engine.swarm-benchmark-workload-catalog-findings.v1" \
  --arg decision "$decision" \
  --arg source_manifest_hash "$source_manifest_hash" \
  --slurpfile findings "${run_dir}/findings.json" \
  '{schema_version:$schema_version,decision:$decision,source_manifest_hash:$source_manifest_hash,findings:$findings[0]}' >"$findings_path"

{
  printf '# Swarm Benchmark Workload Catalog\n\n'
  printf -- "- decision: \`%s\`\n" "$decision"
  printf -- "- workloads: \`%s\`\n" "$workload_count"
  printf -- "- fail_closed findings: \`%s\`\n" "$fail_closed_count"
  printf -- "- degraded findings: \`%s\`\n" "$degraded_count"
  printf -- "- catalog: \`%s\`\n" "$catalog_path"
  printf -- "- findings: \`%s\`\n" "$findings_path"
  if [[ "$fail_closed_count" -gt 0 ]]; then
    printf '\n## Fail-Closed Findings\n'
    jq -r '.[] | select(.severity == "fail_closed") | "- `" + .workload_id + "` `" + .code + "`: " + .detail' "${run_dir}/findings.json"
  fi
  if [[ "$degraded_count" -gt 0 ]]; then
    printf '\n## Degraded Findings\n'
    jq -r '.[] | select(.severity == "degraded") | "- `" + .workload_id + "` `" + .code + "`: " + .detail' "${run_dir}/findings.json"
  fi
} >"$report_path"

write_event "catalog_emitted" "$decision"
exit "$exit_code"
