#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_CONTROL_SURFACE_CATALOG_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-control-surface-catalog}"
run_id="${SWARM_CONTROL_SURFACE_CATALOG_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_CONTROL_SURFACE_CATALOG_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

source_manifest_json=""
workspace_root="$root_dir"
source_revision="${SWARM_CONTROL_SURFACE_CATALOG_SOURCE_REVISION:-}"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_control_surface_catalog_normalizer.sh --source-manifest-json FILE [OPTIONS]

Normalize a fixture-fed SWARM-CTRL-XVII control-surface manifest into a
deterministic catalog. The normalizer reads only explicit files and repo-local
path evidence. It does not query live br, Agent Mail, rch, git, cargo, or workers.

Required:
  --source-manifest-json FILE

Optional:
  --workspace-root DIR
  --source-revision REV
  --output-dir DIR

Artifacts:
  swarm_control_surface_catalog.json
  catalog_findings.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  catalog emitted with decision pass or degraded
  42 fail-closed catalog violation
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
  printf 'jq is required for swarm control-surface catalog normalization\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for swarm control-surface catalog normalization\n' >&2
  exit 2
fi
if [[ -z "$source_manifest_json" ]]; then
  printf '--source-manifest-json is required\n' >&2
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

mkdir -p "$run_dir"
catalog_path="${run_dir}/swarm_control_surface_catalog.json"
findings_path="${run_dir}/catalog_findings.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
source_manifest_normalized="${run_dir}/source_manifest.normalized.json"
source_surfaces_json="${run_dir}/source_surfaces.json"
normalized_surfaces_jsonl="${run_dir}/normalized_surfaces.jsonl"
findings_jsonl="${run_dir}/findings.jsonl"
duplicate_surface_ids_path="${run_dir}/duplicate_surface_ids.txt"

: >"$events_path"
: >"$findings_jsonl"
: >"$normalized_surfaces_jsonl"
: >"$duplicate_surface_ids_path"

printf './scripts/swarm_control_surface_catalog_normalizer.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

jq -cS . "$source_manifest_json" >"$source_manifest_normalized"
source_manifest_hash="$(sha256sum "$source_manifest_normalized" | awk '{print $1}')"

if ! jq -e '((.source_inventory // .surfaces) | type == "array")' "$source_manifest_json" >/dev/null; then
  printf 'source manifest must contain source_inventory or surfaces array\n' >&2
  exit 64
fi
jq -cS '(.source_inventory // .surfaces)' "$source_manifest_json" >"$source_surfaces_json"

required_fields_json="$(jq -c '
  .required_surface_fields // [
    "surface_id",
    "track",
    "purpose",
    "intent_tags",
    "symptom_tags",
    "required_inputs",
    "emitted_artifacts",
    "implementation_script",
    "smoke_script",
    "runbook_doc",
    "contract_json",
    "owning_bead_id",
    "upstream_surface_ids",
    "downstream_surface_ids",
    "mutation_policy",
    "rch_policy",
    "source_freshness_policy",
    "operator_status_section",
    "failure_reason_codes",
    "validation_commands"
  ]
' "$source_manifest_json")"

jq -r '.[].surface_id // empty' "$source_surfaces_json" | sort | uniq -d >"$duplicate_surface_ids_path"

fail_closed_count=0
degraded_count=0

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-control-surface-catalog.event.v1" \
    --arg event_name "$1" \
    --arg detail "$2" \
    --arg source_revision "$source_revision" \
    '{schema_version:$schema_version,event_name:$event_name,detail:$detail,source_revision:$source_revision}' >>"$events_path"
}

append_finding() {
  local severity="$1"
  local code="$2"
  local surface_id="$3"
  local field="$4"
  local detail="$5"

  jq -nc \
    --arg severity "$severity" \
    --arg code "$code" \
    --arg surface_id "$surface_id" \
    --arg field "$field" \
    --arg detail "$detail" \
    '{severity:$severity,code:$code,surface_id:$surface_id,field:$field,detail:$detail}' >>"$findings_jsonl"

  if [[ "$severity" == "fail_closed" ]]; then
    fail_closed_count=$((fail_closed_count + 1))
  elif [[ "$severity" == "degraded" ]]; then
    degraded_count=$((degraded_count + 1))
  fi
  write_event "$severity" "${surface_id}:${code}:${detail}"
}

missing_path_code() {
  case "$1" in
    implementation_script)
      printf 'FE-SWARM-CATALOG-MISSING-SCRIPT'
      ;;
    smoke_script)
      printf 'FE-SWARM-CATALOG-MISSING-SMOKE'
      ;;
    runbook_doc)
      printf 'FE-SWARM-CATALOG-MISSING-DOC'
      ;;
    contract_json)
      printf 'FE-SWARM-CATALOG-MISSING-CONTRACT'
      ;;
    *)
      printf 'FE-SWARM-CATALOG-MISSING-CONTRACT'
      ;;
  esac
}

surface_count="$(jq 'length' "$source_surfaces_json")"
for ((idx = 0; idx < surface_count; idx++)); do
  row="$(jq -c ".[$idx]" "$source_surfaces_json")"
  surface_id="$(jq -r '.surface_id // ""' <<<"$row")"
  if [[ -z "$surface_id" ]]; then
    surface_id="surface_index_${idx}"
  fi

  surface_failed=false
  surface_degraded=false

  while IFS= read -r missing_field; do
    append_finding "fail_closed" "FE-SWARM-CATALOG-MALFORMED-CONTRACT" "$surface_id" "$missing_field" "missing required catalog row field"
    surface_failed=true
  done < <(jq -r --argjson required_fields "$required_fields_json" '
    . as $row
    | $required_fields[] as $field
    | select($row | has($field) | not)
    | $field
  ' <<<"$row")

  if grep -Fxq "$surface_id" "$duplicate_surface_ids_path"; then
    append_finding "fail_closed" "FE-SWARM-CATALOG-DUPLICATE-SURFACE" "$surface_id" "surface_id" "duplicate surface_id in manifest"
    surface_failed=true
  fi

  for path_field in implementation_script smoke_script runbook_doc contract_json; do
    has_field="$(jq -r --arg field "$path_field" 'has($field)' <<<"$row")"
    if [[ "$has_field" != "true" ]]; then
      continue
    fi

    is_null="$(jq -r --arg field "$path_field" '.[$field] == null' <<<"$row")"
    if [[ "$is_null" == "true" ]]; then
      if [[ "$path_field" == "runbook_doc" ]] \
        && jq -e '.source_freshness_policy.missing_runbook_doc_decision == "degraded"' <<<"$row" >/dev/null; then
        append_finding "degraded" "FE-SWARM-CATALOG-MISSING-DOC" "$surface_id" "$path_field" "optional runbook_doc intentionally absent"
        surface_degraded=true
      else
        append_finding "fail_closed" "$(missing_path_code "$path_field")" "$surface_id" "$path_field" "required path is null"
        surface_failed=true
      fi
      continue
    fi

    path_value="$(jq -r --arg field "$path_field" '.[$field] // ""' <<<"$row")"
    if [[ -z "$path_value" ]]; then
      append_finding "fail_closed" "$(missing_path_code "$path_field")" "$surface_id" "$path_field" "required path is empty"
      surface_failed=true
      continue
    fi
    if [[ ! -f "${workspace_root}/${path_value}" ]]; then
      append_finding "fail_closed" "$(missing_path_code "$path_field")" "$surface_id" "$path_field" "path not found: ${path_value}"
      surface_failed=true
      continue
    fi
    if [[ "$path_field" == "contract_json" ]]; then
      if ! jq empty "${workspace_root}/${path_value}" >/dev/null 2>&1; then
        append_finding "fail_closed" "FE-SWARM-CATALOG-MALFORMED-CONTRACT" "$surface_id" "$path_field" "contract JSON is not parseable: ${path_value}"
        surface_failed=true
      elif ! jq -e '(.schema_version | type == "string" and length > 0)' "${workspace_root}/${path_value}" >/dev/null; then
        append_finding "fail_closed" "FE-SWARM-CATALOG-MALFORMED-CONTRACT" "$surface_id" "$path_field" "contract JSON lacks schema_version: ${path_value}"
        surface_failed=true
      fi
    fi
  done

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
    append_finding "fail_closed" "FE-SWARM-CATALOG-UNSAFE-MUTATION" "$surface_id" "mutation_policy" "catalog row claims unsupported live mutation"
    surface_failed=true
  fi

  if jq -e '
    [.validation_commands[]? | select(
      test("(^|[[:space:]])cargo (check|test|clippy|run)")
      and (startswith("rch exec -- env CARGO_TARGET_DIR=") | not)
    )] | length > 0
  ' <<<"$row" >/dev/null; then
    append_finding "fail_closed" "FE-SWARM-CATALOG-BARE-HEAVY-CARGO" "$surface_id" "validation_commands" "heavy Cargo command is not rch exec -- env CARGO_TARGET_DIR= wrapped"
    surface_failed=true
  fi

  if [[ "$surface_failed" == "true" ]]; then
    catalog_state="fail_closed"
  elif [[ "$surface_degraded" == "true" ]]; then
    catalog_state="degraded"
  else
    catalog_state="pass"
  fi
  surface_hash="$(jq -cS . <<<"$row" | sha256sum | awk '{print $1}')"
  jq -cS \
    --arg catalog_state "$catalog_state" \
    --arg surface_hash "$surface_hash" \
    '. + {catalog_state:$catalog_state,surface_hash:$surface_hash}' <<<"$row" >>"$normalized_surfaces_jsonl"
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

jq -s . "$normalized_surfaces_jsonl" >"${run_dir}/normalized_surfaces.json"
jq -s . "$findings_jsonl" >"${run_dir}/findings.json"

# shellcheck disable=SC2094
jq -n \
  --arg schema_version "franken-engine.swarm-control-surface-catalog.v1" \
  --arg source_revision "$source_revision" \
  --arg source_manifest "$source_manifest_json" \
  --arg source_manifest_hash "$source_manifest_hash" \
  --arg decision "$decision" \
  --arg catalog_json "$catalog_path" \
  --arg findings_json "$findings_path" \
  --arg events_jsonl "$events_path" \
  --arg commands_txt "$commands_path" \
  --arg report_md "$report_path" \
  --argjson surface_count "$surface_count" \
  --argjson fail_closed_count "$fail_closed_count" \
  --argjson degraded_count "$degraded_count" \
  --slurpfile surfaces "${run_dir}/normalized_surfaces.json" \
  --slurpfile findings "${run_dir}/findings.json" \
  '{
    schema_version: $schema_version,
    source_revision: $source_revision,
    source_manifest: $source_manifest,
    source_manifest_hash: $source_manifest_hash,
    decision: $decision,
    surface_count: $surface_count,
    fail_closed_count: $fail_closed_count,
    degraded_count: $degraded_count,
    surfaces: $surfaces[0],
    findings: $findings[0],
    artifact_paths: {
      swarm_control_surface_catalog_json: $catalog_json,
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
  --arg schema_version "franken-engine.swarm-control-surface-catalog-findings.v1" \
  --arg decision "$decision" \
  --arg source_manifest_hash "$source_manifest_hash" \
  --slurpfile findings "${run_dir}/findings.json" \
  '{schema_version:$schema_version,decision:$decision,source_manifest_hash:$source_manifest_hash,findings:$findings[0]}' >"$findings_path"

{
  printf '# Swarm Control-Surface Catalog\n\n'
  printf -- "- decision: \`%s\`\n" "$decision"
  printf -- "- surfaces: \`%s\`\n" "$surface_count"
  printf -- "- fail_closed findings: \`%s\`\n" "$fail_closed_count"
  printf -- "- degraded findings: \`%s\`\n" "$degraded_count"
  printf -- "- catalog: \`%s\`\n" "$catalog_path"
  printf -- "- findings: \`%s\`\n" "$findings_path"
} >"$report_path"

write_event "catalog_emitted" "$decision"
exit "$exit_code"
