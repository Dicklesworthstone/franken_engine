#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo_root="${REMOTE_PROOF_CONTRACT_CATALOG_GATE_REPO_ROOT:-$root_dir}"
artifact_root="${REMOTE_PROOF_CONTRACT_CATALOG_GATE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-remote-proof-contract-catalog-gate}"
run_id="${REMOTE_PROOF_CONTRACT_CATALOG_GATE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${REMOTE_PROOF_CONTRACT_CATALOG_GATE_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

surface_manifest_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/remote_proof_contract_catalog_gate.sh --surface-manifest-json FILE [OPTIONS]

Validate that remote-proof control-plane contracts, implementation scripts,
smoke scripts, operator docs, and upstream schema links still agree.

Required:
  --surface-manifest-json FILE

Optional:
  --output-dir DIR
  --repo-root DIR

Artifacts:
  contract_catalog_report.json
  surface_manifest.normalized.json
  catalog_entries.jsonl
  commands.txt
  events.jsonl
  report.md

Exit codes:
  0  contract catalog is coherent
  42 fail-closed due to catalog drift
  64 invalid or missing input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --surface-manifest-json)
      surface_manifest_json="${2:-}"
      shift 2
      ;;
    --output-dir)
      run_dir="${2:-}"
      shift 2
      ;;
    --repo-root)
      repo_root="${2:-}"
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

if [[ -z "$surface_manifest_json" ]]; then
  printf 'remote proof contract catalog gate requires --surface-manifest-json\n' >&2
  usage
  exit 64
fi
if [[ -z "$repo_root" || ! -d "$repo_root" ]]; then
  printf 'remote proof contract catalog gate requires an existing --repo-root directory: %s\n' "$repo_root" >&2
  exit 64
fi
if [[ ! -f "$surface_manifest_json" ]]; then
  printf 'remote proof contract catalog gate missing surface manifest JSON: %s\n' "$surface_manifest_json" >&2
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for remote proof contract catalog gating\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for remote proof contract catalog gating\n' >&2
  exit 2
fi
if ! jq empty "$surface_manifest_json" >/dev/null 2>&1; then
  printf 'remote proof contract catalog gate invalid surface manifest JSON: %s\n' "$surface_manifest_json" >&2
  exit 64
fi

mkdir -p "$run_dir"
manifest_normalized="${run_dir}/surface_manifest.normalized.json"
entries_path="${run_dir}/catalog_entries.jsonl"
entries_array_path="${run_dir}/catalog_entries.json"
findings_path="${run_dir}/findings.jsonl"
findings_array_path="${run_dir}/findings.json"
report_path="${run_dir}/contract_catalog_report.json"
report_tmp="${report_path}.tmp"
summary_path="${run_dir}/report.md"
summary_tmp="${summary_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
: >"$entries_path"
: >"$findings_path"
: >"$events_path"

printf './scripts/remote_proof_contract_catalog_gate.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  jq -nc \
    --arg event "$1" \
    --arg detail "$2" \
    '{event: $event, detail: $detail}' >>"$events_path"
}

record_finding() {
  local surface_id="$1"
  local code="$2"
  local detail="$3"

  jq -nc \
    --arg surface_id "$surface_id" \
    --arg code "$code" \
    --arg detail "$detail" \
    '{
      severity: "error",
      surface_id: (if $surface_id == "" then null else $surface_id end),
      code: $code,
      detail: $detail
    }' >>"$findings_path"
}

valid_repo_path() {
  local path="$1"

  [[ -n "$path" && "$path" != /* && "$path" != *".."* ]]
}

abs_path_for() {
  local path="$1"

  printf '%s/%s' "$repo_root" "$path"
}

grep_literal() {
  local needle="$1"
  local path="$2"

  grep -Fq -- "$needle" "$path"
}

jq -cS '
  {
    schema_version: (.schema_version // "unknown"),
    external_schemas: (
      (.external_schemas // [])
      | if type == "array" then map(tostring) else [] end
      | unique
      | sort
    ),
    surfaces: (
      (.surfaces // [])
      | if type == "array" then . else [] end
      | map({
          surface_id: (.surface_id // .id // ""),
          contract_json: (.contract_json // ""),
          implementation_script: (.implementation_script // .script_path // ""),
          smoke_script: (.smoke_script // ""),
          doc_path: (.doc_path // .operator_doc // ""),
          emitted_schema: (.emitted_schema // ""),
          upstream_schemas: (
            (.upstream_schemas // [])
            | if type == "array" then map(tostring) else [] end
            | unique
            | sort
          )
        })
      | sort_by(.surface_id)
    )
  }
' "$surface_manifest_json" >"$manifest_normalized"
write_event "surface_manifest_loaded" "normalized remote-proof surface catalog manifest"

surface_count="$(jq -r '.surfaces | length' "$manifest_normalized")"
if [[ "$surface_count" -eq 0 ]]; then
  record_finding "" "catalog_empty" "surface manifest must list at least one remote-proof surface"
fi

if [[ "$surface_count" -gt 0 ]]; then
  for ((idx = 0; idx < surface_count; idx += 1)); do
    surface_row="${run_dir}/surface-${idx}.json"
    jq -cS ".surfaces[$idx]" "$manifest_normalized" >"$surface_row"

    surface_id="$(jq -r '.surface_id' "$surface_row")"
    contract_json="$(jq -r '.contract_json' "$surface_row")"
    implementation_script="$(jq -r '.implementation_script' "$surface_row")"
    smoke_script="$(jq -r '.smoke_script' "$surface_row")"
    doc_path="$(jq -r '.doc_path' "$surface_row")"
    emitted_schema="$(jq -r '.emitted_schema' "$surface_row")"
    manifest_upstream_json="$(jq -c '.upstream_schemas' "$surface_row")"

    contract_schema_version=""
    contract_upstream_json="[]"
    required_inputs_json="[]"
    required_artifacts_json="[]"
    determinism_present="false"

    if [[ -z "$surface_id" ]]; then
      record_finding "" "missing_surface_id" "surface row ${idx} must declare surface_id"
      surface_id="surface-${idx}"
    fi

    for path_field in contract_json implementation_script smoke_script doc_path; do
      path_value="${!path_field}"
      if ! valid_repo_path "$path_value"; then
        record_finding "$surface_id" "unsupported_path_shape" "${path_field} must be a non-empty repo-relative path without parent traversal"
      fi
    done

    if [[ -z "$emitted_schema" ]]; then
      record_finding "$surface_id" "missing_emitted_schema" "surface must declare the schema emitted by its implementation"
    fi

    contract_abs=""
    implementation_abs=""
    smoke_abs=""
    doc_abs=""
    if valid_repo_path "$contract_json"; then
      contract_abs="$(abs_path_for "$contract_json")"
    fi
    if valid_repo_path "$implementation_script"; then
      implementation_abs="$(abs_path_for "$implementation_script")"
    fi
    if valid_repo_path "$smoke_script"; then
      smoke_abs="$(abs_path_for "$smoke_script")"
    fi
    if valid_repo_path "$doc_path"; then
      doc_abs="$(abs_path_for "$doc_path")"
    fi

    if [[ -z "$contract_abs" || ! -f "$contract_abs" ]]; then
      record_finding "$surface_id" "missing_contract_json" "contract JSON is missing: ${contract_json}"
    elif ! jq empty "$contract_abs" >/dev/null 2>&1; then
      record_finding "$surface_id" "invalid_contract_json" "contract JSON is not valid JSON: ${contract_json}"
    else
      contract_schema_version="$(jq -r '.schema_version // ""' "$contract_abs")"
      contract_upstream_json="$(jq -c '(.required_upstream_schemas // []) | if type == "array" then map(tostring) else [] end | unique | sort' "$contract_abs")"
      required_inputs_json="$(jq -c '(.required_inputs // []) | if type == "array" then map(tostring) else [] end | unique | sort' "$contract_abs")"
      required_artifacts_json="$(jq -c '(.required_artifacts // []) | if type == "array" then map(tostring) else [] end | unique | sort' "$contract_abs")"
      determinism_present="$(jq -r '(.determinism | type) == "object"' "$contract_abs")"

      if [[ -z "$contract_schema_version" ]]; then
        record_finding "$surface_id" "missing_contract_schema_version" "contract JSON must declare schema_version"
      fi
      if [[ "$(jq -r 'length' <<<"$required_inputs_json")" -eq 0 ]]; then
        record_finding "$surface_id" "missing_required_inputs" "contract JSON must declare required_inputs"
      fi
      if [[ "$(jq -r 'length' <<<"$required_artifacts_json")" -eq 0 ]]; then
        record_finding "$surface_id" "missing_required_artifacts" "contract JSON must declare required_artifacts"
      fi
      if [[ "$determinism_present" != "true" ]]; then
        record_finding "$surface_id" "missing_determinism_metadata" "contract JSON must declare determinism metadata"
      fi
    fi

    upstream_schemas_json="$(jq -nc --argjson manifest "$manifest_upstream_json" --argjson contract "$contract_upstream_json" '$manifest + $contract | unique | sort')"

    if [[ -z "$implementation_abs" || ! -f "$implementation_abs" ]]; then
      record_finding "$surface_id" "missing_implementation_script" "implementation script is missing: ${implementation_script}"
    else
      while IFS= read -r required_input; do
        if [[ -n "$required_input" ]] && ! grep_literal "$required_input" "$implementation_abs"; then
          record_finding "$surface_id" "implementation_missing_required_input" "implementation script does not mention required input ${required_input}"
        fi
      done < <(jq -r '.[]' <<<"$required_inputs_json")
    fi

    if [[ -z "$smoke_abs" || ! -f "$smoke_abs" ]]; then
      record_finding "$surface_id" "missing_smoke_script" "smoke script is missing: ${smoke_script}"
    else
      if ! grep_literal "check)" "$smoke_abs"; then
        record_finding "$surface_id" "smoke_missing_check_mode" "smoke script must expose a check mode"
      fi
      if ! grep_literal "selftest)" "$smoke_abs"; then
        record_finding "$surface_id" "smoke_missing_selftest_mode" "smoke script must expose a selftest mode"
      fi
    fi

    if [[ -z "$doc_abs" || ! -f "$doc_abs" ]]; then
      record_finding "$surface_id" "missing_operator_doc" "operator doc is missing: ${doc_path}"
    else
      if [[ -n "$implementation_script" ]] && ! grep_literal "$implementation_script" "$doc_abs"; then
        record_finding "$surface_id" "doc_missing_implementation_script" "operator doc does not mention ${implementation_script}"
      fi
      if [[ -n "$emitted_schema" ]] && ! grep_literal "$emitted_schema" "$doc_abs"; then
        record_finding "$surface_id" "doc_missing_emitted_schema" "operator doc does not mention emitted schema ${emitted_schema}"
      fi
      while IFS= read -r required_artifact; do
        if [[ -n "$required_artifact" ]] && ! grep_literal "$required_artifact" "$doc_abs"; then
          record_finding "$surface_id" "doc_missing_required_artifact" "operator doc does not mention required artifact ${required_artifact}"
        fi
      done < <(jq -r '.[]' <<<"$required_artifacts_json")
    fi

    jq -nc \
      --arg surface_id "$surface_id" \
      --arg contract_json "$contract_json" \
      --arg implementation_script "$implementation_script" \
      --arg smoke_script "$smoke_script" \
      --arg doc_path "$doc_path" \
      --arg emitted_schema "$emitted_schema" \
      --arg contract_schema_version "$contract_schema_version" \
      --argjson required_inputs "$required_inputs_json" \
      --argjson required_artifacts "$required_artifacts_json" \
      --argjson upstream_schemas "$upstream_schemas_json" \
      '{
        surface_id: $surface_id,
        contract_json: $contract_json,
        implementation_script: $implementation_script,
        smoke_script: $smoke_script,
        doc_path: $doc_path,
        contract_schema_version: $contract_schema_version,
        emitted_schema: $emitted_schema,
        upstream_schemas: $upstream_schemas,
        required_inputs: $required_inputs,
        required_artifacts: $required_artifacts
      }' >>"$entries_path"
    write_event "surface_cataloged" "$surface_id"
  done
fi

jq -s 'sort_by(.surface_id)' "$entries_path" >"$entries_array_path"

while IFS= read -r duplicate_surface_id; do
  record_finding "$duplicate_surface_id" "duplicate_surface_id" "surface_id appears more than once in the catalog"
done < <(jq -r '[.[].surface_id | select(length > 0)] | group_by(.)[] | select(length > 1) | .[0]' "$entries_array_path")

while IFS= read -r duplicate_contract_schema; do
  record_finding "" "duplicate_contract_schema_version" "contract schema_version appears more than once: ${duplicate_contract_schema}"
done < <(jq -r '[.[].contract_schema_version | select(length > 0)] | group_by(.)[] | select(length > 1) | .[0]' "$entries_array_path")

while IFS= read -r duplicate_emitted_schema; do
  record_finding "" "duplicate_emitted_schema" "emitted_schema appears more than once: ${duplicate_emitted_schema}"
done < <(jq -r '[.[].emitted_schema | select(length > 0)] | group_by(.)[] | select(length > 1) | .[0]' "$entries_array_path")

known_schemas_json="$(jq -nc \
  --slurpfile entries "$entries_array_path" \
  --slurpfile manifest "$manifest_normalized" \
  '(
    ($entries[0] | map(.emitted_schema) | map(select(length > 0)))
    + ($manifest[0].external_schemas // [])
  ) | unique | sort')"

while IFS=$'\t' read -r surface_id upstream_schema; do
  record_finding "$surface_id" "dangling_upstream_schema" "upstream schema is neither emitted by the catalog nor declared external: ${upstream_schema}"
done < <(jq -r --argjson known "$known_schemas_json" '
  .[]
  | . as $surface
  | (.upstream_schemas // [])[] as $upstream
  | select(($known | index($upstream)) == null)
  | [$surface.surface_id, $upstream]
  | @tsv
' "$entries_array_path")

jq -s 'sort_by(.code, (.surface_id // ""), .detail)' "$findings_path" >"$findings_array_path"
finding_count="$(jq -r 'length' "$findings_array_path")"
if [[ "$finding_count" -eq 0 ]]; then
  catalog_decision="pass"
  reason="all catalog surfaces have coherent contracts, docs, scripts, and upstream schema links"
  exit_code=0
else
  catalog_decision="fail_closed"
  reason="remote-proof contract catalog drift detected"
  exit_code=42
fi

catalog_hash="$(jq -cS \
  --slurpfile manifest "$manifest_normalized" \
  --slurpfile entries "$entries_array_path" \
  --slurpfile findings "$findings_array_path" \
  '{manifest: $manifest[0], entries: $entries[0], findings: $findings[0]}' \
  | sha256sum | awk '{print $1}')"
catalog_id="contract-catalog-${catalog_hash:0:16}"

jq -n \
  --arg catalog_id "$catalog_id" \
  --arg catalog_decision "$catalog_decision" \
  --arg reason "$reason" \
  --arg surface_manifest_json "$surface_manifest_json" \
  --arg manifest_normalized "$manifest_normalized" \
  --arg entries_path "$entries_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_md "$summary_path" \
  --arg report_path "$report_path" \
  --arg repo_root "$repo_root" \
  --arg catalog_hash "$catalog_hash" \
  --argjson entries "$(cat "$entries_array_path")" \
  --argjson findings "$(cat "$findings_array_path")" \
  '{
    schema_version: "franken-engine.remote-proof-contract-catalog-report.v1",
    catalog_id: $catalog_id,
    catalog_decision: $catalog_decision,
    reason: $reason,
    surface_count: ($entries | length),
    finding_count: ($findings | length),
    surfaces: $entries,
    findings: $findings,
    hash_basis: {
      catalog_hash: $catalog_hash
    },
    upstream_artifact_paths: {
      surface_manifest_json: $surface_manifest_json,
      repo_root: $repo_root
    },
    artifact_paths: {
      contract_catalog_report_json: $report_path,
      surface_manifest_normalized_json: $manifest_normalized,
      catalog_entries_jsonl: $entries_path,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $report_md
    }
  }' >"$report_tmp"
mv "$report_tmp" "$report_path"

write_event "contract_catalog_completed" "${catalog_decision} with ${finding_count} finding(s)"

{
  printf '# Remote Proof Contract Catalog Gate\n\n'
  printf '%s\n' "- Catalog ID: \`$(jq -r '.catalog_id' "$report_path")\`"
  printf '%s\n' "- Decision: \`$(jq -r '.catalog_decision' "$report_path")\`"
  printf '%s\n' "- Surface count: \`$(jq -r '.surface_count' "$report_path")\`"
  printf '%s\n' "- Finding count: \`$(jq -r '.finding_count' "$report_path")\`"
  printf '\n## Findings\n\n'
  if [[ "$finding_count" -eq 0 ]]; then
    printf -- '- no catalog drift detected\n'
  else
    jq -r '
      .findings[]
      | "- [`" + .severity + "`] `"
        + .code + "`"
        + (if .surface_id == null then "" else " on `" + .surface_id + "`" end)
        + ": " + .detail
    ' "$report_path"
  fi
} >"$summary_tmp"
mv "$summary_tmp" "$summary_path"

printf 'remote_proof_contract_catalog_report=%s\n' "$report_path"
printf 'remote_proof_contract_catalog_summary=%s\n' "$summary_path"

exit "$exit_code"
