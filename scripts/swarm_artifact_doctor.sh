#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_ARTIFACT_DOCTOR_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-artifact-doctor}"
run_id="${SWARM_ARTIFACT_DOCTOR_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_ARTIFACT_DOCTOR_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${SWARM_ARTIFACT_DOCTOR_SOURCE_REVISION:-}"
original_args=("$@")

declare -a artifact_dirs=()
contract_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_artifact_doctor.sh --artifact-dir DIR [--artifact-dir DIR ...] [OPTIONS]

Validates preserved SWARM gate bundles for replay integrity. The doctor is
strictly read-only: it never deletes, repairs, rewrites, runs Cargo, invokes rch,
creates beads, or mutates inspected bundles.

Required:
  --artifact-dir DIR       Bundle/run directory to inspect; may be repeated

Options:
  --contract-json FILE     Optional contract metadata with required_files or required_artifacts
  --output-dir DIR
  --source-revision REV

Writes:
  artifact_doctor_report.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0   pass or warning-only diagnostics
  42  error diagnostics found
  64  invalid option or malformed input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --artifact-dir)
      artifact_dirs+=("${2:-}")
      shift 2
      ;;
    --contract-json)
      contract_json="${2:-}"
      shift 2
      ;;
    --output-dir)
      run_dir="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
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

if [[ "${#artifact_dirs[@]}" -eq 0 ]]; then
  printf 'at least one --artifact-dir is required\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm artifact doctor\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for artifact hash checks\n' >&2
  exit 2
fi
if [[ -n "$contract_json" && ! -f "$contract_json" ]]; then
  printf 'contract JSON not found: %s\n' "$contract_json" >&2
  exit 64
fi
if [[ -n "$contract_json" ]] && ! jq empty "$contract_json" >/dev/null 2>&1; then
  printf 'invalid contract JSON: %s\n' "$contract_json" >&2
  exit 64
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
doctor_report_path="${run_dir}/artifact_doctor_report.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
diagnostics_jsonl="${run_dir}/diagnostics.jsonl"
required_files_path="${run_dir}/required_files.txt"
doctor_report_tmp="${doctor_report_path}.tmp"

for artifact_path in \
  "$doctor_report_path" \
  "$events_path" \
  "$commands_path" \
  "$report_path" \
  "$diagnostics_jsonl" \
  "$required_files_path" \
  "$doctor_report_tmp"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

: >"$events_path"
: >"$diagnostics_jsonl"
printf './scripts/swarm_artifact_doctor.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  local event="$1"
  local outcome="$2"
  local detail="$3"
  local evidence_path="$4"

  jq -nc \
    --arg schema_version "franken-engine.swarm-artifact-doctor.event.v1" \
    --arg component "swarm_artifact_doctor" \
    --arg event "$event" \
    --arg outcome "$outcome" \
    --arg detail "$detail" \
    --arg evidence_path "$evidence_path" \
    '{
      schema_version: $schema_version,
      component: $component,
      event: $event,
      outcome: $outcome,
      detail: $detail,
      evidence_path: $evidence_path
    }' >>"$events_path"
}

emit_diag() {
  local bundle_id="$1"
  local severity="$2"
  local code="$3"
  local path="$4"
  local detail="$5"
  local remediation="$6"

  jq -nc \
    --arg schema_version "franken-engine.swarm-artifact-doctor.diagnostic.v1" \
    --arg bundle_id "$bundle_id" \
    --arg severity "$severity" \
    --arg code "$code" \
    --arg path "$path" \
    --arg detail "$detail" \
    --arg remediation "$remediation" \
    '{
      schema_version: $schema_version,
      bundle_id: $bundle_id,
      severity: $severity,
      code: $code,
      path: (if $path == "" then null else $path end),
      detail: $detail,
      remediation: $remediation
    }' >>"$diagnostics_jsonl"
}

resolve_bundle_path() {
  local bundle_dir="$1"
  local candidate="$2"
  if [[ "$candidate" = /* ]]; then
    printf '%s\n' "$candidate"
  else
    printf '%s/%s\n' "$bundle_dir" "$candidate"
  fi
}

write_required_files() {
  local bundle_dir="$1"
  local manifest_path="${bundle_dir}/run_manifest.json"

  : >"$required_files_path"
  {
    printf 'run_manifest.json\n'
    printf 'events.jsonl\n'
    printf 'commands.txt\n'
    printf 'report.md\n'
  } >>"$required_files_path"

  if [[ -n "$contract_json" ]]; then
    jq -r '
      (.required_files // .required_artifacts // .artifact_contract.required_files // [])
      | .[]?
      | strings
    ' "$contract_json" >>"$required_files_path"
  fi

  if [[ -f "$manifest_path" ]] && jq empty "$manifest_path" >/dev/null 2>&1; then
    jq -r '
      (.artifact_paths // {})
      | to_entries[]
      | .value
      | if type == "array" then .[] else . end
      | strings
    ' "$manifest_path" >>"$required_files_path"
  fi

  sort -u "$required_files_path" -o "$required_files_path"
}

check_hashes() {
  local bundle_id="$1"
  local bundle_dir="$2"
  local manifest_path="${bundle_dir}/run_manifest.json"
  local rel_path expected_hash actual_hash resolved_path

  if [[ ! -f "$manifest_path" ]] || ! jq empty "$manifest_path" >/dev/null 2>&1; then
    return
  fi

  while IFS=$'\t' read -r rel_path expected_hash; do
    [[ -z "$rel_path" ]] && continue
    resolved_path="$(resolve_bundle_path "$bundle_dir" "$rel_path")"
    if [[ ! -f "$resolved_path" ]]; then
      emit_diag "$bundle_id" "error" "hash_target_missing" "$rel_path" "manifest content_hashes references a missing file" "Restore the hashed artifact or remove the stale hash after regenerating the bundle."
      continue
    fi
    actual_hash="$(sha256sum "$resolved_path" | awk '{print $1}')"
    if [[ "$actual_hash" != "$expected_hash" ]]; then
      emit_diag "$bundle_id" "error" "stale_hash" "$rel_path" "content hash mismatch: expected ${expected_hash}, actual ${actual_hash}" "Regenerate the bundle manifest from current artifact contents before using this evidence."
    fi
  done < <(
    jq -r '
      (.content_hashes // .hashes // {})
      | to_entries[]
      | [.key, .value]
      | @tsv
    ' "$manifest_path"
  )
}

check_bundle() {
  local bundle_dir="$1"
  local bundle_id manifest_path events_file commands_file required_rel resolved_path schema_version

  bundle_dir="$(cd "$bundle_dir" && pwd)"
  bundle_id="$(basename "$bundle_dir")"
  manifest_path="${bundle_dir}/run_manifest.json"
  events_file="${bundle_dir}/events.jsonl"
  commands_file="${bundle_dir}/commands.txt"

  write_event "bundle.started" "ok" "$bundle_id" "$bundle_dir"

  write_required_files "$bundle_dir"
  while IFS= read -r required_rel; do
    [[ -z "$required_rel" ]] && continue
    resolved_path="$(resolve_bundle_path "$bundle_dir" "$required_rel")"
    if [[ ! -e "$resolved_path" ]]; then
      emit_diag "$bundle_id" "error" "missing_required_artifact" "$required_rel" "required artifact is absent" "Regenerate the bundle or restore the missing artifact before consuming this evidence."
    fi
  done <"$required_files_path"

  if [[ ! -f "$manifest_path" ]]; then
    emit_diag "$bundle_id" "error" "missing_manifest" "run_manifest.json" "run_manifest.json is missing" "Regenerate the bundle with a manifest before replay or dashboard consumption."
  elif ! jq empty "$manifest_path" >/dev/null 2>&1; then
    emit_diag "$bundle_id" "error" "invalid_manifest_json" "run_manifest.json" "run_manifest.json is not valid JSON" "Regenerate or repair the manifest from source artifacts."
  else
    schema_version="$(jq -r '.schema_version // ""' "$manifest_path")"
    if [[ -z "$schema_version" && -z "$contract_json" ]]; then
      emit_diag "$bundle_id" "warning" "unknown_contract" "run_manifest.json" "manifest has no schema_version and no contract metadata was supplied" "Supply --contract-json or add schema_version to the manifest before relying on contract-specific checks."
    fi
    if ! jq -e '(.artifact_paths // {}) | type == "object" and length > 0' "$manifest_path" >/dev/null; then
      emit_diag "$bundle_id" "error" "manifest_missing_artifact_paths" "run_manifest.json" "manifest lacks non-empty artifact_paths" "Regenerate the manifest with explicit artifact paths."
    fi
  fi

  if [[ ! -f "$events_file" ]]; then
    emit_diag "$bundle_id" "error" "missing_events" "events.jsonl" "events.jsonl is missing" "Regenerate the bundle with event evidence."
  elif [[ ! -s "$events_file" ]]; then
    emit_diag "$bundle_id" "error" "empty_events" "events.jsonl" "events.jsonl is empty" "Rerun the producing gate so event evidence is preserved."
  elif ! jq -s . "$events_file" >/dev/null 2>&1; then
    emit_diag "$bundle_id" "error" "invalid_events_jsonl" "events.jsonl" "events.jsonl contains invalid JSON" "Regenerate the event log from the producing gate."
  fi

  if [[ ! -f "$commands_file" ]]; then
    emit_diag "$bundle_id" "error" "missing_commands" "commands.txt" "commands.txt is missing" "Regenerate the bundle with the exact source command receipt."
  elif [[ ! -s "$commands_file" ]]; then
    emit_diag "$bundle_id" "error" "empty_commands" "commands.txt" "commands.txt is empty" "Regenerate the bundle with the exact source command receipt."
  fi

  # rch-policy-waive: local_fallback_not_rejected reason=doctor scans preserved bundles for fallback contamination markers
  if grep -Eiq 'local[ _-]*fallback|falling[[:space:]]+back[[:space:]]+to[[:space:]]+local|running[[:space:]]+locally|Executing command locally' "$bundle_dir"/* 2>/dev/null; then
    emit_diag "$bundle_id" "error" "local_fallback_marker" "$bundle_dir" "local fallback marker found in preserved bundle artifacts" "Do not consume this as remote proof; rerun with remote-required rch evidence."
  fi

  check_hashes "$bundle_id" "$bundle_dir"
  write_event "bundle.checked" "ok" "$bundle_id" "$bundle_dir"
}

for artifact_dir in "${artifact_dirs[@]}"; do
  if [[ ! -d "$artifact_dir" ]]; then
    printf 'artifact directory not found: %s\n' "$artifact_dir" >&2
    exit 64
  fi
  check_bundle "$artifact_dir"
done

jq -s \
  --arg schema_version "franken-engine.swarm-artifact-doctor-report.v1" \
  --arg source_revision "$source_revision" \
  --arg contract_json "$contract_json" \
  --arg report_path "$doctor_report_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg markdown_report_path "$report_path" \
  --argjson checked_bundle_count "${#artifact_dirs[@]}" \
  '
    . as $diagnostics
    | {
        schema_version: $schema_version,
        source_revision: $source_revision,
        checked_bundle_count: $checked_bundle_count,
        contract_json: (if $contract_json == "" then null else $contract_json end),
        status: (
          if any($diagnostics[]; .severity == "error") then "fail"
          elif any($diagnostics[]; .severity == "warning") then "warn"
          else "pass"
          end
        ),
        diagnostic_counts: {
          total: ($diagnostics | length),
          errors: ($diagnostics | map(select(.severity == "error")) | length),
          warnings: ($diagnostics | map(select(.severity == "warning")) | length)
        },
        diagnostics: $diagnostics,
        artifact_paths: {
          artifact_doctor_report_json: $report_path,
          events_jsonl: $events_path,
          commands_txt: $commands_path,
          report_md: $markdown_report_path
        },
        non_mutation_attestation: {
          reads_only: true,
          deletes_files: false,
          repairs_bundles: false,
          rewrites_bundles: false,
          runs_cargo: false,
          runs_rch: false,
          creates_beads: false,
          mutates_beads: false
        }
      }
  ' "$diagnostics_jsonl" >"$doctor_report_tmp"
mv "$doctor_report_tmp" "$doctor_report_path"

jq -r '
  "# SWARM Artifact Doctor Report",
  "",
  ("- Status: `" + .status + "`"),
  ("- Checked bundles: `" + (.checked_bundle_count | tostring) + "`"),
  ("- Errors: `" + (.diagnostic_counts.errors | tostring) + "`"),
  ("- Warnings: `" + (.diagnostic_counts.warnings | tostring) + "`"),
  "",
  "## Diagnostics",
  "",
  (if (.diagnostics | length) == 0 then
    "none"
  else
    (.diagnostics[]
      | "- `" + .severity + "` `" + .code + "` `" + (.path // "bundle") + "`: " + .detail + " Remediation: " + .remediation)
  end)
' "$doctor_report_path" >"$report_path"

write_event "doctor.completed" "$(jq -r '.status' "$doctor_report_path")" "artifact doctor report emitted" "$doctor_report_path"

printf 'swarm_artifact_doctor_report=%s\n' "$doctor_report_path"
printf 'swarm_artifact_doctor_events=%s\n' "$events_path"
printf 'swarm_artifact_doctor_markdown=%s\n' "$report_path"

if jq -e '.status == "fail"' "$doctor_report_path" >/dev/null; then
  exit 42
fi
exit 0
