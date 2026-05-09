#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${RCH_COMPILE_PROOF_ISOLATION_PROFILE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-rch-compile-proof-isolation-profile}"
run_id="${RCH_COMPILE_PROOF_ISOLATION_PROFILE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${RCH_COMPILE_PROOF_ISOLATION_PROFILE_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

metadata_json=""
changed_paths_json=""
source_revision="${RCH_COMPILE_PROOF_ISOLATION_PROFILE_SOURCE_REVISION:-}"
case_id_override=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/rch_compile_proof_isolation_profile.sh --metadata-json FILE [OPTIONS]

Classifies preserved validation command metadata into a proof-isolation profile.
This profiler is advisory-only: it does not execute Cargo, invoke rch, mutate
beads, send Agent Mail, edit files, or touch workers.

Required:
  --metadata-json FILE

Options:
  --changed-paths-json FILE
  --source-revision REV
  --case-id ID
  --output-dir DIR

Artifacts:
  compile_proof_isolation_profile.json
  run_manifest.json
  events.jsonl
  commands.txt
  report.md
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --metadata-json)
      metadata_json="${2:-}"
      shift 2
      ;;
    --changed-paths-json)
      changed_paths_json="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    --case-id)
      case_id_override="${2:-}"
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

if [[ -z "$metadata_json" ]]; then
  printf 'compile proof isolation profile requires --metadata-json\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for compile proof isolation profiling\n' >&2
  exit 2
fi
if [[ ! -f "$metadata_json" ]]; then
  printf 'metadata JSON not found: %s\n' "$metadata_json" >&2
  exit 64
fi
if ! jq empty "$metadata_json" >/dev/null 2>&1; then
  printf 'invalid metadata JSON: %s\n' "$metadata_json" >&2
  exit 64
fi
if [[ -n "$changed_paths_json" ]]; then
  if [[ ! -f "$changed_paths_json" ]]; then
    printf 'changed paths JSON not found: %s\n' "$changed_paths_json" >&2
    exit 64
  fi
  if ! jq empty "$changed_paths_json" >/dev/null 2>&1; then
    printf 'invalid changed paths JSON: %s\n' "$changed_paths_json" >&2
    exit 64
  fi
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
profile_path="${run_dir}/compile_proof_isolation_profile.json"
profile_tmp="${profile_path}.tmp"
manifest_path="${run_dir}/run_manifest.json"
manifest_tmp="${manifest_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
metadata_normalized_path="${run_dir}/metadata.normalized.json"
changed_paths_normalized_path="${run_dir}/changed_paths.normalized.json"

for artifact_path in \
  "$profile_path" \
  "$profile_tmp" \
  "$manifest_path" \
  "$manifest_tmp" \
  "$events_path" \
  "$commands_path" \
  "$report_path" \
  "$metadata_normalized_path" \
  "$changed_paths_normalized_path"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

: >"$events_path"
printf './scripts/rch_compile_proof_isolation_profile.sh' >"$commands_path"
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
    --arg schema_version "franken-engine.rch-compile-proof-isolation-profile.event.v1" \
    --arg component "rch_compile_proof_isolation_profile" \
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

jq -cS . "$metadata_json" >"$metadata_normalized_path"
if [[ -n "$changed_paths_json" ]]; then
  jq -c '
    if type == "array" then {changed_paths: .}
    else {changed_paths: (.changed_paths // .touched_paths // [])}
    end
  ' "$changed_paths_json" >"$changed_paths_normalized_path"
else
  jq -c '{changed_paths: (.changed_paths // .touched_paths // [])}' "$metadata_normalized_path" >"$changed_paths_normalized_path"
fi

case_id="$(jq -r '.case_id // ""' "$metadata_normalized_path")"
if [[ -n "$case_id_override" ]]; then
  case_id="$case_id_override"
fi

jq -n \
  --slurpfile metadata "$metadata_normalized_path" \
  --slurpfile changed "$changed_paths_normalized_path" \
  --arg schema_version "franken-engine.rch-compile-proof-isolation-profile.v1" \
  --arg source_revision "$source_revision" \
  --arg case_id "$case_id" \
  --arg metadata_json "$metadata_json" \
  --arg changed_paths_json "$changed_paths_json" \
  --arg profile_path "$profile_path" \
  --arg manifest_path "$manifest_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" '
  def low($value): (($value // "") | tostring | ascii_downcase);
  def arr($value): if ($value | type) == "array" then $value else [] end;
  def has_token($command; $token): (" " + $command + " ") | contains(" " + $token + " ");
  def cargo_package($m; $command):
    ($m.package // $m.package_name // $m.cargo_package // (
      if ($command | test("(^|[[:space:]])-p[[:space:]]+[^[:space:]]+")) then
        ($command | capture("(^|[[:space:]])-p[[:space:]]+(?<pkg>[^[:space:]]+)").pkg)
      else "" end
    ));
  def test_target($m; $command):
    ($m.test_target // $m.cargo_test_target // $m.target // (
      if ($command | test("(^|[[:space:]])--test[[:space:]]+[^[:space:]]+")) then
        ($command | capture("(^|[[:space:]])--test[[:space:]]+(?<target>[^[:space:]]+)").target)
      elif has_token($command; "--lib") then "lib"
      elif has_token($command; "--all-targets") then "all-targets"
      else "" end
    ));
  def command_class($command):
    if ($command | test("cargo[[:space:]]+test")) then "cargo_test"
    elif ($command | test("cargo[[:space:]]+check")) then "cargo_check"
    elif ($command | test("cargo[[:space:]]+clippy")) then "cargo_clippy"
    elif ($command | test("(^|[[:space:]])jq[[:space:]]")) then "json_gate"
    elif ($command | test("(^|[[:space:]])(bash|shellcheck|sh)[[:space:]]")) then "shell_gate"
    else "unknown" end;
  def compile_surface($class; $command):
    if $class == "cargo_test" and ($command | test("(^|[[:space:]])--test[[:space:]]+[^[:space:]]+")) then "exact_integration_test"
    elif $class == "cargo_test" and has_token($command; "--lib") then "package_lib_test"
    elif ($class | startswith("cargo_")) and has_token($command; "--all-targets") then "workspace_all_targets"
    elif $class == "cargo_check" then "package_check"
    elif $class == "cargo_clippy" then "package_clippy"
    elif $class == "shell_gate" then "shell_only"
    elif $class == "json_gate" then "json_only"
    else "unknown" end;
  def broadness($surface):
    if $surface == "exact_integration_test" or $surface == "shell_only" or $surface == "json_only" then "narrow"
    elif $surface == "package_check" or $surface == "package_clippy" then "moderate"
    elif $surface == "package_lib_test" or $surface == "workspace_all_targets" then "broad"
    else "unknown" end;
  def proof_strength($surface; $target_relevance):
    if $surface == "exact_integration_test" and $target_relevance != "target_unrelated" then "strong"
    elif ($surface == "shell_only" or $surface == "json_only") and $target_relevance != "target_unrelated" then "medium"
    elif $surface == "package_check" or $surface == "package_clippy" then "medium"
    elif $surface == "package_lib_test" or $surface == "workspace_all_targets" then "weak"
    else "none" end;
  def allowed_fallback($surface; $decision):
    if $decision == "fail_closed" then "none"
    elif $surface == "shell_only" or $surface == "json_only" then "shell_or_json_only"
    elif $surface == "exact_integration_test" or $surface == "package_check" or $surface == "package_clippy" then "rerun_exact_rch"
    else "narrow_rch_only" end;
  def intersects($paths; $hints):
    [$paths[]? as $p | $hints[]? as $h | select(($p | startswith($h)) or ($h | startswith($p)))]
    | length > 0;
  def target_relevance($surface; $paths; $hints):
    if ($paths | length) == 0 then "unknown"
    elif $surface == "shell_only" or $surface == "json_only" then "target_relevant"
    elif ($hints | length) == 0 then "target_ambiguous"
    elif intersects($paths; $hints) then "target_relevant"
    else "target_unrelated" end;
  ($metadata[0]) as $m
  | ($changed[0].changed_paths // []) as $changed_paths
  | (($m.command // $m.validation_command // "") | tostring) as $command
  | command_class($command) as $class
  | compile_surface($class; $command) as $surface
  | cargo_package($m; $command) as $package
  | test_target($m; $command) as $target
  | arr($m.touched_paths) as $touched_paths
  | arr($m.target_paths) as $target_paths
  | ([
      $m.intended_target_path,
      $m.test_file,
      (if $target != "" and $target != "lib" and $target != "all-targets" then ("crates/franken-engine/tests/" + $target + ".rs") else empty end)
    ] + $target_paths | map(select((. // "") != ""))) as $hints
  | target_relevance($surface; (($changed_paths + $touched_paths) | unique); $hints) as $relevance
  | (($m.local_fallback_observed // false) == true or ($command | test("local fallback|Executing command locally|running locally"; "i"))) as $local_fallback
  | (($m.transcript_truncated // false) == true) as $truncated
  | ([
      if $command == "" then "missing_command_metadata" else empty end,
      if $local_fallback then "local_rch_fallback_observed" else empty end,
      if $class == "unknown" then "unknown_validation_command" else empty end,
      if ($class | startswith("cargo_")) and (($package // "") == "") then "cargo_command_without_package" else empty end,
      if $surface == "workspace_all_targets" and (($m.claimed_narrow // false) == true) then "ambiguous_all_targets_claimed_as_narrow" else empty end
    ] | unique) as $fail_reasons
  | (if ($fail_reasons | length) > 0 then "fail_closed"
     elif $surface == "package_lib_test" or $surface == "workspace_all_targets" or $relevance == "target_ambiguous" or $truncated then "degraded"
     else "pass" end) as $decision
  | {
      schema_version: $schema_version,
      case_id: (if $case_id == "" then null else $case_id end),
      source_revision: $source_revision,
      decision: $decision,
      command: {
        text: $command,
        class: $class,
        package: (if ($package // "") == "" then null else $package end),
        target: (if ($target // "") == "" then null else $target end)
      },
      classification: {
        compile_surface: $surface,
        broadness: broadness($surface),
        target_relevance: $relevance,
        proof_strength: (if $decision == "fail_closed" then "none" else proof_strength($surface; $relevance) end),
        allowed_fallback: allowed_fallback($surface; $decision)
      },
      target_context: {
        changed_paths: (($changed_paths + $touched_paths) | unique),
        target_hints: $hints
      },
      evidence_health: {
        local_fallback_observed: $local_fallback,
        transcript_truncated: $truncated,
        missing_command_metadata: ($command == ""),
        fail_closed_reasons: $fail_reasons
      },
      recommendations: (
        if $decision == "fail_closed" then
          ["do_not_use_as_proof", "rerun_with_remote_rch_metadata_before_filing_source_fix"]
        elif $surface == "package_lib_test" or $surface == "workspace_all_targets" then
          ["prefer_exact_integration_or_file_local_filter", "record_unrelated_compile_drift_if_rerun_blocks"]
        elif $relevance == "target_ambiguous" then
          ["add_changed_paths_or_target_hints_before_closing"]
        else
          ["profile_is_suitable_for_manual_review"]
        end
      ),
      artifact_paths: {
        compile_proof_isolation_profile_json: $profile_path,
        run_manifest_json: $manifest_path,
        events_jsonl: $events_path,
        commands_txt: $commands_path,
        report_md: $report_path
      },
      input_artifacts: {
        metadata_json: $metadata_json,
        changed_paths_json: (if $changed_paths_json == "" then null else $changed_paths_json end)
      },
      contract_paths: {
        profile_contract_json: "docs/rch_compile_proof_isolation_profile_contract_v1.json",
        operator_doc: "docs/RCH_COMPILE_PROOF_ISOLATION_PROFILE.md"
      },
      non_mutation_attestation: {
        runs_cargo: false,
        runs_rch: false,
        creates_beads: false,
        mutates_br: false,
        sends_agent_mail: false,
        changes_workers: false
      }
    }' >"$profile_tmp"
mv "$profile_tmp" "$profile_path"

write_event "input.loaded" "ok" "normalized command metadata" "$metadata_json"
write_event "profile.emitted" "$(jq -r '.decision' "$profile_path")" "emitted compile proof isolation profile" "$profile_path"

jq -n \
  --arg schema_version "franken-engine.rch-compile-proof-isolation-profile-run-manifest.v1" \
  --arg source_revision "$source_revision" \
  --arg profile_path "$profile_path" \
  --arg manifest_path "$manifest_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  '{
    schema_version: $schema_version,
    source_revision: $source_revision,
    artifact_paths: {
      compile_proof_isolation_profile_json: $profile_path,
      run_manifest_json: $manifest_path,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $report_path
    },
    mutation_policy: {
      fixture_fed_only: true,
      advisory_only: true,
      runs_cargo: false,
      runs_rch: false,
      creates_beads: false,
      mutates_br: false,
      sends_agent_mail: false,
      mutates_remote_workers: false
    }
  }' >"$manifest_tmp"
mv "$manifest_tmp" "$manifest_path"

jq -r '
  "# RCH Compile Proof Isolation Profile",
  "",
  ("- Decision: `" + .decision + "`"),
  ("- Command class: `" + .command.class + "`"),
  ("- Compile surface: `" + .classification.compile_surface + "`"),
  ("- Broadness: `" + .classification.broadness + "`"),
  ("- Target relevance: `" + .classification.target_relevance + "`"),
  ("- Proof strength: `" + .classification.proof_strength + "`"),
  ("- Allowed fallback: `" + .classification.allowed_fallback + "`"),
  ("- Local fallback observed: `" + (.evidence_health.local_fallback_observed | tostring) + "`"),
  "",
  "## Recommendations",
  "",
  (.recommendations[] | "- `" + . + "`")
' "$profile_path" >"$report_path"

printf 'compile_proof_isolation_profile=%s\n' "$profile_path"
printf 'compile_proof_isolation_report=%s\n' "$report_path"

if jq -e '.decision == "fail_closed"' "$profile_path" >/dev/null; then
  exit 42
fi
exit 0
