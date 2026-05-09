#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_NATIVE_DEPENDENCY_REQUIREMENT_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-native-dependency-requirement}"
run_id="${SWARM_NATIVE_DEPENDENCY_REQUIREMENT_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_NATIVE_DEPENDENCY_REQUIREMENT_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

source_revision="${SWARM_NATIVE_DEPENDENCY_REQUIREMENT_SOURCE_REVISION:-unknown}"
requirement_map_json="${root_dir}/docs/swarm_native_dependency_requirement_map_v1.json"
validation_command_context_json=""
cargo_lock_snapshot_json=""
workspace_manifest_snapshot_json=""
path_dependency_manifests_json=""
build_script_diagnostics_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_native_dependency_requirement_infer.sh [OPTIONS]

Infers native system-library requirements for a proposed validation command from
fixture-fed Cargo.lock, manifest, path dependency, and build-script diagnostic
snapshots. This script is advisory-only. It does not run Cargo or RCH, mutate
workers, install packages, change live queue policy, send Agent Mail, or update
beads.

Required:
  --validation-command-context-json FILE
  --cargo-lock-snapshot-json FILE
  --workspace-manifest-snapshot-json FILE
  --path-dependency-manifests-json FILE
  --build-script-diagnostics-json FILE

Optional:
  --requirement-map-json FILE
  --source-revision REV
  --output-dir DIR

Artifacts:
  native_dependency_requirement_bundle.json
  native_dependency_requirement_sources.json
  events.jsonl
  commands.txt
  summary.md

Exit codes:
  0  requirements were inferred or no native requirements were found
  42 fail-closed due to stale, incomplete, or ambiguous native dependency evidence
  64 invalid invocation or missing input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --validation-command-context-json)
      validation_command_context_json="${2:-}"
      shift 2
      ;;
    --cargo-lock-snapshot-json)
      cargo_lock_snapshot_json="${2:-}"
      shift 2
      ;;
    --workspace-manifest-snapshot-json)
      workspace_manifest_snapshot_json="${2:-}"
      shift 2
      ;;
    --path-dependency-manifests-json)
      path_dependency_manifests_json="${2:-}"
      shift 2
      ;;
    --build-script-diagnostics-json)
      build_script_diagnostics_json="${2:-}"
      shift 2
      ;;
    --requirement-map-json)
      requirement_map_json="${2:-}"
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

if [[ -z "$validation_command_context_json" || -z "$cargo_lock_snapshot_json" || -z "$workspace_manifest_snapshot_json" || -z "$path_dependency_manifests_json" || -z "$build_script_diagnostics_json" ]]; then
  printf 'validation context, Cargo.lock snapshot, workspace manifest snapshot, path dependency manifests, and build-script diagnostics are required\n' >&2
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for native dependency requirement inference\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for native dependency requirement inference\n' >&2
  exit 2
fi

mkdir -p "$run_dir"
bundle_path="${run_dir}/native_dependency_requirement_bundle.json"
sources_path="${run_dir}/native_dependency_requirement_sources.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
summary_path="${run_dir}/summary.md"

validation_normalized="${run_dir}/validation_command_context.normalized.json"
cargo_lock_normalized="${run_dir}/cargo_lock_snapshot.normalized.json"
workspace_normalized="${run_dir}/workspace_manifest_snapshot.normalized.json"
path_deps_normalized="${run_dir}/path_dependency_manifests.normalized.json"
diagnostics_normalized="${run_dir}/build_script_diagnostics.normalized.json"
map_normalized="${run_dir}/requirement_map.normalized.json"

printf './scripts/swarm_native_dependency_requirement_infer.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"
: >"$events_path"

write_event() {
  local validation_id="${1:-unknown}"
  local event="$2"
  local outcome="$3"
  local error_code="$4"
  local detail="$5"
  jq -nc \
    --arg schema_version "franken-engine.native-requirement-infer.event.v1" \
    --arg trace_id "native-requirement-${validation_id}" \
    --arg validation_id "$validation_id" \
    --arg worker_id "not_applicable" \
    --arg dependency_id "not_applicable" \
    --arg component "swarm_native_dependency_requirement_infer" \
    --arg event "$event" \
    --arg outcome "$outcome" \
    --arg error_code "$error_code" \
    --arg detail "$detail" \
    '{schema_version:$schema_version,trace_id:$trace_id,validation_id:$validation_id,worker_id:$worker_id,dependency_id:$dependency_id,component:$component,event:$event,outcome:$outcome,error_code:$error_code,detail:$detail}' \
    >>"$events_path"
}

normalize_required_json() {
  local input="$1"
  local output="$2"
  local label="$3"
  if [[ ! -f "$input" ]]; then
    printf 'missing required %s JSON: %s\n' "$label" "$input" >&2
    exit 64
  fi
  if ! jq empty "$input" >/dev/null 2>&1; then
    printf 'invalid required %s JSON: %s\n' "$label" "$input" >&2
    exit 64
  fi
  jq -cS . "$input" >"$output"
}

normalize_required_json "$validation_command_context_json" "$validation_normalized" "validation command context"
normalize_required_json "$cargo_lock_snapshot_json" "$cargo_lock_normalized" "Cargo.lock snapshot"
normalize_required_json "$workspace_manifest_snapshot_json" "$workspace_normalized" "workspace manifest snapshot"
normalize_required_json "$path_dependency_manifests_json" "$path_deps_normalized" "path dependency manifests"
normalize_required_json "$build_script_diagnostics_json" "$diagnostics_normalized" "build-script diagnostics"
normalize_required_json "$requirement_map_json" "$map_normalized" "requirement map"

validation_id="$(jq -r '.validation_id // "unknown"' "$validation_normalized")"
write_event "$validation_id" "inputs.loaded" "provided" "ok" "normalized input snapshots"

jq -n \
  --arg source_revision "$source_revision" \
  --slurpfile ctx "$validation_normalized" \
  --slurpfile lock "$cargo_lock_normalized" \
  --slurpfile workspace "$workspace_normalized" \
  --slurpfile paths "$path_deps_normalized" \
  --slurpfile diagnostics "$diagnostics_normalized" \
  --slurpfile map "$map_normalized" '
  ($ctx[0]) as $ctx
  | ($lock[0]) as $lock
  | ($workspace[0]) as $workspace
  | ($paths[0]) as $paths
  | ($diagnostics[0]) as $diagnostics
  | ($map[0]) as $map
  | (($workspace.packages // []) + ($paths.packages // [])) as $packages
  | ($packages | map(.name)) as $package_names
  | def package_by_name($name): ($packages[]? | select(.name == $name));
    def lock_package_by_name($name): ($lock.packages[]? | select(.name == $name));
    def dep_name($dep): ($dep.package // $dep.name);
    def dep_enabled($dep):
      if ($dep.optional // false) then
        (($ctx.enabled_optional_dependencies // []) | index(dep_name($dep)) != null)
        or (($ctx.active_features // []) | index($dep.feature // "") != null)
      else true end;
    def closure($roots):
      def visit($seen; $queue):
        if ($queue | length) == 0 then $seen
        else
          ($queue[0]) as $current
          | ($queue[1:]) as $rest
          | if ($seen | index($current)) != null then visit($seen; $rest)
            else
              ((package_by_name($current).dependencies // []) | map(select(dep_enabled(.)) | dep_name(.))) as $deps
              | visit($seen + [$current]; (($rest + $deps) | unique))
            end
        end;
      visit([]; $roots);
    def family_for_crate($crate):
      ($map.native_dependency_families[]? | select((.rust_crates // []) | index($crate) != null));
    def diagnostic_known($diag):
      ($diag.matched_dependency_id // null) as $matched
      | if $matched != null then
          ([($map.native_dependency_families[]?.dependency_id)] | index($matched) != null)
        else
          ((($map.diagnostic_patterns // []) | map(.match as $m | (($diag.message // "") | test($m; "i"))) | any) // false)
        end;
    ($ctx.root_packages // [$ctx.cargo_package]) as $roots
  | (closure($roots)) as $closure
  | ($closure | map(select($package_names | index(.) == null))) as $missing_closure
  | ($packages | map(select(.name as $name | ($closure | index($name) != null)))) as $closure_packages
  | ($closure_packages | map(
      . as $pkg
      | (lock_package_by_name($pkg.name)) as $locked
      | select(($locked == null) or (($locked.version // "") != ($pkg.version // "")))
      | {
          package: $pkg.name,
          manifest_version: ($pkg.version // null),
          cargo_lock_version: ($locked.version // null)
        }
    )) as $version_mismatches
  | ($closure_packages | map(
      . as $pkg
      | (family_for_crate($pkg.name)) as $family
      | select($family != null)
      | {
          dependency_id: $family.dependency_id,
          native_package_name: $family.native_package_name,
          source_crate: $pkg.name,
          source_version: ($pkg.version // null),
          source_path: ($pkg.manifest_path // $pkg.path // null),
          required: (($pkg.native_dependency_required // null) // ($family.default_required // true)),
          probe_kinds: ($family.required_probe_kinds // []),
          pkg_config_names: ($family.pkg_config_names // []),
          environment_roots: ($family.environment_roots // []),
          required_headers: ($family.required_headers // []),
          evidence_confidence: "manifest_mapping"
        }
    )) as $requirements
  | ($packages | map(.dependencies // [] | map(select((.optional // false) and (dep_enabled(.) | not)) | dep_name(.))) | flatten | unique) as $gated_optional
  | ($diagnostics.diagnostics // [] | map(select((.native_dependency_signal // false) and (diagnostic_known(.) | not)))) as $unknown_diagnostics
  | (
      []
      + (if ($requirements | length) > 0 then ["native_requirements_detected"] else ["no_native_requirements_detected"] end)
      + (if ($requirements | any(.dependency_id == "hdf5")) then ["hdf5_required_present"] else [] end)
      + (if ($gated_optional | length) > 0 then ["optional_native_dependency_gated_out"] else [] end)
      + (if ($unknown_diagnostics | length) > 0 then ["ambiguous_build_script_diagnostic"] else [] end)
      + (if ($version_mismatches | length) > 0 or (($lock.freshness_state // "fresh") != "fresh") then ["stale_cargo_lock_manifest_mismatch"] else [] end)
      + (if ($missing_closure | length) > 0 then ["path_dependency_closure_incomplete"] else [] end)
      | unique
    ) as $reason_codes
  | (
      (($unknown_diagnostics | length) > 0)
      or (($version_mismatches | length) > 0)
      or (($lock.freshness_state // "fresh") != "fresh")
      or (($missing_closure | length) > 0)
    ) as $fail_closed
  | {
      schema_version: $map.output_schema_version,
      source_schema_version: $map.source_schema_version,
      source_revision: $source_revision,
      validation_id: ($ctx.validation_id // "unknown"),
      command: ($ctx.command // ""),
      cargo_package: ($ctx.cargo_package // null),
      path_dependency_closure: $closure,
      dependency_requirements: $requirements,
      gated_optional_dependencies: $gated_optional,
      stale_manifest_mismatches: $version_mismatches,
      missing_closure_packages: $missing_closure,
      unknown_native_diagnostics: $unknown_diagnostics,
      reason_codes: $reason_codes,
      truth_state: (if $fail_closed then "unknown" else "confirmed" end),
      decision: (if $fail_closed then "fail_closed" else "pass" end),
      mutation_policy: $map.mutation_policy
    }
' >"$bundle_path"

decision="$(jq -r '.decision' "$bundle_path")"
truth_state="$(jq -r '.truth_state' "$bundle_path")"

jq -n \
  --arg schema_version "franken-engine.native-requirement-infer-sources.v1" \
  --arg source_revision "$source_revision" \
  --arg validation_command_context_json "$validation_command_context_json" \
  --arg cargo_lock_snapshot_json "$cargo_lock_snapshot_json" \
  --arg workspace_manifest_snapshot_json "$workspace_manifest_snapshot_json" \
  --arg path_dependency_manifests_json "$path_dependency_manifests_json" \
  --arg build_script_diagnostics_json "$build_script_diagnostics_json" \
  --arg requirement_map_json "$requirement_map_json" \
  '{
    schema_version: $schema_version,
    source_revision: $source_revision,
    inputs: {
      validation_command_context_json: $validation_command_context_json,
      cargo_lock_snapshot_json: $cargo_lock_snapshot_json,
      workspace_manifest_snapshot_json: $workspace_manifest_snapshot_json,
      path_dependency_manifests_json: $path_dependency_manifests_json,
      build_script_diagnostics_json: $build_script_diagnostics_json,
      requirement_map_json: $requirement_map_json
    }
  }' >"$sources_path"

{
  printf '%s\n\n' '# Native Dependency Requirement Inference'
  printf '%s\n' "- validation_id: \`${validation_id}\`"
  printf '%s\n' "- decision: \`${decision}\`"
  printf '%s\n' "- truth_state: \`${truth_state}\`"
  printf '%s\n' "- requirements: \`$(jq -r '.dependency_requirements | length' "$bundle_path")\`"
  printf '%s\n' "- reason_codes: \`$(jq -c '.reason_codes' "$bundle_path")\`"
} >"$summary_path"

write_event "$validation_id" "inference.completed" "$decision" "$truth_state" "$bundle_path"

if [[ "$decision" == "fail_closed" ]]; then
  exit 42
fi
