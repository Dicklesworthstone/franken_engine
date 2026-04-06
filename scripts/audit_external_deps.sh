#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

artifact_root="${DEPENDENCY_AUDIT_ARTIFACT_ROOT:-artifacts/dependency_audit}"
manifest_path="${artifact_root}/manifest.json"
commands_path="${artifact_root}/commands.txt"
logs_dir="${artifact_root}/logs"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
skip_remote="${DEPENDENCY_AUDIT_SKIP_REMOTE:-0}"

print_usage() {
  cat <<'EOF'
usage: ./scripts/audit_external_deps.sh

Environment:
  DEPENDENCY_AUDIT_ARTIFACT_ROOT  Output directory (default: artifacts/dependency_audit)
  DEPENDENCY_AUDIT_SKIP_REMOTE    Set to 1 to skip rch-backed cargo checks
  RUSTUP_TOOLCHAIN                Toolchain for remote cargo checks (default: nightly)
EOF
}

case "${1:-}" in
  -h|--help)
    print_usage
    exit 0
    ;;
  "")
    ;;
  *)
    print_usage >&2
    exit 2
    ;;
esac

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is required" >&2
  exit 3
fi

mkdir -p "$artifact_root" "$logs_dir"

json_array_from_args() {
  if [[ "$#" -eq 0 ]]; then
    printf '[]'
    return
  fi

  printf '%s\n' "$@" | jq -R . | jq -s .
}

known_imported_symbols_json() {
  case "$1" in
    franken_kernel)
      jq -nc '[
        "Budget",
        "CapabilitySet",
        "Cx",
        "DecisionId",
        "NoCaps",
        "PolicyId",
        "SchemaVersion",
        "TraceId"
      ]'
      ;;
    franken_decision)
      jq -nc '[
        "DecisionContract",
        "DecisionOutcome",
        "EvalContext",
        "FallbackPolicy",
        "LossMatrix",
        "Posterior",
        "evaluate"
      ]'
      ;;
    franken_evidence)
      jq -nc '[
        "EvidenceLedger",
        "EvidenceLedgerBuilder"
      ]'
      ;;
    *)
      printf '[]'
      ;;
  esac
}

approved_boundary_files_json() {
  case "$1" in
    franken_kernel)
      jq -nc '[
        "crates/franken-engine/src/control_plane/mod.rs"
      ]'
      ;;
    franken_decision)
      jq -nc '[
        "crates/franken-engine/src/control_plane/mod.rs",
        "crates/franken-engine/src/safety_decision_router.rs"
      ]'
      ;;
    franken_evidence)
      jq -nc '[
        "crates/franken-engine/src/control_plane/mod.rs"
      ]'
      ;;
    *)
      printf '[]'
      ;;
  esac
}

rch_local_fallback_detected() {
  local log_path="$1"
  grep -Eiq \
    'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Failed to query daemon:.*running locally|Dependency preflight blocked remote execution|RCH-E326' \
    "$log_path"
}

discover_dependency_lines() {
  rg -n \
    '^[[:space:]]*[A-Za-z0-9_-]+[[:space:]]*=[[:space:]]*\{[^}]*path[[:space:]]*=[[:space:]]*"/dp/[^"]+"[^}]*\}' \
    -g 'Cargo.toml' \
    . \
    | sort
}

declare -a commands_run=()
declare -a dependency_entries=()
declare -a discovered_dependency_matches=()

commands_run+=("rg -n 'path = \"/dp/' -g 'Cargo.toml' .")

mapfile -t discovered_dependency_matches < <(discover_dependency_lines)

for match in "${discovered_dependency_matches[@]}"; do
  [[ -z "$match" ]] && continue

  file_path="${match%%:*}"
  rest="${match#*:}"
  line_number="${rest%%:*}"
  line_content="${rest#*:}"

  if [[ ! "$line_content" =~ ^[[:space:]]*([A-Za-z0-9_-]+)[[:space:]]*= ]]; then
    continue
  fi
  dependency_key="${BASH_REMATCH[1]}"

  if [[ ! "$line_content" =~ path[[:space:]]*=[[:space:]]*\"(/dp/[^\"]+)\" ]]; then
    continue
  fi
  dependency_path="${BASH_REMATCH[1]}"

  crate_module="${dependency_key//-/_}"
  dependency_cargo_toml="${dependency_path}/Cargo.toml"
  path_exists=false
  cargo_toml_present=false
  package_name="$dependency_key"

  if [[ -d "$dependency_path" ]]; then
    path_exists=true
  fi

  if [[ -f "$dependency_cargo_toml" ]]; then
    cargo_toml_present=true
    discovered_package_name="$(
      rg -n '^name[[:space:]]*=[[:space:]]*"[^"]+"' -m 1 "$dependency_cargo_toml" \
        | sed -E 's/^[0-9]+:name[[:space:]]*=[[:space:]]*"([^"]+)"/\1/'
    )"
    if [[ -n "$discovered_package_name" ]]; then
      package_name="$discovered_package_name"
    fi
  fi

  mapfile -t source_reference_files < <(
    rg -l --glob '*.rs' "${crate_module}" crates/*/src 2>/dev/null | sort || true
  )
  mapfile -t test_reference_files < <(
    rg -l --glob '*.rs' "${crate_module}" crates/*/tests 2>/dev/null | sort || true
  )

  imported_symbols_json="$(known_imported_symbols_json "$crate_module")"
  boundary_files_json="$(approved_boundary_files_json "$crate_module")"
  source_reference_files_json="$(json_array_from_args "${source_reference_files[@]}")"
  test_reference_files_json="$(json_array_from_args "${test_reference_files[@]}")"

  compile_status="not_attempted"
  compile_attempted=false
  compile_error=""
  compile_log_path=""
  compile_command=""

  if [[ "$skip_remote" == "1" ]]; then
    compile_status="skipped"
  elif [[ "$path_exists" != "true" ]]; then
    compile_status="missing_path"
  elif [[ "$cargo_toml_present" != "true" ]]; then
    compile_status="missing_cargo_toml"
  elif ! command -v rch >/dev/null 2>&1; then
    compile_status="rch_unavailable"
    compile_error="rch is not installed"
  else
    compile_attempted=true
    compile_log_path="${logs_dir}/${crate_module}.log"
    compile_command="cd ${dependency_path} && rch exec -- env RUSTUP_TOOLCHAIN=${toolchain} CARGO_TARGET_DIR=/tmp/rch_target_dependency_audit_${crate_module} cargo check"
    commands_run+=("$compile_command")

    if (
      cd "$dependency_path"
      rch exec -- env \
        "RUSTUP_TOOLCHAIN=${toolchain}" \
        "CARGO_TARGET_DIR=/tmp/rch_target_dependency_audit_${crate_module}" \
        cargo check
    ) >"$compile_log_path" 2>&1 </dev/null; then
      if rch_local_fallback_detected "$compile_log_path"; then
        compile_status="failed_local_fallback"
        compile_error="rch reported a local fallback; remote verification was not accepted"
      else
        compile_status="passed"
      fi
    else
      compile_status="failed"
      compile_error="$(tail -n 20 "$compile_log_path")"
    fi
  fi

  dependency_entries+=(
    "$(
      jq -n \
        --arg dependency_key "$dependency_key" \
        --arg package_name "$package_name" \
        --arg crate_module "$crate_module" \
        --arg dependency_path "$dependency_path" \
        --arg declared_in "$file_path" \
        --argjson declared_line "$line_number" \
        --argjson path_exists "$path_exists" \
        --argjson cargo_toml_present "$cargo_toml_present" \
        --argjson imported_symbols "$imported_symbols_json" \
        --argjson approved_boundary_files "$boundary_files_json" \
        --argjson source_reference_files "$source_reference_files_json" \
        --argjson test_reference_files "$test_reference_files_json" \
        --arg compile_status "$compile_status" \
        --argjson compile_attempted "$compile_attempted" \
        --arg compile_command "$compile_command" \
        --arg compile_log_path "$compile_log_path" \
        --arg compile_error "$compile_error" \
        '{
          dependency_key: $dependency_key,
          package_name: $package_name,
          crate_module: $crate_module,
          dependency_path: $dependency_path,
          declared_in: {
            cargo_toml: $declared_in,
            line: $declared_line
          },
          path_exists: $path_exists,
          cargo_toml_present: $cargo_toml_present,
          imported_symbols: $imported_symbols,
          approved_boundary_files: $approved_boundary_files,
          source_reference_files: $source_reference_files,
          test_reference_files: $test_reference_files,
          compile_check: {
            attempted: $compile_attempted,
            status: $compile_status,
            command: $compile_command,
            log_path: $compile_log_path,
            error: (if $compile_error == "" then null else $compile_error end)
          }
        }'
    )"
  )
done

printf '%s\n' "${commands_run[@]}" >"$commands_path"

if [[ "${#dependency_entries[@]}" -eq 0 ]]; then
  dependency_entries_json='[]'
else
  dependency_entries_json="$(printf '%s\n' "${dependency_entries[@]}" | jq -s 'sort_by(.dependency_key)')"
fi

generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

printf '%s\n' "$dependency_entries_json" | jq \
  --arg schema_version "franken-engine.external-dependency-audit.v1" \
  --arg generated_at_utc "$generated_at_utc" \
  --arg repo_root "$root_dir" \
  --arg manifest_path "$manifest_path" \
  --arg commands_path "$commands_path" \
  --arg skip_remote "$skip_remote" \
  '
  . as $deps
  | {
      schema_version: $schema_version,
      generated_at_utc: $generated_at_utc,
      repo_root: $repo_root,
      manifest_path: $manifest_path,
      commands_path: $commands_path,
      dependencies: $deps,
      summary: {
        dependency_count: ($deps | length),
        existing_dependency_count: ($deps | map(select(.path_exists)) | length),
        compile_check_pass_count: ($deps | map(select(.compile_check.status == "passed")) | length),
        compile_check_fail_count: ($deps | map(select(.compile_check.status == "failed" or .compile_check.status == "failed_local_fallback")) | length)
      },
      standalone_build: (
        if ($deps | length) == 0 then
          {
            status: "ready",
            reason: "no external /dp path dependencies were discovered"
          }
        else
          {
            status: "blocked_by_external_path_dependencies",
            reason: "workspace contains hard /dp path dependencies and is not standalone-ready yet",
            blocking_dependencies: ($deps | map(.dependency_key))
          }
        end
      ),
      full_integration_dependency_health: (
        if $skip_remote == "1" then
          {
            status: "not_verified",
            reason: "compile checks were skipped via DEPENDENCY_AUDIT_SKIP_REMOTE=1"
          }
        elif ($deps | length) == 0 then
          {
            status: "not_applicable",
            reason: "no external dependencies to verify"
          }
        elif ($deps | all(.compile_check.status == "passed")) then
          {
            status: "ready",
            reason: "all discovered external dependencies exist and passed rch-backed cargo check"
          }
        else
          {
            status: "blocked",
            reason: "one or more discovered external dependencies are missing or failed verification",
            failing_dependencies: (
              $deps
              | map(select(.compile_check.status != "passed"))
              | map({
                  dependency_key,
                  dependency_path,
                  compile_status: .compile_check.status
                })
            )
          }
        end
      )
    }
  ' >"$manifest_path"

echo "wrote ${manifest_path}"
