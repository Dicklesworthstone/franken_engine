#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

print_usage() {
  cat <<'EOF'
usage: ./scripts/test_standalone_build.sh [standalone-check|standalone-test|standalone-release|full-check|full-integration|sibling-isolation|patch-version-consistency|ci]

Modes:
  standalone-check    rch-backed cargo check in standalone mode
  standalone-test     rch-backed cargo test in standalone mode
  standalone-release  rch-backed frankenctl release build in standalone mode
  full-check          rch-backed cargo check with all features when sibling deps exist
  sibling-isolation   assert no /dp sibling appears in the manifest or standalone graph
  patch-version-consistency
                      assert no [patch.*] entry substitutes a crate whose version
                      differs from what its consumers declare, and prove the guard
                      can fail via a synthetic skew (bd-h5cl7)
  full-integration    per-sibling smoke (asupersync, frankentui, frankensqlite,
                      sqlmodel_rust, fastapi_rust, frankenpandas) recording each
                      as passed / skipped / failed (bd-cixqu.13.1)
  ci                  standalone-check + standalone-test + standalone-release +
                      full-check + full-integration + sibling-isolation +
                      patch-version-consistency, with manifest/report

Environment:
  STANDALONE_BUILD_GATE_ARTIFACT_ROOT  Output root (default: artifacts/standalone_build_gate)
  STANDALONE_BUILD_GATE_SKIP_REMOTE    Set to 1 to skip heavy rch-backed lanes and emit a manifest only
  STANDALONE_BUILD_GATE_SIBLING_ROOT   Source-checkout smoke root (default: /dp)
  RUSTUP_TOOLCHAIN                     Toolchain for rch-backed cargo lanes (default: nightly)
  CARGO_TARGET_DIR                     Remote cargo target dir (default: repo-local .rch-target/standalone_build_gate_...)
  CARGO_BUILD_JOBS                     Remote cargo build jobs for rch lanes (default: 1)
  CARGO_INCREMENTAL                    Remote cargo incremental mode for rch lanes (default: 0)
  RCH_EXEC_TIMEOUT_SECONDS             Remote timeout for each rch lane (default: 3600);
                                       the local wrapper adds 120s for transfer
EOF
}

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
artifact_root="${STANDALONE_BUILD_GATE_ARTIFACT_ROOT:-artifacts/standalone_build_gate}"
skip_remote="${STANDALONE_BUILD_GATE_SKIP_REMOTE:-0}"
sibling_root="${STANDALONE_BUILD_GATE_SIBLING_ROOT:-/dp}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-3600}"
rch_outer_timeout_seconds=$((rch_timeout_seconds + 120))
cargo_build_jobs="${CARGO_BUILD_JOBS:-1}"
cargo_incremental="${CARGO_INCREMENTAL:-0}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
default_target_dir="${root_dir}/.rch-target/standalone_build_gate_${timestamp}_$$"
target_dir="${CARGO_TARGET_DIR:-${default_target_dir}}"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
step_logs_dir="${run_dir}/step_logs"

case "$mode" in
  standalone-check|standalone-test|standalone-release|full-check|full-integration|sibling-isolation|patch-version-consistency|ci)
    ;;
  -h|--help)
    print_usage
    exit 0
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

if [[ "$skip_remote" != "1" ]] && ! command -v rch >/dev/null 2>&1; then
  echo "error: rch is required unless STANDALONE_BUILD_GATE_SKIP_REMOTE=1" >&2
  exit 4
fi

mkdir -p "$run_dir" "$step_logs_dir"
mkdir -p "${root_dir}/.rch-target"
: >"$events_path"

declare -a commands_run=()
declare -a lane_results=()

json_array_from_args() {
  if [[ "$#" -eq 0 ]]; then
    printf '[]'
    return
  fi

  printf '%s\n' "$@" | jq -R . | jq -s .
}

rch_remote_exit_code() {
  local log_path="$1"
  local remote_exit_line remote_exit_code

  remote_exit_line="$(rg -o 'Remote command finished: exit=[0-9]+' "$log_path" | tail -n 1 || true)"
  if [[ -z "$remote_exit_line" ]]; then
    return 1
  fi

  remote_exit_code="${remote_exit_line##*=}"
  if [[ -z "$remote_exit_code" ]]; then
    return 1
  fi

  printf '%s\n' "$remote_exit_code"
}

rch_local_fallback_detected() {
  local log_path="$1"
  grep -Eiq \
    'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Failed to query daemon:.*running locally|Dependency preflight blocked remote execution|RCH-E326' \
    "$log_path"
}

rch_recovered_success() {
  local log_path="$1"
  if rg -q 'Remote command finished: exit=0|Finished `(dev|test|release)` profile|test result: ok\.' "$log_path" \
    && ! rg -qi 'error(\[[[:alnum:]]+\])?:' "$log_path"; then
    return 0
  fi
  return 1
}

discover_external_dependency_paths() {
  rg -No 'path[[:space:]]*=[[:space:]]*"(/dp/[^"]+)"' crates/franken-engine/Cargo.toml \
    | sed -E 's/.*"([^"]+)"/\1/' \
    | sort -u
}

record_event() {
  local lane="$1"
  local status="$2"
  local note="$3"
  jq -cn \
    --arg lane "$lane" \
    --arg status "$status" \
    --arg note "$note" \
    --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{
      schema_version: "franken-engine.standalone-build-gate.event.v1",
      generated_at_utc: $generated_at_utc,
      lane: $lane,
      status: $status,
      note: $note
    }' >>"$events_path"
}

lane_result_json() {
  local lane="$1"
  local status="$2"
  local command_text="$3"
  local log_path="$4"
  local note="$5"
  jq -cn \
    --arg lane "$lane" \
    --arg status "$status" \
    --arg command "$command_text" \
    --arg log_path "$log_path" \
    --arg note "$note" \
    '{
      lane: $lane,
      status: $status,
      command: $command,
      log_path: $log_path,
      note: $note
    }'
}

run_rch_lane() {
  local lane="$1"
  local command_text="$2"
  shift 2

  local log_path="${step_logs_dir}/${lane}.log"
  local run_status=0
  local lane_status=""
  local note=""
  local remote_exit_code=""

  commands_run+=("$command_text")

  if [[ "$skip_remote" == "1" ]]; then
    : >"$log_path"
    lane_status="skipped"
    note="skip_remote=1"
    record_event "$lane" "$lane_status" "$note"
    lane_results+=("$(lane_result_json "$lane" "$lane_status" "$command_text" "$log_path" "$note")")
    return 0
  fi

  set +e
  timeout "${rch_outer_timeout_seconds}" \
    env \
      "RCH_REQUIRE_REMOTE=1" \
      "RCH_BUILD_TIMEOUT_SEC=${rch_timeout_seconds}" \
      "RCH_TEST_TIMEOUT_SEC=${rch_timeout_seconds}" \
    rch exec -- env \
      "RUSTUP_TOOLCHAIN=${toolchain}" \
      "CARGO_TARGET_DIR=${target_dir}" \
      "CARGO_BUILD_JOBS=${cargo_build_jobs}" \
      "CARGO_INCREMENTAL=${cargo_incremental}" \
      "$@" > >(tee "$log_path") 2>&1
  run_status=$?
  set -e

  remote_exit_code="$(rch_remote_exit_code "$log_path" || true)"
  if [[ "$run_status" -eq 0 ]]; then
    if rch_local_fallback_detected "$log_path"; then
      lane_status="failed"
      note="rch reported local fallback"
    else
      lane_status="passed"
      note="remote_exit=${remote_exit_code:-0}"
    fi
  elif [[ "$run_status" -eq 124 ]]; then
    lane_status="failed"
    note="rch wrapper timeout after ${rch_outer_timeout_seconds}s"
  elif rch_recovered_success "$log_path"; then
    if rch_local_fallback_detected "$log_path"; then
      lane_status="failed"
      note="rch recovered success marker but reported local fallback"
    else
      lane_status="passed"
      note="remote success recovered after local artifact retrieval issue"
    fi
  elif rch_local_fallback_detected "$log_path"; then
    lane_status="failed"
    note="rch reported local fallback"
  else
    lane_status="failed"
    if [[ -n "$remote_exit_code" ]]; then
      note="rch_exit=${run_status}, remote_exit=${remote_exit_code}"
    else
      note="rch_exit=${run_status}, remote exit marker missing"
    fi
  fi

  record_event "$lane" "$lane_status" "$note"
  lane_results+=("$(lane_result_json "$lane" "$lane_status" "$command_text" "$log_path" "$note")")
  [[ "$lane_status" == "passed" ]]
}

mark_full_check_skipped() {
  local command_text="cargo check -p frankenengine-engine --all-features"
  local log_path="${step_logs_dir}/full-check.log"
  local note="$1"

  commands_run+=("$command_text")
  : >"$log_path"
  record_event "full-check" "skipped_missing_external_deps" "$note"
  lane_results+=("$(lane_result_json "full-check" "skipped_missing_external_deps" "$command_text" "$log_path" "$note")")
}

# ---------------------------------------------------------------------------
# bd-cixqu.13.1 — per-sibling pass criteria
# ---------------------------------------------------------------------------
# The integration boundary with each sibling repo is exercised via a
# lightweight presence + manifest-shape smoke. The check is intentionally
# cheap (no cargo invocation) so the per-sibling lane runs even when
# heavy cargo lanes are skipped via STANDALONE_BUILD_GATE_SKIP_REMOTE=1.
#
# Pass criterion per sibling:
#   1. /dp/<sibling> directory exists.
#   2. /dp/<sibling>/Cargo.toml is readable.
#   3. /dp/<sibling>/Cargo.toml declares either a [package] or a
#      [workspace] section (i.e. the manifest is at least a valid
#      cargo entry point).
#
# Outcome per sibling: passed | skipped | failed.
#
# The fail-shape (manifest exists but is malformed) is treated as
# `failed`. The missing-shape (no directory) is treated as `skipped`
# because a deployment may legitimately not have the sibling checked
# out — we record but don't fail the lane.

readonly SIBLING_PASS_CRITERIA_BASE="$sibling_root"
readonly SIBLINGS=(
  "asupersync"
  "frankentui"
  "frankensqlite"
  "sqlmodel_rust"
  "fastapi_rust"
  "frankenpandas"
)

run_sibling_smoke() {
  local sibling="$1"
  local lane="full-integration-${sibling}"
  local sibling_path="${SIBLING_PASS_CRITERIA_BASE}/${sibling}"
  local manifest="${sibling_path}/Cargo.toml"
  local command_text="check ${sibling_path} (presence + Cargo.toml shape)"
  local log_path="${step_logs_dir}/${lane}.log"
  local status=""
  local note=""

  commands_run+=("$command_text")
  : >"$log_path"

  if [[ ! -d "$sibling_path" ]]; then
    status="skipped"
    note="sibling directory not present at ${sibling_path}"
  elif [[ ! -f "$manifest" ]]; then
    status="failed"
    note="sibling directory present but Cargo.toml missing at ${manifest}"
  elif ! grep -Eq '^\[(package|workspace)\]' "$manifest"; then
    status="failed"
    note="Cargo.toml at ${manifest} declares neither [package] nor [workspace]"
  else
    status="passed"
    note="presence + Cargo.toml shape ok"
    {
      printf -- '-- sibling: %s\n' "$sibling"
      printf -- '-- manifest: %s\n' "$manifest"
      printf -- '-- sections: '
      grep -E '^\[(package|workspace)\]' "$manifest" | tr '\n' ' '
      printf -- '\n'
    } >"$log_path"
  fi

  record_event "$lane" "$status" "$note"
  lane_results+=("$(lane_result_json "$lane" "$status" "$command_text" "$log_path" "$note")")

  if [[ "$status" == "failed" ]]; then
    return 1
  fi
  return 0
}

run_full_integration_lane() {
  local sibling
  for sibling in "${SIBLINGS[@]}"; do
    run_sibling_smoke "$sibling" || run_failures=$((run_failures + 1))
  done
}

# bd-ndpm2 — sibling-isolation lane.
#
# Guards both properties needed for a genuinely standalone build: the engine
# manifest contains no `/dp/*` sibling dependency, and no `/dp/*` crate appears
# in the resolved `--no-default-features` graph. The sibling crates were moved
# to optional registry dependencies under bd-gw4cg. Cargo still resolves the
# manifest of an optional path dependency, so merely checking that a `/dp` edge
# is optional would let the original absent-checkout failure return.
#
# Two assertions:
#   1. The engine manifest contains zero `/dp/*` path dependencies.
#   2. `cargo tree --no-default-features -e normal,dev` names zero `/dp/` paths.
# Assertion 1 catches even an optional path edge when assertion 2 cannot run.
#
# `-e normal,dev` rather than `-e normal` is deliberate. The crate carries a self
# dev-dependency (for `tee-test-mock`); while it lacked `default-features =
# false`, feature unification re-enabled `default` for every test target, so
# `cargo test --no-default-features` rebuilt all nine siblings and the
# standalone-test lane was proving nothing. A normal-only assertion is blind to
# that entire class of regression.
run_sibling_isolation_lane() {
  local lane="sibling-isolation"
  local command_text="assert no /dp sibling dependency appears in the engine manifest or --no-default-features graph (normal + dev)"
  local log_path="${step_logs_dir}/${lane}.log"
  local status="passed"
  local note="no /dp sibling dependency appears in the manifest or standalone graph"
  local -a manifest_path_deps=()
  local dep_line dep_name tree_out leaked

  commands_run+=("$command_text")
  : >"$log_path"

  # (1) Any /dp path dependency breaks absent-checkout Cargo resolution,
  # including an optional dependency whose feature is disabled.
  while IFS= read -r dep_line; do
    [[ -z "$dep_line" ]] && continue
    dep_name="${dep_line%%=*}"
    manifest_path_deps+=("$(printf '%s' "$dep_name" | tr -d '[:space:]')")
  done < <(grep -E '^[A-Za-z0-9_-]+[[:space:]]*=.*path[[:space:]]*=[[:space:]]*"/dp/' \
    crates/franken-engine/Cargo.toml || true)

  {
    printf -- '-- assertion 1: the engine manifest contains zero /dp path dependencies\n'
    if [[ "${#manifest_path_deps[@]}" -gt 0 ]]; then
      printf -- '   FAIL: sibling path deps: %s\n' "${manifest_path_deps[*]}"
    else
      printf -- '   ok\n'
    fi
  } >>"$log_path"

  if [[ "${#manifest_path_deps[@]}" -gt 0 ]]; then
    status="failed"
    note="/dp sibling dependencies break absent-checkout resolution: ${manifest_path_deps[*]}"
  fi

  # (2) The resolved standalone graph must name no /dp path at all.
  if command -v cargo >/dev/null 2>&1; then
    if tree_out="$(RCH_CARGO_WRAPPER_BYPASS=1 cargo tree -p frankenengine-engine \
      --no-default-features -e normal,dev 2>>"$log_path")"; then
      leaked="$(printf '%s\n' "$tree_out" | grep -c '/dp/' || true)"
      {
        printf -- '-- assertion 2: cargo tree --no-default-features -e normal,dev names no /dp path\n'
        printf -- '   /dp entries found: %s\n' "$leaked"
      } >>"$log_path"
      if [[ "$leaked" -ne 0 ]]; then
        status="failed"
        note="${leaked} sibling crate(s) remain in the --no-default-features graph"
        printf '%s\n' "$tree_out" | grep '/dp/' >>"$log_path" || true
      fi
    else
      # Resolution failure is itself a finding, not a reason to pass quietly.
      status="failed"
      note="cargo tree --no-default-features failed to resolve"
      printf -- '-- assertion 2: FAILED to resolve\n' >>"$log_path"
    fi
  else
    printf -- '-- assertion 2: skipped (cargo not on PATH)\n' >>"$log_path"
    if [[ "$status" == "passed" ]]; then
      note="${note} (graph assertion skipped: cargo unavailable)"
    fi
  fi

  record_event "$lane" "$status" "$note"
  lane_results+=("$(lane_result_json "$lane" "$status" "$command_text" "$log_path" "$note")")

  [[ "$status" == "failed" ]] && return 1
  return 0
}

# bd-h5cl7 -- `[patch.crates-io]` skew.
#
# The sibling-isolation lane above reads only crates/franken-engine/Cargo.toml, so
# it never saw the root workspace's `[patch.crates-io]` block. That block forced
# sqlmodel-frankensqlite (which declares fsqlite "0.1.18") onto local frankensqlite
# 0.1.19 after it shipped a breaking sync -> async API under a patch-level bump.
# Cargo's 0.x rules let `^0.1.18` admit `0.1.19`, so the substitution applied
# silently: 33 sync call sites met Futures, the default build went red, and 7 of
# the 16 OBSERVED claims became unverifiable because their verification commands
# are default-feature builds.
#
# This lane asserts two things, in order:
#   (1) no `[patch.*]` entry substitutes a crate whose version differs from what
#       any consumer declares;
#   (2) the guard enforcing (1) can actually fail -- proven by a synthetic skew,
#       because a check that has only ever returned 0 is not evidence.
run_patch_version_consistency_lane() {
  local lane="patch-version-consistency"
  local command_text="python3 scripts/check_patch_version_consistency.py && ./scripts/e2e/patch_version_consistency_drift.sh"
  local log_path="${step_logs_dir}/${lane}.log"
  local report_path="${run_dir}/patch_version_consistency_report.json"
  local status="passed"
  local note="no [patch.*] entry substitutes a version its consumers do not declare"
  local guard_exit drill_exit

  commands_run+=("$command_text")
  : >"$log_path"

  printf -- '-- assertion 1: no patched crate is version-skewed\n' >>"$log_path"
  set +e
  RCH_CARGO_WRAPPER_BYPASS=1 python3 scripts/check_patch_version_consistency.py \
    --json "$report_path" >>"$log_path" 2>&1
  guard_exit=$?
  set -e
  printf -- '   guard exit: %s\n' "$guard_exit" >>"$log_path"

  case "$guard_exit" in
    0) ;;
    1)
      status="failed"
      note="patched crate version skew detected; see patch_version_consistency_report.json"
      ;;
    *)
      # Could not evaluate. That is an unknown, not a pass.
      status="failed"
      note="patch version consistency guard could not run (exit ${guard_exit})"
      ;;
  esac

  printf -- '-- assertion 2: the guard rejects a synthetic skew\n' >>"$log_path"
  set +e
  ./scripts/e2e/patch_version_consistency_drift.sh >>"$log_path" 2>&1
  drill_exit=$?
  set -e
  printf -- '   drill exit: %s\n' "$drill_exit" >>"$log_path"

  if [[ "$drill_exit" -ne 0 ]]; then
    status="failed"
    note="${note}; negative drill did not prove the guard can fail"
  fi

  record_event "$lane" "$status" "$note"
  lane_results+=("$(lane_result_json "$lane" "$status" "$command_text" "$log_path" "$note")")

  [[ "$status" == "failed" ]] && return 1
  return 0
}

declare -a external_dependency_paths=()
declare -a missing_external_dependency_paths=()

mapfile -t external_dependency_paths < <(discover_external_dependency_paths)
for dep_path in "${external_dependency_paths[@]}"; do
  if [[ ! -f "${dep_path}/Cargo.toml" ]]; then
    missing_external_dependency_paths+=("$dep_path")
  fi
done

run_failures=0

run_mode() {
  case "$mode" in
    standalone-check)
      run_rch_lane \
        "standalone-check" \
        "cargo check -p frankenengine-engine --no-default-features" \
        cargo check -p frankenengine-engine --no-default-features || run_failures=$((run_failures + 1))
      ;;
    standalone-test)
      run_rch_lane \
        "standalone-test" \
        "cargo test -p frankenengine-engine --no-default-features" \
        cargo test -p frankenengine-engine --no-default-features || run_failures=$((run_failures + 1))
      ;;
    standalone-release)
      run_rch_lane \
        "standalone-release" \
        "cargo build --release --no-default-features -p frankenengine-engine --bin frankenctl" \
        cargo build --release --no-default-features -p frankenengine-engine --bin frankenctl || run_failures=$((run_failures + 1))
      ;;
    full-check)
      if [[ "${#missing_external_dependency_paths[@]}" -gt 0 ]]; then
        mark_full_check_skipped "missing sibling dependency Cargo.toml for: ${missing_external_dependency_paths[*]}"
      else
        run_rch_lane \
          "full-check" \
          "cargo check -p frankenengine-engine --all-features" \
          cargo check -p frankenengine-engine --all-features || run_failures=$((run_failures + 1))
      fi
      ;;
    full-integration)
      # bd-cixqu.13.1 — per-sibling presence + manifest-shape smoke.
      run_full_integration_lane
      ;;
    sibling-isolation)
      # bd-ndpm2 — no sibling crate may be linked with default features off.
      run_sibling_isolation_lane || run_failures=$((run_failures + 1))
      ;;
    patch-version-consistency)
      # bd-h5cl7 — no [patch.*] entry may substitute a version-skewed crate.
      run_patch_version_consistency_lane || run_failures=$((run_failures + 1))
      ;;
    ci)
      run_rch_lane \
        "standalone-check" \
        "cargo check -p frankenengine-engine --no-default-features" \
        cargo check -p frankenengine-engine --no-default-features || run_failures=$((run_failures + 1))
      run_rch_lane \
        "standalone-test" \
        "cargo test -p frankenengine-engine --no-default-features" \
        cargo test -p frankenengine-engine --no-default-features || run_failures=$((run_failures + 1))
      run_rch_lane \
        "standalone-release" \
        "cargo build --release --no-default-features -p frankenengine-engine --bin frankenctl" \
        cargo build --release --no-default-features -p frankenengine-engine --bin frankenctl || run_failures=$((run_failures + 1))
      if [[ "${#missing_external_dependency_paths[@]}" -gt 0 ]]; then
        mark_full_check_skipped "missing sibling dependency Cargo.toml for: ${missing_external_dependency_paths[*]}"
      else
        run_rch_lane \
          "full-check" \
          "cargo check -p frankenengine-engine --all-features" \
          cargo check -p frankenengine-engine --all-features || run_failures=$((run_failures + 1))
      fi
      # bd-cixqu.13.1 — sibling-presence smoke as part of ci.
      run_full_integration_lane
      # bd-ndpm2 — sibling-isolation as part of ci.
      run_sibling_isolation_lane || run_failures=$((run_failures + 1))
      # bd-h5cl7 — patch version consistency as part of ci.
      run_patch_version_consistency_lane || run_failures=$((run_failures + 1))
      ;;
  esac
}

run_mode

printf '%s\n' "${commands_run[@]}" >"$commands_path"

if [[ "${#lane_results[@]}" -eq 0 ]]; then
  lane_results_json='[]'
else
  lane_results_json="$(printf '%s\n' "${lane_results[@]}" | jq -s '.')"
fi

external_dependency_paths_json="$(json_array_from_args "${external_dependency_paths[@]}")"
missing_external_dependency_paths_json="$(json_array_from_args "${missing_external_dependency_paths[@]}")"
generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

standalone_check_status="$(printf '%s\n' "$lane_results_json" | jq -r 'map(select(.lane == "standalone-check")) | .[0].status // "not_run"')"
standalone_test_status="$(printf '%s\n' "$lane_results_json" | jq -r 'map(select(.lane == "standalone-test")) | .[0].status // "not_run"')"
standalone_release_status="$(printf '%s\n' "$lane_results_json" | jq -r 'map(select(.lane == "standalone-release")) | .[0].status // "not_run"')"
full_check_status="$(printf '%s\n' "$lane_results_json" | jq -r 'map(select(.lane == "full-check")) | .[0].status // "not_run"')"
sibling_isolation_status="$(printf '%s\n' "$lane_results_json" | jq -r 'map(select(.lane == "sibling-isolation")) | .[0].status // "not_run"')"
failed_lane_count="$(printf '%s\n' "$lane_results_json" | jq 'map(select(.status == "failed")) | length')"

if [[ "$standalone_check_status" == "passed" \
  && "$standalone_test_status" == "passed" \
  && "$standalone_release_status" == "passed" ]]; then
  standalone_status="ready"
  standalone_gate_passed=true
elif [[ "$standalone_check_status" == "failed" \
  || "$standalone_test_status" == "failed" \
  || "$standalone_release_status" == "failed" ]]; then
  standalone_status="blocked"
  standalone_gate_passed=false
else
  standalone_status="not_verified"
  standalone_gate_passed=false
fi

case "$full_check_status" in
  passed)
    full_integration_status="ready"
    ;;
  skipped_missing_external_deps)
    full_integration_status="skipped_missing_external_deps"
    ;;
  failed)
    full_integration_status="blocked"
    ;;
  skipped)
    full_integration_status="not_verified"
    ;;
  *)
    full_integration_status="not_run"
    ;;
esac

if [[ "$failed_lane_count" -gt 0 ]]; then
  overall_status="blocked"
elif [[ "$standalone_status" == "ready" && "$full_integration_status" == "ready" ]]; then
  overall_status="ready"
elif [[ "$standalone_status" == "ready" && "$full_integration_status" == "skipped_missing_external_deps" ]]; then
  overall_status="standalone_ready_full_integration_skipped"
elif [[ "$standalone_status" == "ready" && "$full_integration_status" == "blocked" ]]; then
  overall_status="standalone_ready_full_integration_blocked"
elif [[ "$standalone_status" == "blocked" ]]; then
  overall_status="blocked"
else
  overall_status="not_verified"
fi

# `manifest_path` is serialized as metadata; jq does not read the output file.
# shellcheck disable=SC2094
jq -n \
  --arg schema_version "franken-engine.standalone-build-gate.v1" \
  --arg generated_at_utc "$generated_at_utc" \
  --arg repo_root "$root_dir" \
  --arg mode "$mode" \
  --arg toolchain "$toolchain" \
  --arg target_dir "$target_dir" \
  --arg manifest_path "$manifest_path" \
  --arg commands_path "$commands_path" \
  --arg events_path "$events_path" \
  --arg step_logs_dir "$step_logs_dir" \
  --argjson rch_exec_timeout_seconds "$rch_timeout_seconds" \
  --argjson skip_remote "$([[ "$skip_remote" == "1" ]] && printf 'true' || printf 'false')" \
  --argjson lanes "$lane_results_json" \
  --argjson external_dependency_paths "$external_dependency_paths_json" \
  --argjson missing_external_dependency_paths "$missing_external_dependency_paths_json" \
  --arg standalone_status "$standalone_status" \
  --arg full_integration_status "$full_integration_status" \
  --arg overall_status "$overall_status" \
  --argjson standalone_gate_passed "$standalone_gate_passed" \
  --argjson failed_lane_count "$failed_lane_count" \
  '{
    schema_version: $schema_version,
    generated_at_utc: $generated_at_utc,
    repo_root: $repo_root,
    mode: $mode,
    toolchain: $toolchain,
    cargo_target_dir: $target_dir,
    rch_exec_timeout_seconds: $rch_exec_timeout_seconds,
    skip_remote: $skip_remote,
    manifest_path: $manifest_path,
    commands_path: $commands_path,
    events_path: $events_path,
    step_logs_dir: $step_logs_dir,
    external_dependency_paths: $external_dependency_paths,
    missing_external_dependency_paths: $missing_external_dependency_paths,
    lanes: $lanes,
    build_modes: {
      standalone: {
        status: $standalone_status,
        gate_passed: $standalone_gate_passed,
        commands: [
          "cargo check -p frankenengine-engine --no-default-features",
          "cargo test -p frankenengine-engine --no-default-features",
          "cargo build --release --no-default-features -p frankenengine-engine --bin frankenctl"
        ]
      },
      full_integration: {
        status: $full_integration_status,
        commands: [
          "cargo check -p frankenengine-engine --all-features"
        ]
      }
    },
    summary: {
      lane_count: ($lanes | length),
      failed_lane_count: $failed_lane_count,
      standalone_gate_passed: $standalone_gate_passed,
      overall_status: $overall_status
    }
  }' >"$manifest_path"

echo "wrote ${manifest_path}"

exit_code=0

# Every recorded failure is blocking, including sibling smokes and policy
# drills. Previously `run_failures` was incremented but never consulted, so the
# `ci` mode could return success after a non-standalone lane failed.
if [[ "$run_failures" -gt 0 || "$failed_lane_count" -gt 0 ]]; then
  exit_code=1
fi

if [[ "$skip_remote" == "1" ]]; then
  exit "$exit_code"
fi

case "$mode" in
  standalone-check)
    [[ "$standalone_check_status" == "passed" ]] || exit_code=1
    ;;
  standalone-test)
    [[ "$standalone_test_status" == "passed" ]] || exit_code=1
    ;;
  standalone-release)
    [[ "$standalone_release_status" == "passed" ]] || exit_code=1
    ;;
  full-check)
    [[ "$full_integration_status" == "ready" || "$full_integration_status" == "skipped_missing_external_deps" ]] || exit_code=1
    ;;
  sibling-isolation)
    [[ "$sibling_isolation_status" == "passed" ]] || exit_code=1
    ;;
  ci)
    [[ "$standalone_gate_passed" == "true" ]] || exit_code=1
    ;;
esac

exit "$exit_code"
