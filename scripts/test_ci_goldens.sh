#!/usr/bin/env bash
# Golden artifact testing for CI quality gates.
#
# Runs CI gate scripts against frozen inputs and compares outputs against
# golden reference files to ensure deterministic behavior.
#
# Gates tested:
# - run_rgc_ci_quality_gates.sh (RGC CI lanes)
# - check_extension_host_ambient_authority.sh (security guard)
#
# Usage: scripts/test_ci_goldens.sh [mode]
# Modes: generate, test (default: test)

set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-test}"
golden_dir="scripts/testdata/goldens"
work_dir="/tmp/ci_golden_test_$$"
keep_work_dir="${CI_GOLDEN_KEEP_WORKDIR:-false}"
fake_bin_dir="$work_dir/bin"

cleanup() {
  if [[ "$keep_work_dir" != "true" ]]; then
    rm -rf "$work_dir" 2>/dev/null || true
  fi
}
trap cleanup EXIT

mkdir -p "$work_dir"
mkdir -p "$golden_dir"

install_fake_rch() {
  mkdir -p "$fake_bin_dir"
  cat > "$fake_bin_dir/rch" <<'FAKE_RCH'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" != "exec" ]]; then
  echo "fake rch only supports exec" >&2
  exit 2
fi
shift

if [[ "${1:-}" == "--" ]]; then
  shift
fi

if [[ "${1:-}" == "env" ]]; then
  shift
  while [[ $# -gt 0 && "${1:-}" == *=* ]]; do
    export "$1"
    shift
  done
fi

command_text="$*"
if [[ "${1:-}" == "cargo" ]]; then
  case "$command_text" in
    *"fmt --check"*)
      echo "fake rch: simulated cargo fmt failure for golden fixture"
      echo "Remote command finished: exit=1"
      exit 1
      ;;
    *"test --package frankenengine-engine --lib extension_host_authority_guard"*)
      echo "fake rch: simulated extension_host_authority_guard test pass"
      echo "Remote command finished: exit=0"
      exit 0
      ;;
    *)
      echo "fake rch refusing unexpected cargo command: ${command_text}" >&2
      echo "Remote command finished: exit=2"
      exit 2
      ;;
  esac
fi

set +e
"$@"
status="$?"
set -e
echo "Remote command finished: exit=${status}"
exit "$status"
FAKE_RCH
  chmod +x "$fake_bin_dir/rch"
}

cleanup_temp_file() {
  local path="$1"
  if [[ "$keep_work_dir" != "true" ]]; then
    rm -f "$path"
  fi
}

# Normalize dynamic content in CI outputs for comparison
normalize_ci_output() {
  local input_file="$1"
  local output_file="$2"

  if [[ ! -f "$input_file" ]]; then
    echo "File not found: $input_file" >&2
    return 1
  fi

  # Strip ANSI escape sequences and control characters, then normalize dynamic content
  sed -E 's/\x1B\[[0-9;]*[mK]//g' "$input_file" \
    | tr -d '\000-\010\013\014\016-\037' \
    | sed -E \
      -e 's/"[0-9]{8}T[0-9]{6}Z"/"TIMESTAMP"/g' \
      -e 's/[0-9]{8}T[0-9]{6}Z/TIMESTAMP/g' \
      -e 's/"git_commit": "[0-9a-f]+"/"git_commit": "COMMIT_HASH"/g' \
      -e 's/"trace_id": "trace-[^"]*"/"trace_id": "TRACE_ID"/g' \
      -e 's/"decision_id": "decision-[^"]*"/"decision_id": "DECISION_ID"/g' \
      -e 's/\/tmp\/[^"]*\/[^"]*"/\/tmp\/TEMP_PATH"/g' \
      -e 's/\/tmp\/[^"[:space:]]*/\/tmp\/TEMP_PATH/g' \
      -e 's/_[0-9]+\.log/_PID.log/g' \
      -e 's/_[0-9]+"/}_PID"/g' \
    > "$output_file"
}

# Extract key fields from RGC CI quality gates output
extract_rgc_golden() {
  local run_dir="$1"
  local golden_file="$2"

  # Extract normalized manifest, verdict, and health summary
  {
    echo "=== RUN MANIFEST ==="
    if [[ -f "$run_dir/run_manifest.json" ]]; then
      local temp_manifest="/tmp/norm_manifest_$$"
      normalize_ci_output "$run_dir/run_manifest.json" "$temp_manifest"
      if jq -e . "$temp_manifest" >/dev/null 2>&1; then
        jq '{
          component,
          scenario_id,
          mode,
          outcome,
          error_code,
          commands: (.commands // [])
        }' "$temp_manifest" 2>/dev/null || echo "JSON parse error in manifest"
      else
        echo "Invalid JSON in manifest"
      fi
      cleanup_temp_file "$temp_manifest"
    else
      echo "null"
    fi

    echo "=== CI GATE VERDICT ==="
    if [[ -f "$run_dir/ci_gate_verdict.json" ]]; then
      local temp_verdict="/tmp/norm_verdict_$$"
      normalize_ci_output "$run_dir/ci_gate_verdict.json" "$temp_verdict"
      if jq -e . "$temp_verdict" >/dev/null 2>&1; then
        jq '{
          outcome,
          is_blocking,
          planned_lanes,
          failed_lanes,
          failure: {
            lane: .failure.lane,
            owner_hint: .failure.owner_hint
          }
        }' "$temp_verdict" 2>/dev/null || echo "JSON parse error in verdict"
      else
        echo "Invalid JSON in verdict"
      fi
      cleanup_temp_file "$temp_verdict"
    else
      echo "null"
    fi

    echo "=== GATE HEALTH SUMMARY ==="
    if [[ -f "$run_dir/gate_health_summary.md" ]]; then
      normalize_ci_output "$run_dir/gate_health_summary.md" /dev/stdout | head -20
    else
      echo "File not found"
    fi
  } > "$golden_file"
}

# Extract key fields from ambient authority guard output
extract_authority_golden() {
  local artifact_dir="$1"
  local golden_file="$2"

  # Extract normalized manifest and any violation files
  {
    echo "=== AUTHORITY GUARD MANIFEST ==="
    if [[ -f "$artifact_dir/run_manifest.json" ]]; then
      local temp_manifest="/tmp/norm_auth_$$"
      normalize_ci_output "$artifact_dir/run_manifest.json" "$temp_manifest"
      if jq -e . "$temp_manifest" >/dev/null 2>&1; then
        jq '{
          bead_id,
          mode,
          checks,
          passed
        }' "$temp_manifest" 2>/dev/null || echo "JSON parse error in authority manifest"
      else
        echo "Invalid JSON in authority manifest"
      fi
      cleanup_temp_file "$temp_manifest"
    else
      echo "null"
    fi

    echo "=== VIOLATIONS ==="
    if [[ -f "$artifact_dir/direct_import_violations.txt" ]]; then
      echo "Direct import violations found"
      head -5 "$artifact_dir/direct_import_violations.txt" 2>/dev/null || true
    else
      echo "No direct import violations"
    fi

    echo "=== TYPE SHADOWING ==="
    if [[ -f "$artifact_dir/type_shadowing_violations.txt" ]]; then
      echo "Type shadowing violations found"
      head -5 "$artifact_dir/type_shadowing_violations.txt" 2>/dev/null || true
    else
      echo "No type shadowing violations"
    fi

    echo "=== FORBIDDEN IO ==="
    if [[ -f "$artifact_dir/forbidden_io_violations.txt" ]]; then
      echo "Forbidden I/O violations found"
      head -8 "$artifact_dir/forbidden_io_violations.txt" 2>/dev/null || true
    else
      echo "No forbidden I/O violations"
    fi
  } > "$golden_file"
}

# Test RGC CI quality gates (minimal mode to avoid heavy computation)
test_rgc_gates() {
  echo "Testing RGC CI quality gates..."

  install_fake_rch
  export RGC_CI_QUALITY_GATES_ARTIFACT_ROOT="$work_dir/rgc_artifacts"
  export CARGO_TARGET_DIR="$work_dir/target_rgc"
  export RCH_EXEC_TIMEOUT_SECONDS=30
  export RCH_MISSING_MARKER_RETRY_COUNT=0
  export FUZZ_TIME_SECONDS=1

  # Run the real producer script with a deterministic fake rch so golden tests
  # validate producer output contracts without starting local Cargo work.
  if PATH="$fake_bin_dir:$PATH" timeout 120s ./scripts/run_rgc_ci_quality_gates.sh fmt >/dev/null 2>&1; then
    echo "RGC gates completed"
  else
    echo "RGC gates failed (expected for golden test)"
  fi

  local latest_run_dir
  latest_run_dir="$(find "$work_dir/rgc_artifacts" -type d -name '????????T??????Z' | sort | tail -1 || true)"

  if [[ -n "$latest_run_dir" && -d "$latest_run_dir" ]]; then
    extract_rgc_golden "$latest_run_dir" "$work_dir/rgc_golden.txt"
  else
    echo "=== RGC GATES FAILED TO PRODUCE ARTIFACTS ===" > "$work_dir/rgc_golden.txt"
  fi
}

# Test extension host ambient authority guard
test_authority_guard() {
  echo "Testing extension host ambient authority guard..."

  install_fake_rch
  local artifact_dir="$work_dir/authority_artifacts"
  export EXTENSION_HOST_AMBIENT_AUTHORITY_ARTIFACT_DIR="$artifact_dir"
  mkdir -p "$artifact_dir"

  # Run the real guard script with a deterministic fake rch for its Rust unit
  # test step; source scans still run against the live workspace.
  if PATH="$fake_bin_dir:$PATH" timeout 60s ./scripts/check_extension_host_ambient_authority.sh ci >/dev/null 2>&1; then
    echo "Authority guard completed"
  else
    echo "Authority guard failed"
  fi

  if [[ -d "$artifact_dir" ]]; then
    extract_authority_golden "$artifact_dir" "$work_dir/authority_golden.txt"
  else
    echo "=== AUTHORITY GUARD FAILED TO PRODUCE ARTIFACTS ===" > "$work_dir/authority_golden.txt"
  fi
}

case "$mode" in
  generate)
    echo "Generating golden artifacts..."

    test_rgc_gates
    test_authority_guard

    # Copy normalized outputs to golden directory
    cp "$work_dir/rgc_golden.txt" "$golden_dir/rgc_ci_quality_gates.golden"
    cp "$work_dir/authority_golden.txt" "$golden_dir/extension_host_authority_guard.golden"

    echo "Golden artifacts generated:"
    echo "  $golden_dir/rgc_ci_quality_gates.golden"
    echo "  $golden_dir/extension_host_authority_guard.golden"
    ;;

  test)
    echo "Testing against golden artifacts..."

    if [[ ! -f "$golden_dir/rgc_ci_quality_gates.golden" ]]; then
      echo "ERROR: Missing golden file: $golden_dir/rgc_ci_quality_gates.golden"
      echo "Run: scripts/test_ci_goldens.sh generate"
      exit 1
    fi

    if [[ ! -f "$golden_dir/extension_host_authority_guard.golden" ]]; then
      echo "ERROR: Missing golden file: $golden_dir/extension_host_authority_guard.golden"
      echo "Run: scripts/test_ci_goldens.sh generate"
      exit 1
    fi

    test_rgc_gates
    test_authority_guard

    # Compare against golden files
    echo ""
    echo "Comparing RGC CI quality gates output..."
    if diff -u "$golden_dir/rgc_ci_quality_gates.golden" "$work_dir/rgc_golden.txt"; then
      echo "PASS: RGC CI quality gates output matches golden"
    else
      echo "FAIL: RGC CI quality gates output differs from golden"
      exit 1
    fi

    echo ""
    echo "Comparing extension host authority guard output..."
    if diff -u "$golden_dir/extension_host_authority_guard.golden" "$work_dir/authority_golden.txt"; then
      echo "PASS: Extension host authority guard output matches golden"
    else
      echo "FAIL: Extension host authority guard output differs from golden"
      exit 1
    fi

    echo ""
    echo "All golden artifact tests passed!"
    ;;

  *)
    echo "Usage: $0 [generate|test]"
    exit 2
    ;;
esac
