#!/usr/bin/env bash
# CI guard: reject ambient authority in extension-host control paths.
#
# Checks:
# 1. Direct upstream imports (use franken_kernel/franken_decision/franken_evidence)
#    bypassing the adapter layer (bd-23om) in extension-host source.
# 2. Canonical type shadowing (struct/enum/type TraceId, DecisionId, etc.)
#    in extension-host source.
# 3. std::fs/std::net/std::process/static mut/SystemTime::now in
#    extension-host modules.
# 4. Unit tests for the guard module itself.
#
# Exclusions:
# - control_plane/ adapter layer (legitimately imports upstream crates).
# - extension_host_authority_guard.rs (contains test fixtures with intentional
#   forbidden patterns inside string literals).
# - ambient_authority.rs (contains pattern definitions as string literals).
#
# Plan ref: Section 10.13 item 15, bd-11z7.
# Dependencies: bd-2ygl (Cx threading), bd-1za (ambient authority audit),
#               bd-23om (adapter layer).
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
artifact_dir="${EXTENSION_HOST_AMBIENT_AUTHORITY_ARTIFACT_DIR:-${ARTIFACT_DIR:-artifacts/extension_host_ambient_authority}}"
mkdir -p "$artifact_dir"

errors=0

# ── rch helper (fail-closed: remote execution required) ───────────────────
run_rch() {
  rch exec -- "$@"
}

rch_reject_local_fallback() {
  local log_path="$1"
  if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|running locally|\[RCH\] local \(|Failed to query daemon:.*running locally|Dependency preflight blocked remote execution|RCH-E326' "$log_path"; then
    echo "ERROR: rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

# ── 1. Direct upstream crate imports in extension-host ───────────────────
echo "=== Check 1: Direct upstream crate imports in extension-host ==="

# Scan franken-extension-host crate for direct upstream imports.
bad_imports="$(
  rg -n --glob '*.rs' \
    '\b(use|extern crate)\s+franken_(kernel|decision|evidence)\b' \
    crates/franken-extension-host/src/ \
  || true
)"

if [[ -n "$bad_imports" ]]; then
  echo "ERROR: Direct upstream crate imports found in extension-host:"
  echo "$bad_imports"
  echo "$bad_imports" > "$artifact_dir/direct_import_violations.txt"
  errors=1
else
  echo "PASS: No direct upstream crate imports in extension-host."
fi

# ── 2. Canonical type shadowing in extension-host ────────────────────────
echo ""
echo "=== Check 2: Canonical type shadowing in extension-host ==="

canonical_types=("TraceId" "DecisionId" "PolicyId" "SchemaVersion" "Budget" "Cx")

shadow_errors=0
shadow_violations=""
for ctype in "${canonical_types[@]}"; do
  shadows="$(
    rg -n --glob '*.rs' \
      "^\s*(pub\s+)?(struct|enum|type)\s+${ctype}\b" \
      crates/franken-extension-host/src/ \
    || true
  )"
  if [[ -n "$shadows" ]]; then
    echo "ERROR: Local definition shadows canonical type '${ctype}' in extension-host:"
    echo "$shadows"
    shadow_violations+="type=${ctype}"$'\n'"${shadows}"$'\n'
    shadow_errors=1
  fi
done

if [[ "$shadow_errors" -eq 0 ]]; then
  echo "PASS: No canonical type shadowing in extension-host."
else
  printf '%s' "$shadow_violations" > "$artifact_dir/type_shadowing_violations.txt"
  errors=1
fi

# ── 3. Forbidden I/O patterns in extension-host ──────────────────────────
echo ""
echo "=== Check 3: Forbidden I/O patterns in extension-host ==="

forbidden_patterns=(
  "std::fs::"
  "std::net::"
  "std::process::"
  "static mut "
  "SystemTime::now"
)

io_errors=0
io_violations=""
for pat in "${forbidden_patterns[@]}"; do
  hits="$(
    rg -n --glob '*.rs' \
      "$pat" \
      crates/franken-extension-host/src/ \
    || true
  )"
  if [[ -n "$hits" ]]; then
    # Filter out comments (lines starting with //)
    real_hits="$(echo "$hits" | grep -v '^\s*//' || true)"
    if [[ -n "$real_hits" ]]; then
      echo "ERROR: Forbidden I/O pattern '${pat}' found in extension-host:"
      echo "$real_hits"
      io_violations+="pattern=${pat}"$'\n'"${real_hits}"$'\n'
      io_errors=1
    fi
  fi
done

if [[ "$io_errors" -eq 0 ]]; then
  echo "PASS: No forbidden I/O patterns in extension-host."
else
  printf '%s' "$io_violations" > "$artifact_dir/forbidden_io_violations.txt"
  errors=1
fi

# ── 4. Run the Rust test suite ───────────────────────────────────────────
if [[ "$mode" == "ci" || "$mode" == "test" ]]; then
  echo ""
  echo "=== Check 4: extension_host_authority_guard unit tests ==="
  test_log_path="$artifact_dir/test_output.txt"
  if ! command -v rch >/dev/null 2>&1; then
    echo "ERROR: rch is required for extension_host_authority_guard unit tests" >&2
    errors=1
  else
    if ! run_rch cargo test --package frankenengine-engine --lib extension_host_authority_guard 2>&1 \
      | tee "$test_log_path"; then
      errors=1
    fi
    if ! rch_reject_local_fallback "$test_log_path"; then
      errors=1
    fi
  fi
fi

# ── Produce run manifest ─────────────────────────────────────────────────
ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
cat > "$artifact_dir/run_manifest.json" <<MANIFEST
{
  "bead_id": "bd-11z7",
  "title": "Extension-host ambient authority guard",
  "mode": "${mode}",
  "timestamp": "${ts}",
  "checks": [
    "direct_upstream_imports",
    "canonical_type_shadowing",
    "forbidden_io_patterns",
    "unit_tests"
  ],
  "passed": $([ "$errors" -eq 0 ] && echo true || echo false)
}
MANIFEST

echo ""
if [[ "$errors" -ne 0 ]]; then
  echo "FAILED: Extension-host ambient authority guard detected violations."
  echo "Artifacts: $artifact_dir/"
  exit 1
fi

echo "PASSED: Extension-host ambient authority guard — all checks clean."
echo "Artifacts: $artifact_dir/"
