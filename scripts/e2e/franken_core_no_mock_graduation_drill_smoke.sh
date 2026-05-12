#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
drill="${root_dir}/scripts/franken_core_no_mock_graduation_drill.sh"
contract_json="${root_dir}/docs/franken_core_no_mock_graduation_drill_v1.json"
mode="${1:-check}"

record_pass() {
  printf 'PASS franken-core-no-mock-graduation-drill %s\n' "$1"
}

record_failure() {
  printf 'FAIL franken-core-no-mock-graduation-drill %s\n' "$1" >&2
  exit 1
}

write_truthful_root_manifest() {
  local path="$1"
  cat >"$path" <<'EOF'
[workspace]
members = [
  "crates/franken-engine",
]
exclude = ["crates/franken-core"]
resolver = "2"
EOF
}

write_core_manifest() {
  local path="$1"
  cat >"$path" <<'EOF'
[package]
name = "frankenengine-core"
version = "0.1.0"
edition = "2024"
EOF
}

write_libs_and_sources() {
  local root="$1"
  local core_src="${root}/crates/franken-core/src"
  local engine_src="${root}/crates/franken-engine/src"
  mkdir -p "$core_src" "$engine_src"
  cat >"${core_src}/lib.rs" <<'EOF'
pub mod object_model;
pub mod promise_model;
pub mod profiling;
pub mod control_plane;
pub mod capability;
EOF
  cat >"${engine_src}/lib.rs" <<'EOF'
pub mod object_model;
pub mod promise_model;
pub mod profiling;
pub mod control_plane;
pub mod capability;
EOF
  touch \
    "${core_src}/object_model.rs" \
    "${core_src}/promise_model.rs" \
    "${core_src}/profiling.rs" \
    "${core_src}/control_plane.rs" \
    "${core_src}/capability.rs" \
    "${engine_src}/object_model.rs" \
    "${engine_src}/promise_model.rs" \
    "${engine_src}/profiling.rs" \
    "${engine_src}/control_plane.rs" \
    "${engine_src}/capability.rs"
}

assert_report_shape() {
  local report_path="$1"
  jq -e '
    .schema_version == "franken-engine.franken-core-no-mock-graduation-drill-report.v1"
    and (.decision == "pass" or .decision == "fail_closed")
    and .workspace_membership_mutated == false
    and .workspace_inclusion_ready == false
    and (.selected_modules | index("object_model") != null)
    and (.selected_modules | index("promise_model") != null)
    and (.selected_modules | index("profiling") != null)
    and (.selected_modules | index("control_plane") != null)
    and (.selected_modules | index("capability") != null)
    and (.proofs_still_needed | index("bd-4w7h9.8 final acceptance suite passes") != null)
    and (.non_mutation_attestation.edits_manifests == false)
    and (.non_mutation_attestation.runs_cargo == false)
    and (.non_mutation_attestation.runs_rch == false)
    and (.non_mutation_attestation.changes_workspace_membership == false)
  ' "$report_path" >/dev/null || record_failure "report shape ${report_path}"
}

run_live_case() {
  local tmpdir output_dir report_path
  tmpdir="$(mktemp -d)"
  output_dir="${tmpdir}/out"
  "$drill" --source-revision "smoke-live" --output-dir "$output_dir" >/dev/null
  report_path="${output_dir}/graduation_drill_report.json"
  [[ -f "$report_path" ]] || record_failure "missing live report"
  [[ -f "${output_dir}/events.jsonl" ]] || record_failure "missing live events"
  [[ -f "${output_dir}/commands.txt" ]] || record_failure "missing live commands"
  [[ -f "${output_dir}/report.md" ]] || record_failure "missing live markdown"
  assert_report_shape "$report_path"
  jq -e '
    .decision == "pass"
    and .root_workspace_state == "excluded_standalone"
    and .violation_count == 0
    and all(.module_evidence[]; .core_export_present == true and .engine_export_present == true and (.core_source_path | length > 0) and (.engine_source_path | length > 0))
  ' "$report_path" >/dev/null || record_failure "live report mismatch"
  grep -Fq "bd-4w7h9.8 final acceptance suite passes" "${output_dir}/report.md" \
    || record_failure "live report missing final proof"
  record_pass "live-current-excluded-standalone"
}

run_fixture_case() {
  local case_name="$1"
  local expected_decision="$2"
  local required_reason="$3"
  local claim_text="$4"
  local omit_path="${5:-}"
  local bare_command="${6:-false}"
  local tmpdir output_dir root_manifest core_manifest core_lib engine_lib claim_file status expected_exit report_path

  tmpdir="$(mktemp -d)"
  mkdir -p "${tmpdir}/crates/franken-core" "${tmpdir}/docs"
  root_manifest="${tmpdir}/Cargo.toml"
  core_manifest="${tmpdir}/crates/franken-core/Cargo.toml"
  claim_file="${tmpdir}/docs/status.md"
  output_dir="${tmpdir}/out"
  write_truthful_root_manifest "$root_manifest"
  write_core_manifest "$core_manifest"
  write_libs_and_sources "$tmpdir"
  core_lib="${tmpdir}/crates/franken-core/src/lib.rs"
  engine_lib="${tmpdir}/crates/franken-engine/src/lib.rs"
  printf '%s\n' "$claim_text" >"$claim_file"

  if [[ "$omit_path" == "core_manifest" ]]; then
    core_manifest="${tmpdir}/crates/franken-core/MISSING-Cargo.toml"
  elif [[ "$omit_path" == "engine_lib" ]]; then
    engine_lib="${tmpdir}/crates/franken-engine/src/MISSING-lib.rs"
  fi

  if [[ "$expected_decision" == "fail_closed" ]]; then
    expected_exit=42
  else
    expected_exit=0
  fi

  cmd=(
    "$drill"
    --root-cargo "$root_manifest"
    --core-cargo "$core_manifest"
    --core-lib "$core_lib"
    --engine-lib "$engine_lib"
    --claim-file "$claim_file"
    --source-revision "smoke-${case_name}"
    --output-dir "$output_dir"
  )
  if [[ "$bare_command" == "true" ]]; then
    cmd+=(--required-proof-command "cargo check --all-targets")
  fi

  set +e
  "${cmd[@]}" >/dev/null 2>"${tmpdir}/stderr.log"
  status=$?
  set -e

  if [[ "$status" -ne "$expected_exit" ]]; then
    cat "${tmpdir}/stderr.log" >&2
    record_failure "${case_name} exit ${status}, expected ${expected_exit}"
  fi

  report_path="${output_dir}/graduation_drill_report.json"
  [[ -f "$report_path" ]] || record_failure "missing report ${case_name}"
  [[ -f "${output_dir}/events.jsonl" ]] || record_failure "missing events ${case_name}"
  [[ -f "${output_dir}/commands.txt" ]] || record_failure "missing commands ${case_name}"
  [[ -f "${output_dir}/report.md" ]] || record_failure "missing markdown ${case_name}"
  assert_report_shape "$report_path"
  jq -e --arg decision "$expected_decision" '.decision == $decision' "$report_path" >/dev/null \
    || record_failure "decision mismatch ${case_name}"
  if [[ -n "$required_reason" ]]; then
    jq -e --arg code "$required_reason" '.reason_codes | index($code)' "$report_path" >/dev/null \
      || record_failure "missing reason ${required_reason} ${case_name}"
  fi
  record_pass "$case_name"
}

run_check() {
  jq empty "$contract_json"
  bash -n "$drill" "${BASH_SOURCE[0]}"
  run_live_case
  run_fixture_case \
    "truthful-fixture" \
    "pass" \
    "" \
    "crates/franken-core remains excluded from the root workspace, while its standalone manifest is compileable. Workspace graduation remains blocked until bd-4w7h9.8 passes."
  git -C "$root_dir" diff --check -- \
    docs/FRANKEN_CORE_NO_MOCK_GRADUATION_DRILL_V1.md \
    docs/franken_core_no_mock_graduation_drill_v1.json \
    scripts/franken_core_no_mock_graduation_drill.sh \
    scripts/e2e/franken_core_no_mock_graduation_drill_smoke.sh
  record_pass "check"
}

run_negative() {
  run_fixture_case \
    "missing-core-manifest" \
    "fail_closed" \
    "missing_required_manifest_or_source" \
    "crates/franken-core remains excluded from the root workspace, while its standalone manifest is compileable." \
    "core_manifest"
  run_fixture_case \
    "missing-engine-lib" \
    "fail_closed" \
    "missing_required_manifest_or_source" \
    "crates/franken-core remains excluded from the root workspace, while its standalone manifest is compileable." \
    "engine_lib"
  run_fixture_case \
    "contradictory-doc-cargo-state" \
    "fail_closed" \
    "doc_manifest_contradiction" \
    "crates/franken-core is workspace-ready and included in the workspace."
  run_fixture_case \
    "bare-heavy-cargo-command" \
    "fail_closed" \
    "bare_heavy_cargo_proof" \
    "crates/franken-core remains excluded from the root workspace, while its standalone manifest is compileable." \
    "" \
    "true"
  record_pass "negative"
}

case "$mode" in
  check)
    run_check
    ;;
  negative)
    run_negative
    ;;
  -h|--help|help)
    printf 'Usage: ./scripts/e2e/franken_core_no_mock_graduation_drill_smoke.sh [check|negative]\n'
    ;;
  *)
    printf 'unknown mode: %s\n' "$mode" >&2
    exit 64
    ;;
esac
